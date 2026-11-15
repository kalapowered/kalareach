//! Reading source for every place that starts a task, a blocking pass or a thread.
//!
//! The daemon is one process: its own crate and every local crate it links run in it, and a task
//! that any of them starts lives as long as the process or as long as its owner. This finds each
//! start by reading the source of those crates through `syn`:
//!
//! * a call of a function or a method whose name begins with `spawn` and that is given an
//!   argument (`tokio::spawn`, `tokio::task::spawn_blocking`, `std::thread::spawn`, a join set's
//!   `spawn` under any receiver name, `thread::Builder`'s `spawn`, `Handle::spawn`); a method
//!   `spawn` with no argument starts a child process and is not a start;
//! * a call of a helper that the roster names, which is a function of this code that starts a
//!   task for its caller;
//! * the same, inside the tokens of every macro (`matches!`, `select!`, a `macro_rules!` body),
//!   which `syn` does not parse.
//!
//! Each start is keyed by its file, its function, its form (the name of the start function as
//! written) and its callee (what the start runs), so that one start that replaces another in the
//! same function changes the key.
//!
//! Items under `#[cfg(test)]` are left out: a module, a function, an `impl`, a statement. The
//! modules of a crate are reached through its `mod` declarations from its root file, so a file that
//! no declaration reaches, or that only a test declaration reaches, is not read.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use quote::ToTokens as _;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{Attribute, Expr, Item, Meta, Token};
use toml_edit::{DocumentMut, Item as TomlItem};

/// Where source text comes from: the repository on disk, or a small tree of text in a case.
/// Paths are relative to the repository's root and use the platform's separator.
pub trait Files {
    /// The text of a file, or `None` where there is no such file.
    fn read(&self, path: &Path) -> Option<String>;
}

/// The repository on disk.
pub struct Disk(pub PathBuf);

impl Files for Disk {
    fn read(&self, path: &Path) -> Option<String> {
        std::fs::read_to_string(self.0.join(path)).ok()
    }
}

/// A tree of text.
#[derive(Default)]
pub struct Memory(pub BTreeMap<PathBuf, String>);

impl Memory {
    /// A tree from `(path, text)` pairs.
    pub fn of(files: &[(&str, &str)]) -> Self {
        Self(
            files
                .iter()
                .map(|(path, text)| (PathBuf::from(path), (*text).to_string()))
                .collect(),
        )
    }
}

impl Files for Memory {
    fn read(&self, path: &Path) -> Option<String> {
        self.0.get(path).cloned()
    }
}

/// A local crate that the daemon's process links.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LinkedCrate {
    /// Its package name.
    pub name: String,
    /// Its folder, relative to the repository's root.
    pub dir: PathBuf,
}

/// One place that starts a task, a blocking pass or a thread.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Start {
    /// The source file, relative to the repository's root, with `/` separators.
    pub file: String,
    /// The enclosing function: its modules, its type and its name, joined by `::`.
    pub function: String,
    /// The start function as written: `tokio::spawn`, `.spawn_blocking`.
    pub form: String,
    /// What the start runs: the function it calls, or the first call of an async block or a
    /// closure that does work.
    pub callee: String,
    /// Whether the start's own expression is awaited where it stands: `spawn_blocking(f).await`.
    pub at_once: bool,
    /// Whether the start is in code that a shipped build does not compile in (the `testing`
    /// feature).
    pub unshipped: bool,
}

impl Start {
    /// The four fields that make a start the same as another.
    pub fn key(&self) -> (String, String, String, String) {
        (
            self.file.clone(),
            self.function.clone(),
            self.form.clone(),
            self.callee.clone(),
        )
    }
}

/// A function of this code that starts a task running one of its own parameters and does not
/// await it, so that its caller decides what runs: the roster must name it, and each call of it is
/// a start. A name that begins with `spawn` is a start by its name and needs no line.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct HelperShape {
    /// The file and function that holds the start.
    pub file: String,
    /// The function's name, as a caller writes it.
    pub name: String,
}

/// What a scan found.
#[derive(Debug, Default)]
pub struct Scan {
    /// Every start, in the order the files were read.
    pub starts: Vec<Start>,
    /// Functions that start a task that runs one of their parameters, without awaiting it.
    pub helper_shapes: Vec<HelperShape>,
    /// The files read.
    pub files: BTreeSet<String>,
}

fn normalise(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn slashed(path: &Path) -> String {
    path.components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn manifest(files: &dyn Files, dir: &Path) -> Result<DocumentMut, String> {
    let path = dir.join("Cargo.toml");
    let text = files
        .read(&path)
        .ok_or_else(|| format!("no manifest at {}", path.display()))?;
    text.parse::<DocumentMut>()
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// The local crates that a process of `daemon` links: the crate itself and, through every
/// normal dependency (target-specific ones included, optional ones included), each crate whose
/// folder is in the repository. Development and build dependencies are not linked into a
/// shipped program and are not followed.
pub fn linked_crates(files: &dyn Files, daemon: &Path) -> Result<Vec<LinkedCrate>, String> {
    let workspace = manifest(files, Path::new(""))?;
    let mut by_alias: BTreeMap<String, PathBuf> = BTreeMap::new();
    if let Some(table) = workspace
        .get("workspace")
        .and_then(|item| item.get("dependencies"))
        .and_then(TomlItem::as_table_like)
    {
        for (alias, item) in table.iter() {
            if let Some(path) = item
                .as_table_like()
                .and_then(|entry| entry.get("path"))
                .and_then(TomlItem::as_str)
            {
                by_alias.insert(alias.to_string(), normalise(Path::new(path)));
            }
        }
    }

    let mut found: BTreeMap<PathBuf, LinkedCrate> = BTreeMap::new();
    let mut todo = vec![normalise(daemon)];
    while let Some(dir) = todo.pop() {
        if found.contains_key(&dir) {
            continue;
        }
        let document = manifest(files, &dir)?;
        let name = document
            .get("package")
            .and_then(|package| package.get("name"))
            .and_then(TomlItem::as_str)
            .ok_or_else(|| format!("{}: no package name", dir.display()))?
            .to_string();
        found.insert(
            dir.clone(),
            LinkedCrate {
                name,
                dir: dir.clone(),
            },
        );

        let mut tables: Vec<&dyn toml_edit::TableLike> = Vec::new();
        if let Some(table) = document
            .get("dependencies")
            .and_then(TomlItem::as_table_like)
        {
            tables.push(table);
        }
        if let Some(targets) = document.get("target").and_then(TomlItem::as_table_like) {
            for (_, target) in targets.iter() {
                if let Some(table) = target.get("dependencies").and_then(TomlItem::as_table_like) {
                    tables.push(table);
                }
            }
        }
        for table in tables {
            for (alias, item) in table.iter() {
                let Some(entry) = item.as_table_like() else {
                    continue;
                };
                let local = if entry
                    .get("workspace")
                    .and_then(TomlItem::as_bool)
                    .unwrap_or(false)
                {
                    by_alias.get(alias).cloned()
                } else {
                    entry
                        .get("path")
                        .and_then(TomlItem::as_str)
                        .map(|path| normalise(&dir.join(path)))
                };
                if let Some(path) = local
                    && files.read(&path.join("Cargo.toml")).is_some()
                {
                    todo.push(path);
                }
            }
        }
    }
    Ok(found.into_values().collect())
}

/// The root files of the program's own code in the linked crates: each crate's library and, for
/// the daemon's crate, its binary of the same name.
pub fn root_files(
    files: &dyn Files,
    crates: &[LinkedCrate],
    daemon: &Path,
) -> Result<Vec<PathBuf>, String> {
    let daemon = normalise(daemon);
    let mut roots = Vec::new();
    for linked in crates {
        let document = manifest(files, &linked.dir)?;
        let library = document
            .get("lib")
            .and_then(|lib| lib.get("path"))
            .and_then(TomlItem::as_str)
            .unwrap_or("src/lib.rs");
        let library = normalise(&linked.dir.join(library));
        if files.read(&library).is_some() {
            roots.push(library);
        }
        if linked.dir == daemon {
            let mut named = false;
            if let Some(bins) = document.get("bin").and_then(TomlItem::as_array_of_tables) {
                for bin in bins {
                    if bin.get("name").and_then(TomlItem::as_str) == Some(linked.name.as_str()) {
                        let path = bin.get("path").and_then(TomlItem::as_str).ok_or_else(|| {
                            format!("the daemon's binary has no path in {}", linked.name)
                        })?;
                        roots.push(normalise(&linked.dir.join(path)));
                        named = true;
                    }
                }
            }
            if !named {
                return Err(format!(
                    "{} has no binary of its own name: the daemon's entry point is not found",
                    linked.name
                ));
            }
        }
    }
    Ok(roots)
}

/// Every start in the source reached from `roots`. `helpers` are the names of this code's own
/// functions that start a task for their caller, each with the path (a file or a folder) under which
/// its calls are looked for.
pub fn scan(
    files: &dyn Files,
    roots: &[PathBuf],
    helpers: &[(String, String)],
) -> Result<Scan, String> {
    let mut walker = Walker {
        files,
        helpers,
        file: PathBuf::new(),
        dir: PathBuf::new(),
        inline: 0,
        scope: Vec::new(),
        seen: BTreeSet::new(),
        awaited: BTreeSet::new(),
        unshipped: 0,
        scan: Scan::default(),
        error: None,
    };
    for root in roots {
        let parent = root.parent().map(Path::to_path_buf).unwrap_or_default();
        walker.read_file(root.clone(), parent, "")?;
    }
    match walker.error {
        Some(error) => Err(error),
        None => Ok(walker.scan),
    }
}

struct Walker<'a> {
    files: &'a dyn Files,
    /// Each helper's name and the path that its calls are looked for under.
    helpers: &'a [(String, String)],
    /// The file being read, and the folder that the modules it declares are found in.
    file: PathBuf,
    dir: PathBuf,
    /// How many inline modules the walk is inside.
    inline: usize,
    scope: Vec<String>,
    seen: BTreeSet<PathBuf>,
    /// The addresses of calls that an `.await` waits on directly.
    awaited: BTreeSet<usize>,
    /// How many enclosing items a shipped build does not compile in.
    unshipped: usize,
    scan: Scan,
    error: Option<String>,
}

impl Walker<'_> {
    /// Read one file as a module whose own modules lie in `dir`.
    fn read_file(&mut self, file: PathBuf, dir: PathBuf, label: &str) -> Result<(), String> {
        if !self.seen.insert(file.clone()) {
            return Ok(());
        }
        let text = self
            .files
            .read(&file)
            .ok_or_else(|| format!("{} ({label}) is not a file of this tree", file.display()))?;
        let parsed =
            syn::parse_file(&text).map_err(|error| format!("{}: {error}", file.display()))?;
        self.scan.files.insert(slashed(&file));
        if test_only(&parsed.attrs) {
            return Ok(());
        }
        let saved = (
            std::mem::replace(&mut self.file, file),
            std::mem::replace(&mut self.dir, dir),
            std::mem::replace(&mut self.inline, 0),
            std::mem::take(&mut self.scope),
        );
        self.visit_file(&parsed);
        (self.file, self.dir, self.inline, self.scope) = saved;
        Ok(())
    }

    fn fail(&mut self, message: String) {
        if self.error.is_none() {
            self.error = Some(message);
        }
    }

    fn push_start(&mut self, form: String, callee: String, at_once: bool) {
        self.scan.starts.push(Start {
            file: slashed(&self.file),
            function: self.scope.join("::"),
            form,
            callee,
            at_once,
            unshipped: self.unshipped > 0,
        });
    }

    /// Whether a call of this name is a start. A name that begins with `spawn` is given an
    /// argument; a helper of the roster is any call of its name.
    fn is_start(&self, name: &str, arguments: usize) -> bool {
        (name.starts_with("spawn") && arguments > 0)
            || self.helpers.iter().any(|(helper, scope)| {
                helper == name && slashed(&self.file).starts_with(scope.as_str())
            })
    }

    fn load_module(&mut self, module: &syn::ItemMod) {
        let name = module.ident.to_string();
        let path = module.attrs.iter().find_map(|attribute| {
            if !attribute.path().is_ident("path") {
                return None;
            }
            match &attribute.meta {
                Meta::NameValue(value) => match &value.value {
                    Expr::Lit(literal) => match &literal.lit {
                        syn::Lit::Str(text) => Some(text.value()),
                        _ => None,
                    },
                    _ => None,
                },
                _ => None,
            }
        });
        let from = self.file.clone();
        let (file, dir) = if let Some(path) = path {
            if self.inline > 0 {
                self.fail(format!(
                    "{}: a path attribute inside an inline module is not read by this scan",
                    from.display()
                ));
                return;
            }
            let file = normalise(&from.parent().unwrap_or(Path::new("")).join(path));
            let dir = file.parent().map(Path::to_path_buf).unwrap_or_default();
            (file, dir)
        } else {
            let flat = self.dir.join(format!("{name}.rs"));
            let nested = self.dir.join(&name).join("mod.rs");
            if self.files.read(&flat).is_some() {
                (flat, self.dir.join(&name))
            } else if self.files.read(&nested).is_some() {
                (nested, self.dir.join(&name))
            } else {
                self.fail(format!(
                    "{}: `mod {name};` has no file at {} or {}",
                    from.display(),
                    flat.display(),
                    nested.display()
                ));
                return;
            }
        };
        if let Err(error) = self.read_file(file, dir, &name) {
            self.fail(error);
        }
    }

    fn start_in_call(&mut self, name: &str, form: String, arguments: Vec<&Expr>, at_once: bool) {
        if !self.is_start(name, arguments.len()) {
            return;
        }
        let callee = arguments
            .first()
            .map_or_else(|| "-".to_string(), |first| callee_of(first));
        self.push_start(form, callee, at_once);
    }

    fn scan_tokens(&mut self, stream: TokenStream) {
        let trees: Vec<TokenTree> = stream.into_iter().collect();
        for (index, tree) in trees.iter().enumerate() {
            match tree {
                TokenTree::Group(group) => self.scan_tokens(group.stream()),
                TokenTree::Ident(ident) => {
                    let name = ident.to_string();
                    let Some(group) = call_group(&trees, index + 1) else {
                        continue;
                    };
                    let first = first_argument(group.stream());
                    let arguments = usize::from(!group.stream().is_empty());
                    if !self.is_start(&name, arguments) {
                        continue;
                    }
                    let form = written_form(&trees, index, &name);
                    let callee = first.map_or_else(|| "-".to_string(), callee_of_tokens);
                    self.push_start(form, callee, false);
                }
                _ => {}
            }
        }
    }

    fn visit_function(
        &mut self,
        name: String,
        signature: &syn::Signature,
        walk: impl FnOnce(&mut Self),
    ) {
        self.scope.push(name.clone());
        let before = self.scan.starts.len();
        walk(self);
        self.scope.pop();
        let parameters = parameter_names(signature);
        let runs_a_parameter = !name.starts_with("spawn")
            && self.scan.starts[before..].iter().any(|start| {
                !start.at_once
                    && parameters.contains(&start.callee)
                    && start
                        .form
                        .rsplit("::")
                        .next()
                        .is_some_and(|last| last.trim_start_matches('.').starts_with("spawn"))
            });
        if runs_a_parameter {
            self.scan.helper_shapes.push(HelperShape {
                file: slashed(&self.file),
                name,
            });
        }
    }
}

/// The parenthesised group that follows a name at `index`, past a turbofish.
fn call_group(trees: &[TokenTree], mut index: usize) -> Option<&proc_macro2::Group> {
    if matches!(trees.get(index), Some(TokenTree::Punct(first)) if first.as_char() == ':')
        && matches!(trees.get(index + 1), Some(TokenTree::Punct(second)) if second.as_char() == ':')
        && matches!(trees.get(index + 2), Some(TokenTree::Punct(open)) if open.as_char() == '<')
    {
        let mut depth = 0usize;
        index += 2;
        while let Some(tree) = trees.get(index) {
            if let TokenTree::Punct(mark) = tree {
                match mark.as_char() {
                    '<' => depth += 1,
                    '>' => {
                        depth -= 1;
                        if depth == 0 {
                            index += 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            index += 1;
        }
    }
    match trees.get(index) {
        Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Parenthesis => Some(group),
        _ => None,
    }
}

fn is_punct(tree: Option<&TokenTree>, mark: char) -> bool {
    matches!(tree, Some(TokenTree::Punct(punct)) if punct.as_char() == mark)
}

/// The start function as it is written before its call: `.name` for a method, the path for a
/// function.
fn written_form(trees: &[TokenTree], index: usize, name: &str) -> String {
    if index >= 1 && is_punct(trees.get(index - 1), '.') {
        return format!(".{name}");
    }
    let mut segments = vec![name.to_string()];
    let mut at = index;
    while at >= 3
        && is_punct(trees.get(at - 1), ':')
        && is_punct(trees.get(at - 2), ':')
        && matches!(trees.get(at - 3), Some(TokenTree::Ident(_)))
    {
        if let Some(TokenTree::Ident(segment)) = trees.get(at - 3) {
            segments.insert(0, segment.to_string());
        }
        at -= 3;
    }
    segments.join("::")
}

/// The tokens of a call's first argument: up to the first comma outside any group.
fn first_argument(stream: TokenStream) -> Option<TokenStream> {
    let mut first = TokenStream::new();
    let mut any = false;
    for tree in stream {
        if is_punct(Some(&tree), ',') {
            break;
        }
        any = true;
        first.extend([tree]);
    }
    any.then_some(first)
}

fn callee_of_tokens(tokens: TokenStream) -> String {
    match syn::parse2::<Expr>(tokens.clone()) {
        Ok(expression) => callee_of(&expression),
        Err(_) => {
            let words: Vec<String> = tokens
                .into_iter()
                .filter_map(|tree| match tree {
                    TokenTree::Ident(ident) => Some(ident.to_string()),
                    _ => None,
                })
                .take(3)
                .collect();
            format!("tokens({})", words.join(" "))
        }
    }
}

fn path_text(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

/// What the argument of a start runs.
fn callee_of(expression: &Expr) -> String {
    match expression {
        Expr::Call(call) => match &*call.func {
            Expr::Path(path) => {
                let text = path_text(&path.path);
                // `Box::pin(future)` and `Pin::new(..)` only wrap what is run.
                if matches!(
                    text.as_str(),
                    "Box::pin" | "Pin::new" | "std::pin::Pin::new"
                ) && let Some(inner) = call.args.first()
                {
                    return callee_of(inner);
                }
                text
            }
            other => format!(
                "call({})",
                other.to_token_stream().to_string().replace(' ', "")
            ),
        },
        Expr::MethodCall(call) => format!(".{}", call.method),
        Expr::Async(block) => {
            block_callee("async", |collector| collector.visit_block(&block.block))
        }
        Expr::Closure(closure) => {
            block_callee("closure", |collector| collector.visit_expr(&closure.body))
        }
        Expr::Block(block) => {
            block_callee("block", |collector| collector.visit_block(&block.block))
        }
        Expr::Path(path) => path_text(&path.path),
        Expr::Paren(inner) => callee_of(&inner.expr),
        Expr::Group(inner) => callee_of(&inner.expr),
        Expr::Macro(mac) => format!("{}!", path_text(&mac.mac.path)),
        _ => "expr".to_string(),
    }
}

/// Calls that carry no work of their own: constructors, conversions, handle plumbing. A block's
/// callee is not one of these.
const ADAPTERS: &[&str] = &[
    "Some",
    "Ok",
    "Err",
    "drop",
    "Arc::clone",
    "Rc::clone",
    "Box::new",
    "Box::pin",
    "Vec::new",
    "String::new",
    "Default::default",
    ".clone",
    ".map",
    ".map_err",
    ".and_then",
    ".ok",
    ".ok_or",
    ".ok_or_else",
    ".unwrap",
    ".expect",
    ".unwrap_or",
    ".unwrap_or_else",
    ".unwrap_or_default",
    ".as_ref",
    ".as_mut",
    ".as_deref",
    ".into",
    ".to_string",
    ".to_owned",
    ".to_vec",
    ".iter",
    ".into_iter",
    ".collect",
    ".upgrade",
    ".borrow",
    ".lock",
    ".get",
    ".load",
    ".is_ok",
    ".is_err",
    ".is_some",
    ".is_none",
    ".is_some_and",
    ".is_empty",
    ".len",
    ".min",
    ".max",
    ".take",
];

/// What a block runs, as `kind{call}`: the first call that is awaited and does work or, with none
/// awaited, the first call that does work. A block with no such call is `kind{}`.
fn block_callee(kind: &str, walk: impl FnOnce(&mut Calls)) -> String {
    let mut calls = Calls::default();
    walk(&mut calls);
    let work = calls
        .awaited
        .iter()
        .chain(calls.names.iter())
        .find(|name| !ADAPTERS.contains(&name.as_str()))
        .cloned()
        .unwrap_or_default();
    format!("{kind}{{{work}}}")
}

/// The calls of a block in source order: every one, and the ones that an `.await` waits on.
#[derive(Default)]
struct Calls {
    names: Vec<String>,
    awaited: Vec<String>,
}

fn call_name(expression: &Expr) -> Option<String> {
    match expression {
        Expr::Call(call) => match &*call.func {
            Expr::Path(path) => Some(path_text(&path.path)),
            _ => None,
        },
        Expr::MethodCall(call) => Some(format!(".{}", call.method)),
        Expr::Paren(inner) => call_name(&inner.expr),
        Expr::Try(inner) => call_name(&inner.expr),
        _ => None,
    }
}

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.names.push(path_text(&path.path));
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.names.push(format!(".{}", call.method));
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_await(&mut self, awaited: &'ast syn::ExprAwait) {
        if let Some(name) = call_name(&awaited.base) {
            self.awaited.push(name);
        }
        visit::visit_expr_await(self, awaited);
    }
}

/// The names of a function's parameters.
fn parameter_names(signature: &syn::Signature) -> Vec<String> {
    signature
        .inputs
        .iter()
        .filter_map(|input| match input {
            syn::FnArg::Typed(typed) => match &*typed.pat {
                syn::Pat::Ident(ident) => Some(ident.ident.to_string()),
                _ => None,
            },
            syn::FnArg::Receiver(_) => None,
        })
        .collect()
}

/// Whether a `cfg` condition holds only where `leaf` holds: a leaf is true or false by itself,
/// `all` holds where any part does, `any` where every part does, and `not` never.
fn condition_holds_only_where(condition: &Meta, leaf: &dyn Fn(&Meta) -> bool) -> bool {
    match condition {
        Meta::List(list) => {
            let parts = list
                .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                .unwrap_or_default();
            if list.path.is_ident("all") {
                parts
                    .iter()
                    .any(|part| condition_holds_only_where(part, leaf))
            } else if list.path.is_ident("any") {
                !parts.is_empty()
                    && parts
                        .iter()
                        .all(|part| condition_holds_only_where(part, leaf))
            } else {
                false
            }
        }
        other => leaf(other),
    }
}

fn cfg_holds_only_where(attributes: &[Attribute], leaf: &dyn Fn(&Meta) -> bool) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("cfg")
            && attribute
                .parse_args::<Meta>()
                .is_ok_and(|condition| condition_holds_only_where(&condition, leaf))
    })
}

/// Whether the attributes keep an item out of every build but a test build: `#[cfg(test)]` and
/// the like, and a test function's own attribute.
fn test_only(attributes: &[Attribute]) -> bool {
    cfg_holds_only_where(
        attributes,
        &|meta| matches!(meta, Meta::Path(path) if path.is_ident("test")),
    ) || attributes.iter().any(|attribute| {
        attribute
            .path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "test")
    })
}

/// Whether the attributes keep an item out of a shipped build: a test build or the `testing`
/// feature, which no shipped build enables.
fn unshipped(attributes: &[Attribute]) -> bool {
    cfg_holds_only_where(attributes, &|meta| match meta {
        Meta::Path(path) => path.is_ident("test"),
        Meta::NameValue(pair) => {
            pair.path.is_ident("feature")
                && matches!(&pair.value, Expr::Lit(literal)
                    if matches!(&literal.lit, syn::Lit::Str(text) if text.value() == "testing"))
        }
        Meta::List(_) => false,
    })
}

fn item_attributes(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

fn expression_attributes(expression: &Expr) -> &[Attribute] {
    match expression {
        Expr::Array(e) => &e.attrs,
        Expr::Assign(e) => &e.attrs,
        Expr::Async(e) => &e.attrs,
        Expr::Await(e) => &e.attrs,
        Expr::Binary(e) => &e.attrs,
        Expr::Block(e) => &e.attrs,
        Expr::Break(e) => &e.attrs,
        Expr::Call(e) => &e.attrs,
        Expr::Cast(e) => &e.attrs,
        Expr::Closure(e) => &e.attrs,
        Expr::Const(e) => &e.attrs,
        Expr::Continue(e) => &e.attrs,
        Expr::Field(e) => &e.attrs,
        Expr::ForLoop(e) => &e.attrs,
        Expr::Group(e) => &e.attrs,
        Expr::If(e) => &e.attrs,
        Expr::Index(e) => &e.attrs,
        Expr::Infer(e) => &e.attrs,
        Expr::Let(e) => &e.attrs,
        Expr::Lit(e) => &e.attrs,
        Expr::Loop(e) => &e.attrs,
        Expr::Macro(e) => &e.attrs,
        Expr::Match(e) => &e.attrs,
        Expr::MethodCall(e) => &e.attrs,
        Expr::Paren(e) => &e.attrs,
        Expr::Path(e) => &e.attrs,
        Expr::Range(e) => &e.attrs,
        Expr::RawAddr(e) => &e.attrs,
        Expr::Reference(e) => &e.attrs,
        Expr::Repeat(e) => &e.attrs,
        Expr::Return(e) => &e.attrs,
        Expr::Struct(e) => &e.attrs,
        Expr::Try(e) => &e.attrs,
        Expr::TryBlock(e) => &e.attrs,
        Expr::Tuple(e) => &e.attrs,
        Expr::Unary(e) => &e.attrs,
        Expr::Unsafe(e) => &e.attrs,
        Expr::While(e) => &e.attrs,
        Expr::Yield(e) => &e.attrs,
        _ => &[],
    }
}

fn type_name(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(path) => path
            .path
            .segments
            .last()
            .map_or_else(String::new, |segment| segment.ident.to_string()),
        syn::Type::Reference(reference) => type_name(&reference.elem),
        other => other.to_token_stream().to_string().replace(' ', ""),
    }
}

impl<'ast> Visit<'ast> for Walker<'_> {
    fn visit_item(&mut self, item: &'ast Item) {
        if test_only(item_attributes(item)) {
            return;
        }
        let gated = unshipped(item_attributes(item));
        self.unshipped += usize::from(gated);
        visit::visit_item(self, item);
        self.unshipped -= usize::from(gated);
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        let attributes: &[Attribute] = match item {
            syn::ImplItem::Const(item) => &item.attrs,
            syn::ImplItem::Fn(item) => &item.attrs,
            syn::ImplItem::Type(item) => &item.attrs,
            syn::ImplItem::Macro(item) => &item.attrs,
            _ => &[],
        };
        if test_only(attributes) {
            return;
        }
        let gated = unshipped(attributes);
        self.unshipped += usize::from(gated);
        visit::visit_impl_item(self, item);
        self.unshipped -= usize::from(gated);
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        let attributes: &[Attribute] = match item {
            syn::TraitItem::Const(item) => &item.attrs,
            syn::TraitItem::Fn(item) => &item.attrs,
            syn::TraitItem::Type(item) => &item.attrs,
            syn::TraitItem::Macro(item) => &item.attrs,
            _ => &[],
        };
        if test_only(attributes) {
            return;
        }
        let gated = unshipped(attributes);
        self.unshipped += usize::from(gated);
        visit::visit_trait_item(self, item);
        self.unshipped -= usize::from(gated);
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if test_only(&local.attrs) {
            return;
        }
        visit::visit_local(self, local);
    }

    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        if test_only(&arm.attrs) {
            return;
        }
        visit::visit_arm(self, arm);
    }

    fn visit_expr(&mut self, expression: &'ast Expr) {
        if test_only(expression_attributes(expression)) {
            return;
        }
        visit::visit_expr(self, expression);
    }

    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        match &module.content {
            Some((_, items)) => {
                let name = module.ident.to_string();
                let saved = self.dir.clone();
                self.dir = self.dir.join(&name);
                self.inline += 1;
                self.scope.push(name);
                for item in items {
                    self.visit_item(item);
                }
                self.scope.pop();
                self.inline -= 1;
                self.dir = saved;
            }
            None => self.load_module(module),
        }
    }

    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        self.visit_function(function.sig.ident.to_string(), &function.sig, |walker| {
            visit::visit_item_fn(walker, function);
        });
    }

    fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
        self.visit_function(function.sig.ident.to_string(), &function.sig, |walker| {
            visit::visit_impl_item_fn(walker, function);
        });
    }

    fn visit_trait_item_fn(&mut self, function: &'ast syn::TraitItemFn) {
        self.visit_function(function.sig.ident.to_string(), &function.sig, |walker| {
            visit::visit_trait_item_fn(walker, function);
        });
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        self.scope.push(type_name(&item.self_ty));
        visit::visit_item_impl(self, item);
        self.scope.pop();
    }

    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        self.scope.push(item.ident.to_string());
        visit::visit_item_trait(self, item);
        self.scope.pop();
    }

    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        self.scope.push(item.ident.to_string());
        visit::visit_item_const(self, item);
        self.scope.pop();
    }

    fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
        self.scope.push(item.ident.to_string());
        visit::visit_item_static(self, item);
        self.scope.pop();
    }

    fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
        if let Some(name) = &item.ident {
            self.scope.push(format!("macro_rules!{name}"));
            visit::visit_item_macro(self, item);
            self.scope.pop();
        } else {
            visit::visit_item_macro(self, item);
        }
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.scan_tokens(mac.tokens.clone());
    }

    fn visit_expr_await(&mut self, awaited: &'ast syn::ExprAwait) {
        let mut base = &*awaited.base;
        while let Expr::Paren(inner) = base {
            base = &inner.expr;
        }
        match base {
            Expr::Call(call) => {
                self.awaited.insert(std::ptr::from_ref(call) as usize);
            }
            Expr::MethodCall(call) => {
                self.awaited.insert(std::ptr::from_ref(call) as usize);
            }
            _ => {}
        }
        visit::visit_expr_await(self, awaited);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        let at_once = self.awaited.remove(&(std::ptr::from_ref(call) as usize));
        if let Expr::Path(path) = &*call.func
            && let Some(last) = path.path.segments.last()
        {
            let name = last.ident.to_string();
            self.start_in_call(
                &name,
                path_text(&path.path),
                call.args.iter().collect(),
                at_once,
            );
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let at_once = self.awaited.remove(&(std::ptr::from_ref(call) as usize));
        let name = call.method.to_string();
        self.start_in_call(
            &name,
            format!(".{name}"),
            call.args.iter().collect(),
            at_once,
        );
        visit::visit_expr_method_call(self, call);
    }
}
