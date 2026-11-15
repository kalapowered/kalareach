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
//!   task for its caller. A function is a helper when one of its parameters has a closure or a
//!   future type (`impl FnOnce`, `impl Future`, a generic parameter bounded to one, a boxed one)
//!   and a start that is not awaited where it stands runs it: the start's argument names that
//!   parameter, or runs a local that was made from it (the local is the whole argument, is called
//!   or is awaited). A helper's call is keyed by the argument at that parameter's place;
//! * the same, inside the tokens of every macro (`matches!`, `select!`, a `macro_rules!` body),
//!   which `syn` does not parse.
//!
//! Each start is keyed by its file, its function, its form (the name of the start function as
//! written) and its callee (what the start runs), so that one start that replaces another in the
//! same function changes the key. A start is awaited where it stands when its call is followed by
//! `.await`, in code or in a macro's tokens.
//!
//! The scan also keeps lists for the roster's checks. The first is what is awaited and where:
//! `name.await`, a name in the future of a `select!` branch (the text between the pattern's `=` and
//! the `=>`; a name that a handler or a precondition only drops, aborts or tests is not awaited),
//! and every name inside a `join!`, by file and function. For a start whose handle a `let` holds
//! (`let task = tokio::spawn(..)`) it also records that the name is awaited in the scope where it
//! is bound, so that a second handle of the same name in another scope does not stand for it; a
//! `joined` row's marker is checked against these. A method call by the name of a helper that no
//! function of that name taking `self` defines is not a call of the helper.
//!
//! The names that a macro's tokens bind have their scopes as far as tokens show them, so that a
//! local of the handle's name is not the handle: a `select!` branch's pattern binds for its handler;
//! a `let` binds from the end of its statement to the end of its group; `if let`, `while let` and
//! `for` bind in their block; a `match` arm's pattern binds in its arm. Awaiting a name bound so
//! awaits neither the handle nor the parameter of that name. Every lower-case word of a pattern
//! counts as a binding (a field's name too), which can hide a join from the roster's check and never
//! invents one. What a macro's tokens still hide is a stated limit and no more: the parameters of a
//! closure; a name that a nested macro or a `macro_rules!` expansion binds; an item (`fn`, `use`,
//! `const`) that shadows a name; and a closure or a branch that nothing calls or takes, whose
//! `.await` counts as awaited. The last is the function paths of watched
//! crates that code outside them names: a path in an expression whose last segment is in lower
//! case, with a name that a `use` brought in read as the path it stands for, and each glob import
//! as the glob. A call through another function, and a method called on a value of one of those
//! crates' types, are not seen.
//!
//! Items under `#[cfg(test)]` are left out: a module, a function, an `impl`, a statement. The
//! modules of a crate are reached through its `mod` declarations from its root file, so a file that
//! no declaration reaches, or that only a test declaration reaches, is not read.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use proc_macro2::{Delimiter, Spacing, TokenStream, TokenTree};
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
    /// What each argument of the start's call runs, in order: a helper's caller hands its work
    /// over at the position of the helper's parameter.
    pub arguments: Vec<String>,
    /// The first parameter, by position, of the enclosing function that has a closure or a future
    /// type and that the start uses, directly or through a local made from it.
    pub parameter: Option<usize>,
    /// The roster helper (its name and scope) that the start is a call of, until the callee is
    /// read from the argument at the helper's position.
    helper: Option<(String, String)>,
    /// A number that is the start's own, so that what is awaited can name the start whose handle
    /// it waits on.
    pub id: usize,
    /// The name of the local that holds the start's handle: `let task = tokio::spawn(..)`.
    pub handle: Option<String>,
    /// The call that is the start, by its address in the tree being read.
    call: Option<usize>,
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
    /// The place of the parameter that the start runs, not counting a receiver.
    pub position: usize,
    /// Whether the function takes `self`, which a call through a path hands over as its first
    /// argument.
    pub receiver: bool,
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
    /// What is awaited where the handle of a start may be joined: a file, the function, and the
    /// name of the handle (`name.await`, a name in the future of a `select!` branch, or a name
    /// inside a `join!`).
    pub awaits: BTreeSet<(String, String, String)>,
    /// The starts whose handle is awaited under the name that holds it, in the scope of that name
    /// (`Start::id`).
    pub joined: BTreeSet<usize>,
    /// The function paths of the watched crates that code outside them names: a path in an
    /// expression whose last segment is in lower case, with a name that a `use` brought in read as
    /// the path it stands for, and each glob import.
    pub named: BTreeSet<String>,
}

/// A linked crate whose paths the scan lists where other code names them.
#[derive(Clone, Debug)]
pub struct Watched {
    /// The crate's name as a path is written: `kr_worker`.
    pub ident: String,
    /// Its folder, relative to the repository's root.
    pub dir: PathBuf,
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
/// its calls are looked for. `watched` are the crates whose paths are listed where other code names
/// them.
pub fn scan(
    files: &dyn Files,
    roots: &[PathBuf],
    helpers: &[(String, String)],
    watched: &[Watched],
) -> Result<Scan, String> {
    let mut walker = Walker {
        files,
        helpers,
        watched,
        file: PathBuf::new(),
        dir: PathBuf::new(),
        inline: 0,
        scope: Vec::new(),
        seen: BTreeSet::new(),
        awaited: BTreeSet::new(),
        unshipped: 0,
        outside: false,
        aliases: BTreeMap::new(),
        frames: Vec::new(),
        generics: Vec::new(),
        bindings: Vec::new(),
        call: None,
        next_start: 0,
        scan: Scan::default(),
        error: None,
    };
    for root in roots {
        let parent = root.parent().map(Path::to_path_buf).unwrap_or_default();
        walker.read_file(root.clone(), parent, "")?;
    }
    if let Some(error) = walker.error {
        return Err(error);
    }
    let mut scan = walker.scan;
    // A helper's caller hands its work over at the place of the helper's parameter. A call by a
    // method's form (`.name(..)`) is a call of a helper that takes `self`; where every function of
    // that name under the scope takes none, it is a call of another function, a method of the same
    // name, and is not a start.
    let mut not_calls = BTreeSet::new();
    for start in &mut scan.starts {
        let Some((name, scope)) = start.helper.take() else {
            continue;
        };
        let method_call = start.form.starts_with('.');
        let named: Vec<&HelperShape> = scan
            .helper_shapes
            .iter()
            .filter(|shape| shape.name == name && shape.file.starts_with(&scope))
            .collect();
        let shape = named
            .iter()
            .find(|shape| shape.receiver || !method_call)
            .copied();
        if shape.is_none() && !named.is_empty() {
            not_calls.insert(start.id);
            continue;
        }
        start.callee = shape
            .and_then(|shape| {
                let through_a_path = shape.receiver && !method_call;
                start
                    .arguments
                    .get(shape.position + usize::from(through_a_path))
            })
            .cloned()
            .unwrap_or_else(|| "-".to_string());
    }
    scan.starts.retain(|start| !not_calls.contains(&start.id));
    Ok(scan)
}

struct Walker<'a> {
    files: &'a dyn Files,
    /// Each helper's name and the path that its calls are looked for under.
    helpers: &'a [(String, String)],
    watched: &'a [Watched],
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
    /// Whether the file is outside every watched crate, so that its paths into one are listed.
    outside: bool,
    /// What each name a `use` of the file brings in stands for, as a path.
    aliases: BTreeMap<String, Vec<String>>,
    /// For each function being read, the parameters of a closure or future type and the locals
    /// made from them.
    frames: Vec<Frame>,
    /// The generics of the enclosing `impl` and `trait` items.
    generics: Vec<syn::Generics>,
    /// The names in scope in the function being read, the innermost last, each with the start whose
    /// handle it holds, if it holds one.
    bindings: Vec<Binding>,
    /// The call whose start is being recorded.
    call: Option<usize>,
    /// The number the next start takes.
    next_start: usize,
    scan: Scan,
    error: Option<String>,
}

/// A name in scope and the start whose handle it holds.
struct Binding {
    name: String,
    handle: Option<usize>,
    /// Whether a macro's tokens bind the name (a local of its own, never a handle or a parameter).
    in_tokens: bool,
}

/// Names that tokens bind: the index of the token before which they come into scope, the names, and
/// the index where their scope ends (none: at the end of the tokens' own group).
struct Binder {
    at: usize,
    names: Vec<String>,
    end: Option<usize>,
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
        let outside = self
            .watched
            .iter()
            .all(|watched| !file.starts_with(&watched.dir));
        let mut uses = Uses::default();
        uses.visit_file(&parsed);
        let saved = (
            std::mem::replace(&mut self.file, file),
            std::mem::replace(&mut self.dir, dir),
            std::mem::replace(&mut self.inline, 0),
            std::mem::take(&mut self.scope),
            std::mem::replace(&mut self.outside, outside),
            std::mem::replace(&mut self.aliases, uses.aliases),
        );
        self.visit_file(&parsed);
        (
            self.file,
            self.dir,
            self.inline,
            self.scope,
            self.outside,
            self.aliases,
        ) = saved;
        Ok(())
    }

    fn fail(&mut self, message: String) {
        if self.error.is_none() {
            self.error = Some(message);
        }
    }

    fn push_start(&mut self, start: NewStart) {
        let parameter = self.parameter_used(&start.work);
        let id = self.next_start;
        self.next_start += 1;
        self.scan.starts.push(Start {
            file: slashed(&self.file),
            function: self.scope.join("::"),
            form: start.form,
            callee: start.callee,
            at_once: start.at_once,
            unshipped: self.unshipped > 0,
            arguments: start.arguments,
            parameter,
            helper: start.helper,
            id,
            handle: None,
            call: self.call,
        });
    }

    /// The first parameter of the enclosing function, by position, that the tokens use: one that
    /// has a closure or a future type, named anywhere in them, or a local made from one, run in
    /// them (it is the whole of them, it is called, or it is awaited).
    fn parameter_used(&self, tokens: &TokenStream) -> Option<usize> {
        let frame = self.frames.last()?;
        let named = bare_names(tokens.clone());
        let run = running_names(tokens.clone());
        let by_parameter = named.iter().filter_map(|name| frame.parameters.get(name));
        let by_local = run.iter().filter_map(|name| frame.locals.get(name));
        by_parameter.chain(by_local).min().copied()
    }

    /// What a call of this name is: a start by its name (`spawn` and the like, given an argument),
    /// a call of a helper of the roster under its scope, or neither.
    fn kind_of(&self, name: &str, arguments: usize) -> Kind {
        if name.starts_with("spawn") && arguments > 0 {
            return Kind::Spawn;
        }
        let file = slashed(&self.file);
        self.helpers
            .iter()
            .find(|(helper, scope)| helper == name && file.starts_with(scope.as_str()))
            .map_or(Kind::Not, |(helper, scope)| {
                Kind::Helper(helper.clone(), scope.clone())
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
        let kind = self.kind_of(name, arguments.len());
        if matches!(kind, Kind::Not) {
            return;
        }
        let callees: Vec<String> = arguments
            .iter()
            .map(|argument| callee_of(argument))
            .collect();
        let tokens: Vec<TokenStream> = arguments
            .iter()
            .map(|argument| argument.to_token_stream())
            .collect();
        self.push_call(kind, form, callees, &tokens, at_once);
    }

    /// Records a call that is a start. What it runs is its first argument for a start by name; a
    /// helper's call hands its work over at the helper's parameter, which is read once the whole
    /// tree is, so every argument is kept.
    fn push_call(
        &mut self,
        kind: Kind,
        form: String,
        callees: Vec<String>,
        arguments: &[TokenStream],
        at_once: bool,
    ) {
        let (callee, helper, work) = match kind {
            Kind::Spawn => (
                callees.first().cloned().unwrap_or_else(|| "-".to_string()),
                None,
                arguments.first().cloned().unwrap_or_default(),
            ),
            Kind::Helper(name, scope) => (
                "-".to_string(),
                Some((name, scope)),
                arguments.iter().cloned().collect(),
            ),
            Kind::Not => return,
        };
        self.push_start(NewStart {
            form,
            callee,
            at_once,
            arguments: callees,
            work,
            helper,
        });
    }

    fn scan_tokens(&mut self, stream: TokenStream, joins: bool) {
        let trees: Vec<TokenTree> = stream.into_iter().collect();
        // The names that these tokens bind, from where a binder says to where its scope ends, or to
        // the end of the tokens.
        let level = self.bindings.len();
        let mut binders: Vec<Binder> = Vec::new();
        let mut scopes: Vec<(usize, usize)> = Vec::new();
        for (index, tree) in trees.iter().enumerate() {
            while let Some(&(end, mark)) = scopes.last()
                && index >= end
            {
                self.bindings.truncate(mark);
                scopes.pop();
            }
            for binder in binders.iter().filter(|binder| binder.at == index) {
                let mark = self.bindings.len();
                for name in &binder.names {
                    self.bindings.push(Binding {
                        name: name.clone(),
                        handle: None,
                        in_tokens: true,
                    });
                }
                if let Some(end) = binder.end {
                    scopes.push((end, mark));
                }
            }
            if is_arrow(&trees, index) {
                binders.extend(arm_binder(&trees, index));
            }
            match tree {
                TokenTree::Group(group) => self.scan_tokens(group.stream(), joins),
                TokenTree::Ident(ident) => {
                    let name = ident.to_string();
                    if !is_punct(
                        index.checked_sub(1).and_then(|before| trees.get(before)),
                        '.',
                    ) {
                        match name.as_str() {
                            "let" => binders.extend(let_binder(&trees, index)),
                            "for" => binders.extend(for_binder(&trees, index)),
                            _ => {}
                        }
                    }
                    if joins {
                        self.awaits(&name);
                    }
                    if is_punct(trees.get(index + 1), '.')
                        && matches!(trees.get(index + 2), Some(TokenTree::Ident(word)) if word == "await")
                    {
                        self.awaits(&name);
                    }
                    if !is_punct(
                        index.checked_sub(1).and_then(|before| trees.get(before)),
                        '.',
                    ) {
                        self.name_in_tokens(&trees, index);
                    }
                    let Some((at, group)) = call_group(&trees, index + 1) else {
                        continue;
                    };
                    let argument_count = usize::from(!group.stream().is_empty());
                    let kind = self.kind_of(&name, argument_count);
                    if matches!(kind, Kind::Not) {
                        continue;
                    }
                    let form = written_form(&trees, index, &name);
                    let arguments = arguments_of(group.stream());
                    let callees: Vec<String> =
                        arguments.iter().cloned().map(callee_of_tokens).collect();
                    let at_once = is_punct(trees.get(at + 1), '.')
                        && matches!(trees.get(at + 2), Some(TokenTree::Ident(word)) if word == "await");
                    self.push_call(kind, form, callees, &arguments, at_once);
                }
                _ => {}
            }
        }
        self.bindings.truncate(level);
    }

    /// Records a name as awaited in the function being read, and the start whose handle that name
    /// holds in the scope where the name is awaited.
    fn awaits(&mut self, name: &str) {
        let binding = self
            .bindings
            .iter()
            .rev()
            .find(|binding| binding.name == name);
        // A name that a macro's tokens bind is a local of its own: awaiting it awaits neither the
        // handle nor the parameter of that name.
        if binding.is_some_and(|binding| binding.in_tokens) {
            return;
        }
        let handle = binding.and_then(|binding| binding.handle);
        self.scan
            .awaits
            .insert((slashed(&self.file), self.scope.join("::"), name.to_string()));
        if let Some(handle) = handle {
            self.scan.joined.insert(handle);
        }
    }

    /// Reads the tokens of a `select!`. What it waits on is the future of each branch, between the
    /// pattern's `=` and the `=>` (and before the `, if` of a precondition); the handler after the
    /// `=>` runs when the branch is taken and waits on nothing by being named there, so a name that
    /// a handler only drops or aborts is not awaited. A branch that does not have this shape
    /// awaits nothing, which the roster shows as a join that the source does not make.
    fn scan_select(&mut self, stream: TokenStream) {
        let trees: Vec<TokenTree> = stream.into_iter().collect();
        let mut at = 0;
        while at < trees.len() {
            let Some(arrow) = (at..trees.len()).find(|&index| is_arrow(&trees, index)) else {
                self.scan_trees(&trees[at..], false);
                return;
            };
            let head = &trees[at..arrow];
            let after = arrow + 2;
            let handler_end = match trees.get(after) {
                Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Brace => after + 1,
                _ => (after..trees.len())
                    .find(|&index| is_punct(trees.get(index), ','))
                    .unwrap_or(trees.len()),
            };
            let equals = (0..head.len()).find(|&index| lone_equals(head, index));
            match equals {
                Some(equals) => {
                    let precondition = (equals + 1..head.len()).find(|&index| {
                        is_punct(head.get(index), ',')
                            && matches!(head.get(index + 1), Some(TokenTree::Ident(word)) if word == "if")
                    });
                    let future_end = precondition.unwrap_or(head.len());
                    self.scan_trees(&head[..=equals], false);
                    self.scan_trees(&head[equals + 1..future_end], true);
                    self.scan_trees(&head[future_end..], false);
                }
                None => self.scan_trees(head, false),
            }
            // The branch's pattern binds names for its handler, not for its future or its
            // precondition.
            let mark = self.bindings.len();
            if let Some(equals) = equals {
                for name in pattern_names(&head[..equals]) {
                    self.bindings.push(Binding {
                        name,
                        handle: None,
                        in_tokens: true,
                    });
                }
            }
            self.scan_trees(&trees[after..handler_end.min(trees.len())], false);
            self.bindings.truncate(mark);
            at = handler_end + usize::from(is_punct(trees.get(handler_end), ','));
        }
    }

    fn scan_trees(&mut self, trees: &[TokenTree], joins: bool) {
        self.scan_tokens(trees.iter().cloned().collect(), joins);
    }

    /// A path written in macro tokens (`name`, `name::next`) that starts at `index`: listed when it
    /// is one of a watched crate's.
    fn name_in_tokens(&mut self, trees: &[TokenTree], index: usize) {
        if !self.outside
            || is_punct(
                index.checked_sub(1).and_then(|before| trees.get(before)),
                ':',
            )
        {
            return;
        }
        let mut segments = Vec::new();
        let mut at = index;
        while let Some(TokenTree::Ident(segment)) = trees.get(at) {
            segments.push(segment.to_string());
            if is_punct(trees.get(at + 1), ':') && is_punct(trees.get(at + 2), ':') {
                at += 3;
            } else {
                break;
            }
        }
        self.name_path(&segments);
    }

    /// Lists a path, written as these segments, when it is a path of a watched crate, either by
    /// its first segment or through a name that a `use` of the file brought in.
    fn name_path(&mut self, segments: &[String]) {
        if !self.outside {
            return;
        }
        let Some(first) = segments.first() else {
            return;
        };
        let full: Vec<String> = match self.aliases.get(first) {
            Some(path) => path.iter().chain(&segments[1..]).cloned().collect(),
            None => segments.to_vec(),
        };
        // A function's name is written in lower case; a type, a variant and a constant are not.
        let function = full
            .last()
            .and_then(|last| last.chars().next())
            .is_some_and(char::is_lowercase);
        if function && self.watched.iter().any(|watched| watched.ident == full[0]) {
            self.scan.named.insert(full.join("::"));
        }
    }

    fn visit_function(
        &mut self,
        name: String,
        signature: &syn::Signature,
        walk: impl FnOnce(&mut Self),
    ) {
        self.scope.push(name.clone());
        let function = self.scope.join("::");
        let before = self.scan.starts.len();
        self.frames.push(self.frame_of(signature));
        let outer = std::mem::take(&mut self.bindings);
        walk(self);
        self.bindings = outer;
        self.frames.pop();
        self.scope.pop();
        // A function that starts a task and does not await it, running one of its parameters of a
        // closure or future type, leaves what runs to its caller. A name that begins with `spawn`
        // is a start by its name and needs no line.
        let position = self.scan.starts[before..]
            .iter()
            .filter(|start| start.function == function && !start.at_once)
            .filter_map(|start| start.parameter)
            .min();
        if let Some(position) = position
            && !name.starts_with("spawn")
        {
            self.scan.helper_shapes.push(HelperShape {
                file: slashed(&self.file),
                name,
                position,
                receiver: signature
                    .inputs
                    .iter()
                    .any(|input| matches!(input, syn::FnArg::Receiver(_))),
            });
        }
    }

    /// The parameters of a signature that have a closure or a future type, by name, with their
    /// places not counting a receiver.
    fn frame_of(&self, signature: &syn::Signature) -> Frame {
        let mut frame = Frame::default();
        let typed = signature.inputs.iter().filter_map(|input| match input {
            syn::FnArg::Typed(typed) => Some(typed),
            syn::FnArg::Receiver(_) => None,
        });
        for (position, typed) in typed.enumerate() {
            if let syn::Pat::Ident(ident) = &*typed.pat
                && self.runs_work(&typed.ty, &signature.generics)
            {
                frame.parameters.insert(ident.ident.to_string(), position);
            }
        }
        frame
    }

    /// Whether a type is one that a task can run: a closure, a future, or a generic parameter
    /// bounded to one, however it is boxed, pinned or wrapped.
    fn runs_work(&self, ty: &syn::Type, own: &syn::Generics) -> bool {
        match ty {
            syn::Type::ImplTrait(inner) => bounds_run_work(inner.bounds.iter()),
            syn::Type::TraitObject(inner) => bounds_run_work(inner.bounds.iter()),
            syn::Type::BareFn(_) => true,
            syn::Type::Paren(inner) => self.runs_work(&inner.elem, own),
            syn::Type::Group(inner) => self.runs_work(&inner.elem, own),
            syn::Type::Reference(inner) => self.runs_work(&inner.elem, own),
            syn::Type::Path(path) => {
                if let Some(ident) = path.path.get_ident() {
                    return std::iter::once(own)
                        .chain(self.generics.iter())
                        .any(|generics| generic_runs_work(generics, ident));
                }
                path.path.segments.iter().any(|segment| {
                    matches!(
                        segment.ident.to_string().as_str(),
                        "BoxFuture" | "LocalBoxFuture"
                    ) || match &segment.arguments {
                        syn::PathArguments::AngleBracketed(arguments) => {
                            arguments.args.iter().any(|argument| {
                                matches!(argument, syn::GenericArgument::Type(inner)
                                        if self.runs_work(inner, own))
                            })
                        }
                        _ => false,
                    }
                })
            }
            _ => false,
        }
    }
}

/// The traits whose values a task runs.
const WORK_TRAITS: &[&str] = &["Fn", "FnMut", "FnOnce", "Future", "IntoFuture"];

fn bounds_run_work<'a>(bounds: impl IntoIterator<Item = &'a syn::TypeParamBound>) -> bool {
    bounds.into_iter().any(|bound| {
        matches!(bound, syn::TypeParamBound::Trait(tr)
        if tr.path.segments.last().is_some_and(|segment| {
            WORK_TRAITS.contains(&segment.ident.to_string().as_str())
        }))
    })
}

/// Whether a generic parameter of these generics is bounded to a closure or a future, in its
/// declaration or in the `where` clause.
fn generic_runs_work(generics: &syn::Generics, ident: &syn::Ident) -> bool {
    let declared = generics.params.iter().any(|parameter| {
        matches!(parameter, syn::GenericParam::Type(declared)
            if declared.ident == *ident && bounds_run_work(declared.bounds.iter()))
    });
    declared
        || generics.where_clause.iter().any(|clause| {
            clause.predicates.iter().any(|predicate| {
                matches!(predicate, syn::WherePredicate::Type(bound)
                    if matches!(&bound.bounded_ty, syn::Type::Path(path)
                        if path.path.is_ident(ident))
                        && bounds_run_work(bound.bounds.iter()))
            })
        })
}

/// What a call of a name is.
enum Kind {
    /// A start by its name: `spawn`, `spawn_blocking`.
    Spawn,
    /// A call of a helper of the roster, by its name and the scope its line gives.
    Helper(String, String),
    /// Neither.
    Not,
}

/// A start that is about to be recorded.
struct NewStart {
    form: String,
    callee: String,
    at_once: bool,
    arguments: Vec<String>,
    /// The tokens of what the start runs.
    work: TokenStream,
    helper: Option<(String, String)>,
}

/// The parameters of a function that a task can run, and the locals made from them, by name, each
/// with the first such parameter's place.
#[derive(Default)]
struct Frame {
    parameters: BTreeMap<String, usize>,
    locals: BTreeMap<String, usize>,
}

/// The names that a `use` declaration brings into a file, each as the path it stands for.
#[derive(Default)]
struct Uses {
    aliases: BTreeMap<String, Vec<String>>,
}

impl<'ast> Visit<'ast> for Uses {
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let mut found = Vec::new();
        flatten_use(&item.tree, &mut Vec::new(), &mut found);
        for (alias, path) in found {
            if let Some(alias) = alias {
                self.aliases.insert(alias, path);
            }
        }
    }
}

/// Each name that a use tree brings in with the path it stands for, and each glob with no name.
fn flatten_use(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    found: &mut Vec<(Option<String>, Vec<String>)>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            flatten_use(&path.tree, prefix, found);
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            let mut path = prefix.clone();
            let ident = name.ident.to_string();
            let alias = if ident == "self" {
                prefix.last().cloned()
            } else {
                path.push(ident.clone());
                Some(ident)
            };
            found.push((alias, path));
        }
        syn::UseTree::Rename(rename) => {
            let mut path = prefix.clone();
            if rename.ident != "self" {
                path.push(rename.ident.to_string());
            }
            found.push((Some(rename.rename.to_string()), path));
        }
        syn::UseTree::Glob(_) => {
            let mut path = prefix.clone();
            path.push("*".to_string());
            found.push((None, path));
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                flatten_use(item, prefix, found);
            }
        }
    }
}

/// The names in tokens that are not a method or a field: an identifier not after a `.`.
fn is_brace(tree: Option<&TokenTree>) -> bool {
    matches!(tree, Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Brace)
}

fn is_word(tree: Option<&TokenTree>, word: &str) -> bool {
    matches!(tree, Some(TokenTree::Ident(ident)) if ident == word)
}

/// Whether the tokens have a `:` of its own at this place, not part of a `::`.
fn single_colon(trees: &[TokenTree], index: usize) -> bool {
    is_punct(trees.get(index), ':')
        && !is_punct(trees.get(index + 1), ':')
        && !index
            .checked_sub(1)
            .is_some_and(|before| is_punct(trees.get(before), ':'))
}

/// The names that a pattern written as tokens binds: every lower-case word that is not a path's
/// segment, a keyword of patterns or the `_`. This reads a field's name in a struct pattern as a
/// binding too, which can only hide a join from the roster's check and never invent one.
fn pattern_names(trees: &[TokenTree]) -> Vec<String> {
    let mut names = Vec::new();
    for (index, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Group(group) => {
                let inner: Vec<TokenTree> = group.stream().into_iter().collect();
                names.extend(pattern_names(&inner));
            }
            TokenTree::Ident(ident) => {
                let name = ident.to_string();
                let after_path = index
                    .checked_sub(1)
                    .is_some_and(|before| is_punct(trees.get(before), ':'));
                let before_path =
                    is_punct(trees.get(index + 1), ':') && is_punct(trees.get(index + 2), ':');
                let lower = name
                    .chars()
                    .next()
                    .is_some_and(|first| first.is_lowercase() || first == '_');
                if lower
                    && !after_path
                    && !before_path
                    && !matches!(name.as_str(), "_" | "mut" | "ref" | "box" | "in" | "if")
                {
                    names.push(name);
                }
            }
            _ => {}
        }
    }
    names
}

/// The names that a `let` at `index` binds. A statement's names come into scope at the `;` that
/// ends it and stay to the end of the tokens' group; the names of an `if let`, a `while let` or a
/// `let` in a chain come into scope in the block that follows and stay in it.
fn let_binder(trees: &[TokenTree], index: usize) -> Option<Binder> {
    let before = index.checked_sub(1).and_then(|before| trees.get(before));
    let conditional = is_word(before, "if") || is_word(before, "while") || is_punct(before, '&');
    let ends = (index + 1..trees.len())
        .find(|&at| lone_equals(trees, at) || is_punct(trees.get(at), ';'))
        .unwrap_or(trees.len());
    let pattern_end = (index + 1..ends)
        .find(|&at| single_colon(trees, at))
        .unwrap_or(ends);
    let names = pattern_names(&trees[index + 1..pattern_end]);
    if conditional {
        let block = (ends..trees.len()).find(|&at| is_brace(trees.get(at)))?;
        Some(Binder {
            at: block,
            names,
            end: Some(block + 1),
        })
    } else {
        let stop = (ends..trees.len())
            .find(|&at| is_punct(trees.get(at), ';'))
            .unwrap_or(trees.len());
        Some(Binder {
            at: stop,
            names,
            end: None,
        })
    }
}

/// The names that a `for` at `index` binds, in the block of its loop.
fn for_binder(trees: &[TokenTree], index: usize) -> Option<Binder> {
    if is_punct(trees.get(index + 1), '<') {
        return None;
    }
    let block = (index + 1..trees.len()).find(|&at| is_brace(trees.get(at)))?;
    let within = (index + 1..block).find(|&at| is_word(trees.get(at), "in"))?;
    Some(Binder {
        at: block,
        names: pattern_names(&trees[index + 1..within]),
        end: Some(block + 1),
    })
}

/// The names that the pattern before the `=>` at `arrow` binds, in the arm that follows: a block, or
/// what runs to the next `,`. A guard (`if ..`) is not part of the pattern.
fn arm_binder(trees: &[TokenTree], arrow: usize) -> Option<Binder> {
    let start = (0..arrow)
        .rev()
        .find(|&at| {
            is_punct(trees.get(at), ',')
                || (is_brace(trees.get(at))
                    && at >= 2
                    && is_punct(trees.get(at - 1), '>')
                    && is_arrow(trees, at - 2))
        })
        .map_or(0, |at| at + 1);
    let guard = (start..arrow)
        .find(|&at| is_word(trees.get(at), "if"))
        .unwrap_or(arrow);
    let body = arrow + 2;
    let end = if is_brace(trees.get(body)) {
        body + 1
    } else {
        (body..trees.len())
            .find(|&at| is_punct(trees.get(at), ','))
            .unwrap_or(trees.len())
    };
    Some(Binder {
        at: body,
        names: pattern_names(&trees[start..guard]),
        end: Some(end),
    })
}

fn bare_names(stream: TokenStream) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    collect_names(stream, &mut names);
    names
}

fn collect_names(stream: TokenStream, names: &mut BTreeSet<String>) {
    let mut after_a_dot = false;
    for tree in stream {
        match tree {
            TokenTree::Ident(ident) => {
                if !after_a_dot {
                    names.insert(ident.to_string());
                }
                after_a_dot = false;
            }
            TokenTree::Group(group) => {
                collect_names(group.stream(), names);
                after_a_dot = false;
            }
            TokenTree::Punct(mark) => after_a_dot = mark.as_char() == '.',
            TokenTree::Literal(_) => after_a_dot = false,
        }
    }
}

/// The names that tokens run: one that is the whole of them, one that is called (`name(..)`), and
/// one that is awaited (`name.await`).
fn running_names(stream: TokenStream) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let trees: Vec<TokenTree> = stream.into_iter().collect();
    if let [TokenTree::Ident(only)] = trees.as_slice() {
        names.insert(only.to_string());
    }
    collect_running(&trees, &mut names);
    names
}

fn collect_running(trees: &[TokenTree], names: &mut BTreeSet<String>) {
    for (index, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Group(group) => {
                let inner: Vec<TokenTree> = group.stream().into_iter().collect();
                collect_running(&inner, names);
            }
            TokenTree::Ident(ident) => {
                let after_a_dot_or_path = index > 0
                    && (is_punct(trees.get(index - 1), '.') || is_punct(trees.get(index - 1), ':'));
                if after_a_dot_or_path {
                    continue;
                }
                let called = matches!(trees.get(index + 1),
                    Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Parenthesis);
                let awaited = is_punct(trees.get(index + 1), '.')
                    && matches!(trees.get(index + 2), Some(TokenTree::Ident(word)) if word == "await");
                if called || awaited {
                    names.insert(ident.to_string());
                }
            }
            _ => {}
        }
    }
}

/// The arguments of a call, as the tokens up to each comma outside any group.
fn arguments_of(stream: TokenStream) -> Vec<TokenStream> {
    let mut arguments = Vec::new();
    let mut current = TokenStream::new();
    let mut any = false;
    for tree in stream {
        if is_punct(Some(&tree), ',') {
            if any {
                arguments.push(std::mem::take(&mut current));
            }
            any = false;
            continue;
        }
        any = true;
        current.extend([tree]);
    }
    if any {
        arguments.push(current);
    }
    arguments
}

/// The parenthesised group that follows a name at `index`, past a turbofish, and its place.
fn call_group(trees: &[TokenTree], mut index: usize) -> Option<(usize, &proc_macro2::Group)> {
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
        Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Parenthesis => {
            Some((index, group))
        }
        _ => None,
    }
}

fn is_punct(tree: Option<&TokenTree>, mark: char) -> bool {
    matches!(tree, Some(TokenTree::Punct(punct)) if punct.as_char() == mark)
}

/// Whether the tokens have a `=>` at this place.
fn is_arrow(trees: &[TokenTree], index: usize) -> bool {
    matches!(trees.get(index), Some(TokenTree::Punct(punct))
        if punct.as_char() == '=' && punct.spacing() == Spacing::Joint)
        && is_punct(trees.get(index + 1), '>')
}

/// Whether the tokens have an `=` of its own at this place: not the end of `==`, `!=`, `<=` or
/// `>=`, and not the start of `=>` or `==`.
fn lone_equals(trees: &[TokenTree], index: usize) -> bool {
    let is_equals = is_punct(trees.get(index), '=');
    let starts_longer = matches!(trees.get(index), Some(TokenTree::Punct(punct))
        if punct.spacing() == Spacing::Joint)
        && (is_punct(trees.get(index + 1), '>') || is_punct(trees.get(index + 1), '='));
    let ends_longer = index.checked_sub(1).is_some_and(|before| {
        matches!(trees.get(before), Some(TokenTree::Punct(punct))
            if punct.spacing() == Spacing::Joint)
    });
    is_equals && !starts_longer && !ends_longer
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

/// The name of the handle that an `.await` waits on: `handle`, `self.handle`, `&mut handle`.
fn awaited_name(expression: &Expr) -> Option<String> {
    match expression {
        Expr::Path(path) => path.path.get_ident().map(ToString::to_string),
        Expr::Field(field) => match &field.member {
            syn::Member::Named(name) => Some(name.to_string()),
            syn::Member::Unnamed(_) => None,
        },
        Expr::Reference(inner) => awaited_name(&inner.expr),
        Expr::Paren(inner) => awaited_name(&inner.expr),
        Expr::Unary(inner) => awaited_name(&inner.expr),
        _ => None,
    }
}

/// The names that a pattern binds.
#[derive(Default)]
struct Bindings {
    names: Vec<String>,
}

impl<'ast> Visit<'ast> for Bindings {
    fn visit_pat_ident(&mut self, ident: &'ast syn::PatIdent) {
        self.names.push(ident.ident.to_string());
        visit::visit_pat_ident(self, ident);
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
        // What a `let` starts is read before the pattern binds its names.
        let before = self.scan.starts.len();
        if let Some(init) = &local.init {
            self.visit_expr(&init.expr);
            if let Some((_, diverge)) = &init.diverge {
                self.visit_expr(diverge);
            }
        }
        let mark = self.bindings.len();
        self.visit_pat(&local.pat);
        // `let task = tokio::spawn(..)` binds the handle of that start to `task`, for as long as
        // the name is in scope.
        if let (syn::Pat::Ident(ident), Some(init)) = (&local.pat, &local.init)
            && ident.subpat.is_none()
            && self.bindings.len() == mark + 1
        {
            let call = match &*init.expr {
                Expr::Call(call) => Some(std::ptr::from_ref(call) as usize),
                Expr::MethodCall(call) => Some(std::ptr::from_ref(call) as usize),
                _ => None,
            };
            if let Some(start) = self.scan.starts[before..]
                .iter_mut()
                .find(|start| start.call == call && call.is_some() && !start.at_once)
            {
                start.handle = Some(ident.ident.to_string());
                if let Some(binding) = self.bindings.last_mut() {
                    binding.handle = Some(start.id);
                }
            }
        }
        // A local made from a parameter that a task can run stands for it from here on.
        let Some(init) = &local.init else {
            return;
        };
        let made_from = self.parameter_used(&init.expr.to_token_stream());
        let mut bound = Bindings::default();
        bound.visit_pat(&local.pat);
        if let Some(frame) = self.frames.last_mut() {
            for name in bound.names {
                match made_from {
                    Some(position) => frame.locals.insert(name, position),
                    None => frame.locals.remove(&name),
                };
            }
        }
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if !self.outside {
            return;
        }
        let mut found = Vec::new();
        flatten_use(&item.tree, &mut Vec::new(), &mut found);
        for (alias, path) in found {
            if alias.is_none() && self.watched.iter().any(|watched| watched.ident == path[0]) {
                self.scan.named.insert(path.join("::"));
            }
        }
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        let segments: Vec<String> = path
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        self.name_path(&segments);
        visit::visit_expr_path(self, path);
    }

    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        if test_only(&arm.attrs) {
            return;
        }
        let mark = self.bindings.len();
        visit::visit_arm(self, arm);
        self.bindings.truncate(mark);
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
        self.generics.push(item.generics.clone());
        visit::visit_item_impl(self, item);
        self.generics.pop();
        self.scope.pop();
    }

    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        self.scope.push(item.ident.to_string());
        self.generics.push(item.generics.clone());
        visit::visit_item_trait(self, item);
        self.generics.pop();
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
        // What a `select!` waits on (the future of each branch) or a `join!` is awaited, though no
        // `.await` is written.
        let name = mac
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_default();
        match name.as_str() {
            "select" | "select_biased" => self.scan_select(mac.tokens.clone()),
            "join" | "try_join" => self.scan_tokens(mac.tokens.clone(), true),
            _ => self.scan_tokens(mac.tokens.clone(), false),
        }
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
            other => {
                if let Some(name) = awaited_name(other) {
                    self.awaits(&name);
                }
            }
        }
        visit::visit_expr_await(self, awaited);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        let at_once = self.awaited.remove(&(std::ptr::from_ref(call) as usize));
        if let Expr::Path(path) = &*call.func
            && let Some(last) = path.path.segments.last()
        {
            let name = last.ident.to_string();
            self.call = Some(std::ptr::from_ref(call) as usize);
            self.start_in_call(
                &name,
                path_text(&path.path),
                call.args.iter().collect(),
                at_once,
            );
            self.call = None;
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let at_once = self.awaited.remove(&(std::ptr::from_ref(call) as usize));
        let name = call.method.to_string();
        self.call = Some(std::ptr::from_ref(call) as usize);
        self.start_in_call(
            &name,
            format!(".{name}"),
            call.args.iter().collect(),
            at_once,
        );
        self.call = None;
        visit::visit_expr_method_call(self, call);
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        let mark = self.bindings.len();
        visit::visit_block(self, block);
        self.bindings.truncate(mark);
    }

    fn visit_expr_closure(&mut self, closure: &'ast syn::ExprClosure) {
        let mark = self.bindings.len();
        visit::visit_expr_closure(self, closure);
        self.bindings.truncate(mark);
    }

    fn visit_expr_for_loop(&mut self, expression: &'ast syn::ExprForLoop) {
        let mark = self.bindings.len();
        visit::visit_expr_for_loop(self, expression);
        self.bindings.truncate(mark);
    }

    fn visit_expr_while(&mut self, expression: &'ast syn::ExprWhile) {
        let mark = self.bindings.len();
        visit::visit_expr_while(self, expression);
        self.bindings.truncate(mark);
    }

    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        let mark = self.bindings.len();
        visit::visit_expr_if(self, expression);
        self.bindings.truncate(mark);
    }

    fn visit_pat_ident(&mut self, ident: &'ast syn::PatIdent) {
        self.bindings.push(Binding {
            name: ident.ident.to_string(),
            handle: None,
            in_tokens: false,
        });
        visit::visit_pat_ident(self, ident);
    }
}
