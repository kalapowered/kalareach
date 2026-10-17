//! Following a rule through the source that holds it.
//!
//! A rule that decides what a type accepts is rarely in the type's own definition: an identifier
//! type refuses a control character in a function its macro calls, a set refuses an order in the
//! visitor that reads it, a right refuses to travel in a function a field attribute names. A digest
//! of the definition alone would not move when such a helper changed. This walks from a named
//! root through every item the root names, in the crates of this workspace, and digests all of
//! them: the definition, its `impl` blocks, the macros that define it and the macro bodies they
//! call, the functions, constants and types they name, and so on until nothing new is named.
//!
//! What it follows, and what it does not:
//! * A name is looked up where it is in scope: in the file it is written in, or where a `use` of
//!   that file brings it from, or in the module its path names (`scalars::U64` is `U64` in a
//!   module `scalars`). A bare word that is none of these is a local, a prelude name or a name of
//!   a crate outside the workspace, and is not followed. A path that begins with another crate of
//!   this workspace, and a name a `use` brings in from one, are looked up in that crate, and a
//!   name that crate does not define is an error, never skipped.
//! * Names outside the workspace (the standard library, serde, other crates) are not followed.
//!   Their upgrade shows in the lock file and is read by a person.
//! * A method, or a rule reached through trait dispatch, is not named by a path and is not
//!   followed, except through the `impl` blocks of every type that is followed.
//!
//! The digest is of the token stream of each item, so comments and layout do not move it and
//! string and character literals are kept exactly. Documentation is left out: it is not behaviour.
//! Items under `#[cfg(test)]` are left out as well.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use proc_macro2::{Delimiter, Group, TokenStream, TokenTree};
use quote::ToTokens as _;
use syn::visit::Visit;

/// A source tree: the repository, or a checkout of a release.
pub struct Tree {
    root: PathBuf,
    /// The crates of the workspace, by the name their code uses (`kr_protocol`).
    crates: BTreeMap<String, PathBuf>,
    indexes: RefCell<BTreeMap<String, Rc<CrateIndex>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Kind {
    Named,
    MacroRules,
    Invocation(String),
    /// An `impl` block for a type, and whether it is a trait's.
    Impl(String, bool),
    /// A method of an `impl` block, which only a root can name.
    Method,
}

#[derive(Clone, Debug)]
enum Ref {
    /// A path written in the crate, by its segments.
    Path(Vec<String>),
    /// A bare word from the tokens of a macro call.
    Bare(String),
    /// A path written in the text of a serde attribute (`with = \"worker_rights\"`).
    Attribute(Vec<String>),
    /// The names behind the path of another crate of the workspace, outermost first
    /// (`kr_cbor::Limits::DEFAULT` is `Limits`, `DEFAULT`). The first of them the crate defines is
    /// followed; an associated item is not an item of its own, and its type is.
    In { krate: String, names: Vec<String> },
    /// A macro, by name.
    Macro(String),
}

#[derive(Clone, Debug)]
struct Item {
    file: String,
    label: String,
    kind: Kind,
    text: String,
    refs: Vec<Ref>,
    /// Whether this is the definition of a struct, an enum or a union.
    is_type: bool,
}

struct CrateIndex {
    name: String,
    items: Vec<Item>,
    /// Everything a root can be named by, anywhere in the crate.
    by_name: BTreeMap<String, Vec<usize>>,
    impls_of: BTreeMap<String, Vec<usize>>,
    invocations_of: BTreeMap<String, Vec<usize>>,
    methods: BTreeMap<String, Vec<usize>>,
    defined_by_invocation: BTreeMap<String, Vec<usize>>,
    /// For each file, what it defines, at any depth.
    in_file: BTreeMap<String, BTreeMap<String, Vec<usize>>>,
    /// The files of each module: `scalars` is `src/scalars.rs` and `src/scalars/mod.rs`, and an
    /// inline module is the file it is written in.
    files_of_module: BTreeMap<String, BTreeSet<String>>,
    imports: BTreeMap<String, Imports>,
}

/// What a file brings in with `use`.
#[derive(Default, Clone)]
struct Imports {
    /// Names from other crates of the workspace: the crate and the original name.
    workspace: BTreeMap<String, (String, String)>,
    workspace_globs: Vec<String>,
    /// Names from the crate itself or from a module of it: the path as written.
    own: BTreeMap<String, Vec<String>>,
    /// Globs of modules of the crate: the module's name.
    own_globs: Vec<String>,
}

/// How far a root is followed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Depth {
    /// The roots alone.
    Alone,
    /// The rules of a type: what its macro and its serde attributes name, its trait impls, and
    /// everything those name. Not the types its fields hold, which have rules of their own.
    Rules,
    /// Everything the roots name.
    Everything,
}

/// What was followed from a root.
pub struct Followed {
    /// A digest of everything followed, in a fixed order.
    pub digest: String,
    /// What was followed, as `crate file: name`.
    pub items: Vec<String>,
}

impl Tree {
    /// Reads the crates of the workspace at `root`: the repository's checkout, or a release's.
    pub fn at(root: &Path) -> Result<Self, String> {
        let mut crates = BTreeMap::new();
        let directory = root.join("crates");
        for entry in std::fs::read_dir(&directory)
            .map_err(|error| format!("{}: {error}", directory.display()))?
        {
            let entry = entry.map_err(|error| error.to_string())?;
            let manifest = entry.path().join("Cargo.toml");
            let Ok(text) = std::fs::read_to_string(&manifest) else {
                continue;
            };
            let Some(name) = text
                .lines()
                .skip_while(|line| line.trim() != "[package]")
                .find_map(|line| line.trim().strip_prefix("name = "))
                .map(|name| name.trim_matches('"').replace('-', "_"))
            else {
                continue;
            };
            crates.insert(name, entry.path().join("src"));
        }
        Ok(Self {
            root: root.to_owned(),
            crates,
            indexes: RefCell::new(BTreeMap::new()),
        })
    }

    fn index(&self, krate: &str) -> Result<Rc<CrateIndex>, String> {
        if let Some(found) = self.indexes.borrow().get(krate) {
            return Ok(Rc::clone(found));
        }
        let source = self
            .crates
            .get(krate)
            .ok_or_else(|| format!("{krate} is no crate of this workspace"))?;
        let index = Rc::new(CrateIndex::read(krate, source, &self.root, &self.crates)?);
        self.indexes
            .borrow_mut()
            .insert(krate.to_owned(), Rc::clone(&index));
        Ok(index)
    }

    /// Follows the roots named `names` in `krate`, and digests what they name.
    pub fn follow(&self, krate: &str, names: &[&str]) -> Result<Followed, String> {
        self.follow_with(krate, names, Depth::Everything)
    }

    /// Digests the roots named `names` in `krate` and what they name, as far as `depth` says.
    ///
    /// A digest of the roots alone is what a check would hold without the walk, and is here for a
    /// test to show that such a digest does not move with a helper.
    pub fn follow_with(
        &self,
        krate: &str,
        names: &[&str],
        depth: Depth,
    ) -> Result<Followed, String> {
        let mut seen: BTreeSet<(String, usize)> = BTreeSet::new();
        let mut todo: Vec<(String, usize)> = Vec::new();
        let start = self.index(krate)?;
        for name in names {
            let roots = start.roots_named(name);
            if roots.is_empty() {
                return Err(format!("{krate} defines nothing named {name}"));
            }
            todo.extend(roots.into_iter().map(|at| (krate.to_owned(), at)));
        }
        while let Some((krate, at)) = todo.pop() {
            if !seen.insert((krate.clone(), at)) {
                continue;
            }
            if depth == Depth::Alone {
                continue;
            }
            let index = self.index(&krate)?;
            let item = &index.items[at];
            // A type brings its impls, and every item what it names.
            if matches!(item.kind, Kind::Named) {
                for name in item_names(item) {
                    for impl_at in index.impls_of.get(&name).into_iter().flatten() {
                        todo.push((krate.clone(), *impl_at));
                    }
                }
            }
            // A type's own definition names the types its fields hold, which have rules of their
            // own: at `Rules` depth only what carries a rule is followed from it.
            let definition = item.is_type;
            for reference in &item.refs {
                let carries_a_rule = matches!(reference, Ref::Macro(_) | Ref::Attribute(_));
                if depth == Depth::Rules && definition && !carries_a_rule {
                    continue;
                }
                for next in self.resolve(&index, item, reference)? {
                    todo.push(next);
                }
            }
        }
        let mut ordered: Vec<(String, usize)> = seen.into_iter().collect();
        ordered.sort_by_key(|(krate, at)| {
            let item = &self.index(krate).expect("indexed").items[*at];
            (krate.clone(), item.file.clone(), item.label.clone(), *at)
        });
        let mut digest = Vec::new();
        let mut items = Vec::new();
        for (krate, at) in ordered {
            let index = self.index(&krate)?;
            let item = &index.items[at];
            digest.extend_from_slice(
                format!("{krate} {} {}\n{}\n", item.file, item.label, item.text).as_bytes(),
            );
            items.push(format!("{krate} {}: {}", item.file, item.label));
        }
        items.dedup();
        Ok(Followed {
            digest: hex(&kr_cbor::sha256(&digest)),
            items,
        })
    }

    fn resolve(
        &self,
        index: &CrateIndex,
        item: &Item,
        reference: &Ref,
    ) -> Result<Vec<(String, usize)>, String> {
        let own = |found: Vec<usize>| -> Vec<(String, usize)> {
            found
                .into_iter()
                .map(|at| (index.name.clone(), at))
                .collect()
        };
        match reference {
            Ref::In { krate, names } => self.follow_in(krate, names, &item.label),
            Ref::Macro(name) => {
                let found = index.macro_named(name);
                if !found.is_empty() {
                    return Ok(own(found));
                }
                match index
                    .imports
                    .get(&item.file)
                    .and_then(|i| i.workspace.get(name))
                {
                    Some((krate, original)) => {
                        self.follow_in(krate, std::slice::from_ref(original), &item.label)
                    }
                    None => Ok(Vec::new()),
                }
            }
            Ref::Bare(name) => self.in_scope(index, item, name),
            Ref::Path(segments) | Ref::Attribute(segments) => {
                let mut found: Vec<(String, usize)> = Vec::new();
                let leading_crate = segments.first().is_some_and(|first| first == "crate");
                let leading_super = segments.first().is_some_and(|first| first == "super");
                let rest: Vec<&String> = segments
                    .iter()
                    .skip_while(|segment| matches!(segment.as_str(), "crate" | "self" | "super"))
                    .collect();
                if rest.is_empty() {
                    return Ok(found);
                }
                // `module::Name`: the name in the module the segment before it names.
                for pair in rest.windows(2) {
                    found.extend(own(index.in_module(pair[0], pair[1])));
                }
                if leading_crate && rest.len() == 1 {
                    found.extend(own(index.in_module("crate", rest[0])));
                } else if leading_super && rest.len() == 1 {
                    // The parent module is not known from the path alone.
                    found.extend(own(index.named(rest[0])));
                } else if !leading_crate && !leading_super {
                    found.extend(self.in_scope(index, item, rest[0])?);
                }
                Ok(found)
            }
        }
    }

    /// What a bare name refers to where `item` is: its file, or what the file imports.
    fn in_scope(
        &self,
        index: &CrateIndex,
        item: &Item,
        name: &str,
    ) -> Result<Vec<(String, usize)>, String> {
        let own = |found: Vec<usize>| -> Vec<(String, usize)> {
            found
                .into_iter()
                .map(|at| (index.name.clone(), at))
                .collect()
        };
        if let Some(found) = index
            .in_file
            .get(&item.file)
            .and_then(|names| names.get(name))
        {
            return Ok(own(found.clone()));
        }
        let Some(imports) = index.imports.get(&item.file) else {
            return Ok(Vec::new());
        };
        if let Some((krate, original)) = imports.workspace.get(name) {
            return self.follow_in(krate, std::slice::from_ref(original), &item.label);
        }
        if let Some(path) = imports.own.get(name) {
            let (original, module) = (path.last(), path.iter().rev().nth(1));
            if let (Some(original), Some(module)) = (original, module) {
                let found = match module.as_str() {
                    "super" => index.named(original),
                    module => index.in_module(module, original),
                };
                return Ok(own(found));
            }
        }
        let mut found = Vec::new();
        for module in &imports.own_globs {
            found.extend(own(match module.as_str() {
                "super" => index.named(name),
                module => index.in_module(module, name),
            }));
        }
        for krate in &imports.workspace_globs {
            let other = self.index(krate)?;
            found.extend(other.named(name).into_iter().map(|at| (krate.clone(), at)));
        }
        Ok(found)
    }

    fn follow_in(
        &self,
        krate: &str,
        names: &[String],
        from: &str,
    ) -> Result<Vec<(String, usize)>, String> {
        let other = self.index(krate)?;
        for name in names {
            let found = other.named(name);
            if !found.is_empty() {
                return Ok(found.into_iter().map(|at| (krate.to_owned(), at)).collect());
            }
        }
        Err(format!(
            "{from} names {krate}::{}, which {krate} does not define in a form this can follow",
            names.join("::")
        ))
    }
}

fn item_names(item: &Item) -> Vec<String> {
    item.label.split(", ").map(str::to_owned).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl CrateIndex {
    /// The items a root of this name is: a definition, its impls, the macro calls that define it
    /// and, for a macro, its calls, and a method of that name.
    fn roots_named(&self, name: &str) -> Vec<usize> {
        // `macro:name` is the macro's rules and no call of it.
        if let Some(macro_name) = name.strip_prefix("macro:") {
            return self.macro_named(macro_name);
        }
        let mut found = self.named(name);
        found.extend(self.methods.get(name).into_iter().flatten());
        // `Type::method` names one method of one type.
        if let Some((owner, method)) = name.split_once("::") {
            found.extend(
                self.methods
                    .get(method)
                    .into_iter()
                    .flatten()
                    .filter(|at| self.items[**at].label == format!("{owner}::{method}")),
            );
        }
        found.sort_unstable();
        found.dedup();
        found
    }

    /// What a name refers to anywhere in the crate. A method is not named by a path alone, so none
    /// is here.
    fn named(&self, name: &str) -> Vec<usize> {
        let mut found: Vec<usize> = Vec::new();
        found.extend(self.by_name.get(name).into_iter().flatten());
        found.extend(self.impls_of.get(name).into_iter().flatten());
        found.extend(self.defined_by_invocation.get(name).into_iter().flatten());
        found.extend(self.invocations_of.get(name).into_iter().flatten());
        found.sort_unstable();
        found.dedup();
        found
    }

    fn macro_named(&self, name: &str) -> Vec<usize> {
        self.by_name
            .get(name)
            .into_iter()
            .flatten()
            .copied()
            .filter(|at| self.items[*at].kind == Kind::MacroRules)
            .collect()
    }

    /// What `module` defines under `name`: in the files of the module, and in the file an inline
    /// module of that name is written in.
    fn in_module(&self, module: &str, name: &str) -> Vec<usize> {
        let mut found = Vec::new();
        for file in self.files_of_module.get(module).into_iter().flatten() {
            if let Some(items) = self.in_file.get(file).and_then(|names| names.get(name)) {
                found.extend(items.iter().copied());
            }
            // The types and macro calls a name in that file also stands for.
            found.extend(
                self.impls_of
                    .get(name)
                    .into_iter()
                    .flatten()
                    .filter(|at| &self.items[**at].file == file),
            );
        }
        found.sort_unstable();
        found.dedup();
        found
    }

    fn read(
        name: &str,
        source: &Path,
        root: &Path,
        crates: &BTreeMap<String, PathBuf>,
    ) -> Result<Self, String> {
        let mut index = Self {
            name: name.to_owned(),
            items: Vec::new(),
            by_name: BTreeMap::new(),
            impls_of: BTreeMap::new(),
            invocations_of: BTreeMap::new(),
            methods: BTreeMap::new(),
            defined_by_invocation: BTreeMap::new(),
            in_file: BTreeMap::new(),
            files_of_module: BTreeMap::new(),
            imports: BTreeMap::new(),
        };
        let mut files = Vec::new();
        collect_files(source, &mut files)?;
        files.sort();
        let workspace: BTreeSet<String> = crates.keys().cloned().collect();
        for path in files {
            let text = std::fs::read_to_string(&path)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            let file =
                syn::parse_file(&text).map_err(|error| format!("{}: {error}", path.display()))?;
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .display()
                .to_string();
            index
                .files_of_module
                .entry(module_of(source, &path))
                .or_default()
                .insert(relative.clone());
            let mut imports = Imports::default();
            index.add_items(&file.items, &relative, name, &workspace, &mut imports);
            index.imports.insert(relative, imports);
        }
        Ok(index)
    }

    fn add_items(
        &mut self,
        items: &[syn::Item],
        file: &str,
        krate: &str,
        workspace: &BTreeSet<String>,
        imports: &mut Imports,
    ) {
        for item in items {
            if is_cfg_test(item) {
                continue;
            }
            match item {
                syn::Item::Use(used) => {
                    use_leaves(&used.tree, &mut Vec::new(), workspace, krate, imports);
                    continue;
                }
                syn::Item::Mod(module) => {
                    // The module as a whole (a root can name it), and what is in it as well; an
                    // inline module is also a module whose items are in this file.
                    self.push(
                        item,
                        file,
                        krate,
                        workspace,
                        Kind::Named,
                        vec![module.ident.to_string()],
                    );
                    if let Some((_, inner)) = &module.content {
                        self.files_of_module
                            .entry(module.ident.to_string())
                            .or_default()
                            .insert(file.to_owned());
                        self.add_items(inner, file, krate, workspace, imports);
                    }
                    continue;
                }
                _ => {}
            }
            let (kind, names) = match item {
                syn::Item::Fn(item) => (Kind::Named, vec![item.sig.ident.to_string()]),
                syn::Item::Struct(item) => (Kind::Named, vec![item.ident.to_string()]),
                syn::Item::Enum(item) => (Kind::Named, vec![item.ident.to_string()]),
                syn::Item::Union(item) => (Kind::Named, vec![item.ident.to_string()]),
                syn::Item::Trait(item) => (Kind::Named, vec![item.ident.to_string()]),
                syn::Item::Type(item) => (Kind::Named, vec![item.ident.to_string()]),
                syn::Item::Const(item) => (Kind::Named, vec![item.ident.to_string()]),
                syn::Item::Static(item) => (Kind::Named, vec![item.ident.to_string()]),
                syn::Item::Macro(item) => match &item.ident {
                    Some(name) if item.mac.path.is_ident("macro_rules") => {
                        (Kind::MacroRules, vec![name.to_string()])
                    }
                    _ => (
                        Kind::Invocation(
                            item.mac
                                .path
                                .segments
                                .last()
                                .map_or_else(String::new, |segment| segment.ident.to_string()),
                        ),
                        Vec::new(),
                    ),
                },
                syn::Item::Impl(item) => (
                    Kind::Impl(type_name(&item.self_ty), item.trait_.is_some()),
                    vec![format!("impl {}", type_name(&item.self_ty))],
                ),
                _ => continue,
            };
            self.push(item, file, krate, workspace, kind, names);
            if let syn::Item::Impl(block) = item {
                for inner in &block.items {
                    if let syn::ImplItem::Fn(method) = inner {
                        self.push_method(
                            method,
                            file,
                            krate,
                            workspace,
                            &type_name(&block.self_ty),
                        );
                    }
                }
            }
        }
    }

    fn push_method(
        &mut self,
        method: &syn::ImplItemFn,
        file: &str,
        krate: &str,
        workspace: &BTreeSet<String>,
        owner: &str,
    ) {
        let mut collector = Collector {
            refs: Vec::new(),
            workspace,
            own: krate,
        };
        collector.visit_impl_item_fn(method);
        let at = self.items.len();
        self.methods
            .entry(method.sig.ident.to_string())
            .or_default()
            .push(at);
        self.items.push(Item {
            file: file.to_owned(),
            label: format!("{owner}::{}", method.sig.ident),
            kind: Kind::Method,
            text: without_docs(method.to_token_stream()).to_string(),
            refs: collector.refs,
            is_type: false,
        });
    }

    fn push(
        &mut self,
        item: &syn::Item,
        file: &str,
        krate: &str,
        workspace: &BTreeSet<String>,
        kind: Kind,
        names: Vec<String>,
    ) {
        let mut collector = Collector {
            refs: Vec::new(),
            workspace,
            own: krate,
        };
        collector.visit_item(item);
        let text = without_docs(item.to_token_stream()).to_string();
        let at = self.items.len();
        let label = if names.is_empty() {
            match &kind {
                Kind::Invocation(mac) => format!("{mac}! invocation"),
                _ => "item".to_owned(),
            }
        } else {
            names.join(", ")
        };
        match &kind {
            Kind::Named | Kind::MacroRules => {
                for name in &names {
                    self.by_name.entry(name.clone()).or_default().push(at);
                    self.in_file
                        .entry(file.to_owned())
                        .or_default()
                        .entry(name.clone())
                        .or_default()
                        .push(at);
                }
            }
            Kind::Impl(type_name, _) => {
                self.impls_of.entry(type_name.clone()).or_default().push(at);
            }
            Kind::Invocation(mac) => {
                self.invocations_of.entry(mac.clone()).or_default().push(at);
                if let syn::Item::Macro(invocation) = item
                    && let Some(name) = defined_name(&invocation.mac.tokens)
                {
                    self.defined_by_invocation
                        .entry(name.clone())
                        .or_default()
                        .push(at);
                    self.in_file
                        .entry(file.to_owned())
                        .or_default()
                        .entry(name)
                        .or_default()
                        .push(at);
                }
            }
            Kind::Method => {}
        }
        // What the methods of an inherent block call is not followed from the block: the block is
        // digested whole, and a method that is a rule is a root of its own (`Type::method`). A
        // trait's impl is followed, because the decoders are there.
        let refs = match &kind {
            Kind::Impl(_, false) => Vec::new(),
            _ => collector.refs,
        };
        self.items.push(Item {
            file: file.to_owned(),
            label,
            kind,
            text,
            refs,
            is_type: matches!(
                item,
                syn::Item::Struct(_) | syn::Item::Enum(_) | syn::Item::Union(_)
            ),
        });
    }
}

/// The module a file is: `scalars` for `src/scalars.rs` and `src/scalars/mod.rs`, `crate` for the
/// root.
fn module_of(source: &Path, file: &Path) -> String {
    let relative = file.strip_prefix(source).unwrap_or(file);
    let stem = relative
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    match stem {
        "lib" | "main" if relative.components().count() == 1 => "crate".to_owned(),
        "mod" => relative
            .parent()
            .and_then(|parent| parent.file_name())
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned(),
        other => other.to_owned(),
    }
}

fn collect_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in
        std::fs::read_dir(directory).map_err(|error| format!("{}: {error}", directory.display()))?
    {
        let path = entry.map_err(|error| error.to_string())?.path();
        if path.is_dir() {
            collect_files(&path, files)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
    Ok(())
}

fn is_cfg_test(item: &syn::Item) -> bool {
    let attrs: &[syn::Attribute] = match item {
        syn::Item::Fn(item) => &item.attrs,
        syn::Item::Mod(item) => &item.attrs,
        syn::Item::Impl(item) => &item.attrs,
        syn::Item::Const(item) => &item.attrs,
        syn::Item::Static(item) => &item.attrs,
        syn::Item::Struct(item) => &item.attrs,
        syn::Item::Enum(item) => &item.attrs,
        syn::Item::Use(item) => &item.attrs,
        syn::Item::Type(item) => &item.attrs,
        syn::Item::Trait(item) => &item.attrs,
        syn::Item::Macro(item) => &item.attrs,
        _ => return false,
    };
    attrs.iter().any(|attribute| {
        attribute.path().is_ident("cfg")
            && attribute
                .meta
                .to_token_stream()
                .to_string()
                .replace(' ', "")
                == "cfg(test)"
    })
}

fn type_name(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(path) => path
            .path
            .segments
            .last()
            .map_or_else(String::new, |segment| segment.ident.to_string()),
        syn::Type::Reference(reference) => type_name(&reference.elem),
        _ => String::new(),
    }
}

/// The name a type-defining macro call defines: its first identifier outside any attribute.
fn defined_name(tokens: &TokenStream) -> Option<String> {
    tokens.clone().into_iter().find_map(|tree| match tree {
        TokenTree::Ident(ident) => Some(ident.to_string()),
        _ => None,
    })
}

fn use_leaves(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    workspace: &BTreeSet<String>,
    own: &str,
    imports: &mut Imports,
) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            use_leaves(&path.tree, prefix, workspace, own, imports);
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            record_import(
                prefix,
                &name.ident.to_string(),
                &name.ident.to_string(),
                workspace,
                own,
                imports,
            );
        }
        syn::UseTree::Rename(rename) => {
            record_import(
                prefix,
                &rename.ident.to_string(),
                &rename.rename.to_string(),
                workspace,
                own,
                imports,
            );
        }
        syn::UseTree::Glob(_) => match prefix.first() {
            Some(first) if workspace.contains(first) && first != own => {
                imports.workspace_globs.push(first.clone());
            }
            Some(_) => {
                if let Some(module) = prefix.last() {
                    imports.own_globs.push(module.clone());
                }
            }
            None => {}
        },
        syn::UseTree::Group(group) => {
            for inner in &group.items {
                use_leaves(inner, prefix, workspace, own, imports);
            }
        }
    }
}

fn record_import(
    prefix: &[String],
    original: &str,
    as_name: &str,
    workspace: &BTreeSet<String>,
    own: &str,
    imports: &mut Imports,
) {
    let Some(first) = prefix.first() else {
        return;
    };
    if workspace.contains(first) && first != own {
        imports
            .workspace
            .insert(as_name.to_owned(), (first.clone(), original.to_owned()));
        return;
    }
    // A path of the crate, or of a crate outside the workspace; the lookup finds out which.
    let mut path: Vec<String> = prefix.to_vec();
    path.push(original.to_owned());
    imports.own.insert(as_name.to_owned(), path);
}

fn without_docs(stream: TokenStream) -> TokenStream {
    let mut out: Vec<TokenTree> = Vec::new();
    let mut iterator = stream.into_iter().peekable();
    while let Some(tree) = iterator.next() {
        match tree {
            TokenTree::Punct(punct) if punct.as_char() == '#' => {
                let mut ahead = iterator.clone();
                if matches!(ahead.peek(), Some(TokenTree::Punct(next)) if next.as_char() == '!') {
                    ahead.next();
                }
                if let Some(TokenTree::Group(group)) = ahead.peek()
                    && group.delimiter() == Delimiter::Bracket
                    && matches!(group.stream().into_iter().next(), Some(TokenTree::Ident(ident)) if ident == "doc")
                {
                    ahead.next();
                    iterator = ahead;
                    continue;
                }
                out.push(TokenTree::Punct(punct));
            }
            TokenTree::Group(group) => out.push(TokenTree::Group(Group::new(
                group.delimiter(),
                without_docs(group.stream()),
            ))),
            other => out.push(other),
        }
    }
    out.into_iter().collect()
}

/// Collects the paths an item writes, the macros it calls, and the words in the tokens of a macro
/// call.
struct Collector<'a> {
    refs: Vec<Ref>,
    workspace: &'a BTreeSet<String>,
    own: &'a str,
}

impl Collector<'_> {
    fn tokens(&mut self, tokens: &TokenStream) {
        let flat: Vec<TokenTree> = tokens.clone().into_iter().collect();
        let mut at = 0;
        while at < flat.len() {
            match &flat[at] {
                TokenTree::Group(group) => self.tokens(&group.stream()),
                TokenTree::Ident(ident) => {
                    let first = ident.to_string();
                    // `krate::a::b` is a path with its segments.
                    let mut chain: Vec<String> = Vec::new();
                    let mut end = at;
                    while let (
                        Some(TokenTree::Punct(one)),
                        Some(TokenTree::Punct(two)),
                        Some(TokenTree::Ident(next)),
                    ) = (flat.get(end + 1), flat.get(end + 2), flat.get(end + 3))
                    {
                        if one.as_char() != ':' || two.as_char() != ':' {
                            break;
                        }
                        chain.push(next.to_string());
                        end += 3;
                    }
                    if chain.is_empty() {
                        self.refs.push(Ref::Bare(first));
                    } else if self.workspace.contains(&first) && first != self.own {
                        self.refs.push(Ref::In {
                            krate: first,
                            names: chain,
                        });
                    } else {
                        let mut segments = vec![first];
                        segments.extend(chain);
                        self.refs.push(Ref::Path(segments));
                    }
                    at = end;
                }
                _ => {}
            }
            at += 1;
        }
    }

    fn serde_strings(&mut self, tokens: &TokenStream) {
        for tree in tokens.clone() {
            match tree {
                TokenTree::Literal(literal) => {
                    let text = literal.to_string();
                    if let Some(inner) = text
                        .strip_prefix('"')
                        .and_then(|rest| rest.strip_suffix('"'))
                    {
                        let segments: Vec<String> = inner.split("::").map(str::to_owned).collect();
                        if segments.iter().all(|name| {
                            !name.is_empty()
                                && name.chars().all(|ch| ch.is_alphanumeric() || ch == '_')
                        }) {
                            self.refs.push(Ref::Attribute(segments));
                        }
                    }
                }
                TokenTree::Group(group) => self.serde_strings(&group.stream()),
                _ => {}
            }
        }
    }
}

impl<'ast> Visit<'ast> for Collector<'_> {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        let segments: Vec<String> = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        if let Some(first) = segments.first() {
            if self.workspace.contains(first) && first != self.own && segments.len() > 1 {
                self.refs.push(Ref::In {
                    krate: first.clone(),
                    names: segments[1..].to_vec(),
                });
            } else if first != "Self" {
                self.refs.push(Ref::Path(segments));
            }
        }
        syn::visit::visit_path(self, path);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if let Some(last) = mac.path.segments.last() {
            self.refs.push(Ref::Macro(last.ident.to_string()));
        }
        self.tokens(&mac.tokens);
        syn::visit::visit_macro(self, mac);
    }

    fn visit_attribute(&mut self, attribute: &'ast syn::Attribute) {
        // A name inside the text of a serde attribute, such as `with = "worker_rights"`, is a path.
        // The attribute's own path (`serde`, `doc`) is no reference.
        if attribute.path().is_ident("serde")
            && let syn::Meta::List(list) = &attribute.meta
        {
            self.serde_strings(&list.tokens);
        }
    }
}

/// The attribute keywords of serde that change how a type is read or written.
pub const SERDE_RULE_KEYWORDS: [&str; 8] = [
    "with",
    "deserialize_with",
    "serialize_with",
    "try_from",
    "from",
    "into",
    "skip_serializing_if",
    "remote",
];

impl Tree {
    /// For each type or macro-defined name in `crate`, whether it carries a rule of its own: a
    /// hand-written `Deserialize` or `Serialize`, a type-defining macro, or a serde attribute that
    /// changes how it is read or written. Returns the names with a short reason.
    pub fn types_with_rules(&self, krate: &str) -> Result<BTreeMap<String, String>, String> {
        let index = self.index(krate)?;
        let mut found: BTreeMap<String, String> = BTreeMap::new();
        for item in &index.items {
            if let Kind::Impl(name, true) = &item.kind
                && (item.text.contains("Deserialize <")
                    || item.text.contains("Serialize for")
                    || item.text.contains("Deserialize for"))
                && !name.is_empty()
            {
                found
                    .entry(name.clone())
                    .or_insert_with(|| "a hand-written Deserialize or Serialize".to_owned());
            }
            if let Kind::Named = item.kind {
                let compact = item.text.replace(' ', "");
                let carries = SERDE_RULE_KEYWORDS
                    .iter()
                    .any(|keyword| compact.contains(&format!("{keyword}=\"")));
                if carries {
                    for name in item_names(item) {
                        found.entry(name).or_insert_with(|| {
                            "a serde attribute that changes how it is read or written".to_owned()
                        });
                    }
                }
            }
        }
        for (name, at) in &index.defined_by_invocation {
            for position in at {
                if let Kind::Invocation(mac) = &index.items[*position].kind
                    && index.by_name.contains_key(mac)
                    && name != mac
                {
                    found
                        .entry(name.clone())
                        .or_insert_with(|| format!("defined by the macro {mac}"));
                }
            }
        }
        Ok(found)
    }

    /// The types of `kr_protocol` that carry a rule and that are definitions of the schema: the
    /// roots the rules of the surface are followed from.
    pub fn rule_bearing_surface_types(&self) -> Vec<String> {
        let surface = kr_protocol::retained::current();
        self.types_with_rules("kr_protocol")
            .expect("the types with rules")
            .into_keys()
            .filter(|name| surface.definition(name).is_some())
            .collect()
    }

    /// The names of the types the definitions of `types` hold in their fields, and `types`.
    pub fn held_by(
        &self,
        krate: &str,
        types: BTreeSet<String>,
    ) -> Result<BTreeSet<String>, String> {
        let index = self.index(krate)?;
        let mut held = types.clone();
        for name in &types {
            for at in index.named(name) {
                let item = &index.items[at];
                if item.is_type {
                    held.extend(
                        item.text
                            .split(|ch: char| !(ch.is_alphanumeric() || ch == '_'))
                            .filter(|word| word.chars().next().is_some_and(char::is_uppercase))
                            .map(str::to_owned),
                    );
                }
            }
        }
        Ok(held)
    }

    /// The macros of `krate` that something calls to define items.
    pub fn called_macros(&self, krate: &str) -> Result<Vec<String>, String> {
        let index = self.index(krate)?;
        Ok(index
            .invocations_of
            .keys()
            .filter(|name| !index.macro_named(name).is_empty())
            .cloned()
            .collect())
    }

    /// Every `pub const` of `krate` whose name says it is a limit, with the text of its value.
    pub fn limits(&self, krate: &str) -> Result<BTreeMap<String, String>, String> {
        let index = self.index(krate)?;
        let mut found = BTreeMap::new();
        for item in &index.items {
            if !matches!(item.kind, Kind::Named) {
                continue;
            }
            for name in item_names(item) {
                let limit =
                    name.starts_with("MAX_") || name.ends_with("_MAX") || name.contains("LIMIT");
                if limit && item.text.starts_with("pub const") {
                    found.insert(name, item.text.clone());
                }
            }
        }
        Ok(found)
    }
}
