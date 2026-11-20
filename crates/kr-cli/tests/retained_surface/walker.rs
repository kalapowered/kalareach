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
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;

use proc_macro2::{Delimiter, Group, TokenStream, TokenTree};
use quote::ToTokens as _;
use syn::ext::IdentExt as _;
use syn::visit::Visit;

/// A source tree: the repository, or a checkout of a release.
pub struct Tree {
    root: PathBuf,
    /// The crates of the workspace, by the name their code uses (`kr_protocol`).
    crates: BTreeMap<String, PathBuf>,
    /// The manifests that exist and cannot be read as a package: a crate that no manifest names
    /// is then unknown and not absent.
    unreadable: Vec<String>,
    indexes: RefCell<BTreeMap<String, Rc<CrateIndex>>>,
    scans: RefCell<BTreeMap<String, Rc<CrateScan>>>,
}

/// Why a root cannot be followed.
#[derive(Debug)]
pub enum WalkError {
    /// A name the crate does not define.
    Undefined(String),
    Other(String),
}

impl std::fmt::Display for WalkError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Undefined(text) | Self::Other(text) => formatter.write_str(text),
        }
    }
}

impl From<String> for WalkError {
    fn from(text: String) -> Self {
        Self::Other(text)
    }
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
#[derive(Clone)]
pub struct Followed {
    /// A digest of everything followed, in a fixed order.
    pub digest: String,
    /// What was followed, as `crate file: name`.
    pub items: Vec<String>,
}

impl Tree {
    /// Reads the crates of the workspace at `root`: the repository's checkout, or a release's. A
    /// crate is `crates/*` or an application's `apps/*/src-tauri`, named by its manifest's package.
    pub fn at(root: &Path) -> Result<Self, String> {
        // A root with `..` in it (the repository's own is `crates/kr-cli/../..`) gets the form of
        // the module paths the scan compares its files with.
        let root = &lexical(root);
        let mut crates = BTreeMap::new();
        let mut unreadable = Vec::new();
        let directory = root.join("crates");
        let mut manifests: Vec<PathBuf> = Vec::new();
        for entry in std::fs::read_dir(&directory)
            .map_err(|error| format!("{}: {error}", directory.display()))?
        {
            manifests.push(entry.map_err(|error| error.to_string())?.path());
        }
        match std::fs::read_dir(root.join("apps")) {
            Ok(applications) => {
                for entry in applications {
                    manifests.push(
                        entry
                            .map_err(|error| error.to_string())?
                            .path()
                            .join("src-tauri"),
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("{}: {error}", root.join("apps").display())),
        }
        manifests.sort();
        for directory in manifests {
            let manifest = directory.join("Cargo.toml");
            match std::fs::metadata(&manifest) {
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                    ) =>
                {
                    continue;
                }
                Err(_) => {
                    unreadable.push(manifest.display().to_string());
                    continue;
                }
            }
            let package = std::fs::read_to_string(&manifest).ok().and_then(|text| {
                text.lines()
                    .skip_while(|line| line.trim() != "[package]")
                    .find_map(|line| line.trim().strip_prefix("name = "))
                    .map(|name| name.trim_matches('"').replace('-', "_"))
            });
            match package {
                Some(name) => {
                    crates.insert(name, directory.join("src"));
                }
                None => unreadable.push(manifest.display().to_string()),
            }
        }
        Ok(Self {
            root: root.to_owned(),
            crates,
            unreadable,
            indexes: RefCell::new(BTreeMap::new()),
            scans: RefCell::new(BTreeMap::new()),
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
    pub fn follow(&self, krate: &str, names: &[&str]) -> Result<Followed, WalkError> {
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
    ) -> Result<Followed, WalkError> {
        let ordered = self.followed_set(krate, names, depth)?;
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

    /// The items the roots named `names` in `krate` come to, as far as `depth` says, in a fixed
    /// order.
    fn followed_set(
        &self,
        krate: &str,
        names: &[&str],
        depth: Depth,
    ) -> Result<Vec<(String, usize)>, WalkError> {
        let mut seen: BTreeSet<(String, usize)> = BTreeSet::new();
        let mut todo: Vec<(String, usize)> = Vec::new();
        let start = self.index(krate)?;
        for name in names {
            let roots = start.roots_named(name);
            if roots.is_empty() {
                return Err(WalkError::Undefined(format!(
                    "{krate} defines nothing named {name}"
                )));
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
        Ok(ordered)
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
    attrs_are_cfg_test(attrs)
}

/// Whether the attributes are exactly `#[cfg(test)]`; `cfg(any(test, ...))` is no test-only item.
fn attrs_are_cfg_test(attrs: &[syn::Attribute]) -> bool {
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
                            // A path into another crate of the workspace is followed there, like
                            // any other path that names one.
                            match segments.split_first() {
                                Some((first, rest))
                                    if !rest.is_empty()
                                        && self.workspace.contains(first)
                                        && first != self.own =>
                                {
                                    self.refs.push(Ref::In {
                                        krate: first.clone(),
                                        names: rest.to_vec(),
                                    });
                                }
                                _ => self.refs.push(Ref::Attribute(segments)),
                            }
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

/// What a lookup of a crate, an item or a root finds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    Found(String),
    /// The tree was read completely and the thing is not in it.
    Absent,
    Failed(String),
}

/// The text a name stands for, owned, with the digest that holds its path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    pub digest: String,
    pub text: String,
    pub files: Vec<String>,
}

/// What a sighting of a way to build a mutation for a worker names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SightKind {
    /// `Method::<V>` or a wire name as a string, for one of the six methods.
    Names,
    /// `MutationRequest` followed by a brace group.
    Request,
    /// `ActionTarget` followed by a brace group.
    Target,
    /// A `macro_rules!` body that an invocation which is a sighting expands.
    Expands,
}

/// An item that builds, names or sets what a mutation for a worker carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sighting {
    pub krate: String,
    pub name: String,
    pub kinds: BTreeSet<SightKind>,
}

/// The six methods a worker's input rule may refuse more for: their variants and wire names.
const VARIANTS: [&str; 6] = [
    "AgentPromptSubmit",
    "AgentPromptQueue",
    "AgentTurnSteer",
    "AgentTurnCancel",
    "AgentApprovalRespond",
    "PluginActionInvoke",
];
pub const WIRE_NAMES: [&str; 6] = [
    "agent.prompt.submit",
    "agent.prompt.queue",
    "agent.turn.steer",
    "agent.turn.cancel",
    "agent.approval.respond",
    "plugin.action.invoke",
];

/// What the scan found in one crate.
struct CrateScan {
    sightings: Vec<Sighting>,
    /// The names only a scan gives (`use:<file>`, `<macro>! invocation @<file>`), with their text.
    scan_names: BTreeMap<String, Source>,
}

impl Tree {
    /// Whether a manifest names `krate`. A crate that no manifest names is absent only when every
    /// manifest of the tree could be read.
    pub fn krate(&self, krate: &str) -> Lookup {
        if self.crates.contains_key(krate) {
            Lookup::Found(String::new())
        } else if self.unreadable.is_empty() {
            Lookup::Absent
        } else {
            Lookup::Failed(format!(
                "{krate} is in no manifest this tree could read; unreadable: {}",
                self.unreadable.join(", ")
            ))
        }
    }

    /// The digest of the roots named `names` in `krate`, as far as `depth` says. A list of names
    /// of which only some are defined is a failure.
    pub fn lookup(&self, krate: &str, names: &[&str], depth: Depth) -> Lookup {
        match self.krate(krate) {
            Lookup::Found(_) => {}
            other => return other,
        }
        let mut undefined: Vec<&str> = Vec::new();
        for name in names {
            match self.followed_set(krate, &[*name], Depth::Alone) {
                Ok(_) => {}
                Err(WalkError::Undefined(_)) => undefined.push(name),
                Err(WalkError::Other(error)) => return Lookup::Failed(error),
            }
        }
        if undefined.len() == names.len() {
            return Lookup::Absent;
        }
        if !undefined.is_empty() {
            return Lookup::Failed(format!(
                "{krate} defines only some of {}; not {}",
                names.join(", "),
                undefined.join(", ")
            ));
        }
        match self.follow_with(krate, names, depth) {
            Ok(followed) => Lookup::Found(followed.digest),
            Err(error) => Lookup::Failed(error.to_string()),
        }
    }

    /// The item `name` in `krate`, alone: a name the walker knows, else a name the scan gives.
    /// `None` where the crate or the name is absent.
    pub fn source(&self, krate: &str, name: &str) -> Result<Option<Source>, String> {
        match self.krate(krate) {
            Lookup::Found(_) => {}
            Lookup::Absent => return Ok(None),
            Lookup::Failed(error) => return Err(error),
        }
        match self.followed_set(krate, &[name], Depth::Alone) {
            Err(WalkError::Undefined(_)) => {}
            Err(WalkError::Other(error)) => return Err(error),
            Ok(ordered) => {
                let mut digest = Vec::new();
                let mut text = Vec::new();
                let mut files: Vec<String> = Vec::new();
                for (krate, at) in ordered {
                    let index = self.index(&krate)?;
                    let item = &index.items[at];
                    digest.extend_from_slice(
                        format!("{krate} {} {}\n{}\n", item.file, item.label, item.text).as_bytes(),
                    );
                    text.push(item.text.clone());
                    if !files.contains(&item.file) {
                        files.push(item.file.clone());
                    }
                }
                return Ok(Some(Source {
                    digest: hex(&kr_cbor::sha256(&digest)),
                    text: text.join("\n"),
                    files,
                }));
            }
        }
        Ok(self.scan(krate)?.scan_names.get(name).cloned())
    }

    pub fn item(&self, krate: &str, name: &str) -> Lookup {
        match self.source(krate, name) {
            Ok(Some(source)) => Lookup::Found(source.digest),
            Ok(None) => Lookup::Absent,
            Err(error) => Lookup::Failed(error),
        }
    }

    /// The sightings of the crates `include` accepts, outside `#[cfg(test)]` and outside `tests/`.
    pub fn sightings(&self, include: &dyn Fn(&str) -> bool) -> Result<Vec<Sighting>, String> {
        if !self.unreadable.is_empty() {
            return Err(format!(
                "manifests this tree could not read: {}",
                self.unreadable.join(", ")
            ));
        }
        let mut all = Vec::new();
        for krate in self.crates.keys().filter(|krate| include(krate)) {
            all.extend(self.scan(krate)?.sightings.iter().cloned());
        }
        Ok(all)
    }

    fn scan(&self, krate: &str) -> Result<Rc<CrateScan>, String> {
        if let Some(found) = self.scans.borrow().get(krate) {
            return Ok(Rc::clone(found));
        }
        let source = self
            .crates
            .get(krate)
            .ok_or_else(|| format!("{krate} is no crate of this workspace"))?;
        let scan = Rc::new(scan_crate(krate, source, &self.root)?);
        self.scans
            .borrow_mut()
            .insert(krate.to_owned(), Rc::clone(&scan));
        Ok(scan)
    }
}

/// Whether the text holds a word a sighting is made of, so that the file is parsed.
fn mentions_a_sighting(text: &str) -> bool {
    ["Method", "MutationRequest", "ActionTarget", "macro_rules"]
        .iter()
        .any(|word| text.contains(word))
        || WIRE_NAMES.iter().any(|name| text.contains(name))
}

/// Whether the text may declare a module file: a file that does holds the letters `mod`, however
/// the module is named and whatever stands between the keyword and the name.
fn may_declare_modules(text: &str) -> bool {
    text.contains("mod")
}

/// The files of a crate that only a `#[cfg(test)]` module declaration reaches, as rustc finds
/// module files: from the crate's roots through the declarations of each file, a declaration under
/// `#[cfg(test)]` giving the status to what it reaches. A file that a declaration outside
/// `#[cfg(test)]` also reaches is product code.
fn test_only_files(files: &[PathBuf], source: &Path) -> Result<BTreeSet<PathBuf>, String> {
    let present: BTreeSet<&PathBuf> = files.iter().collect();
    let binaries = source.join("bin");
    let roots = || -> Vec<(PathBuf, bool)> {
        files
            .iter()
            .filter(|path| {
                let directory = path.parent();
                let name = path.file_name().and_then(|name| name.to_str());
                (directory == Some(source) && matches!(name, Some("lib.rs" | "main.rs")))
                    || directory == Some(binaries.as_path())
                    || (name == Some("main.rs")
                        && directory.and_then(Path::parent) == Some(binaries.as_path()))
            })
            .map(|path| (path.clone(), true))
            .collect()
    };
    let mut declarations = BTreeMap::new();
    let every = reached(&present, roots(), true, &mut declarations)?;
    let product = reached(&present, roots(), false, &mut declarations)?;
    Ok(every.difference(&product).cloned().collect())
}

/// One module declaration of a file: the files its module may be at, whether it is declared
/// test-only (by its own attribute or by a module around it), and whether a `#[path]` names it.
struct Declared {
    candidates: Vec<PathBuf>,
    test: bool,
    explicit: bool,
}

/// The files reachable from `roots` (each with whether it is a `mod.rs`-like file, whose modules
/// sit beside it), through the module declarations of every file; those under `#[cfg(test)]` only
/// when `with_tests`. A file is visited once for each place its modules are looked up in; each such
/// visit reads and parses the file once for both walks, and `declarations` keeps the result.
fn reached(
    present: &BTreeSet<&PathBuf>,
    roots: Vec<(PathBuf, bool)>,
    with_tests: bool,
    declarations: &mut BTreeMap<(PathBuf, bool), Vec<Declared>>,
) -> Result<BTreeSet<PathBuf>, String> {
    let mut seen: BTreeSet<(PathBuf, bool)> = BTreeSet::new();
    let mut todo = roots;
    while let Some(visit) = todo.pop() {
        if !seen.insert(visit.clone()) {
            continue;
        }
        if !declarations.contains_key(&visit) {
            let found = declarations_of(&visit.0, visit.1)?;
            declarations.insert(visit.clone(), found);
        }
        for declared in &declarations[&visit] {
            if declared.test && !with_tests {
                continue;
            }
            for candidate in &declared.candidates {
                if present.contains(candidate) {
                    // A file that a `#[path]` loads holds its modules beside it, as `mod.rs` does.
                    let beside = declared.explicit
                        || candidate.file_name().is_some_and(|name| name == "mod.rs");
                    todo.push((candidate.clone(), beside));
                }
            }
        }
    }
    Ok(seen.into_iter().map(|(path, _)| path).collect())
}

/// The module declarations of the file at `path`; `mod_rs` is whether its modules sit beside it.
fn declarations_of(path: &Path, mod_rs: bool) -> Result<Vec<Declared>, String> {
    let text =
        std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if !may_declare_modules(&text) {
        return Ok(Vec::new());
    }
    let file = syn::parse_file(&text).map_err(|error| format!("{}: {error}", path.display()))?;
    let directory = path.parent().unwrap_or(Path::new(""));
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    let modules = if mod_rs {
        directory.to_owned()
    } else {
        directory.join(stem)
    };
    let mut declared = Vec::new();
    declared_modules(&file.items, directory, &modules, false, &mut declared);
    Ok(declared)
}

/// `path` with its `.` components left out and each `..` taken with the component before it, as
/// the file system resolves them where no link is in the way.
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// The module declarations `items` hold. `path_base` is what a `#[path]` is relative to, `modules`
/// what a module's file is looked up under; an inline module with a `#[path]` moves both to that
/// path, taken from `path_base`, as rustc does.
fn declared_modules(
    items: &[syn::Item],
    path_base: &Path,
    modules: &Path,
    under_test: bool,
    out: &mut Vec<Declared>,
) {
    for item in items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        let test = under_test || attrs_are_cfg_test(&module.attrs);
        let name = module.ident.unraw().to_string();
        let explicit = module.attrs.iter().find_map(|attribute| {
            if !attribute.path().is_ident("path") {
                return None;
            }
            match &attribute.meta {
                syn::Meta::NameValue(pair) => match &pair.value {
                    syn::Expr::Lit(literal) => match &literal.lit {
                        syn::Lit::Str(text) => Some(text.value()),
                        _ => None,
                    },
                    _ => None,
                },
                _ => None,
            }
        });
        if let Some((_, inner)) = &module.content {
            let inside = match &explicit {
                Some(directory) => lexical(&path_base.join(directory)),
                None => modules.join(&name),
            };
            declared_modules(inner, &inside, &inside, test, out);
            continue;
        }
        match explicit {
            Some(explicit) => out.push(Declared {
                candidates: vec![lexical(&path_base.join(explicit))],
                test,
                explicit: true,
            }),
            None => out.push(Declared {
                candidates: vec![
                    modules.join(format!("{name}.rs")),
                    modules.join(&name).join("mod.rs"),
                ],
                test,
                explicit: false,
            }),
        }
    }
}

struct Scanner {
    sightings: BTreeMap<String, BTreeSet<SightKind>>,
    /// The text of each scan-only name, in file order, with the file it is in.
    scan_only: BTreeMap<String, (String, Vec<String>)>,
    macro_rules: BTreeSet<String>,
    expanded: BTreeSet<String>,
}

impl Scanner {
    /// The tokens of an item: its kinds, and the macros it calls when it is a sighting, whose
    /// bodies then give the parameters' target.
    fn body(&mut self, name: String, tokens: TokenStream) {
        called_macros(&tokens, &mut self.expanded);
        self.sight(name, kinds_of(&tokens));
    }

    /// The tokens of an item that only the scan names: when they hold a sighting, their text
    /// joins the text and the digest of `name`.
    fn scan_only_body(&mut self, name: String, file: &str, tokens: TokenStream) {
        let kinds = kinds_of(&tokens);
        if kinds.is_empty() {
            return;
        }
        called_macros(&tokens, &mut self.expanded);
        self.scan_only
            .entry(name.clone())
            .or_insert_with(|| (file.to_owned(), Vec::new()))
            .1
            .push(tokens.to_string());
        self.sight(name, kinds);
    }

    /// A constant or a macro call of an `impl` block: named by the block's type, and by the file
    /// where the type has no path (`impl T for [u8]`), as a `use` is.
    fn impl_item(&mut self, owner: &str, file: &str, under_src: &str, tokens: TokenStream) {
        if owner.is_empty() {
            self.scan_only_body(format!("impl:{under_src}"), file, tokens);
        } else {
            self.body(owner.to_owned(), tokens);
        }
    }

    fn sight(&mut self, name: String, kinds: BTreeSet<SightKind>) {
        if !kinds.is_empty() && !name.is_empty() {
            self.sightings.entry(name).or_default().extend(kinds);
        }
    }

    fn items(&mut self, items: &[syn::Item], file: &str, under_src: &str) {
        for item in items {
            if is_cfg_test(item) {
                continue;
            }
            let text = || without_docs(item.to_token_stream());
            match item {
                syn::Item::Mod(module) => {
                    if let Some((_, inner)) = &module.content {
                        self.items(inner, file, under_src);
                    }
                }
                syn::Item::Use(_) => {
                    self.scan_only_body(format!("use:{under_src}"), file, text());
                }
                syn::Item::Impl(block) => {
                    let owner = type_name(&block.self_ty);
                    for inner in &block.items {
                        match inner {
                            syn::ImplItem::Fn(method) if !attrs_are_cfg_test(&method.attrs) => {
                                self.body(
                                    format!("{owner}::{}", method.sig.ident),
                                    without_docs(method.to_token_stream()),
                                );
                            }
                            syn::ImplItem::Const(constant)
                                if !attrs_are_cfg_test(&constant.attrs) =>
                            {
                                let tokens = without_docs(constant.to_token_stream());
                                self.impl_item(&owner, file, under_src, tokens);
                            }
                            syn::ImplItem::Macro(call) if !attrs_are_cfg_test(&call.attrs) => {
                                let tokens = without_docs(call.to_token_stream());
                                self.impl_item(&owner, file, under_src, tokens);
                            }
                            _ => {}
                        }
                    }
                }
                syn::Item::Trait(definition) => {
                    let mut kept = definition.clone();
                    kept.items.retain(|member| {
                        let attrs: &[syn::Attribute] = match member {
                            syn::TraitItem::Fn(member) => &member.attrs,
                            syn::TraitItem::Const(member) => &member.attrs,
                            syn::TraitItem::Type(member) => &member.attrs,
                            syn::TraitItem::Macro(member) => &member.attrs,
                            _ => &[],
                        };
                        !attrs_are_cfg_test(attrs)
                    });
                    self.body(
                        definition.ident.to_string(),
                        without_docs(kept.to_token_stream()),
                    );
                }
                syn::Item::Macro(call) => {
                    let kinds = kinds_of(&text());
                    if let (Some(name), true) = (&call.ident, call.mac.path.is_ident("macro_rules"))
                    {
                        self.macro_rules.insert(name.to_string());
                        for expansion in transcribers(&call.mac.tokens) {
                            called_macros(&expansion, &mut self.expanded);
                        }
                        self.sight(format!("macro:{name}"), kinds);
                        continue;
                    }
                    if kinds.is_empty() {
                        continue;
                    }
                    if let Some(last) = call.mac.path.segments.last() {
                        self.expanded.insert(last.ident.to_string());
                    }
                    called_macros(&call.mac.tokens, &mut self.expanded);
                    match defined_name(&call.mac.tokens) {
                        Some(name) => self.sight(name, kinds),
                        None => {
                            let macro_name = call
                                .mac
                                .path
                                .segments
                                .last()
                                .map_or_else(String::new, |segment| segment.ident.to_string());
                            self.scan_only_body(
                                format!("{macro_name}! invocation @{under_src}"),
                                file,
                                text(),
                            );
                        }
                    }
                }
                syn::Item::Fn(definition) => {
                    self.body(definition.sig.ident.to_string(), text());
                }
                syn::Item::Struct(definition) => {
                    self.body(definition.ident.to_string(), text());
                }
                syn::Item::Enum(definition) => {
                    self.body(definition.ident.to_string(), text());
                }
                syn::Item::Union(definition) => {
                    self.body(definition.ident.to_string(), text());
                }
                syn::Item::Type(definition) => {
                    self.body(definition.ident.to_string(), text());
                }
                syn::Item::Const(definition) => {
                    self.body(definition.ident.to_string(), text());
                }
                syn::Item::Static(definition) => {
                    self.body(definition.ident.to_string(), text());
                }
                _ => {}
            }
        }
    }
}

fn scan_crate(krate: &str, source: &Path, root: &Path) -> Result<CrateScan, String> {
    let mut files = Vec::new();
    collect_files(source, &mut files)?;
    files.sort();
    let test_only = test_only_files(&files, source)?;
    let mut scanner = Scanner {
        sightings: BTreeMap::new(),
        scan_only: BTreeMap::new(),
        macro_rules: BTreeSet::new(),
        expanded: BTreeSet::new(),
    };
    for path in &files {
        if test_only.contains(path) {
            continue;
        }
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if !mentions_a_sighting(&text) {
            continue;
        }
        let parsed =
            syn::parse_file(&text).map_err(|error| format!("{}: {error}", path.display()))?;
        let relative = path
            .strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string();
        let under_src = path
            .strip_prefix(source)
            .unwrap_or(path)
            .display()
            .to_string();
        scanner.items(&parsed.items, &relative, &under_src);
    }
    for name in scanner.macro_rules.clone() {
        if scanner.expanded.contains(&name) {
            scanner.sight(
                format!("macro:{name}"),
                BTreeSet::from([SightKind::Expands]),
            );
        }
    }
    let scan_names = scanner
        .scan_only
        .iter()
        .map(|(name, (file, texts))| {
            let mut digest = Vec::new();
            for text in texts {
                digest.extend_from_slice(format!("{krate} {file} {name}\n{text}\n").as_bytes());
            }
            (
                name.clone(),
                Source {
                    digest: hex(&kr_cbor::sha256(&digest)),
                    text: texts.join("\n"),
                    files: vec![file.clone()],
                },
            )
        })
        .collect();
    let sightings = scanner
        .sightings
        .into_iter()
        .map(|(name, kinds)| Sighting {
            krate: krate.to_owned(),
            name,
            kinds,
        })
        .collect();
    Ok(CrateScan {
        sightings,
        scan_names,
    })
}

/// The expansions of the arms of a `macro_rules!` body: what follows each `=>` outside the
/// matchers, where a call is only syntax to match.
fn transcribers(arms: &TokenStream) -> Vec<TokenStream> {
    let flat: Vec<TokenTree> = arms.clone().into_iter().collect();
    flat.iter()
        .enumerate()
        .filter_map(
            |(at, tree)| match (tree, flat.get(at + 1), flat.get(at + 2)) {
                (
                    TokenTree::Punct(equals),
                    Some(TokenTree::Punct(greater)),
                    Some(TokenTree::Group(expansion)),
                ) if equals.as_char() == '=' && greater.as_char() == '>' => {
                    Some(expansion.stream())
                }
                _ => None,
            },
        )
        .collect()
}

/// The names of the macros the tokens call, at any depth, with a sighting in their own arguments:
/// a call that holds none expands to nothing the scan names, whatever else its item holds.
fn called_macros(stream: &TokenStream, out: &mut BTreeSet<String>) {
    let flat: Vec<TokenTree> = stream.clone().into_iter().collect();
    for (at, tree) in flat.iter().enumerate() {
        match tree {
            TokenTree::Group(group) => called_macros(&group.stream(), out),
            TokenTree::Ident(ident)
                if matches!(flat.get(at + 1), Some(TokenTree::Punct(bang)) if bang.as_char() == '!')
                    && matches!(flat.get(at + 2), Some(TokenTree::Group(arguments))
                        if !kinds_of(&arguments.stream()).is_empty()) =>
            {
                out.insert(ident.to_string());
            }
            _ => {}
        }
    }
}

/// The kinds of sighting the tokens hold: a `Method::<V>` path or wire name, a `MutationRequest`
/// or an `ActionTarget` with a brace group after it.
fn kinds_of(stream: &TokenStream) -> BTreeSet<SightKind> {
    let mut kinds = BTreeSet::new();
    collect_kinds(stream, &mut kinds);
    kinds
}

fn collect_kinds(stream: &TokenStream, kinds: &mut BTreeSet<SightKind>) {
    let flat: Vec<TokenTree> = stream.clone().into_iter().collect();
    let is_brace = |tree: Option<&TokenTree>| matches!(tree, Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Brace);
    for (at, tree) in flat.iter().enumerate() {
        match tree {
            TokenTree::Group(group) => collect_kinds(&group.stream(), kinds),
            TokenTree::Literal(literal) => {
                if let Ok(text) = syn::parse_str::<syn::LitStr>(&literal.to_string())
                    && WIRE_NAMES.contains(&text.value().as_str())
                {
                    kinds.insert(SightKind::Names);
                }
            }
            TokenTree::Ident(ident) => {
                let word = ident.to_string();
                if word == "MutationRequest" && is_brace(flat.get(at + 1)) {
                    kinds.insert(SightKind::Request);
                }
                if word == "ActionTarget" && is_brace(flat.get(at + 1)) {
                    kinds.insert(SightKind::Target);
                }
                let separated = matches!(flat.get(at + 1), Some(TokenTree::Punct(one)) if one.as_char() == ':')
                    && matches!(flat.get(at + 2), Some(TokenTree::Punct(two)) if two.as_char() == ':');
                if word == "Method" && separated {
                    let names_one = |tree: &TokenTree| matches!(tree, TokenTree::Ident(variant) if VARIANTS.contains(&variant.to_string().as_str()));
                    let hit = match flat.get(at + 3) {
                        Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Brace => {
                            group.stream().into_iter().any(|inner| names_one(&inner))
                        }
                        Some(other) => names_one(other),
                        None => false,
                    };
                    if hit {
                        kinds.insert(SightKind::Names);
                    }
                }
            }
            TokenTree::Punct(_) => {}
        }
    }
}
