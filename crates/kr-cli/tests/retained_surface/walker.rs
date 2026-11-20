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
use syn::visit::Visit;
use syn::visit_mut::VisitMut;

use super::condition;
use super::inventory::{self, Inventory};

/// A source tree: the repository, or a checkout of a release.
pub struct Tree {
    root: PathBuf,
    /// The crates of the workspace, by the name their code uses (`kr_protocol`).
    crates: BTreeMap<String, PathBuf>,
    /// What Cargo says about each crate's targets, by crate name.
    manifests: BTreeMap<String, Manifest>,
    indexes: RefCell<BTreeMap<String, Rc<CrateIndex>>>,
    scans: RefCell<BTreeMap<String, Rc<CrateScan>>>,
    inventories: RefCell<BTreeMap<String, Rc<Inventory>>>,
    /// The crates that the marks of a name and the renames of a macro's name look at: every crate
    /// where it is not set.
    scope: Option<BTreeSet<String>>,
}

/// What Cargo says of a crate that the inventory needs.
struct Manifest {
    /// The manifest, as a path under the tree.
    shown: String,
    /// The source file of each library and binary target.
    roots: Vec<PathBuf>,
    /// Whether the library is a procedural-macro crate.
    proc_macro: bool,
}

/// The kinds of target that are product code: a library of any crate type, and a binary.
const PRODUCT_KINDS: [&str; 7] = [
    "lib",
    "rlib",
    "dylib",
    "cdylib",
    "staticlib",
    "proc-macro",
    "bin",
];

/// The cargo that built this program: the one that runs it, else the one that compiled it. It is
/// run by its own path, so that no toolchain file of a checked-out release starts an install.
fn cargo() -> PathBuf {
    std::env::var_os("CARGO").map_or_else(|| PathBuf::from(env!("CARGO")), PathBuf::from)
}

/// The members of the workspace at `root` outside `tests/`, as Cargo reads them: by crate name.
fn workspace(root: &Path) -> Result<BTreeMap<String, (PathBuf, Manifest)>, String> {
    let cannot = |why: &str| {
        format!(
            "{}: cargo cannot read the workspace ({why})",
            root.display()
        )
    };
    let output = std::process::Command::new(cargo())
        .args([
            "metadata",
            "--no-deps",
            "--offline",
            "--format-version",
            "1",
        ])
        .current_dir(root)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|error| cannot(&error.to_string()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Cargo may print a `warning:` line first: the complaint is the first line that is an error.
        let first = stderr
            .lines()
            .find(|line| line.starts_with("error"))
            .or_else(|| stderr.lines().find(|line| !line.trim().is_empty()))
            .unwrap_or("it failed");
        return Err(cannot(first.trim()));
    }
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|error| cannot(&error.to_string()))?;
    let reported = metadata["workspace_root"]
        .as_str()
        .ok_or_else(|| cannot("no workspace root"))?;
    if std::fs::canonicalize(reported).ok().as_deref() != Some(root) {
        return Err(cannot(&format!("the workspace root is {reported}")));
    }
    let members: BTreeSet<&str> = metadata["workspace_members"]
        .as_array()
        .ok_or_else(|| cannot("no workspace members"))?
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    let mut found = BTreeMap::new();
    for package in metadata["packages"]
        .as_array()
        .ok_or_else(|| cannot("no packages"))?
    {
        if !package["id"]
            .as_str()
            .is_some_and(|id| members.contains(id))
        {
            continue;
        }
        let name = package["name"]
            .as_str()
            .ok_or_else(|| cannot("a package with no name"))?
            .replace('-', "_");
        let manifest = PathBuf::from(
            package["manifest_path"]
                .as_str()
                .ok_or_else(|| cannot("a package with no manifest"))?,
        );
        let directory = manifest
            .parent()
            .ok_or_else(|| cannot("a manifest with no folder"))?
            .to_owned();
        let shown = manifest
            .strip_prefix(root)
            .map_err(|_| cannot(&format!("{} is not under the tree", manifest.display())))?;
        // The test crates of the repository are not product code.
        if shown.starts_with("tests") {
            continue;
        }
        let mut roots = Vec::new();
        let mut proc_macro = false;
        for target in package["targets"].as_array().into_iter().flatten() {
            let kinds: Vec<&str> = target["kind"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str)
                .collect();
            if !kinds.iter().any(|kind| PRODUCT_KINDS.contains(kind)) {
                continue;
            }
            proc_macro |= kinds.contains(&"proc-macro");
            let source = target["src_path"]
                .as_str()
                .ok_or_else(|| cannot("a target with no source path"))?;
            roots.push(normalised(Path::new(source)));
        }
        found.insert(
            name,
            (
                directory,
                Manifest {
                    shown: shown.display().to_string(),
                    roots,
                    proc_macro,
                },
            ),
        );
    }
    Ok(found)
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
    /// Reads the crates of the workspace at `root`: the repository's checkout, or a release's. The
    /// crates are the members Cargo reports outside `tests/`, named by their package.
    pub fn at(root: &Path) -> Result<Self, String> {
        // The root as the file system names it: a relative root, one with `..` in it (the
        // repository's own is `crates/kr-cli/../..`) and one through a link all give the one path
        // that the files of the tree and the module paths between them are compared in.
        let root =
            &std::fs::canonicalize(root).map_err(|error| format!("{}: {error}", root.display()))?;
        let mut crates = BTreeMap::new();
        let mut described = BTreeMap::new();
        for (name, (directory, manifest)) in workspace(root)? {
            crates.insert(name.clone(), directory.join("src"));
            described.insert(name, manifest);
        }
        Ok(Self {
            root: root.to_owned(),
            crates,
            manifests: described,
            indexes: RefCell::new(BTreeMap::new()),
            scans: RefCell::new(BTreeMap::new()),
            inventories: RefCell::new(BTreeMap::new()),
            scope: None,
        })
    }

    /// The tree with the macro names that a sighting marks (S4) and the renames of a macro's name
    /// (R1) looking at the crates `include` accepts only, as a scan of those crates does.
    pub fn scoped(mut self, include: &dyn Fn(&str) -> bool) -> Self {
        self.scope = Some(
            self.crates
                .keys()
                .filter(|krate| include(krate))
                .cloned()
                .collect(),
        );
        self
    }

    /// The files product code of `krate` is made of: read once, for the index and the scan.
    fn inventory(&self, krate: &str) -> Result<Rc<Inventory>, String> {
        if let Some(found) = self.inventories.borrow().get(krate) {
            return Ok(Rc::clone(found));
        }
        let manifest = self
            .manifests
            .get(krate)
            .ok_or_else(|| format!("{krate} is no crate of this workspace"))?;
        let found = Rc::new(inventory::read(krate, &manifest.roots, &self.root)?);
        self.inventories
            .borrow_mut()
            .insert(krate.to_owned(), Rc::clone(&found));
        Ok(found)
    }

    fn index(&self, krate: &str) -> Result<Rc<CrateIndex>, String> {
        if let Some(found) = self.indexes.borrow().get(krate) {
            return Ok(Rc::clone(found));
        }
        let source = self
            .crates
            .get(krate)
            .ok_or_else(|| format!("{krate} is no crate of this workspace"))?;
        let inventory = self.inventory(krate)?;
        let index = Rc::new(CrateIndex::read(
            krate,
            &inventory,
            source,
            &self.root,
            &self.crates,
        )?);
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
        inventory: &Inventory,
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
        let workspace: BTreeSet<String> = crates.keys().cloned().collect();
        for path in &inventory.files {
            let text = std::fs::read_to_string(path)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            let file =
                syn::parse_file(&text).map_err(|error| format!("{}: {error}", path.display()))?;
            let relative = path
                .strip_prefix(root)
                .unwrap_or(path)
                .display()
                .to_string();
            index
                .files_of_module
                .entry(module_of(source, path))
                .or_default()
                .insert(relative.clone());
            let mut imports = Imports::default();
            index.add_items(&file.items, &relative, name, &workspace, &mut imports)?;
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
    ) -> Result<(), String> {
        for item in items {
            if !condition::enabled(item_attrs(item), file)? {
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
                        self.add_items(inner, file, krate, workspace, imports)?;
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
                        // A method that no configuration without `test` builds is not defined.
                        if !condition::enabled(&method.attrs, file)? {
                            continue;
                        }
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
        Ok(())
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
fn impl_item_attrs(item: &syn::ImplItem) -> &[syn::Attribute] {
    match item {
        syn::ImplItem::Const(member) => &member.attrs,
        syn::ImplItem::Fn(member) => &member.attrs,
        syn::ImplItem::Type(member) => &member.attrs,
        syn::ImplItem::Macro(member) => &member.attrs,
        _ => &[],
    }
}

fn trait_item_attrs(item: &syn::TraitItem) -> &[syn::Attribute] {
    match item {
        syn::TraitItem::Const(member) => &member.attrs,
        syn::TraitItem::Fn(member) => &member.attrs,
        syn::TraitItem::Type(member) => &member.attrs,
        syn::TraitItem::Macro(member) => &member.attrs,
        _ => &[],
    }
}

/// Takes the items that no configuration without `test` builds out of a copy of a node: the items
/// nested in its blocks and modules, and the members of the impl blocks and traits among them. The
/// condition rule decides each.
struct Strip<'a> {
    at: &'a str,
    error: Option<String>,
}

impl Strip<'_> {
    fn keeps(&mut self, attrs: &[syn::Attribute]) -> bool {
        if self.error.is_some() {
            return false;
        }
        match condition::enabled(attrs, self.at) {
            Ok(enabled) => enabled,
            Err(error) => {
                self.error = Some(error);
                false
            }
        }
    }
}

impl VisitMut for Strip<'_> {
    fn visit_block_mut(&mut self, block: &mut syn::Block) {
        let mut kept = Vec::new();
        for mut statement in std::mem::take(&mut block.stmts) {
            if let syn::Stmt::Item(item) = &mut statement {
                if !self.keeps(item_attrs(item)) {
                    continue;
                }
                self.visit_item_mut(item);
            } else {
                self.visit_stmt_mut(&mut statement);
            }
            kept.push(statement);
        }
        block.stmts = kept;
    }

    fn visit_item_mod_mut(&mut self, module: &mut syn::ItemMod) {
        if let Some((_, items)) = &mut module.content {
            let mut kept = Vec::new();
            for mut item in std::mem::take(items) {
                if !self.keeps(item_attrs(&item)) {
                    continue;
                }
                self.visit_item_mut(&mut item);
                kept.push(item);
            }
            *items = kept;
        }
    }

    fn visit_item_impl_mut(&mut self, block: &mut syn::ItemImpl) {
        let mut kept = Vec::new();
        for mut member in std::mem::take(&mut block.items) {
            if !self.keeps(impl_item_attrs(&member)) {
                continue;
            }
            self.visit_impl_item_mut(&mut member);
            kept.push(member);
        }
        block.items = kept;
    }

    fn visit_item_trait_mut(&mut self, block: &mut syn::ItemTrait) {
        let mut kept = Vec::new();
        for mut member in std::mem::take(&mut block.items) {
            if !self.keeps(trait_item_attrs(&member)) {
                continue;
            }
            self.visit_trait_item_mut(&mut member);
            kept.push(member);
        }
        block.items = kept;
    }
}

/// A copy of `node` without its nested items that no configuration without `test` builds.
fn stripped<T: Clone>(
    node: &T,
    file: &str,
    visit: impl FnOnce(&mut Strip<'_>, &mut T),
) -> Result<T, String> {
    let mut strip = Strip {
        at: file,
        error: None,
    };
    let mut copy = node.clone();
    visit(&mut strip, &mut copy);
    match strip.error {
        Some(error) => Err(error),
        None => Ok(copy),
    }
}

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

/// The attributes of an item, whatever its kind.
fn item_attrs(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Const(item) => &item.attrs,
        syn::Item::Enum(item) => &item.attrs,
        syn::Item::ExternCrate(item) => &item.attrs,
        syn::Item::Fn(item) => &item.attrs,
        syn::Item::ForeignMod(item) => &item.attrs,
        syn::Item::Impl(item) => &item.attrs,
        syn::Item::Macro(item) => &item.attrs,
        syn::Item::Mod(item) => &item.attrs,
        syn::Item::Static(item) => &item.attrs,
        syn::Item::Struct(item) => &item.attrs,
        syn::Item::Trait(item) => &item.attrs,
        syn::Item::TraitAlias(item) => &item.attrs,
        syn::Item::Type(item) => &item.attrs,
        syn::Item::Union(item) => &item.attrs,
        syn::Item::Use(item) => &item.attrs,
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
            // The rebuilt group keeps the span of the written one: the lines a sighting covers come from
            // the span of the last token of its item.
            TokenTree::Group(group) => {
                let mut rebuilt = Group::new(group.delimiter(), without_docs(group.stream()));
                rebuilt.set_span(group.span());
                out.push(TokenTree::Group(rebuilt));
            }
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
    /// One of the six variant names, or a wire name in a string.
    Names,
    /// `MutationRequest` followed by a brace group.
    Request,
    /// `ActionTarget` followed by a brace group.
    Target,
    /// A `macro_rules!` body that an invocation which is a sighting expands.
    Expands,
}

/// The lines of a product file that the item of a sighting covers: the file, the first and the last
/// line (the first line of a file is 1).
pub type Extent = (String, usize, usize);

/// An item that builds, names or sets what a mutation for a worker carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sighting {
    pub krate: String,
    pub name: String,
    pub kinds: BTreeSet<SightKind>,
}

/// The six methods a worker's input rule may refuse more for: their variants and wire names.
pub(super) const VARIANTS: [&str; 6] = [
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
    /// The sightings of the crate's items, without the `Expands` of a `macro_rules!` that a call
    /// marks: the names a call with a sighting marks are taken over every crate in scope.
    sightings: Vec<Sighting>,
    /// The names only a scan gives (`use:<file>`, `<macro>! invocation @<file>`), with their text.
    scan_names: BTreeMap<String, Source>,
    /// The names of the macros called with a sighting in their own arguments.
    sighted: BTreeSet<String>,
    /// What the transcribers of each `macro_rules!` definition call, at any depth.
    callees: BTreeMap<String, Callees>,
    /// The names of the `macro_rules!` items the crate defines.
    rules: BTreeSet<String>,
    /// The lines each sighted name's items cover.
    extents: BTreeMap<String, BTreeSet<Extent>>,
}

impl Tree {
    /// Whether the workspace has a crate `krate` outside `tests/`.
    pub fn krate(&self, krate: &str) -> Lookup {
        if self.crates.contains_key(krate) {
            Lookup::Found(String::new())
        } else {
            Lookup::Absent
        }
    }

    /// The digest of the roots named `names` in `krate`, as far as `depth` says. A list of names
    /// of which only some are defined is a failure.
    pub fn lookup(&self, krate: &str, names: &[&str], depth: Depth) -> Lookup {
        match self.krate(krate) {
            Lookup::Found(_) => {}
            other => return other,
        }
        if let Err(error) = self.refusals(krate) {
            return Lookup::Failed(error);
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
        self.refusals(krate)?;
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
        let marked = self.marked(include);
        let mut all = Vec::new();
        for krate in self.crates.keys().filter(|krate| include(krate)) {
            let scan = self.refused(krate, include)?;
            let mut found: BTreeMap<String, BTreeSet<SightKind>> = scan
                .sightings
                .iter()
                .map(|sighting| (sighting.name.clone(), sighting.kinds.clone()))
                .collect();
            // A `macro_rules!` whose name is marked is expanded (S4), wherever the call is.
            for rules in scan.rules.iter().filter(|rules| marked.contains(*rules)) {
                found
                    .entry(format!("macro:{rules}"))
                    .or_default()
                    .insert(SightKind::Expands);
            }
            all.extend(found.into_iter().map(|(name, kinds)| Sighting {
                krate: krate.clone(),
                name,
                kinds,
            }));
        }
        Ok(all)
    }

    /// The lines that the items of each sighting of the crates `include` accepts cover, by crate and
    /// name: a sighting that only a mark gives (`Expands`) covers none.
    pub fn sighting_extents(
        &self,
        include: &dyn Fn(&str) -> bool,
    ) -> Result<BTreeMap<(String, String), BTreeSet<Extent>>, String> {
        let mut all = BTreeMap::new();
        for krate in self.crates.keys().filter(|krate| include(krate)) {
            for (name, extents) in &self.refused(krate, include)?.extents {
                all.insert((krate.clone(), name.clone()), extents.clone());
            }
        }
        Ok(all)
    }

    /// The macro names a sighting marks over the crates `include` accepts (S4): the name that ends a
    /// call with a sighting in its own arguments, and each name that the transcribers of a
    /// definition of a marked name call, wherever the definition is. The closure only adds marks. A
    /// crate the scan cannot read marks nothing: its own results are its refusals.
    fn marked(&self, include: &dyn Fn(&str) -> bool) -> BTreeSet<String> {
        let scans: Vec<Rc<CrateScan>> = self
            .crates
            .keys()
            .filter(|krate| include(krate) && !self.manifests[*krate].proc_macro)
            .filter_map(|krate| self.scan(krate).ok())
            .collect();
        let mut marked: BTreeSet<String> = scans
            .iter()
            .flat_map(|scan| scan.sighted.iter().cloned())
            .collect();
        let mut todo: Vec<String> = marked.iter().cloned().collect();
        while let Some(name) = todo.pop() {
            for callees in scans.iter().filter_map(|scan| scan.callees.get(&name)) {
                for callee in &callees.names {
                    if marked.insert(callee.clone()) {
                        todo.push(callee.clone());
                    }
                }
            }
        }
        marked
    }

    /// What stops a crate from being read: the forms the inventory refuses, and the refusals of the
    /// scan (X8 and the renames of R1) and of a procedural-macro crate (X10). A lookup in the crate
    /// gives none of its results while one holds.
    pub fn refusals(&self, krate: &str) -> Result<(), String> {
        self.refused(krate, &|other| {
            self.scope
                .as_ref()
                .is_none_or(|scope| scope.contains(other))
        })
        .map(|_| ())
    }

    /// The scan of `krate`, where no refusal holds, with the names marked over the crates `include`
    /// accepts.
    fn refused(
        &self,
        krate: &str,
        include: &dyn Fn(&str) -> bool,
    ) -> Result<Rc<CrateScan>, String> {
        if self.manifests[krate].proc_macro {
            return Err(format!(
                "{}: a procedural-macro crate; the scan does not read what it generates",
                self.manifests[krate].shown
            ));
        }
        let scan = self.scan(krate)?;
        let imported = self.inventory(krate)?;
        // A rename of the name of a macro that a crate in scope defines hides the macro from the scan.
        for (file, old, new) in &imported.renames {
            for other in self.crates.keys().filter(|other| include(other)) {
                let defined = &self.inventory(other)?.defined;
                if defined.contains(old) || defined.contains(new) {
                    return Err(format!(
                        "{file}: the scan does not read a use of {old} under another name (as {new})"
                    ));
                }
            }
        }
        // A marked macro that calls another through a metavariable (R4) cannot be followed.
        let marked = self.marked(include);
        if let Some(name) = scan
            .callees
            .iter()
            .find(|(name, callees)| callees.through_metavariable && marked.contains(*name))
            .map(|(name, _)| name)
        {
            return Err(format!(
                "{krate}: the macro {name} calls a macro through a metavariable, which the scan cannot follow"
            ));
        }
        Ok(scan)
    }

    fn scan(&self, krate: &str) -> Result<Rc<CrateScan>, String> {
        if let Some(found) = self.scans.borrow().get(krate) {
            return Ok(Rc::clone(found));
        }
        let source = self
            .crates
            .get(krate)
            .ok_or_else(|| format!("{krate} is no crate of this workspace"))?;
        let scan = Rc::new(scan_crate(
            krate,
            source,
            &self.root,
            &*self.inventory(krate)?,
        )?);
        self.scans
            .borrow_mut()
            .insert(krate.to_owned(), Rc::clone(&scan));
        Ok(scan)
    }
}

/// `path` with its `.` components left out and each `..` taken with the normal component before
/// it. A `..` that nothing before it can take stays, and one after the root is the root, so a
/// relative path keeps every step up that it makes. Links are not looked at: callers pass an
/// absolute path under a canonical root and test the file they find (3.5).
pub(super) fn normalised(path: &Path) -> PathBuf {
    let mut parts: Vec<Component> = Vec::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => match parts.last() {
                Some(Component::Normal(_)) => {
                    parts.pop();
                }
                Some(Component::RootDir | Component::Prefix(_)) => {}
                _ => parts.push(part),
            },
            other => parts.push(other),
        }
    }
    parts.iter().collect()
}

struct Scanner {
    /// The file being scanned, relative to the root.
    file: String,
    /// The lines of the items that gave each sighted name its sightings.
    extents: BTreeMap<String, BTreeSet<Extent>>,
    /// The kind of the type of the `impl` block the scan is in, when it is `MutationRequest` or
    /// `ActionTarget`.
    self_kind: Option<SightKind>,
    sightings: BTreeMap<String, BTreeSet<SightKind>>,
    /// The text of each scan-only name, in file order, with the file it is in.
    scan_only: BTreeMap<String, (String, Vec<String>)>,
    macro_rules: BTreeSet<String>,
    /// The macros called in what the scan read.
    calls: Calls,
}

/// What the transcribers of one `macro_rules!` definition call, at any depth.
#[derive(Default)]
struct Callees {
    /// The names called.
    names: BTreeSet<String>,
    /// Whether one is called through a metavariable (`$m!(..)`).
    through_metavariable: bool,
}

/// The macros called in some tokens.
#[derive(Default)]
struct Calls {
    /// The macros called with a sighting in their own arguments.
    sighted: BTreeSet<String>,
    /// Every macro called.
    all: Callees,
    /// What the transcribers of each `macro_rules!` definition call, at any depth, a definition
    /// written in a function's body included: that definition is part of the function.
    defined: BTreeMap<String, Callees>,
}

impl Calls {
    /// Takes in what the transcribers of the definition `name` call.
    fn absorb(&mut self, name: String, inner: Self) {
        self.sighted.extend(inner.sighted);
        for (nested, callees) in inner.defined {
            let entry = self.defined.entry(nested).or_default();
            entry.names.extend(callees.names);
            entry.through_metavariable |= callees.through_metavariable;
        }
        // Definitions of one name, which the inventory let through, are one under it: what either
        // calls is called.
        let entry = self.defined.entry(name).or_default();
        entry.names.extend(inner.all.names);
        entry.through_metavariable |= inner.all.through_metavariable;
    }
}

impl Scanner {
    /// The tokens of an item: its kinds, and the macros it calls when it is a sighting, whose
    /// bodies then give the parameters' target.
    fn body(&mut self, name: String, tokens: TokenStream) {
        calls_in(&tokens, &mut self.calls);
        let kinds = kinds_in(&tokens, self.self_kind);
        self.sight(name, kinds, &tokens);
    }

    /// The tokens of an item that only the scan names: when `tokens` (the item without the nested
    /// places that no configuration builds) hold a sighting, the item's `written` tokens join the
    /// text and the digest of `name`.
    fn scan_only_body(
        &mut self,
        name: String,
        file: &str,
        tokens: TokenStream,
        written: &TokenStream,
    ) {
        let kinds = kinds_in(&tokens, self.self_kind);
        if kinds.is_empty() {
            return;
        }
        calls_in(&tokens, &mut self.calls);
        self.scan_only
            .entry(name.clone())
            .or_insert_with(|| (file.to_owned(), Vec::new()))
            .1
            .push(written.to_string());
        self.sight(name, kinds, written);
    }

    /// A constant or a macro call of an `impl` block: named by the block's type, and by the file
    /// where the type has no path (`impl T for [u8]`), as a `use` is.
    fn impl_item(
        &mut self,
        owner: &str,
        file: &str,
        under_src: &str,
        tokens: TokenStream,
        written: &TokenStream,
    ) {
        if owner.is_empty() {
            self.scan_only_body(format!("impl:{under_src}"), file, tokens, written);
        } else {
            self.body(owner.to_owned(), tokens);
        }
    }

    /// A sighting of `name` by an item whose tokens are `tokens`: the lines they cover are kept.
    fn sight(&mut self, name: String, kinds: BTreeSet<SightKind>, tokens: &TokenStream) {
        if !kinds.is_empty() && !name.is_empty() {
            if let Some((first, last)) = lines_of(tokens) {
                self.extents.entry(name.clone()).or_default().insert((
                    self.file.clone(),
                    first,
                    last,
                ));
            }
            self.sightings.entry(name).or_default().extend(kinds);
        }
    }

    fn items(&mut self, items: &[syn::Item], file: &str, under_src: &str) -> Result<(), String> {
        for item in items {
            if !condition::enabled(item_attrs(item), file)? {
                continue;
            }
            // The item's tokens, without the nested items that no configuration builds.
            let text = || -> Result<TokenStream, String> {
                let kept = stripped(item, file, |strip, node| strip.visit_item_mut(node))?;
                Ok(without_docs(kept.to_token_stream()))
            };
            let plain = || without_docs(item.to_token_stream());
            match item {
                syn::Item::Mod(module) => {
                    if let Some((_, inner)) = &module.content {
                        self.items(inner, file, under_src)?;
                    }
                }
                syn::Item::Use(_) => {
                    self.scan_only_body(format!("use:{under_src}"), file, plain(), &plain());
                }
                syn::Item::Impl(block) => {
                    let owner = type_name(&block.self_ty);
                    // `Self { .. }` in an impl for one of the two types is a literal of it.
                    let outer = std::mem::replace(
                        &mut self.self_kind,
                        match owner.as_str() {
                            "MutationRequest" => Some(SightKind::Request),
                            "ActionTarget" => Some(SightKind::Target),
                            _ => None,
                        },
                    );
                    for inner in &block.items {
                        if !condition::enabled(impl_item_attrs(inner), file)? {
                            continue;
                        }
                        match inner {
                            syn::ImplItem::Fn(method) => {
                                let kept = stripped(method, file, |strip, node| {
                                    strip.visit_impl_item_fn_mut(node);
                                })?;
                                self.body(
                                    format!("{owner}::{}", method.sig.ident),
                                    without_docs(kept.to_token_stream()),
                                );
                            }
                            syn::ImplItem::Const(constant) => {
                                let kept = stripped(constant, file, |strip, node| {
                                    strip.visit_impl_item_const_mut(node);
                                })?;
                                let tokens = without_docs(kept.to_token_stream());
                                let written = without_docs(constant.to_token_stream());
                                self.impl_item(&owner, file, under_src, tokens, &written);
                            }
                            syn::ImplItem::Macro(call) => {
                                let tokens = without_docs(call.to_token_stream());
                                self.impl_item(&owner, file, under_src, tokens.clone(), &tokens);
                            }
                            _ => {}
                        }
                    }
                    self.self_kind = outer;
                }
                syn::Item::Trait(definition) => {
                    // `Strip` takes the members that no configuration builds out of the trait.
                    self.body(definition.ident.to_string(), text()?);
                }
                syn::Item::Macro(call) => {
                    let kinds = kinds_of(&plain());
                    if let (Some(name), true) = (&call.ident, call.mac.path.is_ident("macro_rules"))
                    {
                        self.macro_rules.insert(name.to_string());
                        let mut inner = Calls::default();
                        for expansion in transcribers(&call.mac.tokens) {
                            calls_in(&expansion, &mut inner);
                        }
                        self.calls.absorb(name.to_string(), inner);
                        self.sight(format!("macro:{name}"), kinds, &plain());
                        continue;
                    }
                    if kinds.is_empty() {
                        continue;
                    }
                    if let Some(last) = call.mac.path.segments.last() {
                        self.calls.sighted.insert(last.ident.to_string());
                    }
                    calls_in(&call.mac.tokens, &mut self.calls);
                    match defined_name(&call.mac.tokens) {
                        Some(name) => self.sight(name, kinds, &plain()),
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
                                plain(),
                                &plain(),
                            );
                        }
                    }
                }
                syn::Item::Fn(definition) => {
                    self.body(definition.sig.ident.to_string(), text()?);
                }
                syn::Item::Struct(definition) => {
                    self.body(definition.ident.to_string(), text()?);
                }
                syn::Item::Enum(definition) => {
                    self.body(definition.ident.to_string(), text()?);
                }
                syn::Item::Union(definition) => {
                    self.body(definition.ident.to_string(), text()?);
                }
                syn::Item::Type(definition) => {
                    self.body(definition.ident.to_string(), text()?);
                }
                syn::Item::Const(definition) => {
                    self.body(definition.ident.to_string(), text()?);
                }
                syn::Item::Static(definition) => {
                    self.body(definition.ident.to_string(), text()?);
                }
                _ => {}
            }
        }
        Ok(())
    }
}

fn scan_crate(
    krate: &str,
    source: &Path,
    root: &Path,
    inventory: &Inventory,
) -> Result<CrateScan, String> {
    let mut scanner = Scanner {
        file: String::new(),
        extents: BTreeMap::new(),
        self_kind: None,
        sightings: BTreeMap::new(),
        scan_only: BTreeMap::new(),
        macro_rules: BTreeSet::new(),
        calls: Calls::default(),
    };
    for path in &inventory.files {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
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
        scanner.file.clone_from(&relative);
        scanner.items(&parsed.items, &relative, &under_src)?;
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
        sighted: scanner.calls.sighted,
        callees: scanner.calls.defined,
        rules: scanner.macro_rules,
        extents: scanner.extents,
    })
}

/// The first and the last line of the tokens, from the line of their first token to the line where
/// their last one ends (the span's lines need proc-macro2's `span-locations`).
fn lines_of(tokens: &TokenStream) -> Option<(usize, usize)> {
    let all: Vec<TokenTree> = tokens.clone().into_iter().collect();
    let first = all.first()?.span().start().line;
    let last = all.last()?.span().end().line;
    Some((first, last))
}

/// The expansions of the arms of a `macro_rules!` body: what follows each `=>` outside the
/// matchers, where a call is only syntax to match.
pub(super) fn transcribers(arms: &TokenStream) -> Vec<TokenStream> {
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

/// The path that the macro name at `flat[at]` is written with: the segments before it that `::`
/// joins to it, `$crate` as one segment.
pub(super) fn path_before(flat: &[TokenTree], at: usize) -> Vec<String> {
    let colon = |tree: &TokenTree| matches!(tree, TokenTree::Punct(one) if one.as_char() == ':');
    let mut path = vec![flat[at].to_string()];
    let mut index = at;
    while index >= 3
        && colon(&flat[index - 1])
        && colon(&flat[index - 2])
        && let TokenTree::Ident(segment) = &flat[index - 3]
    {
        let mut text = segment.to_string();
        index -= 3;
        if text == "crate"
            && index >= 1
            && matches!(&flat[index - 1], TokenTree::Punct(dollar) if dollar.as_char() == '$')
        {
            text = "$crate".to_owned();
            index -= 1;
        }
        path.push(text);
    }
    path.reverse();
    path
}

/// The macros the tokens call, at any depth. A `macro_rules!` definition is read by its
/// transcribers, never by its matchers, where a call is only syntax to match: what they call is
/// kept under the definition's name, and a call with a sighting in its arguments is marked.
fn calls_in(stream: &TokenStream, calls: &mut Calls) {
    let flat: Vec<TokenTree> = stream.clone().into_iter().collect();
    let mut at = 0;
    while at < flat.len() {
        match &flat[at] {
            TokenTree::Ident(word) if word == "macro_rules" => {
                if let (
                    Some(TokenTree::Punct(bang)),
                    Some(TokenTree::Ident(name)),
                    Some(TokenTree::Group(arms)),
                ) = (flat.get(at + 1), flat.get(at + 2), flat.get(at + 3))
                    && bang.as_char() == '!'
                {
                    let mut inner = Calls::default();
                    for expansion in transcribers(&arms.stream()) {
                        calls_in(&expansion, &mut inner);
                    }
                    calls.absorb(name.to_string(), inner);
                    at += 4;
                    continue;
                }
            }
            TokenTree::Group(group) => calls_in(&group.stream(), calls),
            TokenTree::Ident(ident)
                if matches!(flat.get(at + 1), Some(TokenTree::Punct(bang)) if bang.as_char() == '!')
                    && matches!(flat.get(at + 2), Some(TokenTree::Group(_))) =>
            {
                let name = ident.to_string();
                calls.all.names.insert(name.clone());
                if at > 0
                    && matches!(&flat[at - 1], TokenTree::Punct(dollar) if dollar.as_char() == '$')
                {
                    calls.all.through_metavariable = true;
                }
                if matches!(flat.get(at + 2), Some(TokenTree::Group(arguments))
                    if !kinds_of(&arguments.stream()).is_empty())
                {
                    calls.sighted.insert(name);
                }
            }
            _ => {}
        }
        at += 1;
    }
}

/// The kinds of sighting the tokens hold: a variant name or a wire name, a `MutationRequest` or an
/// `ActionTarget` with a brace group after it.
fn kinds_of(stream: &TokenStream) -> BTreeSet<SightKind> {
    kinds_in(stream, None)
}

/// What the tokens of an item sight. `owner` is the kind of the type of an enclosing `impl` for
/// `MutationRequest` or `ActionTarget`, whose `Self { .. }` is a literal of it.
fn kinds_in(stream: &TokenStream, owner: Option<SightKind>) -> BTreeSet<SightKind> {
    let mut kinds = BTreeSet::new();
    collect_kinds(stream, &mut kinds, owner);
    kinds
}

/// Whether a literal's value, once its escapes are decoded, holds a wire name: a string, a raw
/// string, a byte string or a C string.
fn holds_a_wire_name(literal: &proc_macro2::Literal) -> bool {
    let holds = |value: &[u8]| {
        WIRE_NAMES.iter().any(|wire| {
            value
                .windows(wire.len())
                .any(|window| window == wire.as_bytes())
        })
    };
    match syn::parse_str::<syn::Lit>(&literal.to_string()) {
        Ok(syn::Lit::Str(text)) => holds(text.value().as_bytes()),
        Ok(syn::Lit::ByteStr(bytes)) => holds(&bytes.value()),
        Ok(syn::Lit::CStr(text)) => holds(text.value().to_bytes()),
        _ => false,
    }
}

/// Each of the six variant names, wherever it stands, is a sighting, but for the one path
/// `ActionRight::<Variant>`, which is a right of the same name. A wire name in a literal, and the
/// brace form of `MutationRequest` and `ActionTarget`, are sightings.
fn collect_kinds(stream: &TokenStream, kinds: &mut BTreeSet<SightKind>, owner: Option<SightKind>) {
    let flat: Vec<TokenTree> = stream.clone().into_iter().collect();
    let is_brace = |tree: Option<&TokenTree>| matches!(tree, Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Brace);
    let is_colon = |tree: Option<&TokenTree>| matches!(tree, Some(TokenTree::Punct(punct)) if punct.as_char() == ':');
    for (at, tree) in flat.iter().enumerate() {
        match tree {
            TokenTree::Group(group) => collect_kinds(&group.stream(), kinds, owner),
            TokenTree::Literal(literal) => {
                if holds_a_wire_name(literal) {
                    kinds.insert(SightKind::Names);
                }
            }
            TokenTree::Ident(ident) => {
                let word = ident.to_string();
                let word = word.trim_start_matches("r#");
                if word == "MutationRequest" && is_brace(flat.get(at + 1)) {
                    kinds.insert(SightKind::Request);
                }
                if word == "ActionTarget" && is_brace(flat.get(at + 1)) {
                    kinds.insert(SightKind::Target);
                }
                if word == "Self"
                    && let Some(kind) = owner
                    && is_brace(flat.get(at + 1))
                {
                    kinds.insert(kind);
                }
                let right = at >= 3
                    && is_colon(flat.get(at - 1))
                    && is_colon(flat.get(at - 2))
                    && matches!(flat.get(at - 3), Some(TokenTree::Ident(before)) if before == "ActionRight");
                if VARIANTS.contains(&word) && !right {
                    kinds.insert(SightKind::Names);
                }
            }
            TokenTree::Punct(_) => {}
        }
    }
}
