//! The module inventory of a crate: the files that product code is made of.
//!
//! The inventory starts at the crate's roots, the library and binary targets Cargo reports for it,
//! and follows the module declarations that some configuration without `test` builds (see
//! `condition`), as rustc finds the files: `mod name;` is `name.rs` or `name/mod.rs` beside the file
//! or in a folder of its name, and `#[path = "..."]` is relative to the file's folder, or to the
//! inline module's folder inside one. A file is read under the condition of the declaration that
//! reaches it, and under each when several do. A file no declaration reaches is not read. The item
//! index and the scan both take their files, with those conditions, from here.
//!
//! What the inventory does not read it refuses, with an error that names the file: a path through a
//! link or outside the checkout, a module declared in a block or by a macro, `include!`, a `#[path]`
//! that is not one string, a module that is at no file or at two, a crate with no target, a macro
//! defined twice, and an item-position macro of another crate that is not on the list of those
//! accepted.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use proc_macro2::{TokenStream, TokenTree};
use syn::ext::IdentExt as _;
use syn::visit::Visit;

use super::condition::Condition;
use super::walker::normalised;

/// The item-position macros of other crates that product code may call, with why none of them can
/// make a module file or a sender.
const ACCEPTED: &[(&str, &str)] = &[
    (
        "thread_local",
        "the standard library's macro makes thread-local statics from `static` items: no module and no path of `Method`",
    ),
    (
        "task_local",
        "tokio's macro makes task-local statics from `static` items, as `thread_local` does",
    ),
    (
        "bindgen",
        "wasmtime's `component::bindgen!` makes the WIT bindings' types, traits and inline modules from a .wit file; it reads no Rust file module and names no KR method",
    ),
    (
        "compile_error",
        "makes no item: it stops the build with a message",
    ),
    (
        "ios_plugin_binding",
        "tauri's macro makes the iOS plugin's start function; it reads no Rust file module and names no KR method",
    ),
    (
        "debug_as_display",
        "kr_client's macro writes a `Debug` impl that prints the failure's `Display`: an impl of a trait of its own and nothing it holds",
    ),
    (
        "debug_as_name",
        "kr_client's macro writes a `Debug` impl that prints the type's name only",
    ),
    (
        "debug_fields",
        "kr_client's macro writes a `Debug` impl that prints the fields named",
    ),
    (
        "display_as_said",
        "kr_client's macro writes a `Display` impl from a `Said` implementation",
    ),
];

/// A target Cargo builds from one source file, which is where the inventory of its crate starts.
pub struct Root {
    pub path: PathBuf,
    /// The features the target requires: it is read under each of them.
    pub features: Vec<String>,
}

/// A product file, with the condition it is reached under.
pub struct File {
    /// The canonical path.
    pub path: PathBuf,
    /// The condition around the declaration that reaches the file, or any one of them when several
    /// do. The file's own inner attributes and its items add to it.
    pub condition: Condition,
}

/// What the product code of a crate is made of.
pub struct Inventory {
    /// The product files in path order.
    pub files: Vec<File>,
    /// The `macro_rules!` names product code defines, at any depth.
    pub defined: BTreeSet<String>,
    /// The names of those that carry `#[macro_export]`.
    pub exported: BTreeSet<String>,
    /// The files that import `Method::*` or `Method` under another name.
    pub method_uses: Vec<String>,
    /// The item-position macros that nothing in the crate defines and the scan does not accept:
    /// the file and the name of the first call of each.
    pub unaccepted: Vec<(String, String)>,
}

/// One body-less module declaration that product code makes: where its file may be, and whether a
/// `#[path]` names it.
struct Declared {
    name: String,
    candidates: Vec<PathBuf>,
    explicit: bool,
    /// Whether `#[macro_use]` is on the declaration, so that the macros of its file stay in scope
    /// after it.
    macro_use: bool,
    /// What holds around the declaration: the file is read under it.
    condition: Condition,
}

/// Whether `path` is a file: a path that is not there, or has a file where a folder should be, is
/// not, and any other failure is an error.
fn is_file(path: &Path) -> Result<bool, String> {
    match std::fs::metadata(path) {
        Ok(found) => Ok(found.is_file()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// Reads the inventory of the crate `krate`, which Cargo builds from `roots`, inside the tree at
/// `root`.
pub fn read(krate: &str, roots: &[Root], root: &Path) -> Result<Inventory, String> {
    if roots.is_empty() {
        return Err(format!("{krate}: no library or binary target"));
    }
    let shown = |path: &Path| {
        path.strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string()
    };
    let mut todo: Vec<(PathBuf, bool, bool, Condition)> = roots
        .iter()
        .map(|target| {
            (
                target.path.clone(),
                true,
                false,
                Condition::requiring(&target.features),
            )
        })
        .collect();
    let mut seen: BTreeSet<(PathBuf, bool, bool, Condition)> = BTreeSet::new();
    let mut reached: BTreeMap<PathBuf, BTreeSet<Condition>> = BTreeMap::new();
    // For each macro name: where it is defined, and whether the definition's scope reaches
    // beyond its module (`#[macro_export]`, or a module under `#[macro_use]`).
    let mut defined: BTreeMap<String, Vec<(String, bool)>> = BTreeMap::new();
    let mut exported = BTreeSet::new();
    let mut calls: Vec<(String, String)> = Vec::new();
    let mut method_uses = Vec::new();
    while let Some(visit) = todo.pop() {
        if !seen.insert(visit.clone()) {
            continue;
        }
        let (path, beside, macro_use, carried) = visit;
        let at = shown(&path);
        let real = std::fs::canonicalize(&path).map_err(|error| format!("{at}: {error}"))?;
        if real != path || !path.starts_with(root) {
            return Err(format!(
                "{at}: the scan does not read a path through a link or outside the checkout (it is {})",
                real.display()
            ));
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let parsed =
            syn::parse_file(&text).map_err(|error| format!("{}: {error}", path.display()))?;
        let Some(condition) = carried.within(&parsed.attrs, &at)? else {
            continue;
        };
        reached
            .entry(path.clone())
            .or_default()
            .insert(carried.clone());
        let directory = path.parent().unwrap_or(Path::new(""));
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or_default();
        // The modules of a root and of a `mod.rs` sit beside the file, those of other files in a
        // folder of the file's name.
        let modules = if beside {
            directory.to_owned()
        } else {
            directory.join(stem)
        };
        let mut reader = Reader {
            at: &at,
            condition,
            saved: Vec::new(),
            path_base: directory.to_owned(),
            modules,
            macro_use: usize::from(macro_use),
            block: 0,
            declared: Vec::new(),
            defined: Vec::new(),
            calls: Vec::new(),
            method_use: false,
            error: None,
        };
        reader.visit_file(&parsed);
        if let Some(error) = reader.error {
            return Err(error);
        }
        for (name, export, leaks) in reader.defined {
            if export {
                exported.insert(name.clone());
            }
            defined
                .entry(name)
                .or_default()
                .push((at.clone(), export || leaks));
        }
        calls.extend(reader.calls.into_iter().map(|name| (at.clone(), name)));
        if reader.method_use {
            method_uses.push(at.clone());
        }
        for declared in reader.declared {
            let mut found: Vec<&PathBuf> = Vec::new();
            for candidate in &declared.candidates {
                if is_file(candidate)? {
                    found.push(candidate);
                }
            }
            let list = |paths: &[&PathBuf]| {
                paths
                    .iter()
                    .map(|path| shown(path))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            match found.as_slice() {
                [one] => {
                    // A file that a `#[path]` loads keeps its modules beside it, as `mod.rs` does.
                    let beside =
                        declared.explicit || one.file_name().is_some_and(|name| name == "mod.rs");
                    todo.push((
                        (*one).clone(),
                        beside,
                        declared.macro_use,
                        declared.condition.clone(),
                    ));
                }
                [] => {
                    let tried: Vec<&PathBuf> = declared.candidates.iter().collect();
                    return Err(format!(
                        "{at}: mod {} is at no file the scan can find (tried {})",
                        declared.name,
                        list(&tried)
                    ));
                }
                _ => {
                    return Err(format!(
                        "{at}: mod {} is at two files ({})",
                        declared.name,
                        list(&found)
                    ));
                }
            }
        }
    }
    // Two definitions of a name in different files, each private to its module, do not meet: the
    // scan takes the calls of both under the name. One file twice shadows, and a definition whose
    // scope reaches beyond its module can hide, or be hidden by, any other.
    for (name, places) in &defined {
        let files: BTreeSet<&String> = places.iter().map(|(file, _)| file).collect();
        if places.len() > 1
            && (files.len() < places.len() || places.iter().any(|(_, leaks)| *leaks))
        {
            return Err(format!(
                "{krate}: the macro {name} is defined twice where one definition can hide the other ({}); the scan reads one definition of a name",
                places
                    .iter()
                    .map(|(file, _)| file.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    let mut unaccepted: BTreeMap<String, String> = BTreeMap::new();
    for (at, name) in &calls {
        let accepted = ACCEPTED.iter().any(|(accepted, _)| accepted == name);
        if !defined.contains_key(name) && !accepted {
            unaccepted.entry(name.clone()).or_insert_with(|| at.clone());
        }
    }
    Ok(Inventory {
        files: reached
            .into_iter()
            .map(|(path, conditions)| File {
                path,
                condition: Condition::any_of(&conditions.into_iter().collect::<Vec<_>>()),
            })
            .collect(),
        defined: defined.into_keys().collect(),
        exported,
        method_uses,
        unaccepted: unaccepted
            .into_iter()
            .map(|(name, at)| (at, name))
            .collect(),
    })
}

/// Reads one parsed file: the module declarations product code makes in it, and what the inventory
/// refuses.
struct Reader<'a> {
    at: &'a str,
    condition: Condition,
    saved: Vec<Condition>,
    path_base: PathBuf,
    modules: PathBuf,
    /// How many blocks the visit is inside.
    block: usize,
    declared: Vec<Declared>,
    /// `macro_rules!` definitions: the name, whether it is exported, and whether a module under
    /// `#[macro_use]` holds it.
    defined: Vec<(String, bool, bool)>,
    /// How many `#[macro_use]` modules the visit is inside (the file itself counts).
    macro_use: usize,
    /// The macros called at item position.
    calls: Vec<String>,
    method_use: bool,
    error: Option<String>,
}

impl Reader<'_> {
    /// Enters a place with these attributes: whether product code is there.
    fn enter(&mut self, attrs: &[syn::Attribute]) -> bool {
        if self.error.is_some() {
            return false;
        }
        match self.condition.within(attrs, self.at) {
            Ok(Some(inner)) => {
                self.saved
                    .push(std::mem::replace(&mut self.condition, inner));
                true
            }
            Ok(None) => false,
            Err(error) => {
                self.error = Some(error);
                false
            }
        }
    }

    fn leave(&mut self) {
        if let Some(outer) = self.saved.pop() {
            self.condition = outer;
        }
    }

    fn call(&mut self, path: &syn::Path) {
        if let Some(last) = path.segments.last() {
            self.calls.push(last.ident.to_string());
        }
    }
}

/// The overrides that leave a place out where no configuration without `test` builds it.
macro_rules! gated {
    ($($visit:ident => $walk:ident($node:ty);)*) => {$(
        fn $visit(&mut self, node: &'ast $node) {
            if self.enter(&node.attrs) {
                syn::visit::$walk(self, node);
                self.leave();
            }
        }
    )*};
}

impl<'ast> Visit<'ast> for Reader<'_> {
    gated! {
        visit_item_const => visit_item_const(syn::ItemConst);
        visit_item_enum => visit_item_enum(syn::ItemEnum);
        visit_item_extern_crate => visit_item_extern_crate(syn::ItemExternCrate);
        visit_item_fn => visit_item_fn(syn::ItemFn);
        visit_item_foreign_mod => visit_item_foreign_mod(syn::ItemForeignMod);
        visit_item_impl => visit_item_impl(syn::ItemImpl);
        visit_item_static => visit_item_static(syn::ItemStatic);
        visit_item_struct => visit_item_struct(syn::ItemStruct);
        visit_item_trait => visit_item_trait(syn::ItemTrait);
        visit_item_trait_alias => visit_item_trait_alias(syn::ItemTraitAlias);
        visit_item_type => visit_item_type(syn::ItemType);
        visit_item_union => visit_item_union(syn::ItemUnion);
        visit_impl_item_const => visit_impl_item_const(syn::ImplItemConst);
        visit_impl_item_fn => visit_impl_item_fn(syn::ImplItemFn);
        visit_impl_item_type => visit_impl_item_type(syn::ImplItemType);
        visit_trait_item_const => visit_trait_item_const(syn::TraitItemConst);
        visit_trait_item_fn => visit_trait_item_fn(syn::TraitItemFn);
        visit_trait_item_type => visit_trait_item_type(syn::TraitItemType);
    }

    fn visit_block(&mut self, node: &'ast syn::Block) {
        self.block += 1;
        syn::visit::visit_block(self, node);
        self.block -= 1;
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if !self.enter(&node.attrs) {
            return;
        }
        let name = node.ident.unraw().to_string();
        match path_attribute(&node.attrs) {
            Err(()) => {
                self.error = Some(format!(
                    "{}: the scan reads #[path] as one string literal only (mod {name})",
                    self.at
                ));
            }
            Ok(explicit) => match &node.content {
                Some(_) => {
                    // The folder of an inline module with a `#[path]` is that path, taken from the
                    // file's folder, and holds the modules inside it.
                    let inside = match &explicit {
                        Some(path) => normalised(&self.path_base.join(path)),
                        None => self.modules.join(&name),
                    };
                    let outer_base = std::mem::replace(&mut self.path_base, inside.clone());
                    let outer_modules = std::mem::replace(&mut self.modules, inside);
                    let uses = usize::from(has_macro_use(&node.attrs));
                    self.macro_use += uses;
                    syn::visit::visit_item_mod(self, node);
                    self.macro_use -= uses;
                    self.path_base = outer_base;
                    self.modules = outer_modules;
                }
                None if self.block > 0 => {
                    self.error = Some(format!(
                        "{}: the scan does not read a module declared in a block (mod {name};)",
                        self.at
                    ));
                }
                None => {
                    let (candidates, explicit) = match explicit {
                        Some(path) => (vec![normalised(&self.path_base.join(path))], true),
                        None => (
                            vec![
                                self.modules.join(format!("{name}.rs")),
                                self.modules.join(&name).join("mod.rs"),
                            ],
                            false,
                        ),
                    };
                    self.declared.push(Declared {
                        name,
                        candidates,
                        explicit,
                        macro_use: has_macro_use(&node.attrs),
                        condition: self.condition.clone(),
                    });
                }
            },
        }
        self.leave();
    }

    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        if !self.enter(&node.attrs) {
            return;
        }
        match &node.ident {
            Some(name) if node.mac.path.is_ident("macro_rules") => {
                let exported = node
                    .attrs
                    .iter()
                    .any(|attribute| attribute.path().is_ident("macro_export"));
                self.defined
                    .push((name.to_string(), exported, self.macro_use > 0));
            }
            _ => self.call(&node.mac.path),
        }
        syn::visit::visit_item_macro(self, node);
        self.leave();
    }

    fn visit_impl_item_macro(&mut self, node: &'ast syn::ImplItemMacro) {
        if self.enter(&node.attrs) {
            self.call(&node.mac.path);
            syn::visit::visit_impl_item_macro(self, node);
            self.leave();
        }
    }

    fn visit_trait_item_macro(&mut self, node: &'ast syn::TraitItemMacro) {
        if self.enter(&node.attrs) {
            self.call(&node.mac.path);
            syn::visit::visit_trait_item_macro(self, node);
            self.leave();
        }
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if self.error.is_none() {
            let name = node
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
                .unwrap_or_default();
            if name == "include" {
                self.error = Some(format!("{}: the scan does not read include!", self.at));
            } else if let Some(module) = module_in(&node.tokens) {
                self.error = Some(format!(
                    "{}: the scan does not read a module declared in a macro (mod {module}; in the tokens of {name}!)",
                    self.at
                ));
            }
        }
        syn::visit::visit_macro(self, node);
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        if self.enter(&node.attrs) {
            self.method_use |= renames_method(&node.tree, false);
            self.leave();
        }
    }
}

fn has_macro_use(attrs: &[syn::Attribute]) -> bool {
    attrs
        .iter()
        .any(|attribute| attribute.path().is_ident("macro_use"))
}

/// The string of a `#[path = "..."]` attribute: `Ok(None)` where there is none, `Err` where there is
/// one that is not a string literal.
fn path_attribute(attrs: &[syn::Attribute]) -> Result<Option<String>, ()> {
    for attribute in attrs {
        if !attribute.path().is_ident("path") {
            continue;
        }
        return match &attribute.meta {
            syn::Meta::NameValue(pair) => match &pair.value {
                syn::Expr::Lit(literal) => match &literal.lit {
                    syn::Lit::Str(text) => Ok(Some(text.value())),
                    _ => Err(()),
                },
                _ => Err(()),
            },
            _ => Err(()),
        };
    }
    Ok(None)
}

/// The name of a `mod name;` written in the tokens: in a macro's arguments, or in its definition.
fn module_in(tokens: &TokenStream) -> Option<String> {
    let flat: Vec<TokenTree> = tokens.clone().into_iter().collect();
    for (at, tree) in flat.iter().enumerate() {
        match tree {
            TokenTree::Group(group) => {
                if let Some(found) = module_in(&group.stream()) {
                    return Some(found);
                }
            }
            TokenTree::Ident(word) if word == "mod" => {
                let named = match (flat.get(at + 1), flat.get(at + 2), flat.get(at + 3)) {
                    (Some(TokenTree::Ident(name)), Some(TokenTree::Punct(end)), _)
                        if end.as_char() == ';' =>
                    {
                        Some(name.to_string())
                    }
                    (
                        Some(TokenTree::Punct(dollar)),
                        Some(TokenTree::Ident(name)),
                        Some(TokenTree::Punct(end)),
                    ) if dollar.as_char() == '$' && end.as_char() == ';' => {
                        Some(format!("${name}"))
                    }
                    _ => None,
                };
                if named.is_some() {
                    return named;
                }
            }
            _ => {}
        }
    }
    None
}

/// Whether a `use` tree imports `Method::*`, or `Method` under another name.
fn renames_method(tree: &syn::UseTree, under_method: bool) -> bool {
    match tree {
        syn::UseTree::Path(path) => renames_method(&path.tree, path.ident == "Method"),
        syn::UseTree::Group(group) => group
            .items
            .iter()
            .any(|inner| renames_method(inner, under_method)),
        syn::UseTree::Glob(_) => under_method,
        syn::UseTree::Rename(rename) => {
            rename.ident == "Method" || (under_method && rename.ident == "self")
        }
        syn::UseTree::Name(_) => false,
    }
}
