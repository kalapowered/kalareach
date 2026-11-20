//! The module inventory of a crate: the files that product code is made of.
//!
//! The inventory starts at the crate's roots, the library and binary targets Cargo reports for it,
//! and follows the module declarations that are not false without `test` (see `condition`), as
//! rustc finds the files: `mod name;` is `name.rs` or `name/mod.rs` beside the file or in a folder of
//! its name, and `#[path = "..."]` is relative to the file's folder, or to the inline module's folder
//! inside one. A file is read when a declaration that is not false reaches it and its own inner
//! attributes are not false. A file no declaration reaches is not read. The item index and the scan
//! both take their files from here.
//!
//! What the inventory does not read it refuses, with an error that names the file: a path through a
//! link or outside the checkout, a module declared in a block or by a macro, `include!`, a `#[path]`
//! that is not one string, a module that is at no file or at two, a crate with no target, a macro
//! defined twice, and an item-position macro of another crate that is not on the list of those
//! accepted. The macros called in the transcribers of a `macro_rules!` definition, at any depth,
//! are held to the same list.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use proc_macro2::{TokenStream, TokenTree};
use syn::ext::IdentExt as _;
use syn::visit::Visit;

use super::condition;
use super::walker::{VARIANTS, is_own_prefix, normalised, path_before, transcribers};

/// The macros of other crates that product code may call at item position and in a transcriber, each
/// with the paths that name its provider (`""` is a bare call) and why none of them can make a module
/// file or a sender. A name from any other provider is refused.
const ACCEPTED: &[(&str, &[&str], &str)] = &[
    (
        "thread_local",
        &["", "std"],
        "the standard library's macro makes thread-local statics from `static` items: no module and no path of `Method`",
    ),
    (
        "task_local",
        &["tokio"],
        "tokio's macro makes task-local statics from `static` items, as `thread_local` does",
    ),
    (
        "bindgen",
        &["wasmtime::component"],
        "wasmtime's `component::bindgen!` makes the WIT bindings' types, traits and inline modules from a .wit file; it reads no Rust file module and names no KR method",
    ),
    (
        "compile_error",
        &["", "std", "core"],
        "makes no item: it stops the build with a message",
    ),
    (
        "ios_plugin_binding",
        &["tauri"],
        "tauri's macro makes the iOS plugin's start function; it reads no Rust file module and names no KR method",
    ),
    (
        "json_schema",
        &["schemars"],
        "builds a schema value from its tokens; it reads no Rust file module and makes no item",
    ),
    (
        "debug_as_display",
        &["kr_client"],
        "kr_client's macro writes a `Debug` impl that prints the failure's `Display`: an impl of a trait of its own and nothing it holds",
    ),
    (
        "debug_as_name",
        &["kr_client"],
        "kr_client's macro writes a `Debug` impl that prints the type's name only",
    ),
    (
        "debug_fields",
        &["kr_client"],
        "kr_client's macro writes a `Debug` impl that prints the fields named",
    ),
    (
        "display_as_said",
        &["kr_client"],
        "kr_client's macro writes a `Display` impl from a `Said` implementation",
    ),
];

/// The macros of the standard library that a bare call names and that make no item and read no file:
/// the ones the transcribers of the workspace and of its release tags call, and their siblings.
/// `include` is not among them (the scan does not read it), and `thread_local` and `compile_error`
/// are in [`ACCEPTED`].
const STD_MACROS: &[&str] = &[
    "assert",
    "assert_eq",
    "assert_ne",
    "column",
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
    "todo",
    "unimplemented",
    "unreachable",
    "vec",
    "write",
    "writeln",
];

/// What a macro call is resolved in: the crate's own definitions and modules, and what its `use`
/// lines import by name.
struct Scope {
    /// The `macro_rules!` names defined in the crate, and those written in the tokens of one.
    defined: BTreeSet<String>,
    /// The names of the modules the crate declares.
    modules: BTreeSet<String>,
    /// For each name a `use` brings in, the full paths it stands for. A glob stands for none.
    imports: BTreeMap<String, BTreeSet<Vec<String>>>,
}

impl Scope {
    /// Whether the call written as `path` is the crate's own macro, a macro of the standard library
    /// that makes no item (by its bare name or by a path of `std`, `core` or `alloc`), or one of
    /// [`ACCEPTED`] from the provider that makes it safe.
    fn accepts(&self, path: &[String]) -> bool {
        let Some(first) = path.first() else {
            return false;
        };
        match self.imports.get(first) {
            Some(fulls) => fulls.iter().all(|full| {
                let mut resolved = full.clone();
                resolved.extend_from_slice(&path[1..]);
                self.resolved(&resolved)
            }),
            None => self.resolved(path),
        }
    }

    /// `accepts` for a path whose first segment is no imported name.
    fn resolved(&self, path: &[String]) -> bool {
        let (Some(name), Some(first)) = (path.last(), path.first()) else {
            return false;
        };
        if path.len() == 1 {
            return self.defined.contains(name)
                || STD_MACROS.contains(&name.as_str())
                || Self::provided(name, "");
        }
        if is_own_prefix(first) {
            return true;
        }
        if matches!(first.as_str(), "std" | "core" | "alloc") && STD_MACROS.contains(&name.as_str())
        {
            return true;
        }
        self.modules.contains(first) || Self::provided(name, &path[..path.len() - 1].join("::"))
    }

    /// Whether `provider` is one of those the family `name` is accepted from.
    fn provided(name: &str, provider: &str) -> bool {
        ACCEPTED
            .iter()
            .any(|(accepted, providers, _)| *accepted == name && providers.contains(&provider))
    }
}

/// What the product code of a crate is made of.
pub struct Inventory {
    /// The product files in path order, by canonical path.
    pub files: Vec<PathBuf>,
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

/// Reads the inventory of the crate `krate`, which Cargo builds from the source files `roots`, inside
/// the tree at `root`.
pub fn read(krate: &str, roots: &[PathBuf], root: &Path) -> Result<Inventory, String> {
    if roots.is_empty() {
        return Err(format!("{krate}: no library or binary target"));
    }
    let shown = |path: &Path| {
        path.strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string()
    };
    let mut todo: Vec<(PathBuf, bool)> = roots.iter().map(|target| (target.clone(), true)).collect();
    let mut seen: BTreeSet<(PathBuf, bool)> = BTreeSet::new();
    let mut reached: BTreeSet<PathBuf> = BTreeSet::new();
    // The names the crate defines a `macro_rules!` for. Definitions of one name, in any place, are one
    // under it: what either calls is called, so a name defined twice adds marks and takes none away.
    let mut defined: BTreeSet<String> = BTreeSet::new();
    let mut exported = BTreeSet::new();
    let mut calls: Vec<(String, Vec<String>)> = Vec::new();
    let mut imports: BTreeMap<String, BTreeSet<Vec<String>>> = BTreeMap::new();
    let mut module_set: BTreeSet<String> = BTreeSet::new();
    let mut token_defined: BTreeSet<String> = BTreeSet::new();
    let mut method_uses = Vec::new();
    let mut defines_method = false;
    while let Some(visit) = todo.pop() {
        if !seen.insert(visit.clone()) {
            continue;
        }
        let (path, beside) = visit;
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
        if !condition::enabled(&parsed.attrs, &at)? {
            continue;
        }
        reached.insert(path.clone());
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
            path_base: directory.to_owned(),
            modules,
            block: 0,
            declared: Vec::new(),
            defined: Vec::new(),
            calls: Vec::new(),
            token_defined: Vec::new(),
            imports: Vec::new(),
            module_names: Vec::new(),
            method_use: false,
            defines_method: false,
            in_method_impl: false,
            error: None,
        };
        reader.visit_file(&parsed);
        if let Some(error) = reader.error {
            return Err(error);
        }
        for (name, export) in reader.defined {
            if export {
                exported.insert(name.clone());
            }
            defined.insert(name);
        }
        calls.extend(reader.calls.into_iter().map(|path| (at.clone(), path)));
        for (local, full) in reader.imports {
            imports.entry(local).or_default().insert(full);
        }
        module_set.extend(reader.module_names);
        token_defined.extend(reader.token_defined);
        if reader.method_use {
            method_uses.push(at.clone());
        }
        defines_method |= reader.defines_method;
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
                    todo.push(((*one).clone(), beside));
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
    let scope = Scope {
        defined: defined.iter().cloned().chain(token_defined).collect(),
        modules: module_set,
        imports,
    };
    let mut unaccepted: BTreeMap<String, String> = BTreeMap::new();
    for (at, path) in &calls {
        if let Some(name) = path.last()
            && !scope.accepts(path)
        {
            unaccepted.entry(name.clone()).or_insert_with(|| at.clone());
        }
    }
    Ok(Inventory {
        files: reached.into_iter().collect(),
        defined,
        exported,
        // The crate that defines `Method` names its own variants (`Self::Variant`, a glob of them,
        // an alias) and matches them: it is the definition and is not read as a sender.
        method_uses: if defines_method {
            Vec::new()
        } else {
            method_uses
        },
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
    path_base: PathBuf,
    modules: PathBuf,
    /// How many blocks the visit is inside.
    block: usize,
    declared: Vec<Declared>,
    /// `macro_rules!` definitions: the name, and whether it is exported.
    defined: Vec<(String, bool)>,
    /// The macros called at item position and in the transcribers of a definition, as written.
    calls: Vec<Vec<String>>,
    /// The `macro_rules!` names written in those transcribers.
    token_defined: Vec<String>,
    /// What each `use` brings in: the name it gives, and the path it stands for.
    imports: Vec<(String, Vec<String>)>,
    /// The modules declared.
    module_names: Vec<String>,
    method_use: bool,
    /// Whether an `enum Method` is defined.
    defines_method: bool,
    /// Whether the visit is inside an `impl` for `Method`.
    in_method_impl: bool,
    error: Option<String>,
}

impl Reader<'_> {
    /// Whether product code is in a place with these attributes.
    fn enter(&mut self, attrs: &[syn::Attribute]) -> bool {
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

    /// The path a `#[path]` names: the string written, taken from the folder it is relative to, with
    /// its steps up cancelled. No step of the string leads through a link, whatever file the link
    /// leads to: the steps are taken one by one, each looked at as the file system holds it, and a
    /// link is refused where it stands. A path that stops at a folder that is not there is left as
    /// written and finds no file.
    fn explicit_path(&mut self, written: &str) -> PathBuf {
        let joined = self.path_base.join(written);
        let mut walked = self.path_base.clone();
        for step in Path::new(written).components() {
            walked.push(step);
            if matches!(step, std::path::Component::ParentDir) {
                continue;
            }
            match std::fs::symlink_metadata(&walked) {
                Ok(found) if found.file_type().is_symlink() => {
                    self.error = Some(format!(
                        "{}: the scan does not read a path through a link or outside the checkout ({} is a link)",
                        self.at,
                        walked.display()
                    ));
                    break;
                }
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                    ) =>
                {
                    return joined;
                }
                Err(error) => {
                    self.error = Some(format!("{}: {error}", walked.display()));
                    break;
                }
            }
        }
        normalised(&joined)
    }

    fn call(&mut self, path: &syn::Path) {
        if !path.segments.is_empty() {
            self.calls.push(
                path.segments
                    .iter()
                    .map(|segment| segment.ident.unraw().to_string())
                    .collect(),
            );
        }
    }

    /// Whether the attributes carry `#[name]`, written or added by a `cfg_attr` that some
    /// configuration enables.
    fn carries(&mut self, attrs: &[syn::Attribute], name: &str) -> bool {
        match condition::carries(attrs, name, self.at) {
            Ok(found) => found,
            Err(error) => {
                self.error.get_or_insert(error);
                false
            }
        }
    }
}

/// The overrides that leave a place out where no configuration without `test` builds it.
macro_rules! gated {
    ($($visit:ident => $walk:ident($node:ty);)*) => {$(
        fn $visit(&mut self, node: &'ast $node) {
            if self.enter(&node.attrs) {
                syn::visit::$walk(self, node);
            }
        }
    )*};
}

impl<'ast> Visit<'ast> for Reader<'_> {
    gated! {
        visit_item_const => visit_item_const(syn::ItemConst);
        visit_item_extern_crate => visit_item_extern_crate(syn::ItemExternCrate);
        visit_item_fn => visit_item_fn(syn::ItemFn);
        visit_item_foreign_mod => visit_item_foreign_mod(syn::ItemForeignMod);
        visit_item_static => visit_item_static(syn::ItemStatic);
        visit_item_struct => visit_item_struct(syn::ItemStruct);
        visit_item_trait => visit_item_trait(syn::ItemTrait);
        visit_item_trait_alias => visit_item_trait_alias(syn::ItemTraitAlias);
        visit_item_union => visit_item_union(syn::ItemUnion);
        visit_impl_item_const => visit_impl_item_const(syn::ImplItemConst);
        visit_impl_item_fn => visit_impl_item_fn(syn::ImplItemFn);
        visit_impl_item_type => visit_impl_item_type(syn::ImplItemType);
        visit_trait_item_const => visit_trait_item_const(syn::TraitItemConst);
        visit_trait_item_fn => visit_trait_item_fn(syn::TraitItemFn);
        visit_trait_item_type => visit_trait_item_type(syn::TraitItemType);
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        if self.enter(&node.attrs) {
            self.defines_method |= node.ident == "Method";
            syn::visit::visit_item_enum(self, node);
        }
    }

    /// An alias of `Method` names its variants under another name.
    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        if self.enter(&node.attrs) {
            self.method_use |= ends_in_method(&node.ty);
            syn::visit::visit_item_type(self, node);
        }
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if self.enter(&node.attrs) {
            let outer = std::mem::replace(&mut self.in_method_impl, ends_in_method(&node.self_ty));
            syn::visit::visit_item_impl(self, node);
            self.in_method_impl = outer;
        }
    }

    /// `Self::<Variant>` in an impl for `Method` is the variant by another name.
    fn visit_path(&mut self, node: &'ast syn::Path) {
        if self.in_method_impl
            && let [first, second, ..] = node.segments.iter().collect::<Vec<_>>().as_slice()
            && first.ident == "Self"
            && VARIANTS.contains(&second.ident.to_string().as_str())
        {
            self.method_use = true;
        }
        syn::visit::visit_path(self, node);
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
        self.module_names.push(name.clone());
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
                        Some(path) => self.explicit_path(path),
                        None => self.modules.join(&name),
                    };
                    let outer_base = std::mem::replace(&mut self.path_base, inside.clone());
                    let outer_modules = std::mem::replace(&mut self.modules, inside);
                    syn::visit::visit_item_mod(self, node);
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
                        Some(path) => (vec![self.explicit_path(&path)], true),
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
                    });
                }
            },
        }
    }

    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        if !self.enter(&node.attrs) {
            return;
        }
        match &node.ident {
            Some(name) if node.mac.path.is_ident("macro_rules") => {
                let exported = self.carries(&node.attrs, "macro_export");
                self.defined.push((name.to_string(), exported));
                for expansion in transcribers(&node.mac.tokens) {
                    token_calls(&expansion, &mut self.calls, &mut self.token_defined);
                }
            }
            _ => self.call(&node.mac.path),
        }
        syn::visit::visit_item_macro(self, node);
    }

    fn visit_impl_item_macro(&mut self, node: &'ast syn::ImplItemMacro) {
        if self.enter(&node.attrs) {
            self.call(&node.mac.path);
            syn::visit::visit_impl_item_macro(self, node);
        }
    }

    fn visit_trait_item_macro(&mut self, node: &'ast syn::TraitItemMacro) {
        if self.enter(&node.attrs) {
            self.call(&node.mac.path);
            syn::visit::visit_trait_item_macro(self, node);
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
            } else {
                match form_in(&node.tokens) {
                    Some(Form::Include) => {
                        self.error = Some(format!("{}: the scan does not read include!", self.at));
                    }
                    Some(Form::Module(module)) => {
                        self.error = Some(format!(
                            "{}: the scan does not read a module declared in a macro (mod {module}; in the tokens of {name}!)",
                            self.at
                        ));
                    }
                    None => {}
                }
            }
        }
        syn::visit::visit_macro(self, node);
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        if self.enter(&node.attrs) {
            self.method_use |= renames_method(&node.tree, false);
            use_paths(&node.tree, &mut Vec::new(), &mut self.imports);
        }
    }
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

/// Whether a type is a path that ends in `Method`.
fn ends_in_method(ty: &syn::Type) -> bool {
    matches!(ty, syn::Type::Path(path) if path.qself.is_none()
        && path.path.segments.last().is_some_and(|segment| segment.ident == "Method"))
}

/// What the inventory does not read, written in the tokens of a macro.
enum Form {
    /// `include!(..)`.
    Include,
    /// A module declaration, with the name as written: `name`, `$name`, or `$(...)` for a
    /// repetition.
    Module(String),
}

/// The first form the inventory refuses in some tokens, in a macro's arguments or in its
/// definition, at any depth.
fn form_in(tokens: &TokenStream) -> Option<Form> {
    let flat: Vec<TokenTree> = tokens.clone().into_iter().collect();
    for (at, tree) in flat.iter().enumerate() {
        match tree {
            TokenTree::Group(group) => {
                if let Some(found) = form_in(&group.stream()) {
                    return Some(found);
                }
            }
            TokenTree::Ident(word) if word == "include" => {
                if matches!(flat.get(at + 1), Some(TokenTree::Punct(bang)) if bang.as_char() == '!')
                    && matches!(flat.get(at + 2), Some(TokenTree::Group(_)))
                {
                    return Some(Form::Include);
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
                    (Some(TokenTree::Punct(dollar)), Some(TokenTree::Group(_)), _)
                        if dollar.as_char() == '$' =>
                    {
                        Some("$(...)".to_owned())
                    }
                    _ => None,
                };
                if let Some(name) = named {
                    return Some(Form::Module(name));
                }
            }
            _ => {}
        }
    }
    None
}

/// The macros the tokens of a transcriber call, at any depth, each as the path it is written with,
/// and the names of the `macro_rules!` definitions written in them. The matchers of a definition
/// written in them are not read, and a call through a metavariable (`$m!(..)`) names no macro.
fn token_calls(stream: &TokenStream, calls: &mut Vec<Vec<String>>, defined: &mut Vec<String>) {
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
                    defined.push(name.to_string());
                    for expansion in transcribers(&arms.stream()) {
                        token_calls(&expansion, calls, defined);
                    }
                    at += 4;
                    continue;
                }
            }
            TokenTree::Group(group) => token_calls(&group.stream(), calls, defined),
            TokenTree::Ident(_)
                if matches!(flat.get(at + 1), Some(TokenTree::Punct(bang)) if bang.as_char() == '!')
                    && matches!(flat.get(at + 2), Some(TokenTree::Group(_)))
                    && !(at > 0
                        && matches!(&flat[at - 1], TokenTree::Punct(dollar) if dollar.as_char() == '$')) =>
            {
                calls.push(path_before(&flat, at));
            }
            _ => {}
        }
        at += 1;
    }
}

/// What each name a `use` tree brings in stands for. A glob stands for nothing.
fn use_paths(tree: &syn::UseTree, prefix: &mut Vec<String>, out: &mut Vec<(String, Vec<String>)>) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            use_paths(&path.tree, prefix, out);
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            let mut full = prefix.clone();
            if name.ident == "self" {
                if let Some(last) = full.last() {
                    out.push((last.clone(), full));
                }
            } else {
                full.push(name.ident.to_string());
                out.push((name.ident.to_string(), full));
            }
        }
        syn::UseTree::Rename(rename) => {
            let mut full = prefix.clone();
            if rename.ident != "self" {
                full.push(rename.ident.to_string());
            }
            out.push((rename.rename.to_string(), full));
        }
        syn::UseTree::Glob(_) => {}
        syn::UseTree::Group(group) => {
            for item in &group.items {
                use_paths(item, prefix, out);
            }
        }
    }
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
