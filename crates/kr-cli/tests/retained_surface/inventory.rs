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
//! What the inventory does not read it refuses, with an error that names the file (the crate, for a
//! crate with no target): a path through a link, with `..` or from the root of the file system, a
//! module declared in a block or by a macro, `include!`, a `#[path]` that is not one string, a module
//! that is at no file or at two, a crate with no target, a `macro_rules!` written in the tokens of
//! another macro, `#[macro_use]` on `extern crate`, a `use` or `extern crate` that renames a name the
//! scan reads, a `type` alias of `MutationRequest` or `ActionTarget`, a definition named
//! `ActionRight`, and an item-position macro of
//! another crate that is not on the list of those accepted. The macros called in the transcribers of
//! a `macro_rules!` definition, at any depth, are held to the same list. A `macro_rules!` name that
//! is defined more than once is one definition under it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use syn::ext::IdentExt as _;
use syn::visit::Visit;

use super::condition;
use super::walker::{
    VARIANTS, is_macro_rules, names_a_macro, normalised, path_before, transcribers,
};

/// The macros of other crates that product code may call at item position and in a transcriber, each
/// with the paths that name its provider (`""` is a bare call) and why none of them can make a module
/// file or a sender. A name from any other provider is refused.
const ACCEPTED: &[(&str, &[&str], &str)] = &[
    (
        "thread_local",
        &["", "std"],
        "the standard library's macro makes thread-local statics from `static` items: it makes no module, and the scan reads the initialisers in the call's tokens as written",
    ),
    (
        "task_local",
        &["tokio"],
        "tokio's macro makes task-local statics from `static` items, as `thread_local` does: it makes no module, and the scan reads the call's tokens as written",
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

/// The macros of the standard library that a bare call names and that make no item and read no Rust
/// file: the ones the transcribers of the workspace and of its release tags call, and their
/// siblings. `include_str` and `include_bytes` read a data file, whose wire names the scan does not
/// see.
/// `include` is not among them (the scan does not read it), and `thread_local` and `compile_error`
/// are in [`ACCEPTED`].
const STD_MACROS: &[&str] = &[
    "assert",
    "assert_eq",
    "assert_ne",
    "cfg",
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

/// Where a macro of another crate may be called that the scan does not read: at item position, or in
/// the transcriber of a `macro_rules!` definition.
#[derive(Clone, Copy)]
enum Position {
    Item,
    Transcriber,
}

impl Position {
    fn words(self) -> &'static str {
        match self {
            Self::Item => "item position",
            Self::Transcriber => "a transcriber",
        }
    }
}

/// What one file's `use` lines bring in by name: for each name, the full paths it stands for. A glob
/// stands for none.
type Imports = BTreeMap<String, BTreeSet<Vec<String>>>;

/// The macro calls of one file: its path, its imports, and the calls at item position or in a
/// transcriber with the paths they are written as.
type FileCalls = (String, Imports, Vec<(Position, Vec<String>)>);

/// Whether the call written as `path` in a file with these imports is a macro the scan accepts (R3):
/// the crate's own (a bare call, or one written from `crate`, `self`, `super`, `$crate` or one of its
/// modules, of a name the crate defines), a macro of the standard library that makes no item (by its
/// bare name or by a path of `std`, `core` or `alloc`), or one of [`ACCEPTED`] written with the path
/// of its provider. A bare name that the file imports stands for the paths it imports; a qualified
/// call is judged as written.
fn accepts(
    path: &[String],
    imports: &Imports,
    defined: &BTreeSet<String>,
    modules: &BTreeSet<String>,
) -> bool {
    let Some(first) = path.first() else {
        return false;
    };
    // Only a bare call takes the paths its name stands for from the file's imports: a qualified call
    // is judged by the path as written, so a name that stands for a module gives it no provider.
    match imports.get(first) {
        Some(fulls) if path.len() == 1 => fulls
            .iter()
            .all(|full| written_as_accepted(full, defined, modules)),
        _ => written_as_accepted(path, defined, modules),
    }
}

/// `accepts` for a path whose first segment no `use` of the file gives.
fn written_as_accepted(
    path: &[String],
    defined: &BTreeSet<String>,
    modules: &BTreeSet<String>,
) -> bool {
    let (Some(name), Some(first)) = (path.last(), path.first()) else {
        return false;
    };
    if path.len() == 1 {
        return defined.contains(name) || STD_MACROS.contains(&name.as_str()) || provided(name, "");
    }
    // The crate's own prefix names a macro the crate defines: a name that a `use` brought from
    // elsewhere, or that a re-export holds, is none. A module of the crate is one too, and a path from
    // a module named like a provider is never that provider's.
    if matches!(first.as_str(), "crate" | "$crate" | "self" | "super") || modules.contains(first) {
        return defined.contains(name);
    }
    if matches!(first.as_str(), "std" | "core" | "alloc") && STD_MACROS.contains(&name.as_str()) {
        return true;
    }
    provided(name, &path[..path.len() - 1].join("::"))
}

/// Whether `provider` is one of those the family `name` is accepted from.
fn provided(name: &str, provider: &str) -> bool {
    ACCEPTED
        .iter()
        .any(|(accepted, providers, _)| *accepted == name && providers.contains(&provider))
}

/// How much of what the inventory refuses applies to a crate.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Rules {
    /// Every refusal: the crate is one the scan reads for sightings.
    All,
    /// The renames of a name the scan reads and the aliases of the two types (R1 and R2), in its files
    /// and in the tokens of its macros: a crate that the scan does not read for sightings is still one
    /// that a crate it reads may reach a type through, by a `pub use` or a `pub type`. The module
    /// walk's own refusals (a link, `..` or a root in a `#[path]`, a module at no file or at two, a
    /// `#[path]` that is no string, a module declared in a block, a condition the rule cannot read,
    /// a `cfg_attr` that sets a path, a file that does not parse) hold for it too: the walk cannot
    /// read what it cannot reach.
    Renames,
}

/// The refusal of a `use`, an `extern crate` or a run of tokens that gives `old` the name `new`.
pub(super) fn rename_refusal(at: &str, old: &str, new: &str) -> String {
    format!("{at}: the scan does not read {old} under another name (as {new})")
}

/// The file that defines `ActionRight`, in the tokens of a macro: the one definition the refusal
/// leaves out.
const ACTION_RIGHT_HOME: &str = "crates/kr-protocol/src/rights.rs";

/// The refusal of a definition named `ActionRight`, of the kind `kind`.
fn definition_refusal(at: &str, kind: &str) -> String {
    format!("{at}: the scan does not read a {kind} named ActionRight")
}

/// The refusal of a `type` alias of `target`, one of the two types.
fn alias_refusal(at: &str, target: &str, alias: &str) -> String {
    format!("{at}: the scan does not read a type alias of {target} ({alias})")
}

/// What the product code of a crate is made of.
pub struct Inventory {
    /// The product files in path order, by canonical path.
    pub files: Vec<PathBuf>,
    /// The `macro_rules!` names product code defines, at any depth.
    pub defined: BTreeSet<String>,
    /// Each `use` or `extern crate` that gives a name another name: the file, the name it came as and
    /// the name it gives.
    pub renames: Vec<(String, String, String)>,
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
/// the tree at `root`, holding it to the refusals `rules` names. The module walk's own refusals (a
/// link, a module that is at no file or at two, a `#[path]` that is not one string) hold for both.
pub fn read(
    krate: &str,
    roots: &[PathBuf],
    root: &Path,
    rules: Rules,
) -> Result<Inventory, String> {
    if roots.is_empty() {
        return Err(format!("{krate}: no library or binary target"));
    }
    let shown = |path: &Path| {
        path.strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string()
    };
    let mut todo: Vec<(PathBuf, bool)> =
        roots.iter().map(|target| (target.clone(), true)).collect();
    let mut seen: BTreeSet<(PathBuf, bool)> = BTreeSet::new();
    let mut reached: BTreeSet<PathBuf> = BTreeSet::new();
    // The names the crate defines a `macro_rules!` for. Definitions of one name, in any place, are one
    // under it: what either calls is called, so a name defined twice adds marks and takes none away.
    let mut defined: BTreeSet<String> = BTreeSet::new();
    // The macros called at item position and in transcribers, with the imports of the file they are in.
    let mut calls: Vec<FileCalls> = Vec::new();
    let mut module_set: BTreeSet<String> = BTreeSet::new();
    let mut renames: Vec<(String, String, String)> = Vec::new();
    while let Some(visit) = todo.pop() {
        if !seen.insert(visit.clone()) {
            continue;
        }
        let (path, beside) = visit;
        let at = shown(&path);
        let real = std::fs::canonicalize(&path).map_err(|error| format!("{at}: {error}"))?;
        if real != path || !path.starts_with(root) {
            return Err(format!(
                "{at}: the scan does not read a path through a link, with .. or from the root of the file system (it is {})",
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
            imports: Imports::new(),
            module_names: Vec::new(),
            renamed: Vec::new(),
            all: rules == Rules::All,
            error: None,
        };
        reader.visit_file(&parsed);
        if let Some(error) = reader.error {
            return Err(error);
        }
        defined.extend(reader.defined);
        calls.push((at.clone(), reader.imports, reader.calls));
        module_set.extend(reader.module_names);
        renames.extend(
            reader
                .renamed
                .into_iter()
                .map(|(old, new)| (at.clone(), old, new)),
        );
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
    // R3: a macro called at item position or in a transcriber is the crate's own, a macro of the
    // standard library or one the scan lists, each by its written path. The first refused, by name.
    let mut unaccepted: BTreeMap<String, (String, Position, Option<String>)> = BTreeMap::new();
    for (at, imports, found) in calls.iter().filter(|_| rules == Rules::All) {
        for (position, path) in found {
            if !path.is_empty() && !accepts(path, imports, &defined, &module_set) {
                // A bare call that the file imports is refused by the path it imports.
                let imported = match path.as_slice() {
                    [name] => imports.get(name).and_then(|fulls| {
                        fulls
                            .iter()
                            .find(|full| !written_as_accepted(full, &defined, &module_set))
                            .map(|full| full.join("::"))
                    }),
                    _ => None,
                };
                unaccepted
                    .entry(path.join("::"))
                    .or_insert_with(|| (at.clone(), *position, imported));
            }
        }
    }
    if let Some((path, (at, position, imported))) = unaccepted.into_iter().next() {
        let from = imported.map_or_else(String::new, |from| format!(", imported from {from},"));
        return Err(format!(
            "{at}: {path}! is called at {}{from} and is not written as one of the macros the scan accepts",
            position.words()
        ));
    }
    Ok(Inventory {
        files: reached.into_iter().collect(),
        defined,
        renames,
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
    /// The names of the `macro_rules!` definitions.
    defined: Vec<String>,
    /// The macros called at item position and in the transcribers of a definition, as written.
    calls: Vec<(Position, Vec<String>)>,
    /// What each `use` brings in: the name it gives, and the paths it stands for.
    imports: Imports,
    /// The modules declared.
    module_names: Vec<String>,
    /// The names a `use` or an `extern crate` gives another name: the name it came as, and its own.
    renamed: Vec<(String, String)>,
    /// Whether every refusal applies, and not R1 and R2 only.
    all: bool,
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
        // A `..` or a start at the root of the file system leaves the folder the path is written in.
        if Path::new(written).components().any(|step| {
            matches!(
                step,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        }) {
            self.error.get_or_insert(format!(
                "{}: the scan does not read a path through a link, with .. or from the root of the file system (it is {written})",
                self.at
            ));
            return joined;
        }
        let mut walked = self.path_base.clone();
        for step in Path::new(written).components() {
            walked.push(step);
            match std::fs::symlink_metadata(&walked) {
                Ok(found) if found.file_type().is_symlink() => {
                    self.error = Some(format!(
                        "{}: the scan does not read a path through a link, with .. or from the root of the file system ({} is a link)",
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
            self.calls.push((
                Position::Item,
                path.segments
                    .iter()
                    .map(|segment| segment.ident.unraw().to_string())
                    .collect(),
            ));
        }
    }

    /// Takes the renames of a `use` or an `extern crate`, and refuses one of a name the scan reads.
    fn note_renames(&mut self, found: Vec<(String, String)>) {
        for (old, new) in found {
            if self.error.is_none() && (read_by_name(&old) || read_by_name(&new)) {
                self.error = Some(rename_refusal(self.at, &old, &new));
            }
            self.renamed.push((old, new));
        }
    }

    /// Refuses a definition named `ActionRight`: the scan leaves out `ActionRight::<Variant>` as the
    /// right of that name, so a crate that defines the name another way hides a variant.
    fn refuse_definition(&mut self, name: &syn::Ident, kind: &str) {
        if self.all && self.error.is_none() && name.unraw() == "ActionRight" {
            self.error = Some(definition_refusal(self.at, kind));
        }
    }

    /// Refuses a `type` alias of `MutationRequest` or `ActionTarget`.
    fn refuse_alias(&mut self, alias: &syn::Ident, ty: &syn::Type) {
        // Parentheses and invisible groups around the type name the same type.
        let mut ty = ty;
        while let syn::Type::Paren(syn::TypeParen { elem, .. })
        | syn::Type::Group(syn::TypeGroup { elem, .. }) = ty
        {
            ty = elem;
        }
        if self.error.is_none()
            && let syn::Type::Path(path) = ty
            && let Some(last) = path.path.segments.last()
            && (last.ident.unraw() == "MutationRequest" || last.ident.unraw() == "ActionTarget")
        {
            self.error = Some(alias_refusal(
                self.at,
                &last.ident.unraw().to_string(),
                &alias.unraw().to_string(),
            ));
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
        visit_item_fn => visit_item_fn(syn::ItemFn);
        visit_item_impl => visit_item_impl(syn::ItemImpl);
        visit_item_foreign_mod => visit_item_foreign_mod(syn::ItemForeignMod);
        visit_item_static => visit_item_static(syn::ItemStatic);
        visit_item_trait_alias => visit_item_trait_alias(syn::ItemTraitAlias);
        visit_impl_item_const => visit_impl_item_const(syn::ImplItemConst);
        visit_variant => visit_variant(syn::Variant);
        visit_field => visit_field(syn::Field);
        visit_impl_item_fn => visit_impl_item_fn(syn::ImplItemFn);
        visit_trait_item_const => visit_trait_item_const(syn::TraitItemConst);
        visit_trait_item_fn => visit_trait_item_fn(syn::TraitItemFn);
        visit_trait_item_type => visit_trait_item_type(syn::TraitItemType);
    }

    fn visit_item_extern_crate(&mut self, node: &'ast syn::ItemExternCrate) {
        if self.enter(&node.attrs) {
            // A `#[macro_use]` on `extern crate` brings the macros of that crate in by name (R4).
            if self.all && self.carries(&node.attrs, "macro_use") {
                self.error.get_or_insert(format!(
                    "{}: the scan does not read #[macro_use] on extern crate",
                    self.at
                ));
            }
            if let Some((_, rename)) = &node.rename {
                self.note_renames(vec![(
                    node.ident.unraw().to_string(),
                    rename.unraw().to_string(),
                )]);
            }
            syn::visit::visit_item_extern_crate(self, node);
        }
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        if self.enter(&node.attrs) {
            self.refuse_definition(&node.ident, "enum");
            syn::visit::visit_item_enum(self, node);
        }
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        if self.enter(&node.attrs) {
            self.refuse_definition(&node.ident, "struct");
            syn::visit::visit_item_struct(self, node);
        }
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        if self.enter(&node.attrs) {
            self.refuse_definition(&node.ident, "trait");
            syn::visit::visit_item_trait(self, node);
        }
    }

    fn visit_item_union(&mut self, node: &'ast syn::ItemUnion) {
        if self.enter(&node.attrs) {
            self.refuse_definition(&node.ident, "union");
            syn::visit::visit_item_union(self, node);
        }
    }

    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        if self.enter(&node.attrs) {
            self.refuse_definition(&node.ident, "type alias");
            self.refuse_alias(&node.ident, &node.ty);
            syn::visit::visit_item_type(self, node);
        }
    }

    fn visit_impl_item_type(&mut self, node: &'ast syn::ImplItemType) {
        if self.enter(&node.attrs) {
            self.refuse_alias(&node.ident, &node.ty);
            syn::visit::visit_impl_item_type(self, node);
        }
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
        self.refuse_definition(&node.ident, "module");
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
            Some(name) if is_macro_rules(&node.mac.path) => {
                self.defined.push(name.unraw().to_string());
                for expansion in transcribers(&node.mac.tokens) {
                    token_calls(&expansion, &mut self.calls);
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
                .map(|segment| segment.ident.unraw().to_string())
                .unwrap_or_default();
            if self.all && name == "include" {
                self.error = Some(format!("{}: the scan does not read include!", self.at));
            } else {
                let mut forms = Vec::new();
                forms_in(&node.tokens, &mut forms);
                // Every rename is kept, for the check against the macros a crate in scope defines.
                for form in &forms {
                    if let Form::Rename(old, new) = form {
                        self.renamed.push((old.clone(), new.clone()));
                    }
                }
                // The first form that applies, in the order the tokens give them.
                self.error = forms.into_iter().find_map(|form| match form {
                    Form::Include if self.all => {
                        Some(format!("{}: the scan does not read include!", self.at))
                    }
                    Form::Module(module) if self.all => Some(format!(
                        "{}: the scan does not read a module declared in a macro (mod {module}; in the tokens of {name}!)",
                        self.at
                    )),
                    Form::Rules(rules) if self.all => Some(format!(
                        "{}: the scan does not read a macro_rules! written in the tokens of another macro (macro_rules! {rules} in the tokens of {name}!)",
                        self.at
                    )),
                    Form::Rename(old, new) if read_by_name(&old) || read_by_name(&new) => {
                        Some(rename_refusal(self.at, &old, &new))
                    }
                    Form::Alias(target, alias) => Some(alias_refusal(self.at, &target, &alias)),
                    // The protocol defines `ActionRight` itself, in a macro of its own file.
                    Form::Definition(kind) if self.all && self.at != ACTION_RIGHT_HOME => {
                        Some(definition_refusal(self.at, kind))
                    }
                    _ => None,
                });
            }
        }
        syn::visit::visit_macro(self, node);
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        if self.enter(&node.attrs) {
            let mut found = Vec::new();
            use_paths(&node.tree, &mut Vec::new(), &mut found);
            self.note_renames(
                found
                    .iter()
                    .filter_map(|(local, full)| {
                        full.last()
                            .filter(|original| *original != local)
                            .map(|original| (original.clone(), local.clone()))
                    })
                    .collect(),
            );
            for (local, full) in found {
                self.imports.entry(local).or_default().insert(full);
            }
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

/// Whether the scan reads the name wherever it stands: a rename of it hides it.
fn read_by_name(name: &str) -> bool {
    ["Method", "MutationRequest", "ActionTarget", "ActionRight"].contains(&name)
        || VARIANTS.contains(&name)
        || ACCEPTED.iter().any(|(listed, _, _)| *listed == name)
}

/// What the inventory does not read, written in the tokens of a macro.
enum Form {
    /// `include!(..)`.
    Include,
    /// A module declaration, with the name as written: `name`, `$name`, or `$(...)` for a
    /// repetition.
    Module(String),
    /// A `macro_rules!` definition, with its name.
    Rules(String),
    /// `<name> as <name>` in a `use` or an `extern crate`: a name given another name (R1), the old
    /// name and the new one, each as written (`$name` for a metavariable). Every one is kept, for the
    /// check against the names of the macros a crate defines; one of a name the scan reads refuses.
    Rename(String, String),
    /// `type <alias> = <path>;` where the path ends in `MutationRequest` or `ActionTarget` (R2): the
    /// type and the alias.
    Alias(String, String),
    /// `type`, `struct`, `enum`, `union`, `trait` or `mod` and then `ActionRight`: the kind of
    /// definition.
    Definition(&'static str),
}

/// The kind of definition that the keyword begins, as the refusal says it.
fn definition_kind(word: &str) -> Option<&'static str> {
    match word {
        "type" => Some("type alias"),
        "mod" => Some("module"),
        "enum" => Some("enum"),
        "struct" => Some("struct"),
        "union" => Some("union"),
        "trait" => Some("trait"),
        _ => None,
    }
}

/// The name that begins at `at` in the tokens, and how many tokens it takes: an identifier, or `$`
/// and an identifier for a metavariable (written `$name`).
fn written_name(run: &[TokenTree], at: usize) -> Option<(String, usize)> {
    match run.get(at) {
        Some(TokenTree::Ident(name)) => Some((name.unraw().to_string(), 1)),
        Some(TokenTree::Punct(dollar)) if dollar.as_char() == '$' => match run.get(at + 1) {
            Some(TokenTree::Ident(name)) => Some((format!("${}", name.unraw()), 2)),
            _ => None,
        },
        _ => None,
    }
}

/// Each `<old> as <new>` in the tokens of a `use` or an `extern crate`, groups of a use tree
/// included. `self` stands for the segment before the group that holds it (`prefix`), and `as _`
/// brings the name in under no name.
fn renames_in(run: &[TokenTree], prefix: Option<&str>, found: &mut Vec<Form>) {
    for (at, tree) in run.iter().enumerate() {
        match tree {
            TokenTree::Group(group) => {
                let inner: Vec<TokenTree> = group.stream().into_iter().collect();
                let before = at.checked_sub(3).and_then(|from| match &run[from..at] {
                    [
                        TokenTree::Ident(name),
                        TokenTree::Punct(first),
                        TokenTree::Punct(second),
                    ] if first.as_char() == ':' && second.as_char() == ':' => {
                        Some(name.unraw().to_string())
                    }
                    _ => None,
                });
                renames_in(&inner, before.as_deref(), found);
            }
            TokenTree::Ident(word) if word == "as" => {
                let old = match at.checked_sub(1).and_then(|before| run.get(before)) {
                    Some(TokenTree::Ident(name)) => {
                        let dollar = at.checked_sub(2).is_some_and(|from| {
                            matches!(&run[from], TokenTree::Punct(dollar) if dollar.as_char() == '$')
                        });
                        if dollar {
                            Some(format!("${}", name.unraw()))
                        } else if name == "self" {
                            prefix.map(str::to_owned)
                        } else {
                            Some(name.unraw().to_string())
                        }
                    }
                    _ => None,
                };
                if let (Some(old), Some((new, _))) = (old, written_name(run, at + 1))
                    && new != "_"
                {
                    found.push(Form::Rename(old, new));
                }
            }
            _ => {}
        }
    }
}

/// Each form the inventory refuses in some tokens, in a macro's arguments or in its definition, at
/// any depth, in the order the tokens give them.
fn forms_in(tokens: &TokenStream, found: &mut Vec<Form>) {
    let flat: Vec<TokenTree> = tokens.clone().into_iter().collect();
    for (at, tree) in flat.iter().enumerate() {
        if let TokenTree::Ident(word) = tree
            && let Some(kind) = definition_kind(&word.to_string())
            && matches!(flat.get(at + 1), Some(TokenTree::Ident(name)) if name.unraw() == "ActionRight")
        {
            found.push(Form::Definition(kind));
        }
        match tree {
            TokenTree::Group(group) => forms_in(&group.stream(), found),
            TokenTree::Ident(word) if word.unraw() == "include" => {
                if matches!(flat.get(at + 1), Some(TokenTree::Punct(bang)) if bang.as_char() == '!')
                    && matches!(flat.get(at + 2), Some(TokenTree::Group(_)))
                {
                    found.push(Form::Include);
                }
            }
            // A rename is `as` in a `use` or an `extern crate`: a cast or a qualified path, written
            // `<T as Trait>`, is none.
            TokenTree::Ident(word)
                if word == "use"
                    || (word == "extern"
                        && matches!(flat.get(at + 1), Some(TokenTree::Ident(next)) if next == "crate")) =>
            {
                let end = flat[at..]
                    .iter()
                    .position(|tree| matches!(tree, TokenTree::Punct(end) if end.as_char() == ';'))
                    .map_or(flat.len(), |end| at + end);
                renames_in(&flat[at + 1..end], None, found);
            }
            TokenTree::Ident(word) if word == "type" => {
                // The alias is a name or a metavariable, with generic parameters or none.
                if let Some((alias, length)) = written_name(&flat, at + 1) {
                    let mut next = at + 1 + length;
                    if matches!(flat.get(next), Some(TokenTree::Punct(open)) if open.as_char() == '<')
                    {
                        let mut angles = 0usize;
                        while let Some(tree) = flat.get(next) {
                            if let TokenTree::Punct(punct) = tree {
                                match punct.as_char() {
                                    '<' => angles += 1,
                                    '>' => angles -= 1,
                                    _ => {}
                                }
                            }
                            next += 1;
                            if angles == 0 {
                                break;
                            }
                        }
                    }
                    if matches!(flat.get(next), Some(TokenTree::Punct(equals)) if equals.as_char() == '=')
                    {
                        let end = flat[next + 1..]
                            .iter()
                            .position(
                                |tree| matches!(tree, TokenTree::Punct(end) if end.as_char() == ';'),
                            )
                            .map_or(flat.len(), |end| next + 1 + end);
                        if let Some(target) = aliased_type(&flat[next + 1..end]) {
                            found.push(Form::Alias(target, alias));
                        }
                    }
                }
            }
            TokenTree::Ident(word) if word.unraw() == "macro_rules" => {
                if let (
                    Some(TokenTree::Punct(bang)),
                    Some(TokenTree::Ident(name)),
                    Some(TokenTree::Group(_)),
                ) = (flat.get(at + 1), flat.get(at + 2), flat.get(at + 3))
                    && bang.as_char() == '!'
                {
                    found.push(Form::Rules(name.unraw().to_string()));
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
                    found.push(Form::Module(name));
                }
            }
            _ => {}
        }
    }
}

/// The name of the type of the two that `run` is a path to, as `Type::Path` of `refuse_alias` reads
/// it: identifiers joined by `::`, in one pair of parentheses or invisible groups or not.
fn aliased_type(run: &[TokenTree]) -> Option<String> {
    if let [TokenTree::Group(group)] = run
        && matches!(group.delimiter(), Delimiter::Parenthesis | Delimiter::None)
    {
        let inner: Vec<TokenTree> = group.stream().into_iter().collect();
        return aliased_type(&inner);
    }
    // `$crate::path` is a path as well.
    let path = run.iter().all(|tree| match tree {
        TokenTree::Ident(_) => true,
        TokenTree::Punct(punct) => matches!(punct.as_char(), ':' | '$'),
        _ => false,
    });
    match run.last() {
        Some(TokenTree::Ident(last))
            if path
                && ["MutationRequest", "ActionTarget"]
                    .contains(&last.unraw().to_string().as_str()) =>
        {
            Some(last.unraw().to_string())
        }
        _ => None,
    }
}

/// The macros the tokens of a transcriber call, at any depth, each as the path it is written with.
/// A call through a metavariable (`$m!(..)`) names no macro, and a `macro_rules!` written in the
/// tokens is refused before this is read.
fn token_calls(stream: &TokenStream, calls: &mut Vec<(Position, Vec<String>)>) {
    let flat: Vec<TokenTree> = stream.clone().into_iter().collect();
    let mut at = 0;
    while at < flat.len() {
        match &flat[at] {
            TokenTree::Group(group) => token_calls(&group.stream(), calls),
            TokenTree::Ident(word)
                if names_a_macro(word)
                    && matches!(flat.get(at + 1), Some(TokenTree::Punct(bang)) if bang.as_char() == '!')
                    && matches!(flat.get(at + 2), Some(TokenTree::Group(_)))
                    && !(at > 0
                        && matches!(&flat[at - 1], TokenTree::Punct(dollar) if dollar.as_char() == '$')) =>
            {
                calls.push((Position::Transcriber, path_before(&flat, at)));
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
            prefix.push(path.ident.unraw().to_string());
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
                full.push(name.ident.unraw().to_string());
                out.push((name.ident.unraw().to_string(), full));
            }
        }
        syn::UseTree::Rename(rename) => {
            let mut full = prefix.clone();
            if rename.ident != "self" {
                full.push(rename.ident.unraw().to_string());
            }
            out.push((rename.rename.unraw().to_string(), full));
        }
        syn::UseTree::Glob(_) => {}
        syn::UseTree::Group(group) => {
            for item in &group.items {
                use_paths(item, prefix, out);
            }
        }
    }
}
