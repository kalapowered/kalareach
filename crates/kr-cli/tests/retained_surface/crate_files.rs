//! The files of a crate's product code, for the root digests' index.
//!
//! This is the file list of the digests and no reader of what sends a mutation: the compiler reads
//! that (see `compiler`). The walk starts at each library and binary root that Cargo names and follows
//! the `mod` declarations by rustc's two file rules (`name.rs`, `name/mod.rs`) and `#[path]`, leaving
//! out a place whose `cfg` is false for every configuration without `test`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use syn::ext::IdentExt as _;
use syn::visit::Visit;

use super::condition;
use super::walker::normalised;

/// One body-less module declaration: where its file may be, and whether a `#[path]` names it.
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

/// The product files of the crate `krate` that Cargo builds from the source files `roots`, inside the
/// tree at `root`, in path order, by canonical path.
pub fn read(krate: &str, roots: &[PathBuf], root: &Path) -> Result<Vec<PathBuf>, String> {
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
    while let Some(visit) = todo.pop() {
        if !seen.insert(visit.clone()) {
            continue;
        }
        let (path, beside) = visit;
        let at = shown(&path);
        let real = std::fs::canonicalize(&path).map_err(|error| format!("{at}: {error}"))?;
        if real != path || !path.starts_with(root) {
            return Err(format!(
                "{at}: the file is reached through a link, with .. or from the root of the file system (it is {})",
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
            error: None,
        };
        reader.visit_file(&parsed);
        if let Some(error) = reader.error {
            return Err(error);
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
                    todo.push(((*one).clone(), beside));
                }
                [] => {
                    let tried: Vec<&PathBuf> = declared.candidates.iter().collect();
                    return Err(format!(
                        "{at}: mod {} is at no file (tried {})",
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
    Ok(reached.into_iter().collect())
}

/// Reads one parsed file for the module declarations that product code makes in it.
struct Reader<'a> {
    at: &'a str,
    path_base: PathBuf,
    modules: PathBuf,
    /// How many function bodies and blocks the walk is inside.
    block: usize,
    declared: Vec<Declared>,
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
    /// its steps up cancelled.
    fn explicit_path(&self, written: &str) -> PathBuf {
        normalised(&self.path_base.join(written))
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
        visit_item_extern_crate => visit_item_extern_crate(syn::ItemExternCrate);
        visit_item_enum => visit_item_enum(syn::ItemEnum);
        visit_item_struct => visit_item_struct(syn::ItemStruct);
        visit_item_trait => visit_item_trait(syn::ItemTrait);
        visit_item_union => visit_item_union(syn::ItemUnion);
        visit_item_type => visit_item_type(syn::ItemType);
        visit_impl_item_type => visit_impl_item_type(syn::ImplItemType);
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
                    "{}: #[path] is one string literal only (mod {name})",
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
                        "{}: a module is declared in a block (mod {name};)",
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
