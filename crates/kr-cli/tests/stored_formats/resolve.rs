//! Where a type a stored item holds is defined.
//!
//! The detection of undeclared kept types asks of each type a stored item holds not what it is
//! called but where it comes from: two types of one name are two types. A type named in a field is
//! followed through the `use` lines of the file that holds it, and through the modules and
//! re-exports it names, to the file that defines it. What cannot be followed is not skipped: it is
//! an error, and the detection reports it, so that nothing a stored item holds goes unchecked
//! because the walk lost its way.
//!
//! What this resolves: paths, generic arguments, tuples, references, arrays and slices; `use` lines
//! with renames, groups and globs; `crate::`, `self::` and `super::`; modules that are files or
//! inline; and re-exports. What it refuses to resolve, and says so: a type made by a macro, a trait
//! object, an `impl` type, a qualified path (`<T as Trait>::Name`), an alias, a name that is not
//! brought in by any `use` and is not defined in the file, and an item defined twice in one file.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::rc::Rc;

/// Where a type comes from.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Origin {
    /// The standard library.
    Std,
    /// One of the protocol's identifier and scalar types, whose forms the committed protocol schema
    /// records.
    Scalar,
    /// A file of this workspace, relative to the repository's root.
    Defined(String),
    /// A crate that is not this workspace's, by name.
    External(String),
}

/// A type, by where it comes from and its name.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Type {
    /// Where it comes from.
    pub origin: Origin,
    /// Its name.
    pub name: String,
}

/// The standard library's types and the prelude's that a stored item may hold.
const STANDARD: [&str; 14] = [
    "Self", "String", "Vec", "Option", "Box", "BTreeMap", "BTreeSet", "HashMap", "HashSet", "Arc",
    "PathBuf", "Duration", "Result", "Cow",
];

/// The names of the crates the standard library is.
const STANDARD_CRATES: [&str; 3] = ["std", "core", "alloc"];

/// The deepest chain of re-exports and `use` lines followed.
const DEPTH: usize = 12;

/// One `use` line, reduced to the name it binds and the path it names.
#[derive(Clone, Debug)]
struct Binding {
    bound: String,
    path: Vec<String>,
}

/// What a file brings in and defines.
#[derive(Debug, Default)]
struct Contents {
    /// The names `use` lines bind.
    bindings: Vec<Binding>,
    /// The paths whose contents `use ...::*` brings in.
    globs: Vec<Vec<String>>,
    /// The structs, enums and unions the file defines, by name, with how many times.
    defined: HashMap<String, usize>,
    /// The aliases it defines.
    aliases: BTreeSet<String>,
    /// The words in the macro invocations at its top level, which can define types.
    macro_words: BTreeSet<String>,
    /// The inline modules it declares, and the modules it declares that are files.
    modules: BTreeSet<String>,
}

/// The sources of a workspace.
pub struct Workspace {
    root: PathBuf,
    files: RefCell<HashMap<String, Rc<Contents>>>,
    scalars: Vec<String>,
}

impl Workspace {
    /// The workspace at `root`, with the protocol's scalar types read from its sources.
    ///
    /// # Errors
    ///
    /// Returns what stops the protocol's identifier files being read.
    pub fn at(root: PathBuf) -> Result<Self, String> {
        let mut scalars = Vec::new();
        let ids = std::fs::read_to_string(root.join("crates/kr-protocol/src/ids.rs"))
            .map_err(|error| format!("ids.rs: {error}"))?;
        for line in ids.lines() {
            if let Some(name) = line
                .strip_prefix("    ")
                .and_then(|rest| rest.strip_suffix(','))
                && name.chars().next().is_some_and(char::is_uppercase)
                && name.chars().all(char::is_alphanumeric)
            {
                scalars.push(name.to_owned());
            }
        }
        let text = std::fs::read_to_string(root.join("crates/kr-protocol/src/scalars.rs"))
            .map_err(|error| format!("scalars.rs: {error}"))?;
        let lines: Vec<&str> = text.lines().collect();
        for (at, line) in lines.iter().enumerate() {
            if let Some(rest) = line
                .strip_prefix("pub struct ")
                .or_else(|| line.strip_prefix("pub enum "))
            {
                scalars.push(rest.chars().take_while(|c| c.is_alphanumeric()).collect());
            }
            // A fixed-size byte string is made by a macro that names it, then gives its length:
            // `Digest256,` and `32,` on the next line.
            if let Some(name) = line
                .strip_prefix("    ")
                .and_then(|rest| rest.strip_suffix(','))
                && name.chars().next().is_some_and(char::is_uppercase)
                && name.chars().all(char::is_alphanumeric)
                && lines.get(at + 1).is_some_and(|next| {
                    next.trim()
                        .strip_suffix(',')
                        .is_some_and(|length| length.chars().all(|c| c.is_ascii_digit()))
                })
            {
                scalars.push(name.to_owned());
            }
        }
        Ok(Self {
            root,
            files: RefCell::new(HashMap::new()),
            scalars,
        })
    }

    /// What a file brings in and defines.
    fn contents(&self, file: &str) -> Result<Rc<Contents>, String> {
        if let Some(found) = self.files.borrow().get(file) {
            return Ok(Rc::clone(found));
        }
        let text = std::fs::read_to_string(self.root.join(file))
            .map_err(|error| format!("{file}: {error}"))?;
        let parsed = syn::parse_file(&text).map_err(|error| format!("{file}: {error}"))?;
        let mut contents = Contents::default();
        collect(&parsed.items, &mut contents);
        let contents = Rc::new(contents);
        self.files
            .borrow_mut()
            .insert(file.to_owned(), Rc::clone(&contents));
        Ok(contents)
    }

    /// The source file of a crate's root, by the crate's name as Rust writes it.
    fn crate_root(&self, krate: &str) -> Option<String> {
        let directory = krate.replace('_', "-");
        let lib = format!("crates/{directory}/src/lib.rs");
        self.root.join(&lib).is_file().then_some(lib)
    }

    /// The crate a file belongs to, as Rust writes its name, and the module path inside it.
    fn place_of(file: &str) -> Result<(String, Vec<String>), String> {
        let rest = file
            .strip_prefix("crates/")
            .ok_or_else(|| format!("{file} is not in a crate of this workspace"))?;
        let (directory, inside) = rest
            .split_once("/src/")
            .ok_or_else(|| format!("{file} is not in a crate's sources"))?;
        let mut module: Vec<String> = inside
            .trim_end_matches(".rs")
            .split('/')
            .map(str::to_owned)
            .collect();
        match module.last().map(String::as_str) {
            Some("mod") => {
                module.pop();
            }
            Some("lib" | "main") if module.len() == 1 => {
                module.clear();
            }
            _ => {}
        }
        Ok((directory.replace('-', "_"), module))
    }

    /// The file that is module `module` of crate `krate`, and the inline modules inside it that
    /// reach the module, or an error when the module cannot be found.
    fn module_file(&self, krate: &str, module: &[String]) -> Result<String, String> {
        let mut file = self
            .crate_root(krate)
            .ok_or_else(|| format!("{krate} is not a crate of this workspace"))?;
        let mut directory = PathBuf::from(format!("crates/{}/src", krate.replace('_', "-")));
        for step in module {
            let as_file = directory.join(format!("{step}.rs"));
            let as_directory = directory.join(step).join("mod.rs");
            if self.root.join(&as_file).is_file() {
                file = as_file.to_string_lossy().into_owned();
                directory = directory.join(step);
            } else if self.root.join(&as_directory).is_file() {
                file = as_directory.to_string_lossy().into_owned();
                directory = directory.join(step);
            } else if self.contents(&file)?.modules.contains(step) {
                // An inline module: its items are read with the file's.
            } else if let Some(binding) = self
                .contents(&file)?
                .bindings
                .iter()
                .find(|binding| &binding.bound == step)
            {
                // A module brought in by a `use`: not followed through here.
                return Err(format!(
                    "the module {step} of {file} is a re-export of {}",
                    binding.path.join("::")
                ));
            } else {
                return Err(format!("the module {step} of {file} cannot be found"));
            }
        }
        Ok(file)
    }

    /// Where the type `name` that module `module` of `krate` defines or re-exports comes from.
    fn defined_in(
        &self,
        krate: &str,
        module: &[String],
        name: &str,
        depth: usize,
    ) -> Result<Type, String> {
        if depth > DEPTH {
            return Err(format!(
                "{name} is re-exported more deeply than is followed"
            ));
        }
        let file = self.module_file(krate, module)?;
        let contents = self.contents(&file)?;
        // The protocol's scalars, whether a macro makes them or a struct defines them, are one
        // kind of thing whose forms the committed protocol schema records.
        if (file.ends_with("kr-protocol/src/ids.rs")
            || file.ends_with("kr-protocol/src/scalars.rs"))
            && self.scalars.iter().any(|scalar| scalar == name)
        {
            return Ok(Type {
                origin: Origin::Scalar,
                name: name.to_owned(),
            });
        }
        if contents.aliases.contains(name) {
            return Err(format!("{name} is an alias in {file}"));
        }
        match contents.defined.get(name) {
            Some(1) => {
                return Ok(Type {
                    origin: Origin::Defined(file),
                    name: name.to_owned(),
                });
            }
            Some(_) => return Err(format!("{name} is defined more than once in {file}")),
            None => {}
        }
        if let Some(binding) = contents
            .bindings
            .iter()
            .find(|binding| binding.bound == name)
        {
            let (inner_crate, inner_module) = Self::place_of(&file)?;
            return self.follow(&inner_crate, &inner_module, &binding.path, depth + 1, &file);
        }
        for glob in &contents.globs {
            let (inner_crate, inner_module) = Self::place_of(&file)?;
            let mut path = glob.clone();
            path.push(name.to_owned());
            if let Ok(found) = self.follow(&inner_crate, &inner_module, &path, depth + 1, &file) {
                return Ok(found);
            }
        }
        if contents.macro_words.contains(name) {
            return Ok(Type {
                origin: Origin::Defined(file),
                name: name.to_owned(),
            });
        }
        Err(format!(
            "{name} is neither defined nor re-exported in {file}"
        ))
    }

    /// Where the type at `path`, written in module `module` of `krate`, comes from.
    fn follow(
        &self,
        krate: &str,
        module: &[String],
        path: &[String],
        depth: usize,
        holder: &str,
    ) -> Result<Type, String> {
        let Some((name, steps)) = path.split_last() else {
            return Err("an empty path".to_owned());
        };
        let Some(first) = steps.first().or(Some(name)) else {
            return Err("an empty path".to_owned());
        };
        // Where the path starts.
        let (start_crate, start_module, rest): (String, Vec<String>, &[String]) =
            match first.as_str() {
                "crate" => (krate.to_owned(), Vec::new(), &steps[1..]),
                "self" => (krate.to_owned(), module.to_vec(), &steps[1..]),
                "super" => {
                    let mut up = module.to_vec();
                    let mut at = 0;
                    while steps.get(at).is_some_and(|step| step == "super") {
                        if up.pop().is_none() {
                            return Err(format!("{} goes above the crate", path.join("::")));
                        }
                        at += 1;
                    }
                    (krate.to_owned(), up, &steps[at..])
                }
                other if STANDARD_CRATES.contains(&other) => {
                    return Ok(Type {
                        origin: Origin::Std,
                        name: name.clone(),
                    });
                }
                other if self.crate_root(other).is_some() && !steps.is_empty() => {
                    (other.to_owned(), Vec::new(), &steps[1..])
                }
                _ if steps.is_empty() => {
                    // A bare name: the standard library's, or the holder's own, or one a `use` brings.
                    return self.bare(krate, module, name, depth, holder);
                }
                other => {
                    // The first step is a module the holder declares or a module a `use` brought
                    // in, or a crate that is not this workspace's.
                    let holder_contents = self.contents(holder)?;
                    if let Some(binding) = holder_contents
                        .bindings
                        .iter()
                        .find(|binding| binding.bound == other)
                    {
                        let mut expanded = binding.path.clone();
                        expanded.extend(steps[1..].iter().cloned());
                        expanded.push(name.clone());
                        if depth > DEPTH {
                            return Err(format!("{} is imported too deeply", path.join("::")));
                        }
                        return self.follow(krate, module, &expanded, depth + 1, holder);
                    }
                    if holder_contents.modules.contains(other) {
                        let mut here = module.to_vec();
                        here.push(other.to_owned());
                        return self.defined_in(
                            krate,
                            &[here, steps[1..].to_vec()].concat(),
                            name,
                            depth,
                        );
                    }
                    if other.chars().next().is_some_and(char::is_lowercase)
                        && !holder_contents.defined.contains_key(other)
                    {
                        return Ok(Type {
                            origin: Origin::External(other.to_owned()),
                            name: name.clone(),
                        });
                    }
                    return Err(format!(
                        "{} cannot be followed from {holder}",
                        path.join("::")
                    ));
                }
            };
        let mut full = start_module;
        full.extend(rest.iter().cloned());
        self.defined_in(&start_crate, &full, name, depth)
    }

    /// Where the bare name `name`, as written in `holder`, comes from.
    fn bare(
        &self,
        krate: &str,
        module: &[String],
        name: &str,
        depth: usize,
        holder: &str,
    ) -> Result<Type, String> {
        let contents = self.contents(holder)?;
        if contents.aliases.contains(name) {
            return Err(format!("{name} is an alias in {holder}"));
        }
        match contents.defined.get(name) {
            Some(1) => {
                return Ok(Type {
                    origin: Origin::Defined(holder.to_owned()),
                    name: name.to_owned(),
                });
            }
            Some(_) => return Err(format!("{name} is defined more than once in {holder}")),
            None => {}
        }
        if let Some(binding) = contents
            .bindings
            .iter()
            .find(|binding| binding.bound == name)
        {
            if depth > DEPTH {
                return Err(format!("{name} is imported too deeply"));
            }
            return self.follow(krate, module, &binding.path, depth + 1, holder);
        }
        if STANDARD.contains(&name) {
            return Ok(Type {
                origin: Origin::Std,
                name: name.to_owned(),
            });
        }
        for glob in &contents.globs {
            let mut path = glob.clone();
            path.push(name.to_owned());
            if let Ok(found) = self.follow(krate, module, &path, depth + 1, holder) {
                return Ok(found);
            }
        }
        if contents.macro_words.contains(name) {
            return Ok(Type {
                origin: Origin::Defined(holder.to_owned()),
                name: name.to_owned(),
            });
        }
        Err(format!(
            "{name} is neither defined in {holder} nor brought in by a use line that is followed"
        ))
    }

    /// The types the item `item` that `file` defines holds in its fields.
    ///
    /// # Errors
    ///
    /// Returns what stops the item being found or a type in it being followed, one message for
    /// each, in the order they are met.
    pub fn held_by(&self, file: &str, item: &str) -> Result<Vec<Type>, Vec<String>> {
        let text = std::fs::read_to_string(self.root.join(file))
            .map_err(|error| vec![format!("{file}: {error}")])?;
        let parsed = syn::parse_file(&text).map_err(|error| vec![format!("{file}: {error}")])?;
        let contents = self.contents(file).map_err(|error| vec![error])?;
        if contents.defined.get(item) != Some(&1) {
            return Err(vec![format!(
                "{item} is not defined exactly once in {file}"
            )]);
        }
        let Some(found) = find(&parsed.items, item) else {
            return Err(vec![format!("{item} is not a struct or an enum in {file}")]);
        };
        let (krate, module) = Self::place_of(file).map_err(|error| vec![error])?;
        let mut walker = Walker::default();
        walker.of_item(found);
        let mut held = Vec::new();
        let mut problems = walker.problems;
        for path in walker.paths {
            match self.follow(&krate, &module, &path, 0, file) {
                Ok(found) => held.push(found),
                Err(why) => problems.push(format!("{}: {why}", path.join("::"))),
            }
        }
        if problems.is_empty() {
            Ok(held)
        } else {
            Err(problems)
        }
    }

    /// Where the type that `std::any::type_name` gives the path `type_name` of comes from.
    ///
    /// # Errors
    ///
    /// Returns what stops the type being followed.
    pub fn of_type_name(&self, type_name: &str) -> Result<Type, String> {
        let path: Vec<String> = type_name
            .split('<')
            .next()
            .unwrap_or(type_name)
            .split("::")
            .map(str::to_owned)
            .collect();
        let Some((krate, _)) = path.split_first() else {
            return Err("an empty type name".to_owned());
        };
        let Some((name, steps)) = path.split_last() else {
            return Err("an empty type name".to_owned());
        };
        if STANDARD_CRATES.contains(&krate.as_str()) {
            return Ok(Type {
                origin: Origin::Std,
                name: name.clone(),
            });
        }
        if self.crate_root(krate).is_none() {
            return Ok(Type {
                origin: Origin::External(krate.clone()),
                name: name.clone(),
            });
        }
        self.defined_in(krate, &steps[1..], name, 0)
    }
}

/// Records what a list of items brings in and defines.
fn collect(items: &[syn::Item], contents: &mut Contents) {
    for item in items {
        match item {
            syn::Item::Struct(item) => {
                *contents.defined.entry(item.ident.to_string()).or_default() += 1;
            }
            syn::Item::Enum(item) => {
                *contents.defined.entry(item.ident.to_string()).or_default() += 1;
            }
            syn::Item::Union(item) => {
                *contents.defined.entry(item.ident.to_string()).or_default() += 1;
            }
            syn::Item::Type(item) => {
                contents.aliases.insert(item.ident.to_string());
            }
            syn::Item::Use(item) => flatten(&item.tree, &mut Vec::new(), contents),
            syn::Item::Mod(item) => {
                contents.modules.insert(item.ident.to_string());
                let test_only = item.attrs.iter().any(|attribute| {
                    attribute.path().is_ident("cfg")
                        && attribute
                            .meta
                            .require_list()
                            .is_ok_and(|list| list.tokens.to_string() == "test")
                });
                if let (Some((_, inside)), false) = (&item.content, test_only) {
                    collect(inside, contents);
                }
            }
            syn::Item::Macro(item) => {
                for word in item
                    .mac
                    .tokens
                    .to_string()
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .filter(|word| !word.is_empty())
                {
                    contents.macro_words.insert(word.to_owned());
                }
            }
            _ => {}
        }
    }
}

/// Reduces a `use` tree to the names it binds.
fn flatten(tree: &syn::UseTree, prefix: &mut Vec<String>, contents: &mut Contents) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            flatten(&path.tree, prefix, contents);
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            let leaf = name.ident.to_string();
            if leaf == "self" {
                if let Some(last) = prefix.last() {
                    contents.bindings.push(Binding {
                        bound: last.clone(),
                        path: prefix.clone(),
                    });
                }
            } else {
                let mut path = prefix.clone();
                path.push(leaf.clone());
                contents.bindings.push(Binding { bound: leaf, path });
            }
        }
        syn::UseTree::Rename(rename) => {
            let mut path = prefix.clone();
            path.push(rename.ident.to_string());
            contents.bindings.push(Binding {
                bound: rename.rename.to_string(),
                path,
            });
        }
        syn::UseTree::Glob(_) => contents.globs.push(prefix.clone()),
        syn::UseTree::Group(group) => {
            for inner in &group.items {
                flatten(inner, prefix, contents);
            }
        }
    }
}

/// The struct, enum or union named `name` among `items`, at any depth of inline modules.
fn find<'a>(items: &'a [syn::Item], name: &str) -> Option<&'a syn::Item> {
    for item in items {
        match item {
            syn::Item::Struct(found) if found.ident == name => return Some(item),
            syn::Item::Enum(found) if found.ident == name => return Some(item),
            syn::Item::Union(found) if found.ident == name => return Some(item),
            syn::Item::Mod(module) => {
                if let Some((_, inside)) = &module.content
                    && let Some(found) = find(inside, name)
                {
                    return Some(found);
                }
            }
            _ => {}
        }
    }
    None
}

/// The paths of the types in the fields of an item, and what it holds that cannot be followed.
#[derive(Default)]
struct Walker {
    paths: Vec<Vec<String>>,
    problems: Vec<String>,
}

impl Walker {
    fn of_item(&mut self, item: &syn::Item) {
        use syn::visit::Visit as _;

        match item {
            syn::Item::Struct(item) => {
                for field in &item.fields {
                    self.visit_type(&field.ty);
                }
            }
            syn::Item::Enum(item) => {
                for variant in &item.variants {
                    for field in &variant.fields {
                        self.visit_type(&field.ty);
                    }
                }
            }
            syn::Item::Union(item) => {
                for field in &item.fields.named {
                    self.visit_type(&field.ty);
                }
            }
            _ => {}
        }
    }
}

impl<'ast> syn::visit::Visit<'ast> for Walker {
    fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
        if path.qself.is_some() {
            self.problems
                .push("a qualified path (<T as Trait>::Name) is not followed".to_owned());
            return;
        }
        let names: Vec<String> = path
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        // A primitive is a single lowercase name.
        let primitive = names.len() == 1 && names[0].chars().next().is_some_and(char::is_lowercase);
        if !primitive {
            self.paths.push(names);
        }
        syn::visit::visit_type_path(self, path);
    }

    fn visit_type_trait_object(&mut self, _: &'ast syn::TypeTraitObject) {
        self.problems
            .push("a trait object (dyn Trait) is not followed".to_owned());
    }

    fn visit_type_impl_trait(&mut self, _: &'ast syn::TypeImplTrait) {
        self.problems
            .push("an `impl Trait` type is not followed".to_owned());
    }

    fn visit_type_macro(&mut self, _: &'ast syn::TypeMacro) {
        self.problems
            .push("a type made by a macro is not followed".to_owned());
    }
}
