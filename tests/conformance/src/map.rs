//! The map from identifiers to the tests that name them, built from the sources every time the
//! report runs. Nothing here is written down in advance: a test is keyed because its source says
//! so, in one of these forms, and in no other way.
//!
//! In Rust:
//!
//! * a comment attached to a test function (a documentation comment above it, or a plain comment
//!   directly above it with no blank line between them) or inside its body keys that test;
//! * a test function's name keys it when it spells an identifier in snake case (`kr_req_11_07_…`);
//! * a module comment (`//!`) of test code keys every test in that module and the modules inside
//!   it. Test code is a test or bench target, or a module compiled under `cfg(test)`;
//! * in test code, a comment block that stands on its own, with a blank line after it, opens a
//!   section: its identifiers key every test from there to the next such block or the end of the
//!   module;
//! * in test code, a comment on a function keys every test of the same target whose body calls it,
//!   which is how a case that thin per-shell or per-platform tests share is keyed where it is
//!   written. Such a helper key holds only inside a boundary the report checks: every file of the
//!   target keeps to conventions `rust_items::breaches` reads on tokens, and a target that breaks
//!   one stops the report and keys nothing through a helper. Inside it, a call keys the helper only
//!   where the target's own source proves the compiler resolves the call to it, visibility
//!   included, and a call the reading cannot prove keys nothing;
//! * a `const` or `static` case table names identifiers in its `covers` fields, and those key every
//!   test of the same package whose body names the table.
//!
//! In data files, a case table's `covers` field keys the tests `plan::CASE_TABLES` says run its
//! cases. In TypeScript, `crate::typescript` states the rules. A Kotlin or Swift test file in one
//! of `plan::LANES` keys itself as a whole, because another toolchain builds it.
//!
//! Every other mention (a comment on product code, a script) is a reference: it is listed with the
//! identifier, and it is never a test. Every mention of any kind is checked against the grammar,
//! and a refused one stops the report.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Serialize;

use crate::id::{self, Identifier, Refusal};
use crate::plan::{CaseTable, Lane, matches};
use crate::rust_items::{
    self, Breach, Entry, FN_TRAITS, Import, KEYWORDS, Module, STANDARD_ROOTS, Sources, Visibility,
};
use crate::typescript::{self, FileFacts, Keys, TsBinding};
use crate::workspace::{self, Package, TargetId, TargetKind};

/// Where a keyed test is.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Place {
    /// A Rust test, by its full name within its target.
    Rust {
        /// The target.
        target: TargetId,
        /// The test's name, module path included.
        name: String,
    },
    /// Every Rust test in a module of a target, and in the modules inside it.
    RustModule {
        /// The target.
        target: TargetId,
        /// The module path, empty for the whole target.
        module: String,
    },
    /// A TypeScript test.
    TypeScript {
        /// The package's directory.
        package: String,
        /// The file, relative to the repository.
        file: String,
        /// The line a test run reports the call at, which is where its arguments open.
        line: usize,
        /// Its full title.
        title: String,
    },
    /// A file of tests another toolchain builds.
    Lane {
        /// The file.
        file: String,
        /// Why the report does not build it.
        reason: String,
    },
}

/// How a test came to be keyed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Binding {
    /// A comment attached to it.
    AttachedComment,
    /// A comment inside it.
    CommentInside,
    /// Its own name.
    TestName,
    /// A comment that opens the section it is in.
    SectionComment,
    /// A comment on a function of test code that it calls.
    CalledFunction,
    /// A module comment of a module it is in.
    ModuleComment,
    /// A case table it runs.
    CaseTable,
    /// Its title, or its suite's.
    Title,
    /// A comment at the head of its file, or anywhere in a file another toolchain builds.
    FileComment,
}

/// One keyed test of one identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    /// How it was keyed.
    pub binding: Binding,
    /// Where the key is written: a file and a line.
    pub source: String,
}

/// A mention that keys no test.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Reference {
    /// Where it is: a file and a line.
    pub source: String,
    /// What it is on.
    pub context: String,
}

/// A mention the grammar refuses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Refused {
    /// Where it is.
    pub source: String,
    /// Why.
    pub refusal: Refusal,
}

/// What the map is built from besides the Rust workspace.
#[derive(Clone, Copy, Debug)]
pub struct Declarations<'a> {
    /// The data-file case tables.
    pub case_tables: &'a [CaseTable],
    /// The lanes.
    pub lanes: &'a [Lane],
    /// The TypeScript packages' directories, when TypeScript is read.
    pub typescript: Option<&'a [&'a str]>,
    /// Directories whose files are read as scripts.
    pub scripts: &'a [&'a str],
}

/// The map.
#[derive(Debug, Default)]
pub struct Map {
    /// Each identifier's keyed tests: where each is, and the first way it was keyed.
    pub keys: BTreeMap<Identifier, BTreeMap<Place, Key>>,
    /// Each identifier's references.
    pub references: BTreeMap<Identifier, BTreeSet<Reference>>,
    /// The refused mentions.
    pub refused: Vec<Refused>,
    /// What stops the map being trusted: a case table naming a test that does not exist, a
    /// source that cannot be read.
    pub problems: Vec<String>,
    /// What the report notes and carries on past, such as a module file that is not there.
    pub warnings: Vec<String>,
    /// Each target's tests, as its sources declare them.
    pub rust_tests: BTreeMap<TargetId, BTreeSet<String>>,
    /// The workspace's packages.
    pub packages: Vec<Package>,
    /// The TypeScript files read, with their tests.
    pub typescript: Vec<FileFacts>,
}

impl Map {
    fn key(&mut self, identifier: Identifier, place: Place, binding: Binding, source: String) {
        let places = self.keys.entry(identifier).or_default();
        match places.get(&place) {
            Some(existing) if existing.binding <= binding => {}
            _ => {
                places.insert(place, Key { binding, source });
            }
        }
    }

    fn reference(&mut self, identifier: Identifier, source: String, context: &str) {
        self.references
            .entry(identifier)
            .or_default()
            .insert(Reference {
                source,
                context: context.to_owned(),
            });
    }

    /// Reads the mentions in `text`, whose first line is `line` of `file`, refusing what the
    /// grammar refuses and returning the rest with where each is.
    fn mentions(&mut self, text: &str, file: &str, line: usize) -> Vec<(Identifier, String)> {
        let mut found = Vec::new();
        for mention in id::scan(text) {
            let at = line + text[..mention.at].matches('\n').count();
            let source = format!("{file}:{at}");
            match mention.read {
                Ok(identifier) => found.push((identifier, source)),
                Err(refusal) => self.refused.push(Refused { source, refusal }),
            }
        }
        found
    }

    /// Every identifier the map knows: keyed, referenced, or one of the tables' rows.
    #[must_use]
    pub fn identifiers(&self) -> BTreeSet<Identifier> {
        self.keys
            .keys()
            .chain(self.references.keys())
            .copied()
            .collect()
    }
}

/// Builds the map for the repository at `root`.
#[must_use]
pub fn build(root: &Path, declarations: &Declarations<'_>) -> Map {
    let mut map = Map::default();
    match workspace::read(root) {
        Ok(packages) => {
            let mut sources = Sources::default();
            for package in &packages {
                rust_package(&mut map, &mut sources, root, package);
            }
            map.packages = packages;
        }
        Err(problem) => map.problems.push(problem),
    }
    data_tables(&mut map, root, declarations.case_tables);
    if let Some(directories) = declarations.typescript {
        typescript_sources(&mut map, root, directories, declarations.lanes);
    }
    lane_files(&mut map, root, declarations.lanes);
    for directory in declarations.scripts {
        for file in walk(root, directory, &|_| true) {
            let Ok(text) = std::fs::read_to_string(root.join(&file)) else {
                continue;
            };
            for (identifier, source) in map.mentions(&text, &file, 1) {
                map.reference(identifier, source, "a script");
            }
        }
    }
    map
}

/// A case table found in Rust: its name, and what its `covers` fields and comments name.
struct Table {
    name: String,
    file: String,
    mentions: Vec<(Identifier, String)>,
}

/// A function of test code whose comments name rows: the tests that call it are keyed to them.
struct Helper {
    name: String,
    file: String,
    line: usize,
    module: Vec<String>,
    mentions: Vec<(Identifier, String)>,
    /// Whether a `cfg` of its own may leave it out of a build.
    conditional: bool,
}

/// A test and what its body names: the functions it calls, the names its own `use` declarations
/// bring in, the case tables it reads, and the macro and attribute names its reading took on trust.
struct Use {
    target: TargetId,
    name: String,
    /// The file and line it is defined at.
    file: String,
    line: usize,
    module: Vec<String>,
    uses: BTreeSet<String>,
    calls: BTreeSet<Vec<String>>,
    imports: Vec<Import>,
    assumes: BTreeSet<String>,
}

fn rust_package(map: &mut Map, sources: &mut Sources, root: &Path, package: &Package) {
    let mut tables: Vec<Table> = Vec::new();
    let mut uses: Vec<Use> = Vec::new();
    // A helper module can be part of several targets, and a helper one of them calls is keyed
    // there; it is a reference only when no target of the package calls it.
    let mut called: BTreeSet<(String, String)> = BTreeSet::new();
    let mut uncalled: BTreeMap<(String, String), Vec<(Identifier, String)>> = BTreeMap::new();
    for target in &package.targets {
        let mut helpers: Vec<Helper> = Vec::new();
        let mut scope = Scope {
            modules: BTreeSet::new(),
            functions: BTreeMap::new(),
            imports: BTreeMap::new(),
            expanded: BTreeSet::new(),
            names: BTreeMap::new(),
            conditional: BTreeSet::new(),
            conditional_globs: BTreeSet::new(),
        };
        let first_use = uses.len();
        let test_target = matches!(target.id.kind, TargetKind::Test | TargetKind::Bench);
        let (modules, warnings) =
            match rust_items::scan_target(sources, root, &target.src_path, test_target) {
                Ok(scanned) => scanned,
                Err(error) => {
                    map.problems.push(format!("{}: {}", error.file, error.what));
                    continue;
                }
            };
        for warning in warnings {
            let text = format!("{}: {}", warning.file, warning.what);
            if !map.warnings.contains(&text) {
                map.warnings.push(text);
            }
        }
        map.rust_tests.entry(target.id.clone()).or_default();
        for module in &modules {
            rust_module(map, target, module, &mut tables, &mut helpers, &mut uses);
            scope.modules.insert(module.path.clone());
            if let Some((name, parent)) = module.path.split_last() {
                *scope
                    .names
                    .entry((parent.to_vec(), name.clone()))
                    .or_default() += 1;
                if module.conditional {
                    scope.conditional.insert((parent.to_vec(), name.clone()));
                }
            }
            for entry in &module.entries {
                let mut take = |name: &str| {
                    *scope
                        .names
                        .entry((module.path.clone(), name.to_owned()))
                        .or_default() += 1;
                };
                match entry {
                    Entry::Item(item) => {
                        let absent = item.conditional || module.conditional;
                        if matches!(
                            item.kind.as_str(),
                            "fn" | "const"
                                | "static"
                                | "struct"
                                | "enum"
                                | "union"
                                | "trait"
                                | "type"
                        ) && let Some(name) = &item.name
                        {
                            take(name);
                            if absent {
                                scope
                                    .conditional
                                    .insert((module.path.clone(), name.clone()));
                            }
                        }
                        for import in &item.imports {
                            match import {
                                Import::Name { name, .. } => {
                                    take(name);
                                    if absent {
                                        scope
                                            .conditional
                                            .insert((module.path.clone(), name.clone()));
                                    }
                                }
                                Import::Glob { .. } if absent => {
                                    scope.conditional_globs.insert(module.path.clone());
                                }
                                Import::Glob { .. } => {}
                            }
                        }
                        scope
                            .imports
                            .entry(module.path.clone())
                            .or_default()
                            .extend(
                                item.imports
                                    .iter()
                                    .map(|import| (item.visibility, import.clone())),
                            );
                        match (item.kind.as_str(), &item.name) {
                            ("fn", Some(name)) => {
                                scope
                                    .functions
                                    .insert((module.path.clone(), name.clone()), item.visibility);
                            }
                            ("macro", Some(name)) if name != "macro_rules" => {
                                scope.expanded.insert(module.path.clone());
                            }
                            _ => {}
                        }
                    }
                    Entry::Test(test) => {
                        take(&test.name);
                        scope
                            .functions
                            .insert((module.path.clone(), test.name.clone()), test.visibility);
                    }
                    Entry::Section(_) => {}
                }
            }
        }
        // A target that defines one test name twice has at most one of them in a build: a `cfg`
        // chooses, and the report does not evaluate `cfg`, so it cannot say which one ran.
        let mut found = defined_twice(&uses[first_use..], &target.id);
        // A helper key relies on conventions the target's source keeps to; a target that breaks
        // one keys no test through a helper, and the report stops.
        if !helpers.is_empty() {
            found.extend(breaches(
                sources, root, package, target, &modules, &scope, &helpers,
            ));
        }
        for breach in &found {
            let text = breach.to_string();
            if !map.problems.contains(&text) {
                map.problems.push(text);
            }
        }
        if !found.is_empty() && !helpers.is_empty() {
            for helper in helpers {
                let context = format!(
                    "a comment on fn {} in {}, in a target whose source steps outside the conventions a helper key relies on",
                    helper.name, helper.file
                );
                for (identifier, source) in helper.mentions {
                    map.reference(identifier, source, &context);
                }
            }
            continue;
        }
        // A keyed function of test code keys the tests of this target that call it: a case a
        // family of thin tests shares, one per shell or per platform, is keyed where it is written.
        // A helper keys only where every build has it and nothing else of its name: not under a
        // `cfg` of its own (another item, or a glob's, may take its place), not where its module
        // takes its name twice, and not in a module declared twice, one for each platform.
        let mut declared: BTreeMap<&[String], usize> = BTreeMap::new();
        for module in &modules {
            *declared.entry(module.path.as_slice()).or_default() += 1;
        }
        let mut kept = Vec::new();
        for helper in helpers {
            let twin = (0..=helper.module.len()).any(|depth| {
                declared
                    .get(&helper.module[..depth])
                    .is_some_and(|n| *n > 1)
            });
            let taken = scope
                .names
                .get(&(helper.module.clone(), helper.name.clone()))
                .is_some_and(|n| *n > 1);
            let reason = if helper.conditional {
                "which a cfg may leave out of a build"
            } else if taken {
                "which its module defines or brings in more than once"
            } else if twin {
                "whose module is declared more than once"
            } else {
                kept.push(helper);
                continue;
            };
            let context = format!(
                "a comment on fn {} in {}, {reason}",
                helper.name, helper.file
            );
            for (identifier, source) in helper.mentions {
                map.reference(identifier, source, &context);
            }
        }
        let helpers = kept;
        // A test's calls prove nothing where the target brings in names its source does not list,
        // or where a crate or tool root its reading took on trust is not what the package makes it.
        let unlisted = unlisted_names(&modules, &scope);
        for helper in helpers {
            let callers: Vec<String> = uses[first_use..]
                .iter()
                .filter(|test| {
                    !unlisted
                        && crates_named(&test.assumes, package)
                        && modules
                            .iter()
                            .all(|module| crates_named(&module.assumes, package))
                })
                .filter(|test| {
                    test.calls
                        .iter()
                        .any(|path| reaches(path, &test.module, &test.imports, &scope, &helper))
                })
                .map(|test| test.name.clone())
                .collect();
            let known = (helper.file.clone(), helper.name.clone());
            if callers.is_empty() {
                uncalled.entry(known).or_insert(helper.mentions);
                continue;
            }
            called.insert(known);
            for (identifier, source) in helper.mentions {
                for caller in &callers {
                    map.key(
                        identifier,
                        Place::Rust {
                            target: target.id.clone(),
                            name: caller.clone(),
                        },
                        Binding::CalledFunction,
                        source.clone(),
                    );
                }
            }
        }
    }
    for ((file, name), mentions) in uncalled {
        if called.contains(&(file.clone(), name.clone())) {
            continue;
        }
        for (identifier, source) in mentions {
            map.reference(
                identifier,
                source,
                &format!("a comment on fn {name} in {file}, which no test is proved to call"),
            );
        }
    }
    for table in tables {
        let consumers: Vec<&Use> = uses
            .iter()
            .filter(|test| test.uses.contains(&table.name))
            .collect();
        for (identifier, source) in &table.mentions {
            if consumers.is_empty() {
                map.reference(
                    *identifier,
                    source.clone(),
                    &format!(
                        "the case table {} in {}, which no test names",
                        table.name, table.file
                    ),
                );
            }
            for test in &consumers {
                map.key(
                    *identifier,
                    Place::Rust {
                        target: test.target.clone(),
                        name: test.name.clone(),
                    },
                    Binding::CaseTable,
                    source.clone(),
                );
            }
        }
    }
}

/// The modules, functions and `use` declarations of one target: what a call is resolved against.
struct Scope {
    modules: BTreeSet<Vec<String>>,
    /// Every function of the target, tests included, by module and name, with who may name it.
    functions: BTreeMap<(Vec<String>, String), Visibility>,
    /// Every module's `use` declarations, each with who may name what it brings in.
    imports: BTreeMap<Vec<String>, Vec<(Visibility, Import)>>,
    /// The modules with a macro invoked among their items, which can make items this reading does
    /// not see.
    expanded: BTreeSet<Vec<String>>,
    /// How many times each module takes each name: by an item of any kind, a test, a child module
    /// or a named `use`. A name taken twice (in two namespaces, or under two `cfg`s) cannot be
    /// said to mean the function.
    names: BTreeMap<(Vec<String>, String), usize>,
    /// The names each module takes under a `cfg` that may leave them out of a build, an item, a
    /// named `use` or a child module; where one is absent, a glob's name may stand in its place.
    conditional: BTreeSet<(Vec<String>, String)>,
    /// The modules with a glob under such a `cfg`.
    conditional_globs: BTreeSet<Vec<String>>,
}

/// What a name comes to, as far as the target's own source proves it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Found {
    /// The function of that name in this module.
    Function(Vec<String>),
    /// Proven not to be there.
    Absent,
    /// Anything the reading cannot prove either way.
    Unproved,
}

/// How far one name is followed through `use` declarations before the reading gives up on it.
const DEPTH: usize = 8;

/// Whether code in `from` may name an item of `owner` that has `visibility`, or `None` when the
/// reading cannot tell.
fn visible(visibility: Visibility, owner: &[String], from: &[String]) -> Option<bool> {
    match visibility {
        Visibility::Crate => Some(true),
        Visibility::Private => Some(from.starts_with(owner)),
        Visibility::Parent => owner
            .split_last()
            .map(|(_, parent)| from.starts_with(parent)),
        Visibility::Restricted => None,
    }
}

impl Scope {
    /// Whether the calling body brings `name` in for itself, in any of its blocks, or brings in
    /// a glob, which could be any name. A name a body binds is not followed.
    fn bound_in_body(local: &[Import], name: &str) -> bool {
        local.iter().any(|import| match import {
            Import::Name { name: bound, .. } => bound == name,
            Import::Glob { .. } => true,
        })
    }

    fn imports_in(&self, module: &[String]) -> impl Iterator<Item = &(Visibility, Import)> {
        self.imports.get(module).into_iter().flatten()
    }

    /// The module `path` names when it is written in `from`: from the crate's root after `crate`,
    /// from `from` after `self`, up one module for each `super`, and otherwise from a first name
    /// that is a child module of `from`, or a module a `use` there brings in by its own name. Every
    /// later name has to be a child module. Anything else is not followed.
    fn module(
        &self,
        from: &[String],
        path: &[String],
        local: &[Import],
        depth: usize,
    ) -> Option<Vec<String>> {
        if depth > DEPTH {
            return None;
        }
        let (mut at, rest) = match path.first().map(String::as_str) {
            None => return Some(from.to_vec()),
            Some("crate") => (Vec::new(), &path[1..]),
            Some("self" | "super") => (from.to_vec(), path),
            Some(first) => {
                if Self::bound_in_body(local, first) {
                    return None;
                }
                (self.named_module(from, first, depth)?, &path[1..])
            }
        };
        for segment in rest {
            match segment.as_str() {
                "self" => {}
                "super" => {
                    at.pop()?;
                }
                name => {
                    if !self.sole(&at, name) {
                        return None;
                    }
                    at.push(name.to_owned());
                    if !self.modules.contains(&at) {
                        return None;
                    }
                }
            }
        }
        Some(at)
    }

    /// Whether `module` takes `name` once, in every build: a child module or `use` of that name
    /// beside another, or under a `cfg`, may not be the one a path means.
    fn sole(&self, module: &[String], name: &str) -> bool {
        let key = (module.to_vec(), name.to_owned());
        self.names.get(&key).is_none_or(|count| *count <= 1) && !self.conditional.contains(&key)
    }

    /// The module one name refers to in `from`: a child module, or the module a `use` there brings
    /// in by its own name. A name a glob brings in is not followed.
    fn named_module(&self, from: &[String], name: &str, depth: usize) -> Option<Vec<String>> {
        if !self.sole(from, name) {
            return None;
        }
        let child: Vec<String> = from.iter().cloned().chain([name.to_owned()]).collect();
        if self.modules.contains(&child) {
            return Some(child);
        }
        self.imports_in(from).find_map(|(_, import)| match import {
            Import::Name { name: bound, path }
                if bound == name && path.last().map(String::as_str) == Some(name) =>
            {
                self.module(from, path, &[], depth + 1)
            }
            _ => None,
        })
    }

    /// What `module` offers `caller` under `name`, reached through `importer`: the module itself
    /// when the caller names it directly, or the module whose `use` or glob reached it. An item or a
    /// `use` counts only where both the importer and the caller may name it, since a re-export
    /// never makes anything more visible than it is. First the module's own function, which a
    /// macro's item or a `use` of the same name could not stand beside; then a `use` that brings an
    /// item in by that very name; then its globs, each for what the module it names offers. The
    /// answer from the globs is a function only when exactly one of them offers one and nothing
    /// about any of them is in doubt: a glob the reading cannot follow, a renaming `use` among
    /// them, a visibility it cannot work out, or a module whose macros could make items.
    fn offered(
        &self,
        module: &[String],
        name: &str,
        importer: &[String],
        caller: &[String],
        depth: usize,
    ) -> Found {
        if depth > DEPTH {
            return Found::Unproved;
        }
        // A name the module takes twice may mean either; one it takes once is the function or
        // the named `use` below, or else an item that is no function this reading can follow.
        let taken = self
            .names
            .get(&(module.to_vec(), name.to_owned()))
            .copied()
            .unwrap_or(0);
        if taken > 1
            || self
                .conditional
                .contains(&(module.to_vec(), name.to_owned()))
        {
            return Found::Unproved;
        }
        let reachable = |visibility: Visibility| match (
            visible(visibility, module, importer),
            visible(visibility, module, caller),
        ) {
            (Some(true), Some(true)) => Some(true),
            (Some(false), _) | (_, Some(false)) => Some(false),
            _ => None,
        };
        if let Some(visibility) = self.functions.get(&(module.to_vec(), name.to_owned())) {
            return match reachable(*visibility) {
                Some(true) => Found::Function(module.to_vec()),
                Some(false) => Found::Absent,
                None => Found::Unproved,
            };
        }
        for (visibility, import) in self.imports_in(module) {
            let Import::Name { name: bound, path } = import else {
                continue;
            };
            if bound != name {
                continue;
            }
            if path.last().map(String::as_str) != Some(name) {
                return Found::Unproved;
            }
            return match reachable(*visibility) {
                Some(false) => Found::Absent,
                None => Found::Unproved,
                Some(true) => {
                    let Some(target) = self.module(module, &path[..path.len() - 1], &[], depth + 1)
                    else {
                        return Found::Unproved;
                    };
                    // A `use` names something; if the reading finds nothing there, it cannot say
                    // what.
                    match self.offered(&target, name, module, caller, depth + 1) {
                        Found::Absent => Found::Unproved,
                        found => found,
                    }
                }
            };
        }
        if taken == 1 || self.expanded.contains(module) || self.conditional_globs.contains(module) {
            return Found::Unproved;
        }
        let mut found = BTreeSet::new();
        let mut unknown = false;
        for (visibility, import) in self.imports_in(module) {
            let Import::Glob { path } = import else {
                continue;
            };
            match reachable(*visibility) {
                Some(false) => continue,
                None => {
                    unknown = true;
                    continue;
                }
                Some(true) => {}
            }
            let Some(target) = self.module(module, path, &[], depth + 1) else {
                unknown = true;
                continue;
            };
            match self.offered(&target, name, module, caller, depth + 1) {
                Found::Function(defined) => {
                    found.insert(defined);
                }
                Found::Absent => {}
                Found::Unproved => unknown = true,
            }
        }
        match (found.len(), unknown) {
            (1, false) => Found::Function(found.into_iter().next().unwrap_or_default()),
            (0, false) => Found::Absent,
            _ => Found::Unproved,
        }
    }
}

/// Whether the target brings in names its source does not list: through `#[macro_use]`, an
/// `extern crate`, a macro invoked among a module's items, an item under an attribute that may be a
/// macro, or a glob from outside the crate and the standard library. A name the target declares for
/// itself that a trusted macro or attribute name could be is a breach of the conventions instead.
fn unlisted_names(modules: &[Module], scope: &Scope) -> bool {
    modules.iter().any(|module| {
        module.unlisted_names
            || module
                .entries
                .iter()
                .flat_map(|entry| match entry {
                    Entry::Item(item) => item.imports.as_slice(),
                    Entry::Test(test) => test.imports.as_slice(),
                    Entry::Section(_) => &[],
                })
                .any(|import| {
                    let Import::Glob { path } = import else {
                        return false;
                    };
                    let root = path.first().map_or("", String::as_str);
                    let mut child = module.path.clone();
                    child.push(root.to_owned());
                    !(matches!(root, "crate" | "self" | "super")
                        || STANDARD_ROOTS.contains(&root)
                        || scope.modules.contains(&child))
                })
    })
}

/// The test names a target defines more than once, each as a breach at its first definition that
/// names every one.
fn defined_twice(tests: &[Use], target: &TargetId) -> Vec<Breach> {
    let mut defined: BTreeMap<&str, Vec<&Use>> = BTreeMap::new();
    for test in tests {
        defined.entry(test.name.as_str()).or_default().push(test);
    }
    defined
        .into_iter()
        .filter(|(_, definitions)| definitions.len() > 1)
        .map(|(name, definitions)| {
            let places: Vec<String> = definitions
                .iter()
                .map(|test| format!("{}:{}", test.file, test.line))
                .collect();
            Breach {
                file: definitions[0].file.clone(),
                line: definitions[0].line,
                what: format!(
                    "{target} defines the test `{name}` more than once ({}): a `cfg` chooses which one a build has, and the report does not evaluate `cfg`",
                    places.join(", ")
                ),
            }
        })
        .collect()
}

/// Where a target with keyed helpers steps outside the conventions a helper key relies on: its
/// files as [`rust_items::breaches`] reads them; a helper named like a keyword or like a trait a type
/// writes like a call; a plain `use` of a helper's name among a module's items that the reading
/// does not follow to a function of that name; a target of the 2015 edition, whose paths start
/// elsewhere; and a package that names a dependency after a standard crate.
fn breaches(
    sources: &mut Sources,
    root: &Path,
    package: &Package,
    target: &workspace::Target,
    modules: &[Module],
    scope: &Scope,
    helpers: &[Helper],
) -> Vec<Breach> {
    let names: BTreeSet<String> = helpers.iter().map(|helper| helper.name.clone()).collect();
    let mut found = Vec::new();
    let mut files: Vec<&str> = Vec::new();
    for module in modules {
        if !files.contains(&module.file.as_str()) {
            files.push(&module.file);
        }
    }
    for file in files {
        match rust_items::breaches(sources, root, file, &names) {
            Ok(breaches) => found.extend(breaches),
            Err(error) => found.push(Breach {
                file: error.file,
                line: 1,
                what: error.what,
            }),
        }
    }
    for helper in helpers {
        let named = if KEYWORDS.contains(&helper.name.as_str()) {
            Some("a keyword, which the reading cannot tell from the keyword itself")
        } else if FN_TRAITS.contains(&helper.name.as_str()) {
            Some(
                "a trait a type writes like a call, which the reading cannot tell from a call of it",
            )
        } else {
            None
        };
        if let Some(named) = named {
            found.push(Breach {
                file: helper.file.clone(),
                line: helper.line,
                what: format!("the keyed helper `{}` has the name of {named}", helper.name),
            });
        }
    }
    for module in modules {
        for entry in &module.entries {
            let Entry::Item(item) = entry else {
                continue;
            };
            for import in &item.imports {
                let Import::Name { name, path } = import else {
                    continue;
                };
                if !names.contains(name) || path.last() != Some(name) {
                    continue;
                }
                let followed = path.len() > 1
                    && scope
                        .module(&module.path, &path[..path.len() - 1], &[], 0)
                        .is_some_and(|at| {
                            matches!(
                                scope.offered(&at, name, &module.path, &module.path, 0),
                                Found::Function(_)
                            )
                        });
                if !followed {
                    found.push(Breach {
                        file: module.file.clone(),
                        line: item.line,
                        what: format!("a `use` of `{name}`, a keyed helper's name, that the reading does not follow to a function of that name"),
                    });
                }
            }
        }
    }
    if let Some(crate_root) = modules.first()
        && target.edition == "2015"
    {
        found.push(Breach {
            file: crate_root.file.clone(),
            line: 1,
            what: "the target is of the 2015 edition, whose paths start where the reading does not follow them".to_owned(),
        });
    }
    found.extend(standard_dependencies(root, package));
    found
}

/// Where the package names a dependency after a standard crate (`std`, `core` or `alloc`), which
/// the reading takes those names for: its manifest and the line that names it.
fn standard_dependencies(root: &Path, package: &Package) -> Vec<Breach> {
    let manifest = package
        .manifest
        .strip_prefix(root)
        .unwrap_or(&package.manifest)
        .to_string_lossy()
        .replace('\\', "/");
    let text = std::fs::read_to_string(&package.manifest).unwrap_or_default();
    STANDARD_ROOTS
        .iter()
        .filter(|standard| package.dependency_names.contains(**standard))
        .map(|standard| Breach {
            file: manifest.clone(),
            line: text
                .lines()
                .position(|line| {
                    let line = line.trim_start();
                    line.strip_prefix(standard)
                        .is_some_and(|rest| rest.trim_start().starts_with('='))
                        || line.contains(&format!("dependencies.{standard}]"))
                })
                .map_or(1, |at| at + 1),
            what: format!("the package names a dependency `{standard}`, a name the reading takes for the standard library's"),
        })
        .collect()
}

/// Whether every root a trusted name starts at is what the reading took it for: the tool roots
/// `rustfmt::` and `clippy::` are the tools only where no dependency of the package takes their
/// names, and a crate root (`tokio::` for `#[tokio::test]`) must be the registry crate of that
/// name the package depends on, as its lockfile resolves it.
fn crates_named(assumes: &BTreeSet<String>, package: &Package) -> bool {
    assumes
        .iter()
        .filter_map(|name| name.strip_suffix("::"))
        .all(|root| match root {
            "rustfmt" | "clippy" => !package.dependency_names.contains(root),
            _ => package.registry_crates.contains(root),
        })
}

/// Whether a call written in the module `from` by `path` reaches `helper`.
///
/// A call keys a helper only when the reading proves, from the target's own source, that the
/// compiler resolves it to that helper: through module definitions, `crate`, `self` and `super`, a
/// `use` that keeps the item's own name, and globs, each judged by who may name what it brings
/// in. It gives up at a renaming `use`, at a name or glob the calling body brings in for itself, at
/// a module with macro-made items, at a glob it cannot follow and at a visibility it cannot work
/// out, and a call it gives up on keys nothing: the helper's identifiers stay references, which the
/// result lists. It answers only for a target that keeps to the conventions a helper key relies on
/// (see `breaches`), which is what lets it read names as the compiler resolves them. A call whose
/// first name the calling body may bind for itself never comes here: the reading of the body
/// leaves it out.
fn reaches(
    path: &[String],
    from: &[String],
    local: &[Import],
    scope: &Scope,
    helper: &Helper,
) -> bool {
    let Some((name, qualifier)) = path.split_last() else {
        return false;
    };
    if *name != helper.name || Scope::bound_in_body(local, name) {
        return false;
    }
    let module = if qualifier.is_empty() {
        Some(from.to_vec())
    } else {
        scope.module(from, qualifier, local, 0)
    };
    module.is_some_and(|module| {
        scope.offered(&module, name, from, from, 0) == Found::Function(helper.module.clone())
    })
}

fn rust_module(
    map: &mut Map,
    whole: &workspace::Target,
    module: &Module,
    tables: &mut Vec<Table>,
    helpers: &mut Vec<Helper>,
    uses: &mut Vec<Use>,
) {
    let target = &whole.id;
    let prefix = module.path.join("::");
    let full = |name: &str| {
        if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}::{name}")
        }
    };
    for comment in &module.docs {
        for (identifier, source) in map.mentions(&comment.text, &module.file, comment.line) {
            if !whole.harness {
                // A target with a harness of its own reports no test by name, so there is no
                // outcome of its to key.
                map.reference(
                    identifier,
                    source,
                    "the documentation of a target with a harness of its own, whose outcomes the report cannot read",
                );
            } else if module.test_code {
                map.key(
                    identifier,
                    Place::RustModule {
                        target: target.clone(),
                        module: prefix.clone(),
                    },
                    Binding::ModuleComment,
                    source,
                );
            } else {
                map.reference(
                    identifier,
                    source,
                    "the documentation of a module that is not test code",
                );
            }
        }
    }
    let mut section: Vec<(Identifier, String)> = Vec::new();
    let mut section_keyed = true;
    for entry in &module.entries {
        match entry {
            Entry::Section(comments) => {
                if !section_keyed {
                    for (identifier, source) in std::mem::take(&mut section) {
                        map.reference(
                            identifier,
                            source,
                            "a section comment with no test after it",
                        );
                    }
                }
                let mut found = Vec::new();
                for comment in comments {
                    found.extend(map.mentions(&comment.text, &module.file, comment.line));
                }
                if module.test_code {
                    section = found;
                    section_keyed = section.is_empty();
                } else {
                    for (identifier, source) in found {
                        map.reference(identifier, source, "a comment that is not on a test");
                    }
                }
            }
            Entry::Test(test) => {
                let name = full(&test.name);
                map.rust_tests
                    .entry(target.clone())
                    .or_default()
                    .insert(name.clone());
                let place = Place::Rust {
                    target: target.clone(),
                    name: name.clone(),
                };
                for comment in &test.attached {
                    for (identifier, source) in
                        map.mentions(&comment.text, &module.file, comment.line)
                    {
                        map.key(identifier, place.clone(), Binding::AttachedComment, source);
                    }
                }
                for comment in &test.inside {
                    for (identifier, source) in
                        map.mentions(&comment.text, &module.file, comment.line)
                    {
                        map.key(identifier, place.clone(), Binding::CommentInside, source);
                    }
                }
                for identifier in id::in_test_name(&test.name) {
                    map.key(
                        identifier,
                        place.clone(),
                        Binding::TestName,
                        format!("{}:{}", module.file, test.line),
                    );
                }
                for (identifier, source) in &section {
                    map.key(
                        *identifier,
                        place.clone(),
                        Binding::SectionComment,
                        source.clone(),
                    );
                    section_keyed = true;
                }
                uses.push(Use {
                    target: target.clone(),
                    name,
                    file: module.file.clone(),
                    line: test.line,
                    module: module.path.clone(),
                    uses: test.uses.clone(),
                    // An attribute macro on its module may rewrite any call in it.
                    calls: if module.rewritable {
                        BTreeSet::new()
                    } else {
                        test.calls.clone()
                    },
                    imports: test.imports.clone(),
                    assumes: test.assumes.clone(),
                });
            }
            Entry::Item(item) => {
                let mut found = Vec::new();
                for comment in item.attached.iter().chain(&item.inside) {
                    found.extend(map.mentions(&comment.text, &module.file, comment.line));
                }
                let table =
                    matches!(item.kind.as_str(), "const" | "static") && !item.covers.is_empty();
                if table {
                    for covers in &item.covers {
                        found.extend(map.mentions(&covers.text, &module.file, covers.line));
                    }
                    let name = item.name.clone().unwrap_or_default();
                    if let Some(existing) = tables
                        .iter_mut()
                        .find(|t| t.name == name && t.file == module.file)
                    {
                        for mention in found {
                            if !existing.mentions.contains(&mention) {
                                existing.mentions.push(mention);
                            }
                        }
                    } else {
                        tables.push(Table {
                            name,
                            file: module.file.clone(),
                            mentions: found,
                        });
                    }
                } else if module.test_code && item.kind == "fn" && !found.is_empty() {
                    let name = item.name.clone().unwrap_or_default();
                    if module.rewritable || item.rewritable {
                        // An attribute macro may rename or replace it, so no call can be proved
                        // to reach it.
                        let context = format!(
                            "a comment on fn {name} in {}, which an attribute may rewrite",
                            module.file
                        );
                        for (identifier, source) in found {
                            map.reference(identifier, source, &context);
                        }
                    } else {
                        helpers.push(Helper {
                            name,
                            file: module.file.clone(),
                            line: item.line,
                            module: module.path.clone(),
                            mentions: found,
                            conditional: item.conditional || module.conditional,
                        });
                    }
                } else {
                    let context = format!(
                        "a comment on {} {}, which is not a test",
                        item.kind,
                        item.name.as_deref().unwrap_or("an item")
                    );
                    for (identifier, source) in found {
                        map.reference(identifier, source, &context);
                    }
                }
            }
        }
    }
    if !section_keyed {
        for (identifier, source) in section {
            map.reference(
                identifier,
                source,
                "a section comment with no test after it",
            );
        }
    }
}

/// The case tables kept as data files.
fn data_tables(map: &mut Map, root: &Path, tables: &[CaseTable]) {
    for table in tables {
        let target = TargetId {
            package: table.package.to_owned(),
            kind: TargetKind::Test,
            name: table.target.to_owned(),
        };
        if let Some(known) = map.rust_tests.get(&target) {
            for test in table.tests {
                if !known.contains(*test) {
                    map.problems.push(format!(
                        "the case table {} is run by {test} in {target}, which has no such test",
                        table.files
                    ));
                }
            }
        }
        let base = table
            .files
            .split('*')
            .next()
            .unwrap_or_default()
            .trim_end_matches('/');
        for file in walk(root, base, &|path| matches(table.files, path)) {
            let Ok(text) = std::fs::read_to_string(root.join(&file)) else {
                map.problems.push(format!("{file} could not be read"));
                continue;
            };
            if serde_json::from_str::<serde_json::Value>(&text).is_err() {
                map.problems.push(format!("{file} is not JSON"));
                continue;
            }
            for (identifier, source) in covers_in_json(map, &text, &file) {
                for test in table.tests {
                    map.key(
                        identifier,
                        Place::Rust {
                            target: target.clone(),
                            name: (*test).to_owned(),
                        },
                        Binding::CaseTable,
                        source.clone(),
                    );
                }
            }
        }
    }
}

/// The mentions inside every `"covers"` value of a JSON document, with their lines.
fn covers_in_json(map: &mut Map, text: &str, file: &str) -> Vec<(Identifier, String)> {
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(offset) = text[from..].find("\"covers\"") {
        let start = from + offset + "\"covers\"".len();
        let rest = text[start..].trim_start();
        let Some(value) = rest.strip_prefix(':').map(str::trim_start) else {
            from = start;
            continue;
        };
        let value_start = text.len() - value.len();
        let end = if value.starts_with('[') {
            value
                .find(']')
                .map_or(text.len(), |close| value_start + close + 1)
        } else {
            value[1..]
                .find('"')
                .map_or(text.len(), |close| value_start + close + 2)
        };
        let line = 1 + text[..value_start].matches('\n').count();
        found.extend(map.mentions(&text[value_start..end], file, line));
        from = end;
    }
    found
}

fn typescript_sources(map: &mut Map, root: &Path, directories: &[&str], lanes: &[Lane]) {
    const EXTENSIONS: &[&str] = &[".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"];
    const SKIPPED: &[&str] = &[
        "node_modules",
        "dist",
        "build",
        "coverage",
        "target",
        "src-tauri",
        "native",
        "test-results",
        "playwright-report",
        ".vite",
    ];
    for directory in directories {
        let files = walk(root, directory, &|path| {
            EXTENSIONS.iter().any(|extension| path.ends_with(extension))
                && !path
                    .split('/')
                    .any(|component| SKIPPED.contains(&component))
                && !path.ends_with(".d.ts")
        });
        let facts = match typescript::read(root, &files) {
            Ok(facts) => facts,
            Err(problem) => {
                map.problems.push(problem);
                continue;
            }
        };
        for file in facts {
            let lane = lanes.iter().find(|lane| matches(lane.files, &file.file));
            let place = |index: usize| Place::TypeScript {
                package: (*directory).to_owned(),
                file: file.file.clone(),
                line: file.calls[index].reported,
                title: file.full_title(index),
            };
            for comment in &file.comments {
                let mentions = map.mentions(&comment.text, &file.file, comment.line);
                if mentions.is_empty() {
                    continue;
                }
                match file.keyed_by_comment(comment) {
                    Keys::Tests(tests, binding) if !tests.is_empty() => {
                        let binding = match binding {
                            TsBinding::Inside => Binding::CommentInside,
                            TsBinding::Attached => Binding::AttachedComment,
                            TsBinding::File => Binding::FileComment,
                            TsBinding::Title => Binding::Title,
                        };
                        for index in tests {
                            for (identifier, source) in &mentions {
                                map.key(*identifier, place(index), binding, source.clone());
                            }
                        }
                    }
                    _ => {
                        let context = if lane.is_some() || !file.calls.is_empty() {
                            "a comment that is not on a test"
                        } else {
                            "a comment in a file with no tests"
                        };
                        for (identifier, source) in mentions {
                            map.reference(identifier, source, context);
                        }
                    }
                }
            }
            for (index, call) in file.calls.iter().enumerate() {
                let mentions = map.mentions(&call.title_text, &file.file, call.line);
                for test in file.tests_under(index) {
                    for (identifier, source) in &mentions {
                        map.key(*identifier, place(test), Binding::Title, source.clone());
                    }
                }
            }
            map.typescript.push(file);
        }
    }
}

/// The lanes' Kotlin and Swift files, and the rest of those languages' files as references.
fn lane_files(map: &mut Map, root: &Path, lanes: &[Lane]) {
    const EXTENSIONS: &[&str] = &[".kt", ".kts", ".swift", ".java"];
    const SKIPPED: &[&str] = &[
        "node_modules",
        "build",
        ".gradle",
        "Pods",
        "DerivedData",
        "target",
        "gen",
    ];
    for directory in ["apps", "packages"] {
        for file in walk(root, directory, &|path| {
            EXTENSIONS.iter().any(|extension| path.ends_with(extension))
                && !path
                    .split('/')
                    .any(|component| SKIPPED.contains(&component))
        }) {
            let Ok(text) = std::fs::read_to_string(root.join(&file)) else {
                continue;
            };
            let lane = lanes.iter().find(|lane| matches(lane.files, &file));
            for comment in crate::clike::comments(&text) {
                for (identifier, source) in map.mentions(&comment.text, &file, comment.line) {
                    match lane {
                        Some(lane) => map.key(
                            identifier,
                            Place::Lane {
                                file: file.clone(),
                                reason: lane.reason.to_owned(),
                            },
                            Binding::FileComment,
                            source,
                        ),
                        None => {
                            map.reference(identifier, source, "a comment that is not on a test")
                        }
                    }
                }
            }
        }
    }
}

/// Every file under `directory` (relative to `root`) that `keep` accepts, relative to `root`, in
/// order. A directory that is not there has no files.
#[must_use]
pub fn walk(root: &Path, directory: &str, keep: &dyn Fn(&str) -> bool) -> Vec<String> {
    let mut found = Vec::new();
    let mut pending = vec![root.join(directory)];
    while let Some(current) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                if entry.file_name() != "node_modules" && entry.file_name() != "target" {
                    pending.push(path);
                }
            } else if kind.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                if keep(&relative) {
                    found.push(relative);
                }
            }
        }
    }
    found.sort();
    found
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{crates_named, standard_dependencies};
    use crate::workspace::Package;

    fn package(registry: &[&str], dependencies: &[&str]) -> Package {
        Package {
            name: "p".to_owned(),
            version: "0.1.0".to_owned(),
            targets: Vec::new(),
            manifest: "/p/Cargo.toml".into(),
            registry_crates: registry.iter().map(|name| (*name).to_owned()).collect(),
            dependency_names: dependencies.iter().map(|name| (*name).to_owned()).collect(),
        }
    }

    #[test]
    fn a_root_is_trusted_only_as_what_the_package_makes_it() {
        let names = |names: &[&str]| -> BTreeSet<String> {
            names.iter().map(|name| (*name).to_owned()).collect()
        };
        let plain = package(&["tokio"], &["tokio"]);
        assert!(crates_named(
            &names(&["tokio::", "clippy::", "rustfmt::", "test"]),
            &plain
        ));
        // A dependency renamed to a tool's name makes the root the dependency's.
        let renamed = package(&["tokio"], &["tokio", "clippy"]);
        assert!(!crates_named(&names(&["clippy::"]), &renamed));
        assert!(crates_named(&names(&["rustfmt::"]), &renamed));
        // A crate the package does not take from crates.io under that name is not the one meant.
        let elsewhere = package(&[], &["tokio"]);
        assert!(!crates_named(&names(&["tokio::"]), &elsewhere));
    }

    #[test]
    fn a_dependency_named_after_a_standard_crate_is_a_breach_at_its_line() {
        let root = tempfile::tempdir().expect("a directory");
        let manifest = root.path().join("Cargo.toml");
        std::fs::write(
            &manifest,
            "[package]\nname = \"p\"\n\n[dependencies]\ntokio = \"1\"\ncore = { package = \"other\", path = \"other\" }\n",
        )
        .expect("writes");
        let named = |names: &[&str]| Package {
            manifest: manifest.clone(),
            ..package(&[], names)
        };
        let found = standard_dependencies(root.path(), &named(&["tokio", "core"]));
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!((found[0].file.as_str(), found[0].line), ("Cargo.toml", 6));
        assert!(found[0].what.contains("`core`"), "{found:?}");
        assert!(standard_dependencies(root.path(), &named(&["tokio"])).is_empty());
    }
}
