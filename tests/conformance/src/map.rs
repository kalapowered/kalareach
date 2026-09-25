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
//!   written; a call is resolved as the compiler resolves it, through `use` declarations and
//!   globs, and one the reading cannot follow to that one function keys nothing;
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
use crate::rust_items::{self, Entry, Import, Module, Sources};
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
    module: Vec<String>,
    mentions: Vec<(Identifier, String)>,
}

/// A test and what its body names: the functions it calls, the names its own `use` declarations
/// bring in, and the case tables it reads.
struct Use {
    target: TargetId,
    name: String,
    module: Vec<String>,
    uses: BTreeSet<String>,
    calls: BTreeSet<Vec<String>>,
    imports: Vec<Import>,
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
            functions: BTreeSet::new(),
            imports: BTreeMap::new(),
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
            scope
                .imports
                .entry(module.path.clone())
                .or_default()
                .extend(module.entries.iter().flat_map(|entry| match entry {
                    Entry::Item(item) => item.imports.clone(),
                    _ => Vec::new(),
                }));
            scope
                .functions
                .extend(module.entries.iter().filter_map(|entry| match entry {
                    Entry::Item(item) if item.kind == "fn" => {
                        item.name.clone().map(|name| (module.path.clone(), name))
                    }
                    _ => None,
                }));
        }
        // A keyed function of test code keys the tests of this target that call it: a case a
        // family of thin tests shares, one per shell or per platform, is keyed where it is written.
        for helper in helpers {
            let callers: Vec<String> = uses[first_use..]
                .iter()
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
                &format!("a comment on fn {name} in {file}, which no test calls"),
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
    functions: BTreeSet<(Vec<String>, String)>,
    imports: BTreeMap<Vec<String>, Vec<Import>>,
}

/// What a called name comes to, as far as the target's own source says.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Resolved {
    /// The function of that name in this module.
    Function(Vec<String>),
    /// Nothing the target's own modules hold that this reading can prove: the prelude, another
    /// crate, a name two globs both bring in, or one it cannot follow.
    Unproved,
}

/// How far one name is followed through `use` declarations before the reading gives up on it.
const DEPTH: usize = 8;

impl Scope {
    /// The declarations that bring names into `module`: the calling body's own first, then the
    /// module's.
    fn imports_of<'a>(
        &'a self,
        module: &[String],
        local: &'a [Import],
    ) -> impl Iterator<Item = &'a Import> {
        local
            .iter()
            .chain(self.imports.get(module).into_iter().flatten())
    }

    /// The module `path` names when it is written in `from`: from the crate's root after `crate`,
    /// from `from` after `self`, up one module for each `super`, and otherwise from a first name
    /// that is a child module of `from` or a module a `use` there brings in.
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
            Some(first) => (self.named_module(from, first, local, depth)?, &path[1..]),
        };
        for segment in rest {
            match segment.as_str() {
                "self" => {}
                "super" => {
                    at.pop()?;
                }
                name => {
                    at.push(name.to_owned());
                    if !self.modules.contains(&at) {
                        return None;
                    }
                }
            }
        }
        Some(at)
    }

    /// The module one name refers to in `from`: a child module, a module a `use` brings in by that
    /// name, or a child of a module a glob brings in.
    fn named_module(
        &self,
        from: &[String],
        name: &str,
        local: &[Import],
        depth: usize,
    ) -> Option<Vec<String>> {
        let child: Vec<String> = from.iter().cloned().chain([name.to_owned()]).collect();
        if self.modules.contains(&child) {
            return Some(child);
        }
        for import in self.imports_of(from, local) {
            if let Import::Name {
                name: imported,
                path,
            } = import
                && imported == name
            {
                return self.module(from, path, &[], depth + 1);
            }
        }
        self.imports_of(from, local)
            .find_map(|import| match import {
                Import::Glob { path } => {
                    let mut child = self.module(from, path, &[], depth + 1)?;
                    child.push(name.to_owned());
                    self.modules.contains(&child).then_some(child)
                }
                Import::Name { .. } => None,
            })
    }

    /// What calling `name` in `from` calls. The calling body's own `use` comes first; then a
    /// function of the module itself, or a name a `use` of the module brings in, followed to where
    /// it is defined; then the modules its globs bring in, where exactly one of them must have it.
    fn function(&self, from: &[String], name: &str, local: &[Import], depth: usize) -> Resolved {
        if depth > DEPTH {
            return Resolved::Unproved;
        }
        let follow = |path: Vec<String>| {
            let Some((last, modules)) = path.split_last() else {
                return Resolved::Unproved;
            };
            self.module(from, modules, local, depth + 1)
                .map_or(Resolved::Unproved, |module| {
                    self.function(&module, last, &[], depth + 1)
                })
        };
        if let Some(path) = imported(local.iter(), name) {
            return follow(path);
        }
        if self.functions.contains(&(from.to_vec(), name.to_owned())) {
            return Resolved::Function(from.to_vec());
        }
        if let Some(path) = imported(self.imports.get(from).into_iter().flatten(), name) {
            return follow(path);
        }
        let mut found = BTreeSet::new();
        for import in self.imports_of(from, local) {
            if let Import::Glob { path } = import
                && let Some(module) = self.module(from, path, &[], depth + 1)
                && let Resolved::Function(defined) = self.function(&module, name, &[], depth + 1)
            {
                found.insert(defined);
            }
        }
        match found.len() {
            1 => Resolved::Function(found.into_iter().next().unwrap_or_default()),
            _ => Resolved::Unproved,
        }
    }
}

/// The path a `use` among `imports` brings `name` in by.
fn imported<'a>(mut imports: impl Iterator<Item = &'a Import>, name: &str) -> Option<Vec<String>> {
    imports.find_map(|import| match import {
        Import::Name {
            name: imported,
            path,
        } if imported == name => Some(path.clone()),
        _ => None,
    })
}

/// Whether a call written in the module `from` by `path` reaches `helper`.
///
/// Only a call the target's own source proves is one: the path is resolved the way the compiler
/// resolves it, through the calling body's `use` declarations, the module's functions, its `use`
/// declarations and its globs, and a call this reading cannot follow to one function keys nothing.
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
    if *name != helper.name {
        return false;
    }
    let resolved = if qualifier.is_empty() {
        scope.function(from, name, local, 0)
    } else {
        scope
            .module(from, qualifier, local, 0)
            .map_or(Resolved::Unproved, |module| {
                scope.function(&module, name, &[], 0)
            })
    };
    resolved == Resolved::Function(helper.module.clone())
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
                    module: module.path.clone(),
                    uses: test.uses.clone(),
                    calls: test.calls.clone(),
                    imports: test.imports.clone(),
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
                    helpers.push(Helper {
                        name: item.name.clone().unwrap_or_default(),
                        file: module.file.clone(),
                        module: module.path.clone(),
                        mentions: found,
                    });
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
