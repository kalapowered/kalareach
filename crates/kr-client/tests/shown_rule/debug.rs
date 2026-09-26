//! Every `Debug` in the two crates, held to what may be shown.
//!
//! A `Debug` reaches places its reader did not choose as surely as a failure does: an assertion's
//! message, a log a dependency writes, a panic further up, somebody's own `{:?}`. So a type of this
//! library or of the command line that has one says only what may be shown: this program's words,
//! numbers, values claimed `Plain`, a `Shown`, and values whose own `Debug` does the same.
//!
//! What a derived `Debug` prints is decided by the types of its fields, and those come from every
//! crate, so this reads every crate in the workspace for what it declares. A type *carries* text
//! when its `Debug` can print text that arrived: text, a character, bytes, a JSON or CBOR value, a
//! path, a file, a URL, an I/O failure, a trait object; or a type of any crate whose own `Debug`
//! prints one, found to a fixpoint. A type a macro declares is read from the macro's own text at
//! each place it is invoked. The test fails with the file, the line and the item wherever a type of
//! the two crates has
//!
//! * a derived `Debug` over a field whose type names a carrier anywhere in it, its generic
//!   arguments included, or
//! * a `Debug` written by hand that formats a carrier, or a value this reading cannot place.
//!
//! A `Debug` written by hand is read the same way in every crate: the formatter is used only to
//! write this program's words and to format values, and each value is checked for the trait that
//! formats it. Whatever this reading cannot follow counts as a carrier: a type from outside the
//! workspace that it does not list, a name it cannot place, a generic parameter formatted by hand,
//! an expression it does not read. `shown!("{}", value)` is always read: the compiler holds its
//! parts to `Plain`.

use super::*;

/* -------------------------------------------------------------------------------------------- */
/* What types from outside the workspace print                                                   */
/* -------------------------------------------------------------------------------------------- */

/// What a type from outside the workspace prints in its `Debug`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outside {
    /// Text that arrived, or bytes.
    Text,
    /// Nothing it holds: a time, a counter, a handle.
    Nothing,
    /// What its type arguments hold, and nothing else.
    Holds,
}

/// Types from outside the workspace by full path, the standard library's spelled `std::`, each
/// read in its source for what its `Debug` prints. A channel prints what it holds (a `watch`
/// channel prints its value), so channels are listed with the containers.
const OUTSIDE: &[(&str, Outside)] = &[
    ("std::string::String", Outside::Text),
    ("std::ffi::OsString", Outside::Text),
    ("std::ffi::OsStr", Outside::Text),
    ("std::ffi::CString", Outside::Text),
    ("std::ffi::CStr", Outside::Text),
    ("std::path::PathBuf", Outside::Text),
    ("std::path::Path", Outside::Text),
    ("std::fs::File", Outside::Text),
    ("std::io::Error", Outside::Text),
    ("std::fmt::Arguments", Outside::Text),
    ("std::process::Command", Outside::Text),
    ("std::process::Output", Outside::Text),
    ("serde_json::Value", Outside::Text),
    ("serde_json::value::Value", Outside::Text),
    ("serde_json::Map", Outside::Text),
    ("serde_json::map::Map", Outside::Text),
    ("serde_json::value::RawValue", Outside::Text),
    ("bytes::Bytes", Outside::Text),
    ("bytes::BytesMut", Outside::Text),
    ("url::Url", Outside::Text),
    ("ciborium::value::Value", Outside::Text),
    ("ciborium::Value", Outside::Text),
    // A relay's address, a peer's request identifier (a number or whatever text the peer sent),
    // and a TLS configuration or a connection, which print protocol bytes and connection state.
    ("iroh::RelayUrl", Outside::Text),
    ("rmcp::model::RequestId", Outside::Text),
    ("rustls::ClientConfig", Outside::Text),
    ("rustls::client::ClientConfig", Outside::Text),
    ("tokio_rustls::rustls::ClientConfig", Outside::Text),
    ("iroh::endpoint::Connection", Outside::Text),
    ("iroh::endpoint::SendStream", Outside::Text),
    ("iroh::endpoint::RecvStream", Outside::Text),
    ("std::time::Duration", Outside::Nothing),
    ("std::time::Instant", Outside::Nothing),
    ("std::time::SystemTime", Outside::Nothing),
    ("std::marker::PhantomData", Outside::Nothing),
    ("std::fmt::Error", Outside::Nothing),
    ("std::sync::atomic::AtomicBool", Outside::Nothing),
    ("std::sync::atomic::AtomicU8", Outside::Nothing),
    ("std::sync::atomic::AtomicU16", Outside::Nothing),
    ("std::sync::atomic::AtomicU32", Outside::Nothing),
    ("std::sync::atomic::AtomicU64", Outside::Nothing),
    ("std::sync::atomic::AtomicUsize", Outside::Nothing),
    ("std::sync::atomic::AtomicI32", Outside::Nothing),
    ("std::sync::atomic::AtomicI64", Outside::Nothing),
    ("tokio::time::Instant", Outside::Nothing),
    // A child process prints its three pipes, each by its handle alone.
    ("std::process::Child", Outside::Nothing),
    ("std::option::Option", Outside::Holds),
    ("std::result::Result", Outside::Holds),
    ("std::vec::Vec", Outside::Holds),
    ("std::boxed::Box", Outside::Holds),
    ("std::rc::Rc", Outside::Holds),
    ("std::sync::Arc", Outside::Holds),
    ("std::borrow::Cow", Outside::Holds),
    ("std::collections::HashMap", Outside::Holds),
    ("std::collections::BTreeMap", Outside::Holds),
    ("std::collections::HashSet", Outside::Holds),
    ("std::collections::BTreeSet", Outside::Holds),
    ("std::collections::VecDeque", Outside::Holds),
    ("std::collections::hash_map::HashMap", Outside::Holds),
    ("std::collections::btree_map::BTreeMap", Outside::Holds),
    ("std::sync::Mutex", Outside::Holds),
    ("std::sync::RwLock", Outside::Holds),
    ("std::sync::OnceLock", Outside::Holds),
    ("std::cell::Cell", Outside::Holds),
    ("std::cell::RefCell", Outside::Holds),
    ("std::cell::OnceCell", Outside::Holds),
    ("std::cmp::Reverse", Outside::Holds),
    ("tokio::sync::Mutex", Outside::Holds),
    ("tokio::sync::RwLock", Outside::Holds),
    ("tokio::sync::watch::Sender", Outside::Holds),
    ("tokio::sync::watch::Receiver", Outside::Holds),
    ("tokio::sync::mpsc::Sender", Outside::Holds),
    ("tokio::sync::mpsc::Receiver", Outside::Holds),
    ("tokio::sync::mpsc::UnboundedSender", Outside::Holds),
    ("tokio::sync::mpsc::UnboundedReceiver", Outside::Holds),
    ("tokio::sync::oneshot::Sender", Outside::Holds),
    ("tokio::sync::oneshot::Receiver", Outside::Holds),
    ("tokio::sync::broadcast::Sender", Outside::Holds),
    ("tokio::sync::broadcast::Receiver", Outside::Holds),
    ("zeroize::Zeroizing", Outside::Holds),
];

/// The prelude's types, which every file names without importing them.
const PRELUDE: &[(&str, &str)] = &[
    ("Option", "std::option::Option"),
    ("Result", "std::result::Result"),
    ("Vec", "std::vec::Vec"),
    ("String", "std::string::String"),
    ("Box", "std::boxed::Box"),
];

/// The primitive types whose `Debug` is a number or a switch.
const NUMBERS: [&str; 15] = [
    "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize", "bool",
    "f32", "f64",
];

/// The standard library's types whose `len`, `is_empty`, `is_some` and `is_none` return a number
/// or a switch, whatever they hold.
const MEASURED: [&str; 11] = [
    "std::string::String",
    "prim::str",
    "std::vec::Vec",
    "std::option::Option",
    "std::result::Result",
    "std::collections::HashMap",
    "std::collections::BTreeMap",
    "std::collections::HashSet",
    "std::collections::BTreeSet",
    "std::collections::VecDeque",
    "bytes::Bytes",
];

/// The methods that measure one of [`MEASURED`].
const MEASURES: [&str; 6] = ["len", "is_empty", "is_some", "is_none", "is_ok", "is_err"];

/* -------------------------------------------------------------------------------------------- */
/* What every crate declares                                                                     */
/* -------------------------------------------------------------------------------------------- */

/// A type as written somewhere, so its names resolve as the compiler resolves them there.
#[derive(Clone)]
struct Written {
    /// The file, as an index into the sources.
    source: usize,
    /// The scope it is written in.
    scope: usize,
    /// The generic parameters in force there.
    generics: Vec<String>,
    /// The type.
    tokens: Vec<Located>,
}

/// One field of a declared type.
struct Member {
    name: String,
    written: Written,
}

/// A struct's one shape, or one variant of an enum.
struct Shape {
    name: String,
    members: Vec<Member>,
}

/// One struct, enum or union some crate declares.
struct Declared {
    /// The file, as an index into the sources.
    source: usize,
    /// The name it is declared with.
    name: String,
    /// The line of its `derive` that names `Debug`, when it derives one.
    derived: Option<usize>,
    shapes: Vec<Shape>,
}

/// A `Debug` written by hand.
struct ByHand {
    /// The type it is for, by full path.
    target: String,
    /// The type as the `impl` writes it, which is what `self` is.
    written: Written,
    /// The line of the `impl`.
    line: usize,
    /// The `impl` block, from its opening brace to its closing one.
    tokens: Vec<Located>,
}

/// Why a type carries text, or why a `Debug` written by hand is refused.
type Why = String;

/// What every crate in a workspace declares, and what the rule holds of the two crates' `Debug`s.
struct Debugs {
    sources: Vec<Source>,
    /// How many of `sources`, from the first, are the two crates' own.
    guarded: usize,
    /// The workspace's crates, as code names them.
    crates: BTreeSet<String>,
    /// Every name a module imports, as the full path it names.
    aliases: BTreeMap<String, String>,
    /// What each module imports everything from.
    globs: BTreeMap<String, Vec<String>>,
    declared: BTreeMap<String, Declared>,
    type_aliases: BTreeMap<String, Written>,
    by_hand: Vec<ByHand>,
    known: Known,
    plain: BTreeSet<String>,
    /// The types the two files that define what may be shown declare, which write their own
    /// renderings.
    shown_types: BTreeSet<String>,
    /// The functions of those two files that are declared to return a `Shown`.
    shown_functions: BTreeSet<String>,
    /// The types whose `Debug` is their `Display`.
    as_display: BTreeSet<String>,
}

/// Every crate under the workspace's `crates/`, by the name code gives it, and its library's root.
fn workspace_crates(workspace: &Path) -> Vec<(String, PathBuf)> {
    let mut crates = Vec::new();
    let Ok(entries) = std::fs::read_dir(workspace.join("crates")) else {
        return crates;
    };
    for entry in entries.flatten() {
        let root = entry.path().join("src").join("lib.rs");
        let Ok(manifest) = std::fs::read_to_string(entry.path().join("Cargo.toml")) else {
            continue;
        };
        let name = manifest.lines().find_map(|line| {
            let value = line
                .trim()
                .strip_prefix("name")?
                .trim_start()
                .strip_prefix('=')?;
            Some(value.trim().trim_matches('"').replace('-', "_"))
        });
        if let Some(name) = name
            && root.exists()
        {
            crates.push((name, root));
        }
    }
    crates.sort();
    crates
}

impl Debugs {
    /// Reads `guarded`, the two crates' own files, and every crate of `workspace` for what it
    /// declares.
    fn read(workspace: &Path, guarded: Vec<Source>) -> Self {
        let guarded_names: BTreeSet<String> = guarded
            .iter()
            .map(|source| source.crate_name.clone())
            .collect();
        let mut sources = guarded;
        let count = sources.len();
        let mut crates: BTreeSet<String> = guarded_names.clone();
        for (name, root) in workspace_crates(workspace) {
            crates.insert(name.clone());
            if guarded_names.contains(&name) {
                continue;
            }
            if let Ok(found) = read_crate(workspace, &root, &name, false) {
                sources.extend(found);
            }
        }
        let mut aliases = BTreeMap::new();
        let mut globs: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for source in &sources {
            for import in &source.imports {
                if source.scopes[import.scope].block {
                    continue;
                }
                let mut key = source.module_of(import.scope);
                key.push(import.local.clone());
                let target = import.path.join("::");
                let key = key.join("::");
                if key != target {
                    aliases.insert(key, target);
                }
            }
            for (scope, path) in &source.glob_paths {
                if source.scopes[*scope].block {
                    continue;
                }
                globs
                    .entry(source.module_of(*scope).join("::"))
                    .or_default()
                    .push(path.join("::"));
            }
        }
        let known = collect_known(&sources[..count], &aliases);
        let mut debugs = Self {
            sources,
            guarded: count,
            crates,
            aliases,
            globs,
            declared: BTreeMap::new(),
            type_aliases: BTreeMap::new(),
            by_hand: Vec::new(),
            known,
            plain: BTreeSet::new(),
            shown_types: BTreeSet::new(),
            shown_functions: BTreeSet::new(),
            as_display: BTreeSet::new(),
        };
        debugs.plain = debugs
            .known
            .plain
            .iter()
            .map(|path| debugs.normal(path))
            .collect();
        debugs.as_display = debugs
            .known
            .debug_as_display
            .iter()
            .map(|path| debugs.normal(path))
            .collect();
        for index in 0..debugs.sources.len() {
            debugs.declare(index);
        }
        debugs
    }

    /// The source a finding names, when it is one of the two crates' own.
    fn guarded_file(&self, index: usize) -> Option<&str> {
        let name = self.sources[index].name.as_str();
        (index < self.guarded && !SHOWN_FILES.contains(&name)).then_some(name)
    }

    /// A full path as the rule compares them: the standard library's spelled `std::`, and every
    /// prefix that a module imports under another name replaced by what it names.
    fn normal(&self, path: &str) -> String {
        let mut path = path.to_owned();
        for from in ["core::", "alloc::", "::core::", "::std::", "::alloc::"] {
            if let Some(rest) = path.strip_prefix(from) {
                path = format!("std::{rest}");
            }
        }
        for _ in 0..16 {
            let segments: Vec<&str> = path.split("::").collect();
            let replaced = (1..=segments.len()).rev().find_map(|end| {
                let target = self.aliases.get(&segments[..end].join("::"))?;
                let rest = segments[end..].join("::");
                Some(if rest.is_empty() {
                    target.clone()
                } else {
                    format!("{target}::{rest}")
                })
            });
            match replaced {
                Some(next) if next != path => path = next,
                _ => break,
            }
        }
        for from in ["core::", "alloc::"] {
            if let Some(rest) = path.strip_prefix(from) {
                path = format!("std::{rest}");
            }
        }
        path
    }

    /// Finds `path` among `map`'s keys, or through a module that imports everything from another.
    fn find<'a, T>(&self, map: &'a BTreeMap<String, T>, path: &str) -> Option<&'a T> {
        let path = self.normal(path);
        if let Some(found) = map.get(&path) {
            return Some(found);
        }
        let (module, name) = path.rsplit_once("::")?;
        self.globs.get(module)?.iter().find_map(|glob| {
            let candidate = self.normal(&format!("{glob}::{name}"));
            map.get(&candidate)
        })
    }

    /// The full path a path written in `written`'s place names, or `None` when this reading
    /// cannot place it.
    fn resolve(&self, written: &Written, segments: &[String]) -> Option<String> {
        let source = &self.sources[written.source];
        if let Some(path) = source.resolve(segments, written.scope, &self.aliases) {
            return Some(self.normal(&path));
        }
        let [name] = segments else {
            return None;
        };
        // A type a macro declares in this module, which the file's own definitions do not list.
        for visible in source.visible(written.scope) {
            let path = source.defined_path(visible, name);
            if self.declared.contains_key(&path) || self.type_aliases.contains_key(&path) {
                return Some(path);
            }
        }
        let glob = source
            .visible(written.scope)
            .iter()
            .any(|scope| source.globs.contains(scope));
        if glob {
            return None;
        }
        PRELUDE
            .iter()
            .find(|(short, _)| short == name)
            .map(|(_, path)| (*path).to_owned())
    }

    /// Reads what one source declares: its types, its type aliases, its `Debug`s written by hand,
    /// and the types and `Debug`s its macros write where they are invoked.
    fn declare(&mut self, index: usize) {
        let tokens = self.sources[index].tokens.clone();
        let macros = macro_bodies(&tokens);
        let inside_macro = |at: usize| {
            macros
                .iter()
                .any(|(_, open, close)| at > *open && at < *close)
        };
        for at in 0..tokens.len() {
            if inside_macro(at) {
                continue;
            }
            let scope = self.sources[index].scope_at(at);
            match ident(tokens.get(at)) {
                Some("struct" | "enum" | "union")
                    if ident(tokens.get(at + 1)).is_some()
                        && !(at > 0
                            && (punct(tokens.get(at - 1), '.')
                                || ident(tokens.get(at - 1)) == Some("fn"))) =>
                {
                    self.declare_type(index, &tokens, at, scope, None);
                }
                Some("type")
                    if ident(tokens.get(at + 1)).is_some()
                        && !self.sources[index].scopes[scope].block =>
                {
                    self.declare_alias(index, &tokens, at, scope);
                }
                Some("Debug")
                    if ident(tokens.get(at + 1)) == Some("for") && impl_of(&tokens, at) =>
                {
                    self.declare_by_hand(index, &tokens, at, scope, None);
                }
                _ => {}
            }
        }
        // A macro that declares a type or writes a `Debug`, read at each place it is invoked in
        // this file, with its name the first word the invocation gives it.
        for (name, open, close) in &macros {
            let body = &tokens[*open + 1..*close];
            for at in 0..tokens.len() {
                if ident(tokens.get(at)) != Some(name.as_str())
                    || !punct(tokens.get(at + 1), '!')
                    || inside_macro(at)
                    || (at > 0 && ident(tokens.get(at - 1)) == Some("macro_rules"))
                {
                    continue;
                }
                let Some(group_close) = closing(&tokens, at + 2) else {
                    continue;
                };
                let invoked = first_word(&tokens[at + 3..group_close]);
                let scope = self.sources[index].scope_at(at);
                let expanded = substitute(body, invoked.as_deref());
                for item in 0..expanded.len() {
                    match ident(expanded.get(item)) {
                        Some("struct" | "enum" | "union")
                            if ident(expanded.get(item + 1)).is_some() =>
                        {
                            self.declare_type(index, &expanded, item, scope, Some(at));
                        }
                        Some("Debug")
                            if ident(expanded.get(item + 1)) == Some("for")
                                && impl_of(&expanded, item) =>
                        {
                            self.declare_by_hand(index, &expanded, item, scope, Some(at));
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Reads the struct, enum or union whose keyword is at `at`.
    fn declare_type(
        &mut self,
        index: usize,
        tokens: &[Located],
        at: usize,
        scope: usize,
        invoked: Option<usize>,
    ) {
        let Some(name) = ident(tokens.get(at + 1)).map(ToOwned::to_owned) else {
            return;
        };
        let path = self.sources[index].defined_path(scope, &name);
        let (generics, mut cursor) = generic_parameters(tokens, at + 2);
        while cursor < tokens.len()
            && !punct(tokens.get(cursor), '{')
            && !punct(tokens.get(cursor), '(')
            && !punct(tokens.get(cursor), ';')
        {
            cursor += 1;
        }
        let line = invoked.map_or(tokens[at].line, |invoked| {
            self.sources[index].tokens[invoked].line
        });
        let start = before_item(tokens, at);
        let mut derived = None;
        for place in start..at {
            if ident(tokens.get(place)) == Some("derive") && punct(tokens.get(place + 1), '(') {
                let names = derive_names(tokens, place + 1);
                if names
                    .iter()
                    .any(|name| name == "Debug" || name.ends_with("::Debug"))
                {
                    derived = Some(invoked.map_or(tokens[place].line, |_| line));
                }
            }
        }
        let written = |field_tokens: Vec<Located>| Written {
            source: index,
            scope,
            generics: generics.clone(),
            tokens: field_tokens,
        };
        let mut shapes = Vec::new();
        let enumeration = ident(tokens.get(at)) == Some("enum");
        if !punct(tokens.get(cursor), ';') {
            if enumeration {
                let close = closing(tokens, cursor).unwrap_or(tokens.len());
                let mut variant = cursor + 1;
                while variant < close {
                    while punct(tokens.get(variant), '#') {
                        variant = attribute_end(tokens, variant).unwrap_or(close);
                    }
                    let Some(variant_name) = ident(tokens.get(variant)).map(ToOwned::to_owned)
                    else {
                        variant += 1;
                        continue;
                    };
                    variant += 1;
                    let mut members = Vec::new();
                    if punct(tokens.get(variant), '{') || punct(tokens.get(variant), '(') {
                        members = fields(tokens, variant)
                            .into_iter()
                            .map(|field| Member {
                                name: field.name,
                                written: written(field.type_tokens),
                            })
                            .collect();
                        variant = closing(tokens, variant).map_or(close, |end| end + 1);
                    }
                    shapes.push(Shape {
                        name: variant_name,
                        members,
                    });
                    while variant < close && !punct(tokens.get(variant), ',') {
                        variant += 1;
                    }
                    variant += 1;
                }
            } else {
                let members = fields(tokens, cursor)
                    .into_iter()
                    .map(|field| Member {
                        name: field.name,
                        written: written(field.type_tokens),
                    })
                    .collect();
                shapes.push(Shape {
                    name: name.clone(),
                    members,
                });
            }
        }
        self.declared.entry(path).or_insert(Declared {
            source: index,
            name,
            derived,
            shapes,
        });
    }

    /// Reads the type alias whose keyword is at `at`.
    fn declare_alias(&mut self, index: usize, tokens: &[Located], at: usize, scope: usize) {
        let Some(name) = ident(tokens.get(at + 1)).map(ToOwned::to_owned) else {
            return;
        };
        let (generics, cursor) = generic_parameters(tokens, at + 2);
        if !punct(tokens.get(cursor), '=') {
            return;
        }
        let end = (cursor..tokens.len())
            .find(|&end| punct(tokens.get(end), ';'))
            .unwrap_or(tokens.len());
        let path = self.sources[index].defined_path(scope, &name);
        self.type_aliases.insert(
            path,
            Written {
                source: index,
                scope,
                generics,
                tokens: tokens[cursor + 1..end].to_vec(),
            },
        );
    }

    /// Reads the `impl Debug for` whose `Debug` is at `at`.
    fn declare_by_hand(
        &mut self,
        index: usize,
        tokens: &[Located],
        at: usize,
        scope: usize,
        invoked: Option<usize>,
    ) {
        let mut open = at + 2;
        while open < tokens.len()
            && !punct(tokens.get(open), '{')
            && ident(tokens.get(open)) != Some("where")
        {
            open += 1;
        }
        let target_tokens = tokens[at + 2..open].to_vec();
        while open < tokens.len() && !punct(tokens.get(open), '{') {
            open += 1;
        }
        let Some(close) = closing(tokens, open) else {
            return;
        };
        // The `impl`'s own generic parameters, which the target names.
        let mut start = at;
        while start > 0 && ident(tokens.get(start)) != Some("impl") {
            start -= 1;
        }
        let (generics, _) = generic_parameters(tokens, start + 1);
        let written = Written {
            source: index,
            scope,
            generics,
            tokens: target_tokens,
        };
        let (segments, _) = written_path(&strip_references(&written.tokens));
        let target = self
            .resolve(&written, &segments)
            .unwrap_or_else(|| format!("?{}", segments.join("::")));
        let line = invoked.map_or(tokens[at].line, |invoked| {
            self.sources[index].tokens[invoked].line
        });
        self.by_hand.push(ByHand {
            target,
            written,
            line,
            tokens: tokens[open..=close].to_vec(),
        });
    }
}

/// Each `macro_rules!` in `tokens`: its name and its body's braces.
fn macro_bodies(tokens: &[Located]) -> Vec<(String, usize, usize)> {
    let mut found = Vec::new();
    for at in 0..tokens.len() {
        if ident(tokens.get(at)) == Some("macro_rules")
            && punct(tokens.get(at + 1), '!')
            && let Some(name) = ident(tokens.get(at + 2))
            && let Some(close) = closing(tokens, at + 3)
        {
            found.push((name.to_owned(), at + 3, close));
        }
    }
    found
}

/// The first word an invocation gives, past any attributes in front of it.
fn first_word(tokens: &[Located]) -> Option<String> {
    let mut at = 0;
    while at < tokens.len() {
        if punct(tokens.get(at), '#') {
            at = attribute_end(tokens, at)?;
            continue;
        }
        return ident(tokens.get(at)).map(ToOwned::to_owned);
    }
    None
}

/// A macro's body with the fragment each item names itself by replaced by `name`: the one after
/// `struct`, `enum`, `union` or `for`. Every other fragment is left as it is, and a type that holds
/// one is one this reading cannot place.
fn substitute(body: &[Located], name: Option<&str>) -> Vec<Located> {
    let mut named: BTreeSet<String> = BTreeSet::new();
    for at in 0..body.len() {
        if matches!(
            ident(body.get(at)),
            Some("struct" | "enum" | "union" | "for")
        ) && punct(body.get(at + 1), '$')
            && let Some(fragment) = ident(body.get(at + 2))
        {
            named.insert(fragment.to_owned());
        }
    }
    let mut out = Vec::with_capacity(body.len());
    let mut at = 0;
    while at < body.len() {
        if punct(body.get(at), '$')
            && let Some(fragment) = ident(body.get(at + 1))
            && named.contains(fragment)
            && let Some(name) = name
        {
            out.push(Located {
                token: Token::Ident(name.to_owned()),
                line: body[at].line,
            });
            at += 2;
            continue;
        }
        out.push(body[at].clone());
        at += 1;
    }
    out
}

/// The generic parameters of an item whose `<` would be at `at`, and the index past them.
fn generic_parameters(tokens: &[Located], at: usize) -> (Vec<String>, usize) {
    if !punct(tokens.get(at), '<') {
        return (Vec::new(), at);
    }
    let close = angle_close(tokens, at).unwrap_or(tokens.len() - 1);
    let names = split_commas(&tokens[at + 1..close])
        .iter()
        .filter_map(
            |parameter| match parameter.first().map(|located| &located.token) {
                Some(Token::Ident(word)) if word == "const" => {
                    ident(parameter.get(1)).map(ToOwned::to_owned)
                }
                Some(Token::Ident(word)) => Some(word.clone()),
                _ => None,
            },
        )
        .collect();
    (names, close + 1)
}

/// The `>` that closes the `<` at `open`, where an arrow's `>` closes nothing.
fn angle_close(tokens: &[Located], open: usize) -> Option<usize> {
    let mut depth = 0_i64;
    for at in open..tokens.len() {
        match tokens[at].token {
            Token::Punct('<') => depth += 1,
            Token::Punct('>') if !(at > 0 && punct(tokens.get(at - 1), '-')) => {
                depth -= 1;
                if depth == 0 {
                    return Some(at);
                }
            }
            _ => {}
        }
    }
    None
}

/// A type with any references, lifetimes and `mut` in front of it taken off.
fn strip_references(tokens: &[Located]) -> Vec<Located> {
    let mut at = 0;
    while punct(tokens.get(at), '&')
        || matches!(
            tokens.get(at).map(|located| &located.token),
            Some(Token::Lifetime(_))
        )
        || ident(tokens.get(at)) == Some("mut")
        || ident(tokens.get(at)) == Some("dyn")
    {
        at += 1;
    }
    tokens[at.min(tokens.len())..].to_vec()
}

/* -------------------------------------------------------------------------------------------- */
/* Which types carry text                                                                        */
/* -------------------------------------------------------------------------------------------- */

/// The types found to carry text so far, each with why.
type Carrying = BTreeMap<String, Why>;

impl Debugs {
    /// Whether the rule decides what `path`'s `Debug` prints without reading it: a claim, one of the
    /// two crates' failures, a type the files that define what may be shown write, or a `Debug`
    /// that is its `Display`.
    fn decided(&self, path: &str) -> bool {
        self.plain.contains(path)
            || path == SHOWN
            || path == IO_FAULT
            || self.known.errors.contains_key(path)
            || self.shown_types.contains(path)
            || self.as_display.contains(path)
    }

    /// Why the type written in `written` carries text, or `None` when its `Debug` prints none.
    fn carries(&self, written: &Written, carrying: &Carrying) -> Option<Why> {
        self.carries_in(written, &written.tokens, carrying)
    }

    fn carries_in(
        &self,
        written: &Written,
        tokens: &[Located],
        carrying: &Carrying,
    ) -> Option<Why> {
        let Some(first) = tokens.first() else {
            return Some("a type this reading cannot read".to_owned());
        };
        match &first.token {
            Token::Punct('&') => {
                let mut at = 1;
                let lifetime = match tokens.get(at).map(|located| &located.token) {
                    Some(Token::Lifetime(lifetime)) => {
                        at += 1;
                        lifetime.clone()
                    }
                    _ => String::new(),
                };
                if ident(tokens.get(at)) == Some("mut") {
                    at += 1;
                }
                let rest = &tokens[at..];
                if lifetime == "'static" && matches!(rest, [one] if ident(Some(one)) == Some("str"))
                {
                    return None;
                }
                self.carries_in(written, rest, carrying)
            }
            Token::Punct('*') => self.carries_in(written, tokens.get(2..).unwrap_or(&[]), carrying),
            Token::Punct('[') => {
                let close = closing(tokens, 0).unwrap_or(tokens.len());
                let inner = &tokens[1..close.min(tokens.len())];
                let element_end = inner
                    .iter()
                    .position(|located| located.token == Token::Punct(';'))
                    .unwrap_or(inner.len());
                let element = &inner[..element_end];
                if matches!(element, [one] if ident(Some(one)) == Some("u8")) {
                    return Some("bytes".to_owned());
                }
                self.carries_in(written, element, carrying)
            }
            Token::Punct('(') => {
                let close = closing(tokens, 0).unwrap_or(tokens.len());
                split_commas(&tokens[1..close.min(tokens.len())])
                    .iter()
                    .find_map(|part| self.carries_in(written, part, carrying))
            }
            Token::Punct('!') => None,
            Token::Ident(word) if word == "_" => None,
            Token::Ident(word) if word == "fn" || word == "unsafe" || word == "extern" => None,
            Token::Ident(word) if word == "dyn" || word == "impl" => {
                Some("a trait object, which prints whatever implements it".to_owned())
            }
            Token::Ident(_) | Token::Punct(':') => self.path_carries(written, tokens, carrying),
            _ => Some("a type this reading cannot read".to_owned()),
        }
    }

    /// Why a type written as a path carries text.
    fn path_carries(
        &self,
        written: &Written,
        tokens: &[Located],
        carrying: &Carrying,
    ) -> Option<Why> {
        let (segments, after) = written_path(tokens);
        let arguments: Vec<Vec<Located>> = if punct(tokens.get(after), '<') {
            let close = angle_close(tokens, after).unwrap_or(tokens.len());
            split_commas(&tokens[after + 1..close.min(tokens.len())])
                .into_iter()
                .filter(|argument| {
                    !matches!(
                        argument.first().map(|located| &located.token),
                        Some(Token::Lifetime(_) | Token::Number(_) | Token::Punct('{'))
                    )
                })
                .collect()
        } else {
            if after < tokens.len() {
                return Some(format!(
                    "a type this reading cannot read: {}",
                    segments.join("::")
                ));
            }
            Vec::new()
        };
        let arguments_carry = || {
            arguments
                .iter()
                .find_map(|argument| self.carries_in(written, argument, carrying))
        };
        if segments.len() == 1 && segments[0] == "Self" {
            return arguments_carry();
        }
        if written.generics.contains(&segments[0]) {
            // A parameter: where the type is used, its argument is read there.
            return if segments.len() == 1 {
                None
            } else {
                Some(format!(
                    "an associated type this reading cannot follow: {}",
                    segments.join("::")
                ))
            };
        }
        let Some(path) = self.resolve(written, &segments) else {
            return Some(format!(
                "a type this reading cannot place: {}",
                segments.join("::")
            ));
        };
        if let Some(primitive) = path.strip_prefix("prim::") {
            return if NUMBERS.contains(&primitive) {
                None
            } else {
                Some(primitive.to_owned())
            };
        }
        if self.decided(&path) {
            return None;
        }
        if let Some(alias) = self.find(&self.type_aliases, &path) {
            return self.carries(alias, carrying).or_else(arguments_carry);
        }
        if self.find(&self.declared, &path).is_some() {
            if let Some(why) = self.carrying(carrying, &path) {
                return Some(format!("{path}, which carries {why}"));
            }
            return arguments_carry();
        }
        let root = path.split("::").next().unwrap_or_default();
        if self.crates.contains(root) {
            return Some(format!("{path}, a type this reading cannot place"));
        }
        match OUTSIDE.iter().find(|(listed, _)| *listed == path) {
            Some((_, Outside::Text)) => Some(path),
            Some((_, Outside::Nothing)) => None,
            Some((_, Outside::Holds)) => arguments_carry(),
            None => Some(format!(
                "{path}, a type from outside the workspace this reading does not list"
            )),
        }
    }

    /// Why a declared type carries text, when it is found to.
    fn carrying<'a>(&self, carrying: &'a Carrying, path: &str) -> Option<&'a Why> {
        let path = self.normal(path);
        if let Some(why) = carrying.get(&path) {
            return Some(why);
        }
        let (module, name) = path.rsplit_once("::")?;
        self.globs
            .get(module)?
            .iter()
            .find_map(|glob| carrying.get(&self.normal(&format!("{glob}::{name}"))))
    }

    /// Why a derived `Debug` over `declared`'s fields prints text.
    fn derived_carries(&self, declared: &Declared, carrying: &Carrying) -> Option<Why> {
        declared.shapes.iter().find_map(|shape| {
            shape.members.iter().find_map(|member| {
                self.carries(&member.written, carrying).map(|why| {
                    if shape.name == declared.name {
                        format!("the field `{}`: {why}", member.name)
                    } else {
                        format!("the field `{}` of `{}`: {why}", member.name, shape.name)
                    }
                })
            })
        })
    }

    /// Every type whose `Debug` carries text, to a fixpoint.
    fn fixpoint(&self) -> Carrying {
        let mut carrying = Carrying::new();
        loop {
            let mut changed = false;
            for (path, declared) in &self.declared {
                if carrying.contains_key(path) || self.decided(path) {
                    continue;
                }
                let hands: Vec<&ByHand> = self
                    .by_hand
                    .iter()
                    .filter(|hand| hand.target == *path)
                    .collect();
                let why = match declared.derived {
                    Some(_) => self.derived_carries(declared, &carrying),
                    // A type formatted somewhere has a `Debug`: one this reading cannot find is
                    // one it cannot hold.
                    None if hands.is_empty() => {
                        Some("a type whose Debug this reading cannot find".to_owned())
                    }
                    None => hands
                        .iter()
                        .find_map(|hand| self.read_by_hand(hand, &carrying).err())
                        .map(|(_, why)| why),
                };
                if let Some(why) = why {
                    carrying.insert(path.clone(), why);
                    changed = true;
                }
            }
            if !changed {
                return carrying;
            }
        }
    }

    /// Every place in the two crates where a `Debug` can print text that arrived.
    fn findings(&self) -> Vec<Finding> {
        let carrying = self.fixpoint();
        let mut findings = BTreeSet::new();
        for declared in self.declared.values() {
            let (Some(file), Some(line)) = (self.guarded_file(declared.source), declared.derived)
            else {
                continue;
            };
            if let Some(why) = self.derived_carries(declared, &carrying) {
                findings.insert(Finding {
                    file: file.to_owned(),
                    line,
                    item: declared.name.clone(),
                    what: format!("a derived Debug over text that arrived: {why}"),
                });
            }
        }
        for hand in &self.by_hand {
            let Some(file) = self.guarded_file(hand.written.source) else {
                continue;
            };
            if let Err((line, why)) = self.read_by_hand(hand, &carrying) {
                let item = hand.target.rsplit("::").next().unwrap_or("?").to_owned();
                findings.insert(Finding {
                    file: file.to_owned(),
                    line,
                    item,
                    what: format!("a Debug written by hand that formats {why}"),
                });
            }
        }
        findings.into_iter().collect()
    }
}

/* -------------------------------------------------------------------------------------------- */
/* Reading a Debug written by hand                                                               */
/* -------------------------------------------------------------------------------------------- */

/// The trait a value is formatted with.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Trait {
    Debug,
    Display,
    /// `LowerHex` and the other number formats.
    Number,
    /// `write_str`, which writes text as it is.
    Text,
}

/// A name a pattern or a `let` binds in part of a body: its type, when this reading knows it.
struct Binding {
    name: String,
    from: usize,
    to: usize,
    written: Option<Written>,
}

/// One `Debug` written by hand, being read.
struct Reading<'a> {
    debugs: &'a Debugs,
    hand: &'a ByHand,
    carrying: &'a Carrying,
    /// The body of `fmt`, from its opening brace to its closing one.
    body: &'a [Located],
    formatter: String,
    bindings: Vec<Binding>,
}

type Refused = (usize, Why);

impl Debugs {
    /// Reads one `Debug` written by hand, and says the first thing it formats that may carry text.
    fn read_by_hand(&self, hand: &ByHand, carrying: &Carrying) -> Result<(), Refused> {
        let tokens = &hand.tokens;
        let refuse = |why: &str| (hand.line, why.to_owned());
        let at = (0..tokens.len())
            .find(|&at| {
                ident(tokens.get(at)) == Some("fn") && ident(tokens.get(at + 1)) == Some("fmt")
            })
            .ok_or_else(|| refuse("a body this reading cannot find"))?;
        let open = at + 2;
        let close =
            closing(tokens, open).ok_or_else(|| refuse("a body this reading cannot find"))?;
        let parameters = split_commas(&tokens[open + 1..close]);
        let formatter = parameters
            .get(1)
            .and_then(|parameter| ident(parameter.first()))
            .ok_or_else(|| refuse("a formatter this reading cannot find"))?
            .to_owned();
        let body_open = (close..tokens.len())
            .find(|&at| punct(tokens.get(at), '{'))
            .ok_or_else(|| refuse("a body this reading cannot find"))?;
        let body_close =
            closing(tokens, body_open).ok_or_else(|| refuse("a body this reading cannot find"))?;
        let mut reading = Reading {
            debugs: self,
            hand,
            carrying,
            body: &tokens[body_open..=body_close],
            formatter,
            bindings: Vec::new(),
        };
        reading.bind();
        reading.read()
    }
}

impl Reading<'_> {
    fn refuse(&self, at: usize, why: impl Into<String>) -> Refused {
        (
            self.body
                .get(at)
                .map_or(self.hand.line, |located| located.line),
            why.into(),
        )
    }

    /// The type of `self`.
    fn self_type(&self) -> Written {
        self.hand.written.clone()
    }

    /// The binding of `name` in force at `at`, the innermost first.
    fn binding(&self, name: &str, at: usize) -> Option<&Binding> {
        self.bindings
            .iter()
            .filter(|binding| binding.name == name && binding.from <= at && at <= binding.to)
            .max_by_key(|binding| binding.from)
    }

    /// Records every name a `match`, a `let` or an `if let` binds, with where it is in force.
    fn bind(&mut self) {
        let body = self.body;
        for at in 0..body.len() {
            match ident(body.get(at)) {
                Some("match") => {
                    let Some(open) = (at + 1..body.len()).find(|&open| punct(body.get(open), '{'))
                    else {
                        continue;
                    };
                    let scrutinee = self.place_type(&body[at + 1..open], at).ok();
                    let close = closing(body, open).unwrap_or(body.len() - 1);
                    let mut cursor = open + 1;
                    while cursor < close {
                        let Some(arrow) = (cursor..close).find(|&arrow| {
                            punct(body.get(arrow), '=')
                                && punct(body.get(arrow + 1), '>')
                                && depth_between(body, cursor, arrow) == 0
                        }) else {
                            break;
                        };
                        let pattern = &body[cursor..arrow];
                        let arm_start = arrow + 2;
                        let arm_end = if punct(body.get(arm_start), '{') {
                            closing(body, arm_start).unwrap_or(close)
                        } else {
                            (arm_start..close)
                                .find(|&end| {
                                    punct(body.get(end), ',')
                                        && depth_between(body, arm_start, end) == 0
                                })
                                .unwrap_or(close)
                        };
                        self.bind_pattern(pattern, scrutinee.as_ref(), arm_start, arm_end);
                        cursor = arm_end + 1;
                        if punct(body.get(cursor), ',') {
                            cursor += 1;
                        }
                    }
                }
                Some("let") => {
                    let Some(equals) = (at + 1..body.len()).find(|&equals| {
                        (punct(body.get(equals), '=') && !punct(body.get(equals + 1), '='))
                            || punct(body.get(equals), ';')
                    }) else {
                        continue;
                    };
                    let conditional =
                        at > 0 && matches!(ident(body.get(at - 1)), Some("if" | "while"));
                    let end = (equals..body.len())
                        .find(|&end| {
                            (punct(body.get(end), ';')
                                || (conditional && punct(body.get(end), '{')))
                                && depth_between(body, equals, end) == 0
                        })
                        .unwrap_or(body.len() - 1);
                    let value = &body[equals + 1..end];
                    let scrutinee = self.place_type(value, at).ok();
                    let (from, to) = if conditional {
                        (end, closing(body, end).unwrap_or(body.len() - 1))
                    } else {
                        (end, enclosing_close(body, at))
                    };
                    let mut pattern = &body[at + 1..equals];
                    // A type written on the binding is its type.
                    if let Some(colon) = pattern
                        .iter()
                        .position(|located| located.token == Token::Punct(':'))
                    {
                        let written = Written {
                            source: self.hand.written.source,
                            scope: self.hand.written.scope,
                            generics: self.hand.written.generics.clone(),
                            tokens: pattern[colon + 1..].to_vec(),
                        };
                        pattern = &pattern[..colon];
                        if let Some(name) = single_binding(pattern) {
                            self.bindings.push(Binding {
                                name,
                                from,
                                to,
                                written: Some(written),
                            });
                            continue;
                        }
                    }
                    if conditional {
                        self.bind_pattern(pattern, scrutinee.as_ref(), from, to);
                    } else if let Some(name) = single_binding(pattern) {
                        self.bindings.push(Binding {
                            name,
                            from,
                            to,
                            written: scrutinee,
                        });
                    } else {
                        self.bind_unknown(pattern, from, to);
                    }
                }
                _ => {}
            }
        }
    }

    /// Binds what `pattern` names, matched against a value of type `scrutinee`, from `from` to
    /// `to`.
    fn bind_pattern(
        &mut self,
        pattern: &[Located],
        scrutinee: Option<&Written>,
        from: usize,
        to: usize,
    ) {
        if let Some(name) = single_binding(pattern) {
            self.bindings.push(Binding {
                name,
                from,
                to,
                written: scrutinee.cloned(),
            });
            return;
        }
        let (segments, after) = written_path(pattern);
        let group = pattern.get(after);
        let whole = after == pattern.len() || closing(pattern, after) == Some(pattern.len() - 1);
        let shape = match (scrutinee, segments.last()) {
            (Some(scrutinee), Some(variant)) if whole => self.shape_of(scrutinee, variant),
            _ => None,
        };
        let Some(members) = shape else {
            self.bind_unknown(pattern, from, to);
            return;
        };
        let named = punct(group, '{');
        let parts = if punct(group, '(') || named {
            arguments(pattern, after).unwrap_or_default()
        } else {
            Vec::new()
        };
        for (position, part) in parts.iter().enumerate() {
            let (member, sub) = if named {
                match part
                    .iter()
                    .position(|located| located.token == Token::Punct(':'))
                {
                    Some(colon) => (
                        ident(part.first()).map(ToOwned::to_owned),
                        &part[colon + 1..],
                    ),
                    None => (single_binding(part), &part[..]),
                }
            } else {
                (Some(position.to_string()), &part[..])
            };
            if matches!(sub, [one] if ident(Some(one)) == Some("_"))
                || sub.iter().all(|located| located.token == Token::Punct('.'))
            {
                continue;
            }
            let Some(name) = single_binding(sub) else {
                self.bind_unknown(sub, from, to);
                continue;
            };
            let written = member.and_then(|member| {
                members
                    .iter()
                    .find(|(candidate, _)| *candidate == member)
                    .map(|(_, written)| written.clone())
            });
            self.bindings.push(Binding {
                name,
                from,
                to,
                written,
            });
        }
    }

    /// Binds every name in `pattern` with no type this reading knows.
    fn bind_unknown(&mut self, pattern: &[Located], from: usize, to: usize) {
        for (at, located) in pattern.iter().enumerate() {
            if let Token::Ident(word) = &located.token
                && word
                    .chars()
                    .next()
                    .is_some_and(|first| first.is_lowercase() || first == '_')
                && !matches!(word.as_str(), "ref" | "mut" | "_" | "self")
                && !punct(pattern.get(at + 1), ':')
                && !punct(pattern.get(at + 1), '(')
                && !punct(pattern.get(at + 1), '{')
            {
                self.bindings.push(Binding {
                    name: word.clone(),
                    from,
                    to,
                    written: None,
                });
            }
        }
    }

    /// The members of the variant or struct `name` of the type `scrutinee`, each by name with its
    /// type.
    fn shape_of(&self, scrutinee: &Written, name: &str) -> Option<Vec<(String, Written)>> {
        let declared = self.declaration(scrutinee)?;
        let shape = declared
            .shapes
            .iter()
            .find(|shape| shape.name == name)
            .or_else(|| (declared.shapes.len() == 1).then(|| &declared.shapes[0]))?;
        Some(
            shape
                .members
                .iter()
                .map(|member| (member.name.clone(), member.written.clone()))
                .collect(),
        )
    }

    /// The declaration of the type `written` names, through references, `Box`, `Arc` and `Rc`.
    fn declaration(&self, written: &Written) -> Option<&Declared> {
        let inner = self.dereferenced(written)?;
        let (segments, _) = written_path(&inner.tokens);
        let path = self.debugs.resolve(&inner, &segments)?;
        if let Some(alias) = self.debugs.find(&self.debugs.type_aliases, &path) {
            return self.declaration(alias);
        }
        self.debugs.find(&self.debugs.declared, &path)
    }

    /// The type `written` names once references, `Box`, `Arc` and `Rc` are looked through.
    fn dereferenced(&self, written: &Written) -> Option<Written> {
        let tokens = strip_references(&written.tokens);
        let (segments, after) = written_path(&tokens);
        let path = self.debugs.resolve(written, &segments);
        if matches!(
            path.as_deref(),
            Some("std::boxed::Box" | "std::sync::Arc" | "std::rc::Rc")
        ) && punct(tokens.get(after), '<')
        {
            let close = angle_close(&tokens, after)?;
            let inner = Written {
                tokens: tokens[after + 1..close].to_vec(),
                ..written.clone()
            };
            return self.dereferenced(&inner);
        }
        Some(Written {
            tokens,
            ..written.clone()
        })
    }

    /// The full path of the type `written` names once references are looked through.
    fn head(&self, written: &Written) -> Option<String> {
        let tokens = strip_references(&written.tokens);
        if punct(tokens.first(), '[') {
            return Some("prim::slice".to_owned());
        }
        let (segments, _) = written_path(&tokens);
        self.debugs.resolve(written, &segments)
    }

    /// The type of a place, `self` or a binding followed by fields: `self.a.0.b`.
    fn place_type(&self, tokens: &[Located], at: usize) -> Result<Written, Why> {
        let mut tokens = tokens;
        while punct(tokens.first(), '&')
            || punct(tokens.first(), '*')
            || ident(tokens.first()) == Some("mut")
        {
            tokens = &tokens[1..];
        }
        let mut current = match ident(tokens.first()) {
            Some("self") => self.self_type(),
            Some(name) => self
                .binding(name, at)
                .and_then(|binding| binding.written.clone())
                .ok_or_else(|| format!("`{name}`, a value this reading cannot place"))?,
            None => return Err("a value this reading cannot place".to_owned()),
        };
        let mut index = 1;
        while index < tokens.len() {
            if !punct(tokens.get(index), '.') {
                return Err("an expression this reading does not read".to_owned());
            }
            let field = match tokens.get(index + 1).map(|located| &located.token) {
                Some(Token::Ident(word)) => vec![word.clone()],
                Some(Token::Number(number)) => number.split('.').map(ToOwned::to_owned).collect(),
                _ => return Err("an expression this reading does not read".to_owned()),
            };
            if punct(tokens.get(index + 2), '(') {
                return Err("a method call".to_owned());
            }
            for name in field {
                current = self.field_type(&current, &name)?;
            }
            index += 2;
        }
        Ok(current)
    }

    /// The type of the field `name` of a value of type `of`.
    fn field_type(&self, of: &Written, name: &str) -> Result<Written, Why> {
        let declared = self
            .declaration(of)
            .ok_or_else(|| "a field of a type this reading cannot place".to_owned())?;
        let member = declared
            .shapes
            .iter()
            .filter(|shape| shape.name == declared.name)
            .flat_map(|shape| &shape.members)
            .find(|member| member.name == name)
            .ok_or_else(|| format!("the field `{name}`, which this reading cannot find"))?;
        let (segments, after) = written_path(&strip_references(&member.written.tokens));
        if segments.len() == 1
            && member.written.generics.contains(&segments[0])
            && after == strip_references(&member.written.tokens).len()
        {
            return Err(format!(
                "the field `{name}`, whose type is a generic parameter"
            ));
        }
        Ok(member.written.clone())
    }

    /// Reads every use of the formatter, and every value each formats.
    fn read(&self) -> Result<(), Refused> {
        let body = self.body;
        let mut used: BTreeSet<usize> = BTreeSet::new();
        let mut at = 0;
        while at < body.len() {
            let word = ident(body.get(at));
            if word == Some(self.formatter.as_str()) && punct(body.get(at + 1), '.') {
                let end = self.read_chain(at)?;
                used.insert(at);
                at = end;
                continue;
            }
            if matches!(word, Some("write" | "writeln")) && punct(body.get(at + 1), '!') {
                let parts = arguments(body, at + 2).unwrap_or_default();
                if matches!(parts.first().map(Vec::as_slice), Some([one]) if ident(Some(one)) == Some(self.formatter.as_str()))
                {
                    self.read_format(at, &parts)?;
                    if let Some(position) = (at..body.len()).find(|&position| {
                        ident(body.get(position)) == Some(self.formatter.as_str())
                    }) {
                        used.insert(position);
                    }
                }
            }
            if word == Some("fmt")
                && punct(body.get(at + 1), '(')
                && at >= 2
                && punct(body.get(at - 1), ':')
            {
                let parts = arguments(body, at + 1).unwrap_or_default();
                if matches!(parts.get(1).map(Vec::as_slice), Some([one]) if ident(Some(one)) == Some(self.formatter.as_str()))
                {
                    let named = match ident(body.get(at - 3)) {
                        Some("Debug") => Trait::Debug,
                        Some("Display") => Trait::Display,
                        _ => Trait::Number,
                    };
                    self.value(&parts[0], at, named)?;
                    if let Some(position) = (at..body.len()).find(|&position| {
                        ident(body.get(position)) == Some(self.formatter.as_str())
                    }) {
                        used.insert(position);
                    }
                }
            }
            at += 1;
        }
        for (position, located) in body.iter().enumerate() {
            if ident(Some(located)) == Some(self.formatter.as_str()) && !used.contains(&position) {
                return Err(self.refuse(position, "text through a formatter it passes on"));
            }
        }
        Ok(())
    }

    /// Reads a chain of the formatter's methods starting at the formatter at `at`, and returns the
    /// index past it.
    fn read_chain(&self, at: usize) -> Result<usize, Refused> {
        let body = self.body;
        let mut cursor = at + 1;
        let mut kind = "";
        while punct(body.get(cursor), '.') {
            let Some(method) = ident(body.get(cursor + 1)) else {
                break;
            };
            if !punct(body.get(cursor + 2), '(') {
                return Err(self.refuse(cursor, format!("the formatter's `{method}`")));
            }
            let close = closing(body, cursor + 2).unwrap_or(body.len() - 1);
            let parts = arguments(body, cursor + 2).unwrap_or_default();
            match (kind, method) {
                ("", "write_str") => {
                    let [text] = parts.as_slice() else {
                        return Err(self.refuse(cursor, "text it does not read"));
                    };
                    self.value(text, cursor, Trait::Text)?;
                }
                ("", "debug_struct" | "debug_tuple") => {
                    if !matches!(parts.as_slice(), [one] if matches!(one.as_slice(), [Located { token: Token::Str(_), .. }]))
                    {
                        return Err(self.refuse(cursor, "a name that is not this program's words"));
                    }
                    kind = if method == "debug_struct" {
                        "struct"
                    } else {
                        "tuple"
                    };
                }
                ("", "debug_list" | "debug_set") => kind = "list",
                ("", "debug_map") => kind = "map",
                ("", "alternate") => {}
                ("struct", "field") => {
                    let [name, value] = parts.as_slice() else {
                        return Err(self.refuse(cursor, "a field it does not read"));
                    };
                    if !matches!(
                        name.as_slice(),
                        [Located {
                            token: Token::Str(_),
                            ..
                        }]
                    ) {
                        return Err(
                            self.refuse(cursor, "a field name that is not this program's words")
                        );
                    }
                    self.value(value, cursor, Trait::Debug)?;
                }
                ("tuple", "field") | ("list", "entry") | ("map", "key" | "value") => {
                    let [value] = parts.as_slice() else {
                        return Err(self.refuse(cursor, "a field it does not read"));
                    };
                    self.value(value, cursor, Trait::Debug)?;
                }
                ("map", "entry") => {
                    for value in &parts {
                        self.value(value, cursor, Trait::Debug)?;
                    }
                }
                (_, "finish" | "finish_non_exhaustive") => {}
                (_, other) => {
                    return Err(self.refuse(cursor, format!("the formatter's `{other}`")));
                }
            }
            cursor = close + 1;
        }
        Ok(cursor)
    }

    /// Reads `write!(formatter, "…", …)`: each hole's value, for the trait the hole uses.
    fn read_format(&self, at: usize, parts: &[Vec<Located>]) -> Result<(), Refused> {
        let Some(
            [
                Located {
                    token: Token::Str(template),
                    ..
                },
            ],
        ) = parts.get(1).map(Vec::as_slice)
        else {
            return Err(self.refuse(at, "a format that is not this program's words"));
        };
        let rest = &parts[2..];
        let mut positional = rest.iter().filter(|part| {
            !(ident(part.first()).is_some() && punct(part.get(1), '=') && !punct(part.get(2), '='))
        });
        let named = |name: &str| {
            rest.iter()
                .find(|part| {
                    ident(part.first()) == Some(name)
                        && punct(part.get(1), '=')
                        && !punct(part.get(2), '=')
                })
                .map(|part| part[2..].to_vec())
        };
        for hole in holes(template) {
            let (argument, spec) = hole.split_once(':').unwrap_or((hole.as_str(), ""));
            let argument = argument.trim();
            let used = if spec.contains('?') {
                Trait::Debug
            } else if spec.ends_with(|last: char| "xXobeEp".contains(last)) {
                Trait::Number
            } else {
                Trait::Display
            };
            if spec.contains('$') || spec.contains('*') {
                return Err(self.refuse(at, "a format whose width or precision is a value"));
            }
            let value: Vec<Located> = if argument.is_empty() {
                positional
                    .next()
                    .cloned()
                    .ok_or_else(|| self.refuse(at, "a format with more holes than values"))?
            } else if let Ok(position) = argument.parse::<usize>() {
                rest.get(position)
                    .cloned()
                    .ok_or_else(|| self.refuse(at, "a format naming a value it does not have"))?
            } else if let Some(value) = named(argument) {
                value
            } else {
                vec![Located {
                    token: Token::Ident(argument.to_owned()),
                    line: self.body[at].line,
                }]
            };
            self.value(&value, at, used)?;
        }
        Ok(())
    }

    /// Whether a value formatted with `used` says only what may be shown.
    fn value(&self, tokens: &[Located], at: usize, used: Trait) -> Result<(), Refused> {
        let mut tokens = tokens;
        while punct(tokens.first(), '&')
            || punct(tokens.first(), '*')
            || ident(tokens.first()) == Some("mut")
        {
            tokens = &tokens[1..];
        }
        // A literal is this program's words.
        if let [one] = tokens {
            match &one.token {
                Token::Str(_) | Token::Char | Token::Number(_) => return Ok(()),
                Token::Ident(word) if word == "true" || word == "false" => return Ok(()),
                _ => {}
            }
        }
        // A `Shown` by construction, or its text.
        if let Some(end) = self.shown(tokens, at) {
            let rest = &tokens[end..];
            if rest.is_empty()
                || matches!(rest, [dot, method, open, close] if punct(Some(dot), '.') && matches!(ident(Some(method)), Some("as_str" | "into_string")) && punct(Some(open), '(') && punct(Some(close), ')'))
            {
                return Ok(());
            }
            return Err(self.refuse(at, "a value this reading does not read"));
        }
        if used == Trait::Text {
            return Err(self.refuse(at, "text that is neither this program's words nor a Shown"));
        }
        // A place, measured or mapped by what this reading knows.
        let place_end = place_end(tokens);
        let place = self
            .place_type(&tokens[..place_end], at)
            .map_err(|why| self.refuse(at, why))?;
        let tail = &tokens[place_end..];
        if tail.is_empty() {
            return self
                .formats(&place, used)
                .map_err(|why| self.refuse(at, why));
        }
        let Some(method) = ident(tail.get(1)) else {
            return Err(self.refuse(at, "an expression this reading does not read"));
        };
        let head = self.head(&place).unwrap_or_default();
        let after = closing(tail, 2).map_or(tail.len(), |close| close + 1);
        if MEASURES.contains(&method)
            && after == tail.len()
            && (MEASURED.contains(&head.as_str()) || head == "prim::slice")
        {
            return Ok(());
        }
        let mut remainder = tail;
        if matches!(method, "as_ref" | "as_deref") && head == "std::option::Option" {
            remainder = &tail[after..];
        }
        let optional = head == "std::option::Option";
        match (optional, ident(remainder.get(1))) {
            (true, Some(mapping @ ("map" | "map_or"))) => {
                let parts = arguments(remainder, 2).unwrap_or_default();
                let end = closing(remainder, 2).map_or(remainder.len(), |close| close + 1);
                if end != remainder.len() {
                    return Err(self.refuse(at, "an expression this reading does not read"));
                }
                let (fallback, function) = match (mapping, parts.as_slice()) {
                    ("map", [function]) => (None, function),
                    ("map_or", [fallback, function]) => (Some(fallback), function),
                    _ => return Err(self.refuse(at, "a mapping this reading does not read")),
                };
                if let Some(fallback) = fallback
                    && !matches!(
                        fallback.as_slice(),
                        [Located {
                            token: Token::Str(_) | Token::Number(_),
                            ..
                        }]
                    )
                {
                    return Err(self.refuse(at, "a fallback that is not this program's words"));
                }
                if self.mapping_says_nothing(function, at) {
                    return Ok(());
                }
                Err(self.refuse(at, "a mapping this reading does not read"))
            }
            (true, Some("unwrap_or")) => {
                let parts = arguments(remainder, 2).unwrap_or_default();
                let end = closing(remainder, 2).map_or(remainder.len(), |close| close + 1);
                if end != remainder.len()
                    || !matches!(parts.as_slice(), [one] if matches!(one.as_slice(), [Located { token: Token::Str(_) | Token::Number(_), .. }]))
                {
                    return Err(self.refuse(at, "a fallback this reading does not read"));
                }
                let inner = self
                    .option_argument(&place)
                    .ok_or_else(|| self.refuse(at, "an option this reading cannot place"))?;
                self.formats(&inner, used)
                    .map_err(|why| self.refuse(at, why))
            }
            _ => Err(self.refuse(
                at,
                format!("the method `{method}`, which this reading does not read"),
            )),
        }
    }

    /// Whether a function mapped over an option returns only what may be shown: a length, a
    /// `Shown`, or a literal whatever it is given.
    fn mapping_says_nothing(&self, function: &[Located], at: usize) -> bool {
        if let [bar, underscore, bar_again, literal] = function
            && punct(Some(bar), '|')
            && ident(Some(underscore)) == Some("_")
            && punct(Some(bar_again), '|')
            && matches!(literal.token, Token::Str(_) | Token::Number(_))
        {
            return true;
        }
        let (segments, after) = written_path(function);
        let after = past_turbofish(function, after);
        if after != function.len() || segments.len() < 2 {
            return false;
        }
        let (name, owner) = segments.split_last().unwrap_or((&segments[0], &[]));
        if name == "len" {
            let owner = self
                .debugs
                .resolve(&self.hand.written, owner)
                .unwrap_or_default();
            return MEASURED.contains(&owner.as_str());
        }
        self.returns_shown(&segments, at)
    }

    /// Whether the function `segments` names is one this reading knows returns a `Shown`.
    fn returns_shown(&self, segments: &[String], _at: usize) -> bool {
        let Some((name, owner)) = segments.split_last() else {
            return false;
        };
        if owner.is_empty() {
            return false;
        }
        let owner = self
            .debugs
            .resolve(&self.hand.written, owner)
            .unwrap_or_default();
        owner == SHOWN
            || self
                .debugs
                .shown_functions
                .contains(&format!("{owner}::{name}"))
    }

    /// Where a `Shown` built by construction ends in `tokens`, when they start with one.
    fn shown(&self, tokens: &[Located], at: usize) -> Option<usize> {
        let (segments, after) = written_path(tokens);
        let after = past_turbofish(tokens, after);
        if segments.last().map(String::as_str) == Some("shown") && punct(tokens.get(after), '!') {
            return closing(tokens, after + 1).map(|close| close + 1);
        }
        if punct(tokens.get(after), '(') && self.returns_shown(&segments, at) {
            return closing(tokens, after).map(|close| close + 1);
        }
        None
    }

    /// The type an option of type `written` holds.
    fn option_argument(&self, written: &Written) -> Option<Written> {
        let tokens = strip_references(&written.tokens);
        let (_, after) = written_path(&tokens);
        let close = angle_close(&tokens, after)?;
        Some(Written {
            tokens: tokens[after + 1..close].to_vec(),
            ..written.clone()
        })
    }

    /// Whether a value of type `written`, formatted with `used`, says only what may be shown.
    fn formats(&self, written: &Written, used: Trait) -> Result<(), Why> {
        match used {
            Trait::Debug => match self.debugs.carries(written, self.carrying) {
                None => Ok(()),
                Some(why) => Err(why),
            },
            Trait::Display => {
                if matches!(written.tokens.as_slice(), [and, lifetime, word] if punct(Some(and), '&') && matches!(&lifetime.token, Token::Lifetime(name) if name == "'static") && ident(Some(word)) == Some("str"))
                {
                    return Ok(());
                }
                let head = self.head(written).unwrap_or_default();
                let number = head
                    .strip_prefix("prim::")
                    .is_some_and(|primitive| NUMBERS.contains(&primitive));
                let ours = head.starts_with("kr_client::") || head.starts_with("kr_cli::");
                if number
                    || head == SHOWN
                    || self.debugs.plain.contains(&head)
                    || (ours && self.debugs.find(&self.debugs.declared, &head).is_some())
                {
                    Ok(())
                } else {
                    Err(format!(
                        "the Display of {}",
                        if head.is_empty() {
                            "a type this reading cannot place"
                        } else {
                            &head
                        }
                    ))
                }
            }
            Trait::Number | Trait::Text => {
                let head = self.head(written).unwrap_or_default();
                if head
                    .strip_prefix("prim::")
                    .is_some_and(|primitive| NUMBERS.contains(&primitive))
                {
                    Ok(())
                } else {
                    Err(format!("{head} formatted as a number"))
                }
            }
        }
    }
}

/// The index past a path's generic arguments, when a turbofish gives them: `f::<T>`, where the
/// path's reading may already have taken the `::`.
fn past_turbofish(tokens: &[Located], after: usize) -> usize {
    let open = if punct(tokens.get(after), '<') {
        after
    } else if punct(tokens.get(after), ':') && punct(tokens.get(after + 2), '<') {
        after + 2
    } else {
        return after;
    };
    angle_close(tokens, open).map_or(tokens.len(), |close| close + 1)
}

/// The index past the place at the start of `tokens`: a name and the fields after it, up to a
/// method call.
fn place_end(tokens: &[Located]) -> usize {
    let mut at = 1;
    while punct(tokens.get(at), '.')
        && matches!(
            tokens.get(at + 1).map(|located| &located.token),
            Some(Token::Ident(_) | Token::Number(_))
        )
        && !punct(tokens.get(at + 2), '(')
    {
        at += 2;
    }
    at.min(tokens.len())
}

/// The one name a pattern binds when it is only a name, with any `ref` or `mut`.
fn single_binding(pattern: &[Located]) -> Option<String> {
    let words: Vec<&Located> = pattern
        .iter()
        .filter(|located| !matches!(ident(Some(located)), Some("ref" | "mut")))
        .collect();
    match words.as_slice() {
        [one] => match &one.token {
            Token::Ident(word)
                if word
                    .chars()
                    .next()
                    .is_some_and(|first| first.is_lowercase() || first == '_')
                    && word != "_"
                    && word != "self" =>
            {
                Some(word.clone())
            }
            _ => None,
        },
        _ => None,
    }
}

/// How deep in groups `to` is, counted from `from`.
fn depth_between(tokens: &[Located], from: usize, to: usize) -> i64 {
    let mut depth = 0;
    for located in &tokens[from..to.min(tokens.len())] {
        match located.token {
            Token::Punct('{' | '(' | '[') => depth += 1,
            Token::Punct('}' | ')' | ']') => depth -= 1,
            _ => {}
        }
    }
    depth
}

/// The closing brace of the block that `at` is in.
fn enclosing_close(tokens: &[Located], at: usize) -> usize {
    let mut depth = 0_i64;
    for (index, located) in tokens.iter().enumerate().skip(at) {
        match located.token {
            Token::Punct('{' | '(' | '[') => depth += 1,
            Token::Punct('}' | ')' | ']') => {
                depth -= 1;
                if depth < 0 {
                    return index;
                }
            }
            _ => {}
        }
    }
    tokens.len().saturating_sub(1)
}

/* -------------------------------------------------------------------------------------------- */
/* The rule over the two crates, and its controls                                                */
/* -------------------------------------------------------------------------------------------- */

impl Debugs {
    /// Records what the two files that define what may be shown declare, and which of their
    /// functions are declared to return a `Shown`.
    fn read_shown_files(&mut self) {
        let mut types = Vec::new();
        let mut functions = Vec::new();
        for index in 0..self.guarded {
            let source = &self.sources[index];
            if !SHOWN_FILES.contains(&source.name.as_str()) {
                continue;
            }
            let tokens = &source.tokens;
            for at in 0..tokens.len() {
                let scope = source.scope_at(at);
                match ident(tokens.get(at)) {
                    Some("struct" | "enum" | "union") => {
                        if let Some(name) = ident(tokens.get(at + 1)) {
                            types.push(self.normal(&source.defined_path(scope, name)));
                        }
                    }
                    Some("fn") if scope == 0 => {
                        let Some(name) = ident(tokens.get(at + 1)) else {
                            continue;
                        };
                        let Some(open) =
                            (at..tokens.len()).find(|&open| punct(tokens.get(open), '('))
                        else {
                            continue;
                        };
                        let Some(close) = closing(tokens, open) else {
                            continue;
                        };
                        if punct(tokens.get(close + 1), '-') && punct(tokens.get(close + 2), '>') {
                            let end = (close + 3..tokens.len())
                                .find(|&end| {
                                    punct(tokens.get(end), '{')
                                        || ident(tokens.get(end)) == Some("where")
                                })
                                .unwrap_or(tokens.len());
                            let written = Written {
                                source: index,
                                scope,
                                generics: Vec::new(),
                                tokens: tokens[close + 3..end].to_vec(),
                            };
                            let (segments, after) = written_path(&written.tokens);
                            if after == written.tokens.len()
                                && self.resolve(&written, &segments).as_deref() == Some(SHOWN)
                            {
                                let module = source.module_of(scope).join("::");
                                functions.push(format!("{module}::{name}"));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        self.shown_types.extend(types);
        self.shown_functions.extend(functions);
    }
}

/// Every place in the two crates where a `Debug` can print text that arrived.
fn debug_findings(workspace: &Path, guarded: Vec<Source>) -> Vec<Finding> {
    let mut debugs = Debugs::read(workspace, guarded);
    debugs.read_shown_files();
    debugs.findings()
}

/// Every `Debug` in the two crates says only what may be shown.
#[test]
fn no_debug_in_either_crate_prints_text_that_arrived() {
    let findings = debug_findings(&workspace(), both_crates());
    let listed = findings
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        findings.is_empty(),
        "{} places have a Debug that can print text that arrived:\n{listed}",
        findings.len()
    );
}

/// What the `Debug` rule finds in one control file of a command-line crate, beside the claims and
/// the failures every control can use, with `other` as a crate of the workspace it does not hold.
fn debug_findings_in(label: &str, text: &str, other: &str) -> Vec<Finding> {
    let scratch = Scratch::files(
        label,
        &[
            ("crates/kr-cli/Cargo.toml", "[package]\nname = \"kr-cli\"\n"),
            (
                "crates/kr-cli/src/lib.rs",
                "mod control;\nmod error;\nmod shown;\n",
            ),
            ("crates/kr-cli/src/shown.rs", SHOWN_CONTROL),
            ("crates/kr-cli/src/error.rs", ERRORS_CONTROL),
            ("crates/kr-cli/src/control.rs", text),
            (
                "crates/kr-other/Cargo.toml",
                "[package]\nname = \"kr-other\"\n",
            ),
            ("crates/kr-other/src/lib.rs", other),
        ],
    );
    let guarded = crate_sources(
        &scratch.workspace,
        &scratch.workspace.join("crates/kr-cli/src/lib.rs"),
        "kr_cli",
    )
    .expect("the control is readable");
    debug_findings(&scratch.workspace, guarded)
        .into_iter()
        .filter(|finding| finding.file.ends_with("control.rs"))
        .collect()
}

/// The crate every control can name beside its own: a type that holds text, one that does not,
/// and the types a macro declares.
const OTHER_CONTROL: &str = "pub struct Held(pub String);\n\
                             #[derive(Debug)]\npub struct Counted(pub u64);\n\
                             #[derive(Debug)]\npub struct Wrapping(pub Held);\n\
                             macro_rules! opaque {\n    ($name:ident) => {\n        #[derive(Debug)]\n        pub struct $name(String);\n    };\n}\n\
                             opaque!(Opaque);\n\
                             macro_rules! counter {\n    ($name:ident) => {\n        #[derive(Debug)]\n        pub struct $name(u64);\n    };\n}\n\
                             counter!(Revision);\n\
                             impl std::fmt::Debug for Held {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_tuple(\"Held\").field(&self.0).finish()\n    }\n}\n";

/// Each way a `Debug` can print text that arrived is found, at its line, in a source that has
/// nothing else.
#[test]
fn each_debug_that_can_print_text_is_named_with_its_place() {
    let cases: &[(&str, &str, usize, &str)] = &[
        (
            "a derived Debug over text",
            "#[derive(Debug)]\npub struct Planted {\n    pub id: u64,\n    pub text: String,\n}\n",
            1,
            "a derived Debug over text that arrived: the field `text`: std::string::String",
        ),
        (
            "a Debug written by hand that formats text",
            "pub struct Planted {\n    pub text: String,\n}\nimpl std::fmt::Debug for Planted {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_struct(\"Planted\").field(\"text\", &self.text).finish()\n    }\n}\n",
            6,
            "a Debug written by hand that formats std::string::String",
        ),
        (
            "text through another type",
            "pub struct Inner {\n    pub text: String,\n}\n#[derive(Debug)]\npub struct Planted {\n    pub inner: Inner,\n}\nimpl std::fmt::Debug for Inner {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        write!(formatter, \"Inner({:?})\", self.text)\n    }\n}\n",
            4,
            "which carries",
        ),
        (
            "bytes",
            "#[derive(Debug)]\npub struct Planted(pub [u8; 32]);\n",
            1,
            "bytes",
        ),
        (
            "text in a generic argument",
            "#[derive(Debug)]\npub struct Planted {\n    pub names: std::collections::BTreeMap<u64, Vec<String>>,\n}\n",
            1,
            "std::string::String",
        ),
        (
            "a channel that prints its value",
            "#[derive(Debug)]\npub struct Planted {\n    pub latest: tokio::sync::watch::Sender<String>,\n}\n",
            1,
            "std::string::String",
        ),
        (
            "a type from outside the workspace this reading does not list",
            "#[derive(Debug)]\npub struct Planted {\n    pub unknown: somewhere::Unlisted,\n}\n",
            1,
            "does not list",
        ),
        (
            "another crate's type whose Debug is written by hand over text",
            "#[derive(Debug)]\npub struct Planted {\n    pub held: kr_other::Held,\n}\n",
            1,
            "kr_other::Held, which carries",
        ),
        (
            "another crate's type that holds one",
            "#[derive(Debug)]\npub struct Planted {\n    pub held: kr_other::Wrapping,\n}\n",
            1,
            "kr_other::Wrapping, which carries",
        ),
        (
            "a type another crate's macro declares over text",
            "#[derive(Debug)]\npub struct Planted {\n    pub id: kr_other::Opaque,\n}\n",
            1,
            "kr_other::Opaque, which carries",
        ),
        (
            "a character",
            "#[derive(Debug)]\npub enum Planted {\n    Typed(char),\n}\n",
            1,
            "the field `0` of `Typed`: char",
        ),
        (
            "a method this reading does not read",
            "pub struct Planted {\n    pub text: String,\n}\nimpl std::fmt::Debug for Planted {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.write_str(&self.text.clone())\n    }\n}\n",
            6,
            "neither this program's words nor a Shown",
        ),
        (
            "a fallback over text",
            "pub struct Planted {\n    pub text: Option<String>,\n}\nimpl std::fmt::Debug for Planted {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_tuple(\"Planted\").field(&self.text.as_deref().unwrap_or(\"none\")).finish()\n    }\n}\n",
            6,
            "formats std::string::String",
        ),
        (
            "a length that is not the standard library's",
            "pub struct Name(String);\nimpl Name {\n    pub fn len(&self) -> &str { &self.0 }\n}\npub struct Planted {\n    pub name: Name,\n}\nimpl std::fmt::Debug for Planted {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_struct(\"Planted\").field(\"name\", &self.name.len()).finish()\n    }\n}\n",
            10,
            "the method `len`",
        ),
        (
            "a Display of a value that is not Plain",
            "pub struct Planted {\n    pub text: String,\n}\nimpl std::fmt::Debug for Planted {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        write!(formatter, \"Planted({})\", self.text)\n    }\n}\n",
            6,
            "the Display of std::string::String",
        ),
        (
            "a binding a match gives from text",
            "pub enum Planted {\n    Said(String),\n    Counted(u64),\n}\nimpl std::fmt::Debug for Planted {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        match self {\n            Self::Said(text) => formatter.debug_tuple(\"Said\").field(text).finish(),\n            Self::Counted(count) => formatter.debug_tuple(\"Counted\").field(count).finish(),\n        }\n    }\n}\n",
            8,
            "std::string::String",
        ),
        (
            "a formatter passed on",
            "pub struct Planted {\n    pub text: String,\n}\nimpl std::fmt::Debug for Planted {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        std::fmt::Display::fmt(&self.text, formatter)\n    }\n}\n",
            6,
            "the Display of std::string::String",
        ),
        (
            "a name that is not the program's words",
            "pub struct Planted {\n    pub name: &'static str,\n}\nimpl std::fmt::Debug for Planted {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter.debug_struct(self.name).finish()\n    }\n}\n",
            6,
            "a name that is not this program's words",
        ),
    ];
    for (position, (class, text, line, what)) in cases.iter().enumerate() {
        let findings = debug_findings_in(&format!("debug-case-{position}"), text, OTHER_CONTROL);
        assert!(
            findings
                .iter()
                .any(|finding| finding.line == *line && finding.what.contains(what)),
            "{class}: expected a finding at line {line} saying {what:?}, found {findings:?}"
        );
    }
}

/// What the `Debug` rule allows is not found: the same shapes, written the way the rule asks.
#[test]
fn what_the_debug_rule_allows_is_not_named() {
    let text = "use kr_client::shown::Shown;\n\
                #[derive(Debug)]\n\
                pub struct Counts {\n    pub id: u64,\n    pub label: &'static str,\n    pub ids: Vec<kr_protocol::scalars::Uuid>,\n    pub when: std::time::Duration,\n    pub other: kr_other::Counted,\n    pub revision: kr_other::Revision,\n    pub shown: Shown,\n}\n\
                pub enum Said {\n    Text(String),\n    Count(u64),\n}\n\
                pub struct Held {\n    pub text: String,\n    pub maybe: Option<String>,\n    pub count: Option<u64>,\n    pub counts: Counts,\n    pub said: Said,\n}\n\
                impl std::fmt::Debug for Held {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        formatter\n            .debug_struct(\"Held\")\n            .field(\"text_bytes\", &self.text.len())\n            .field(\"maybe_bytes\", &self.maybe.as_ref().map(String::len))\n            .field(\"present\", &self.maybe.as_ref().map(|_| \"<present>\"))\n            .field(\"count\", &self.count.unwrap_or(0))\n            .field(\"counts\", &self.counts)\n            .field(\"said\", &self.said)\n            .field(\"words\", &Shown::said(\"words\"))\n            .field(\"composed\", &kr_client::shown!(\"{}\", 3_u64))\n            .finish_non_exhaustive()\n    }\n}\n\
                impl std::fmt::Debug for Said {\n    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n        match self {\n            Self::Text(text) => write!(formatter, \"Text({} bytes)\", text.len()),\n            Self::Count(count) => write!(formatter, \"Count({count})\"),\n        }\n    }\n}\n";
    let findings = debug_findings_in("debug-allowed", text, OTHER_CONTROL);
    assert!(findings.is_empty(), "{findings:?}");
}
