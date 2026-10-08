//! The stored formats the host keeps, and the lock that records them.
//!
//! Every store under the state root (each SQLite database and each JSON record) has a format
//! version that covers its tables and every value it keeps, recorded in the store and raised by the
//! release that changes any of them. `stored-formats.lock`, at the root of the repository, maps
//! each store to that version and to a digest of what the version stands for:
//!
//! * the store's DDL, as the files a real control daemon wrote hold it;
//! * the schema of each type it keeps, where the protocol generates one, and otherwise the
//!   definition of the type as the source writes it, with comments and spacing left out;
//! * the words it keeps by hand (the names a text column is matched against);
//! * the names under the state root that it owns.
//!
//! The check fails when the version the code writes, or the digest of what the code keeps, is not
//! the lock's, and says which: a digest that moved while the version stood still is a change nobody
//! gave a version to. The lock is written by [`write`], which refuses that same change, a lowered
//! version, and a store moved to another place, so the lock cannot be brought up to the code
//! without the version having been raised first.
//!
//! The lock also names every other thing the host keeps under the state root with the reason it
//! has no version, so that a reference run can tell a file nothing names from one something does.
//!
//! What it cannot see, and the documentation says so: a hand edit of the lock itself (the same
//! check against the lock on main sees that), and a type that a store keeps and the table does not
//! declare.

#![allow(dead_code)]

pub mod table;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kr_protocol::update::{Recording, ReleaseStore, StoreScope};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// The lock's path in the repository.
#[must_use]
pub fn lock_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../stored-formats.lock")
}

/// The repository's root.
fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/* -------------------------------------------------------------------------------------------- */
/* The lock                                                                                     */
/* -------------------------------------------------------------------------------------------- */

/// What `stored-formats.lock` holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lock {
    /// The lock's own format.
    pub format: u32,
    /// Every store, by name.
    pub stores: Vec<Locked>,
    /// Everything else under the state root that is named, with the reason it has no version.
    pub named: Vec<LockedName>,
}

/// One store in the lock: what a release's manifest lists for it, the digest of what its version
/// stands for, and the names of the types it keeps.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Locked {
    /// The manifest entry.
    pub entry: ReleaseStore,
    /// The digest, in hexadecimal.
    pub digest: String,
    /// The labels of what it keeps, for the person who reads the lock.
    pub kept: Vec<String>,
}

/// One named thing under the state root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedName {
    /// Where its path starts.
    pub scope: StoreScope,
    /// Its name or pattern.
    pub path: String,
    /// Why it has no version.
    pub reason: String,
    /// For a directory, the names it may hold.
    pub children: Vec<String>,
    /// Whether a directory's content is left alone.
    pub opaque: bool,
    /// Whether SQLite databases that are not stores are kept in it.
    pub databases: bool,
}

impl LockedName {
    /// What the code says of `name`, as the lock holds it.
    fn of(name: &Named) -> Self {
        Self {
            scope: name.scope,
            path: name.name.to_owned(),
            reason: name.reason.to_owned(),
            children: name
                .children
                .iter()
                .map(|child| (*child).to_owned())
                .collect(),
            opaque: name.opaque,
            databases: name.databases,
        }
    }
}

impl Lock {
    /// Reads the committed lock.
    ///
    /// # Panics
    ///
    /// Panics when the file is not there or is not a lock.
    #[must_use]
    pub fn committed() -> Self {
        let bytes = std::fs::read(lock_path()).expect("stored-formats.lock is in the repository");
        serde_json::from_slice(&bytes).expect("stored-formats.lock is a lock")
    }

    /// The lock as the file holds it: sorted, indented, one newline at the end.
    #[must_use]
    pub fn text(&self) -> String {
        let mut text = serde_json::to_string_pretty(self).expect("a lock encodes");
        text.push('\n');
        text
    }

    /// The manifest entries a release built from this tree lists.
    #[must_use]
    pub fn release_stores(&self) -> Vec<ReleaseStore> {
        self.stores
            .iter()
            .map(|locked| locked.entry.clone())
            .collect()
    }
}

/* -------------------------------------------------------------------------------------------- */
/* The table                                                                                    */
/* -------------------------------------------------------------------------------------------- */

/// Who writes a store, which decides whether a switch can find it at a version no release in the
/// range reads.
///
/// Required of every store, so that adding one forces the decision. It cannot see a writer a later
/// change adds to a store already listed; a review of the change has to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Writers {
    /// Only an environment's control daemon, or a program that holds the environment's singleton
    /// lock, which an update holds across its check of the stores and its switch.
    Daemon,
    /// Only a program that holds the update lock.
    Update,
    /// A command, or another program, that takes a lock of its own and neither of those: nothing
    /// holds it off between an update's check and its switch.
    Commands,
}

/// A store as the code declares it.
pub struct Store {
    /// Who writes it.
    pub writers: Writers,
    /// What a release lists for it, from the versions the store's crate writes.
    pub entry: ReleaseStore,
    /// The other names the store owns in its scope.
    pub owned: Vec<Claim>,
    /// What it keeps.
    pub kept: Vec<Kept>,
}

/// A name a store owns beside its own file.
#[derive(Clone, Copy)]
pub struct Claim {
    /// The name, in the store's scope.
    pub name: &'static str,
    /// For a directory, the names (or `*`-patterns) it may hold directly; empty for a file.
    pub children: &'static [&'static str],
}

/// A name under the state root that no store owns.
#[derive(Clone, Copy)]
pub struct Named {
    /// Where its path starts.
    pub scope: StoreScope,
    /// Its name or pattern.
    pub name: &'static str,
    /// For a directory, the names it may hold directly; empty when it is a file or when its
    /// content is not looked at.
    pub children: &'static [&'static str],
    /// Whether a directory's content is left alone, however deep.
    pub opaque: bool,
    /// Whether SQLite databases are kept in it that are not stores of the host's own.
    pub databases: bool,
    /// Why it has no version.
    pub reason: &'static str,
}

/// What a store keeps that its tables do not describe.
pub enum Kept {
    /// A type the protocol generates a schema for.
    Protocol(&'static str, Value),
    /// Types of the source, by the file they are in (relative to the repository) and their names.
    Source(&'static str, &'static [&'static str]),
    /// Words the code matches stored text against by hand.
    Words(&'static str, Vec<String>),
}

impl Kept {
    /// What the lock says of it.
    pub fn label(&self) -> String {
        match self {
            Self::Protocol(name, _) => (*name).to_owned(),
            Self::Source(file, items) => format!("{} ({file})", items.join(", ")),
            Self::Words(name, _) => format!("words of {name}"),
        }
    }
}

/// The schema of a type the protocol generates one for.
#[must_use]
pub fn protocol<T: JsonSchema>(name: &'static str) -> Kept {
    Kept::Protocol(name, kr_protocol::schema::schema_for::<T>())
}

/* -------------------------------------------------------------------------------------------- */
/* The digest                                                                                   */
/* -------------------------------------------------------------------------------------------- */

/// The digest of what a store's version stands for. `ddl` is what the files a real daemon wrote
/// hold, normalised.
///
/// # Errors
///
/// Returns what stops a kept type being read from the source.
pub fn digest(store: &Store, ddl: &[String]) -> Result<String, String> {
    let mut kept = BTreeMap::new();
    for item in &store.kept {
        let value = match item {
            Kept::Protocol(_, schema) => normalise_schema(schema),
            Kept::Source(file, items) => {
                let mut definitions = Vec::new();
                for name in *items {
                    definitions.push(definition(file, name)?);
                }
                json!(definitions)
            }
            Kept::Words(_, words) => json!(words),
        };
        kept.insert(item.label(), value);
    }
    let mut owned: Vec<String> = vec![store.entry.path.clone()];
    owned.extend(
        store
            .owned
            .iter()
            .map(|claim| format!("{}: {}", claim.name, claim.children.join(", "))),
    );
    owned.sort();
    let basis = json!({ "ddl": ddl, "kept": kept, "owned": owned });
    let bytes = canonical(&basis).into_bytes();
    Ok(hex(&kr_cbor::sha256(&bytes)))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A value as text with every object's members in order of their names.
fn canonical(value: &Value) -> String {
    match value {
        Value::Object(members) => {
            let mut keys: Vec<&String> = members.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .into_iter()
                .map(|key| format!("{}:{}", json!(key), canonical(&members[key])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(canonical).collect();
            format!("[{}]", parts.join(","))
        }
        other => other.to_string(),
    }
}

/// The keywords of a schema that describe it to a reader and say nothing of what it accepts.
const SCHEMA_PROSE: [&str; 6] = [
    "description",
    "title",
    "examples",
    "$comment",
    "$schema",
    "$id",
];

/// A schema with its prose left out and every reference to a definition replaced by the
/// definition, so that neither a doc comment nor the name of a type moves the digest, and a
/// property called `description` stays what it is.
#[must_use]
pub fn normalise_schema(root: &Value) -> Value {
    let definitions = root.get("$defs").cloned().unwrap_or_else(|| json!({}));
    let mut open = Vec::new();
    inline(root, &definitions, &mut open, false)
}

fn inline(value: &Value, definitions: &Value, open: &mut Vec<String>, named: bool) -> Value {
    match value {
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| inline(item, definitions, open, false))
                .collect(),
        ),
        Value::Object(members) if named => {
            // The members are names, each of a schema: none is a keyword.
            Value::Object(
                members
                    .iter()
                    .map(|(name, schema)| (name.clone(), inline(schema, definitions, open, false)))
                    .collect(),
            )
        }
        Value::Object(members) => {
            let mut out = serde_json::Map::new();
            if let Some(Value::String(reference)) = members.get("$ref")
                && let Some(name) = reference.strip_prefix("#/$defs/")
            {
                if open.iter().any(|open| open == name) {
                    out.insert("$recursive".to_owned(), json!(open.len()));
                } else if let Some(definition) = definitions.get(name) {
                    open.push(name.to_owned());
                    if let Value::Object(inlined) = inline(definition, definitions, open, false) {
                        out.extend(inlined);
                    }
                    open.pop();
                }
            }
            for (key, member) in members {
                if key == "$ref" || key == "$defs" || SCHEMA_PROSE.contains(&key.as_str()) {
                    continue;
                }
                let names = matches!(
                    key.as_str(),
                    "properties" | "patternProperties" | "dependentSchemas"
                );
                out.insert(key.clone(), inline(member, definitions, open, names));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// SQL as the digest reads it: comments gone, runs of white space one space, and no space beside
/// a comma or inside a bracket, with everything inside a quotation left as it is.
#[must_use]
pub fn normalise_sql(sql: &str) -> String {
    let characters: Vec<char> = sql.chars().collect();
    let mut out = String::new();
    let mut pending_space = false;
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index];
        let next = characters.get(index + 1).copied();
        if character == '-' && next == Some('-') {
            while index < characters.len() && characters[index] != '\n' {
                index += 1;
            }
            pending_space = true;
            continue;
        }
        if character == '/' && next == Some('*') {
            index += 2;
            while index + 1 < characters.len()
                && !(characters[index] == '*' && characters[index + 1] == '/')
            {
                index += 1;
            }
            index += 2;
            pending_space = true;
            continue;
        }
        if character.is_whitespace() {
            pending_space = true;
            index += 1;
            continue;
        }
        if pending_space
            && !out.is_empty()
            && !matches!(character, ',' | ')')
            && !out.ends_with(['(', ','])
        {
            out.push(' ');
        }
        pending_space = false;
        if matches!(character, '\'' | '"' | '`') {
            out.push(character);
            index += 1;
            while index < characters.len() {
                out.push(characters[index]);
                if characters[index] == character {
                    if characters.get(index + 1) == Some(&character) {
                        index += 1;
                        out.push(characters[index]);
                    } else {
                        break;
                    }
                }
                index += 1;
            }
            index += 1;
            continue;
        }
        out.push(character);
        index += 1;
    }
    out
}

/// A type definition as the source writes it, with its attributes, and without comments or spacing.
fn definition(file: &str, name: &str) -> Result<String, String> {
    let path = repository().join(file);
    let text = std::fs::read_to_string(&path).map_err(|error| format!("{file}: {error}"))?;
    let bare = strip_comments(&text);
    for keyword in ["struct", "enum"] {
        let needle = format!("{keyword} {name}");
        let mut from = 0;
        while let Some(found) = bare[from..].find(&needle) {
            let start = from + found;
            let after = bare[start + needle.len()..].chars().next();
            let before = bare[..start].chars().next_back();
            from = start + needle.len();
            if after.is_some_and(|c| c.is_alphanumeric() || c == '_')
                || before.is_some_and(|c| c.is_alphanumeric() || c == '_')
            {
                continue;
            }
            // Its attributes: the lines above that begin an attribute.
            let line_start = bare[..start].rfind('\n').map_or(0, |at| at + 1);
            let mut begin = line_start;
            loop {
                let above_end = begin.saturating_sub(1);
                let above_start = bare[..above_end].rfind('\n').map_or(0, |at| at + 1);
                if begin == 0 || !bare[above_start..above_end].trim_start().starts_with("#[") {
                    break;
                }
                begin = above_start;
            }
            // Its body: to the closing brace of the first brace, or to the `;` that comes first.
            let rest = &bare[start..];
            let brace = rest.find('{');
            let semicolon = rest.find(';');
            let end = match (brace, semicolon) {
                (Some(open), Some(stop)) if stop < open => stop + 1,
                (None, Some(stop)) => stop + 1,
                (Some(open), _) => {
                    let mut depth = 0_i32;
                    let mut at = open;
                    let mut closed = None;
                    let mut quoted = false;
                    let bytes = rest.as_bytes();
                    while at < bytes.len() {
                        match bytes[at] {
                            b'\\' if quoted => at += 1,
                            b'"' => quoted = !quoted,
                            b'{' if !quoted => depth += 1,
                            b'}' if !quoted => {
                                depth -= 1;
                                if depth == 0 {
                                    closed = Some(at + 1);
                                    break;
                                }
                            }
                            _ => {}
                        }
                        at += 1;
                    }
                    closed.ok_or_else(|| format!("{file}: {name} is not closed"))?
                }
                (None, None) => return Err(format!("{file}: {name} has no body")),
            };
            let text = format!("{}{}", &bare[begin..start], &rest[..end]);
            return Ok(text.split_whitespace().collect::<Vec<_>>().join(" "));
        }
    }
    Err(format!("{file}: no struct or enum named {name}"))
}

/// Source with its comments left out, and its lines as they were.
fn strip_comments(text: &str) -> String {
    let characters: Vec<char> = text.chars().collect();
    let mut out = String::new();
    let mut index = 0;
    let mut quoted = false;
    while index < characters.len() {
        let character = characters[index];
        if quoted {
            out.push(character);
            if character == '\\' {
                index += 1;
                if let Some(escaped) = characters.get(index) {
                    out.push(*escaped);
                }
            } else if character == '"' {
                quoted = false;
            }
            index += 1;
            continue;
        }
        if character == '"' {
            quoted = true;
            out.push(character);
            index += 1;
            continue;
        }
        if character == '/' && characters.get(index + 1) == Some(&'/') {
            while index < characters.len() && characters[index] != '\n' {
                index += 1;
            }
            continue;
        }
        if character == '/' && characters.get(index + 1) == Some(&'*') {
            index += 2;
            while index + 1 < characters.len()
                && !(characters[index] == '*' && characters[index + 1] == '/')
            {
                index += 1;
            }
            index += 2;
            continue;
        }
        out.push(character);
        index += 1;
    }
    out
}

/* -------------------------------------------------------------------------------------------- */
/* Comparing the code with the lock                                                             */
/* -------------------------------------------------------------------------------------------- */

/// What the code says of a store, to be compared with the lock, given the definitions of its
/// database as the files a real daemon kept hold them (none, for a record).
///
/// # Errors
///
/// Returns what stops a kept type being read from the source.
pub fn observe(store: &Store, ddl: &[String]) -> Result<Observed, String> {
    Ok(Observed {
        entry: store.entry.clone(),
        digest: digest(store, ddl)?,
        kept: store.kept.iter().map(Kept::label).collect(),
    })
}

/// What the code says of a store, to be compared with the lock.
pub struct Observed {
    /// What a release would list for it.
    pub entry: ReleaseStore,
    /// The digest of what it stands for.
    pub digest: String,
    /// The labels of what it keeps.
    pub kept: Vec<String>,
}

/// What differs between the code and the lock, in words that say what to do.
#[must_use]
pub fn findings(lock: &Lock, observed: &[Observed], named: &[Named]) -> Vec<String> {
    let mut found = Vec::new();
    for name in named {
        let kept = lock
            .named
            .iter()
            .find(|locked| locked.scope == name.scope && locked.path == name.name);
        match kept {
            None => found.push(format!(
                "{} under the {} is named in the code and not in stored-formats.lock: write the lock",
                name.name,
                scope_name(name.scope)
            )),
            Some(locked) if *locked != LockedName::of(name) => found.push(format!(
                "what the code says of {} under the {}, which has no version, differs from the lock's: write the lock",
                name.name,
                scope_name(name.scope)
            )),
            Some(_) => {}
        }
    }
    for locked in &lock.named {
        if !named
            .iter()
            .any(|name| name.scope == locked.scope && name.name == locked.path)
        {
            found.push(format!(
                "the lock names {} under the {} and the code does not",
                locked.path,
                scope_name(locked.scope)
            ));
        }
    }
    for now in observed {
        let name = &now.entry.store;
        let Some(locked) = lock
            .stores
            .iter()
            .find(|locked| locked.entry.store == *name)
        else {
            found.push(format!(
                "the store {name} is not in stored-formats.lock: write the lock once its version is right"
            ));
            continue;
        };
        if locked.entry.scope != now.entry.scope
            || locked.entry.path != now.entry.path
            || locked.entry.recording != now.entry.recording
        {
            found.push(format!(
                "the store {name} is kept somewhere else than the lock says: a store that moves is a new store, and the old file stays at a version no earlier release reads"
            ));
        }
        let (code, locked_version) = (now.entry.version, locked.entry.version);
        if code != locked_version {
            found.push(format!(
                "the store {name} is at version {code} in the code and {locked_version} in the lock: write the lock"
            ));
        } else if now.entry.migrates_from != locked.entry.migrates_from {
            found.push(format!(
                "the store {name} migrates from version {} in the code and {} in the lock: write the lock",
                now.entry.migrates_from, locked.entry.migrates_from
            ));
        } else if now.digest != locked.digest {
            found.push(format!(
                "what the store {name} keeps has changed and its version is still {code}: raise the version, with the step that brings an earlier store forward, then write the lock"
            ));
        }
    }
    for locked in &lock.stores {
        if !observed
            .iter()
            .any(|now| now.entry.store == locked.entry.store)
        {
            found.push(format!(
                "the lock lists the store {} and the code does not declare it",
                locked.entry.store
            ));
        }
    }
    found
}

/// The lock that brings the committed one up to the code, or why it cannot be.
///
/// A digest that moved while its version stood still, a version that went down, and a store moved
/// to another place are refused: the lock is not brought up to the code past a version that was
/// not raised.
///
/// # Errors
///
/// Returns every reason the lock cannot be written.
pub fn write(
    committed: Option<&Lock>,
    observed: &[Observed],
    named: &[Named],
) -> Result<Lock, Vec<String>> {
    let mut refused = Vec::new();
    if let Some(committed) = committed {
        for locked in &committed.stores {
            if !observed
                .iter()
                .any(|now| now.entry.store == locked.entry.store)
            {
                refused.push(format!(
                    "the store {} would leave the lock: a store the code stops declaring is removed from the lock by hand, in a change that shows it",
                    locked.entry.store
                ));
            }
        }
        for now in observed {
            let Some(locked) = committed
                .stores
                .iter()
                .find(|locked| locked.entry.store == now.entry.store)
            else {
                continue;
            };
            let name = &now.entry.store;
            if locked.entry.scope != now.entry.scope
                || locked.entry.path != now.entry.path
                || locked.entry.recording != now.entry.recording
            {
                refused.push(format!(
                    "the store {name} would be kept somewhere else: list a new store instead"
                ));
            }
            if now.entry.version < locked.entry.version {
                refused.push(format!("the version of the store {name} would go down"));
            }
            if now.entry.version == locked.entry.version && now.digest != locked.digest {
                refused.push(format!(
                    "what the store {name} keeps has changed and its version is still {}: raise it first",
                    now.entry.version
                ));
            }
        }
    }
    if !refused.is_empty() {
        return Err(refused);
    }
    let mut stores: Vec<Locked> = observed
        .iter()
        .map(|now| Locked {
            entry: now.entry.clone(),
            digest: now.digest.clone(),
            kept: now.kept.clone(),
        })
        .collect();
    stores.sort_by(|left, right| left.entry.store.cmp(&right.entry.store));
    let mut names: Vec<LockedName> = named.iter().map(LockedName::of).collect();
    names.sort_by(|left, right| {
        (scope_name(left.scope), &left.path).cmp(&(scope_name(right.scope), &right.path))
    });
    Ok(Lock {
        format: 1,
        stores,
        named: names,
    })
}

fn scope_name(scope: StoreScope) -> &'static str {
    match scope {
        StoreScope::Install => "install",
        StoreScope::StateRoot => "state_root",
        StoreScope::Environment => "environment",
        StoreScope::Configuration => "configuration",
        StoreScope::Unknown => "unknown",
    }
}

/* -------------------------------------------------------------------------------------------- */
/* Coverage                                                                                     */
/* -------------------------------------------------------------------------------------------- */

/// What a name under a scope is claimed as.
struct Covers {
    /// The patterns of the names it may hold directly, when it is a directory looked into.
    children: Vec<&'static str>,
    /// Whether its content is left alone.
    opaque: bool,
    /// Whether it may hold SQLite databases of its own.
    databases: bool,
    /// Whether it is a store's file (its log, journal and shared-memory files go with it).
    sqlite: bool,
}

/// Every claim in a scope, by the first part of its path.
fn claims_in(scope: StoreScope, table: &[Store], named: &[Named]) -> Vec<(String, Covers)> {
    let mut claims: Vec<(String, Covers)> = Vec::new();
    let mut claim =
        |name: String, children: Vec<&'static str>, opaque: bool, databases: bool, sqlite: bool| {
            if let Some((_, existing)) = claims.iter_mut().find(|(known, _)| *known == name) {
                existing.children.extend(children);
                existing.opaque |= opaque;
                existing.databases |= databases;
                existing.sqlite |= sqlite;
            } else {
                claims.push((
                    name,
                    Covers {
                        children,
                        opaque,
                        databases,
                        sqlite,
                    },
                ));
            }
        };
    // The configuration document is in an environment's state directory unless the environment keeps
    // it elsewhere, so a run that finds one there finds a name that is claimed.
    let in_scope = |store: &Store| {
        store.entry.scope == scope
            || (scope == StoreScope::Environment && store.entry.scope == StoreScope::Configuration)
    };
    for store in table.iter().filter(|store| in_scope(store)) {
        let parts: Vec<&str> = store.entry.path.split('/').collect();
        let sqlite = matches!(
            store.entry.recording,
            Recording::SqliteTable { .. } | Recording::SqliteUserVersion
        );
        if parts.len() == 1 {
            claim(parts[0].to_owned(), Vec::new(), false, false, sqlite);
        } else {
            // The first part is the directory, and the rest what it holds: a name or a pattern,
            // or a path down to one.
            let leaked: &'static str = Box::leak(parts[1..].join("/").into_boxed_str());
            claim(parts[0].to_owned(), vec![leaked], false, false, false);
        }
        for owned in &store.owned {
            claim(
                owned.name.to_owned(),
                owned.children.to_vec(),
                false,
                false,
                false,
            );
        }
    }
    for name in named.iter().filter(|name| name.scope == scope) {
        claim(
            name.name.to_owned(),
            name.children.to_vec(),
            name.opaque,
            name.databases,
            false,
        );
    }
    claims
}

fn matches(pattern: &str, name: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == name,
        Some((before, after)) => {
            name.len() >= before.len() + after.len()
                && name.starts_with(before)
                && name.ends_with(after)
        }
    }
}

fn is_sidecar_of(name: &str, file: &str) -> bool {
    ["-wal", "-shm", "-journal"]
        .iter()
        .any(|suffix| name == format!("{file}{suffix}"))
}

/// Looks for the name in the claims: the claim and whether the name is a sidecar of a store's file.
fn find<'a>(claims: &'a [(String, Covers)], name: &str) -> Option<&'a Covers> {
    claims
        .iter()
        .find(|(known, covers)| {
            matches(known, name) || (covers.sqlite && is_sidecar_of(name, known))
        })
        .map(|(_, covers)| covers)
}

/// Every file or directory under a state root that nothing names, as a path relative to the root.
///
/// A name is unnamed when no store and no named entry claims it, when it is inside a directory
/// whose children are listed and is not among them, and when it is a SQLite database that is not a
/// store's file.
#[must_use]
pub fn unnamed(state_root: &Path, table: &[Store], named: &[Named]) -> Vec<String> {
    let mut found = Vec::new();
    let root_claims = claims_in(StoreScope::StateRoot, table, named);
    let environment_claims = claims_in(StoreScope::Environment, table, named);
    let mut stores_files: Vec<String> = Vec::new();
    let Ok(children) = std::fs::read_dir(state_root) else {
        return vec!["the state root cannot be read".to_owned()];
    };
    let mut visit = |directory: &Path, prefix: &str, claims: &[(String, Covers)]| {
        let Ok(children) = std::fs::read_dir(directory) else {
            return;
        };
        for child in children.flatten() {
            let name = child.file_name().to_string_lossy().into_owned();
            let relative = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let Some(covers) = find(claims, &name) else {
                found.push(relative);
                continue;
            };
            let is_directory = child.file_type().is_ok_and(|kind| kind.is_dir());
            if is_directory && !covers.opaque && !covers.children.is_empty() {
                unlisted(&child.path(), &relative, &covers.children, &mut found);
            }
        }
    };
    visit(state_root, "", &root_claims);
    for child in children.flatten() {
        let name = child.file_name().to_string_lossy().into_owned();
        if name == "environments" && child.file_type().is_ok_and(|kind| kind.is_dir()) {
            let Ok(environments) = std::fs::read_dir(child.path()) else {
                continue;
            };
            for environment in environments.flatten() {
                let prefix = format!("environments/{}", environment.file_name().to_string_lossy());
                visit(&environment.path(), &prefix, &environment_claims);
            }
        }
    }
    // A database that is not a store's file, anywhere in the tree.
    let mut pending = vec![(state_root.to_path_buf(), String::new())];
    while let Some((directory, prefix)) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let relative = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                pending.push((entry.path(), relative));
            } else if kind.is_file() && has_sqlite_header(&entry.path()) {
                stores_files.push(relative);
            }
        }
    }
    for database in stores_files {
        if !database_is_named(&database, table, named) {
            found.push(database);
        }
    }
    found.sort();
    found.dedup();
    found
}

/// Every entry of `directory` that none of `patterns` lists, as a path under `relative`. A pattern
/// is a name, or a path down to one: its first part lists a directory, and the rest what that holds.
fn unlisted(directory: &Path, relative: &str, patterns: &[&str], found: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let here = format!("{relative}/{name}");
        let mut listed = false;
        let mut deeper: Vec<&str> = Vec::new();
        for pattern in patterns {
            match pattern.split_once('/') {
                None => {
                    listed |= matches(pattern, &name)
                        || (!pattern.contains('*') && is_sidecar_of(&name, pattern));
                }
                Some((first, rest)) if matches(first, &name) => {
                    listed = true;
                    deeper.push(rest);
                }
                Some(_) => {}
            }
        }
        if !listed {
            found.push(here);
        } else if !deeper.is_empty() && entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            unlisted(&entry.path(), &here, &deeper, found);
        }
    }
}

fn has_sqlite_header(path: &Path) -> bool {
    use std::io::Read as _;

    let mut header = [0_u8; 16];
    std::fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut header))
        .is_ok()
        && &header == b"SQLite format 3\0"
}

/// Whether a database at `relative` (under the state root) is a store's file, or is in a directory
/// that is named as holding databases.
fn database_is_named(relative: &str, table: &[Store], named: &[Named]) -> bool {
    let parts: Vec<&str> = relative.split('/').collect();
    // `environments/<prefix>/...` is an environment's; anything else is the state root's.
    let (scope, inner) = if parts.first() == Some(&"environments") && parts.len() > 2 {
        (StoreScope::Environment, parts[2..].join("/"))
    } else {
        (StoreScope::StateRoot, relative.to_owned())
    };
    if table
        .iter()
        .any(|store| store.entry.scope == scope && store.entry.path == inner)
    {
        return true;
    }
    let first = inner.split('/').next().unwrap_or_default();
    named
        .iter()
        .any(|name| name.scope == scope && name.databases && matches(name.name, first))
}

/* -------------------------------------------------------------------------------------------- */
/* Reading the database definitions the files hold                                              */
/* -------------------------------------------------------------------------------------------- */

/// The definitions in a SQLite file, normalised and in order: kind, name, table and SQL.
///
/// # Errors
///
/// Returns what stops the file being read.
pub fn ddl_of(path: &Path) -> Result<Vec<String>, String> {
    let connection = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| format!("{}: {error}", path.display()))?;
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, sql FROM sqlite_master
              WHERE sql IS NOT NULL ORDER BY type, name",
        )
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([], |row| {
            Ok(format!(
                "{} {} {} {}",
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                normalise_sql(&row.get::<_, String>(3)?)
            ))
        })
        .map_err(|error| error.to_string())?;
    rows.collect::<Result<_, _>>()
        .map_err(|error| error.to_string())
}
