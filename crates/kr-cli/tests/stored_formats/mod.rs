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
//! A store whose document has levels (the configuration document) is locked a little differently.
//! A section of nullable fields that arrives with a level costs the level and no version, so the
//! store's digest covers everything except those sections, and the lock records the store's level,
//! the distance at which a name is taken for a misspelling, and a digest of each such section.
//! A section may be added at the same version when it has the shape that lets an older release
//! ignore it, its level is above the store's level before it and no higher than the store's level
//! now, and no locked section's digest, no level and no distance moves with the version standing
//! still.
//!
//! What it cannot see, and the documentation says so: a hand edit of the lock itself (the same
//! check against the lock on main sees that), a type that a store keeps and the table does not
//! declare, and the checks the code runs on what a section holds (`validate`, a hand-written
//! deserialiser), which no schema shows. A change to what a section accepts needs the version
//! raised even when its digest does not move.

#![allow(dead_code)]

pub mod table;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kr_protocol::hostinfo::configuration::{BASE_LEVEL, Levelled, NEAR_MISS, Release, VERSION};
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
    /// For a store whose document has levels, the level it is read at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<u64>,
    /// For a store whose document has levels, how many edits apart a name may be from one a
    /// release knows before that release takes it for a misspelling. It never goes down.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub near_miss: Option<u32>,
    /// For a store whose document has levels, the sections that arrived with a level.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<LockedMember>,
}

/// One section of a document that arrived with a level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockedMember {
    /// The section's name in the document.
    pub member: String,
    /// The level at which it arrived. It never changes.
    pub level: u64,
    /// The digest of the section's schema with every definition it reaches.
    pub digest: String,
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
    /// A command that takes the writers' lock and asks for the leave to write the record, named and
    /// versioned as the constant says, before it writes it: an update holds that lock across its
    /// check and its switch, and a record the release `current` names lists at another version is
    /// not written.
    Barred(&'static kr_ipc::install::Written),
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
    /// For a store whose document has levels, how it is read.
    pub levels: Option<Levels>,
}

/// How a store's document is read when it has levels.
pub struct Levels {
    /// The release whose level and table of sections the lock records for the store.
    pub release: Release,
    /// The schema of the whole document, with the sections that arrived with a level in it.
    pub document: Value,
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

/// A document schema without the sections that arrived with a level: what the store's version
/// stands for, and so what a raise of the level alone moves nothing of.
#[must_use]
pub fn at_base(schema: &Value, levelled: &[Levelled]) -> Value {
    let mut base = schema.clone();
    if let Some(properties) = base.get_mut("properties").and_then(Value::as_object_mut) {
        for entry in levelled {
            properties.remove(entry.member);
        }
    }
    if let Some(Value::Array(required)) = base.get_mut("required") {
        required.retain(|name| {
            !levelled
                .iter()
                .any(|entry| name.as_str() == Some(entry.member))
        });
    }
    base
}

/// The schema of a type the protocol generates one for, without the sections of `levelled`.
#[must_use]
pub fn protocol_at_base<T: JsonSchema>(name: &'static str, levelled: &[Levelled]) -> Kept {
    Kept::Protocol(
        name,
        at_base(&kr_protocol::schema::schema_for::<T>(), levelled),
    )
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
        levels: store.levels.as_ref().map(observe_levels),
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
    /// For a store whose document has levels, what the code says of them.
    pub levels: Option<ObservedLevels>,
}

/// What the code says of the levels of a store's document.
pub struct ObservedLevels {
    /// The level the document is read at.
    pub level: u64,
    /// How many edits apart a name may be from one a release knows before it is taken for a
    /// misspelling.
    pub near_miss: u32,
    /// The sections that arrived with a level, one for each entry of the release's table, in the
    /// table's order and with a duplicate as many times as it was declared.
    pub members: Vec<ObservedMember>,
    /// Every top-level property of the document.
    pub properties: Vec<Property>,
    /// What the real reader and writer say of the sections the table lists: the sections that are
    /// written when they are unused, and the ones that are not closed. Each is `(section, finding)`.
    pub eligibility: Vec<(String, String)>,
}

/// One section of the document that arrived with a level.
pub struct ObservedMember {
    /// The section's name in the document.
    pub member: String,
    /// The level at which it arrived.
    pub level: u64,
    /// The digest of its schema with every definition it reaches.
    pub digest: String,
}

/// One top-level property of the document.
pub struct Property {
    /// Its name.
    pub name: String,
    /// The level it arrived at, when it is a section of the release's table.
    pub level: Option<u64>,
    /// Its schema with every definition it reaches in place of the reference to it.
    pub schema: Value,
    /// Its own name and every name declared below it.
    pub names: std::collections::BTreeSet<String>,
    /// The references in it that the document's own definitions do not hold.
    pub unresolved: Vec<String>,
}

/// What the code says of the levels of a store's document, with the checks that need the real
/// reader and writer run: a section of the table is held to what `load_in` and `contents_in` do.
#[must_use]
pub fn observe_levels(levels: &Levels) -> ObservedLevels {
    let mut observed = levels_view(&levels.document, &levels.release);
    observed.eligibility = eligibility(&levels.release, &observed.properties);
    observed
}

/// What the code says of the levels of a document of this schema, from the schema and the
/// release's table alone.
#[must_use]
pub fn levels_view(document: &Value, release: &Release) -> ObservedLevels {
    let definitions = document.get("$defs").cloned().unwrap_or_else(|| json!({}));
    let names = kr_protocol::hostinfo::configuration::names_by_member_of(document);
    let properties: Vec<Property> = document
        .get("properties")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .map(|(name, schema)| {
            let mut unresolved = Vec::new();
            unresolved_references(
                schema,
                &definitions,
                &mut std::collections::BTreeSet::new(),
                &mut unresolved,
            );
            let mut root = schema.clone();
            if let Value::Object(members) = &mut root {
                members.insert("$defs".to_owned(), definitions.clone());
            }
            Property {
                name: name.clone(),
                level: release
                    .levelled
                    .iter()
                    .find(|entry| entry.member == name)
                    .map(|entry| entry.level),
                schema: normalise_schema(&root),
                names: names.get(name).cloned().unwrap_or_default(),
                unresolved,
            }
        })
        .collect();
    let members = release
        .levelled
        .iter()
        .map(|entry| ObservedMember {
            member: entry.member.to_owned(),
            level: entry.level,
            digest: properties
                .iter()
                .find(|property| property.name == entry.member)
                .map_or_else(String::new, |property| {
                    hex(&kr_cbor::sha256(canonical(&property.schema).as_bytes()))
                }),
        })
        .collect();
    ObservedLevels {
        level: release.level,
        near_miss: u32::try_from(NEAR_MISS).expect("a small number"),
        members,
        properties,
        eligibility: Vec::new(),
    }
}

/// Every reference in `schema`, and in each definition it reaches, that is not a reference to a
/// definition `definitions` holds. The normaliser drops one without a word, so it is found before
/// the schema is resolved.
fn unresolved_references(
    schema: &Value,
    definitions: &Value,
    seen: &mut std::collections::BTreeSet<String>,
    found: &mut Vec<String>,
) {
    match schema {
        Value::Object(members) => {
            for (key, member) in members {
                if key == "$ref" {
                    let Some(reference) = member.as_str() else {
                        continue;
                    };
                    match reference
                        .strip_prefix("#/$defs/")
                        .and_then(|name| definitions.get(name).map(|held| (name, held)))
                    {
                        Some((name, held)) => {
                            if seen.insert(name.to_owned()) {
                                unresolved_references(held, definitions, seen, found);
                            }
                        }
                        None => found.push(reference.to_owned()),
                    }
                } else {
                    unresolved_references(member, definitions, seen, found);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                unresolved_references(item, definitions, seen, found);
            }
        }
        _ => {}
    }
}

/// What the real reader and writer say of each section the release's table lists. A section that
/// names no property of the schema is the name rules' to refuse, not this.
///
/// An unused section must not be written, so that a document that holds none of the sections of a
/// level is one a release that reads less reads strictly; and a section must be closed, so that
/// the release that knows it keeps reading what is in it strictly.
fn eligibility(release: &Release, properties: &[Property]) -> Vec<(String, String)> {
    use kr_protocol::hostinfo::configuration::{DocumentState, contents_in, load_in};

    let mut found = Vec::new();
    for entry in release.levelled {
        let Some(property) = properties
            .iter()
            .find(|property| property.name == entry.member)
        else {
            continue;
        };
        let version = VERSION;
        let unused: serde_json::Map<String, Value> = property
            .schema
            .get("properties")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .map(|(field, _)| (field.clone(), Value::Null))
            .collect();
        for (what, document) in [
            ("absent", json!({ "version": version })),
            (
                "all null",
                json!({ "version": version, entry.member: unused }),
            ),
        ] {
            let loaded = load_in(Some(document.to_string().as_bytes()), release);
            let Some(read) = loaded
                .document
                .filter(|_| loaded.status.state == DocumentState::Loaded)
            else {
                found.push((
                    entry.member.to_owned(),
                    format!(
                        "a document with the section {what} is not read: {:?}",
                        loaded.status.state
                    ),
                ));
                continue;
            };
            let written: Value =
                serde_json::from_str(&contents_in(&read, release)).unwrap_or(Value::Null);
            if written.get(entry.member).is_some() {
                found.push((
                    entry.member.to_owned(),
                    format!(
                        "the section is written when it is {what}: its field on the document has no \
                         skip_serializing_if of the predicate for an unused section, so a release \
                         that reads less would find a member it does not know"
                    ),
                ));
            }
            if written.get("level").and_then(Value::as_u64) != Some(BASE_LEVEL) {
                found.push((
                    entry.member.to_owned(),
                    format!("a document with the section {what} is not written at the base level"),
                ));
            }
        }
        let probe = json!({
            "version": version,
            "level": entry.level,
            entry.member: { "unknown_field_the_section_does_not_declare": {} },
        });
        if load_in(Some(probe.to_string().as_bytes()), release)
            .status
            .state
            == DocumentState::Loaded
        {
            found.push((
                entry.member.to_owned(),
                "the section reads a field it does not declare: it is not closed".to_owned(),
            ));
        }
    }
    found
}

/// What is wrong with the design of the sections a release lists, whatever the lock holds: the
/// rules a new section must satisfy so that a release that does not know it can ignore it, and a
/// release that does can keep reading it strictly.
#[must_use]
pub fn design_findings(levels: &ObservedLevels) -> Vec<String> {
    let mut found = Vec::new();
    for (index, member) in levels.members.iter().enumerate() {
        let name = &member.member;
        if levels.members[..index]
            .iter()
            .any(|other| other.member == *name)
        {
            found.push(format!("the section {name} is declared more than once"));
        }
        let Some(property) = levels
            .properties
            .iter()
            .find(|property| property.name == *name)
        else {
            found.push(format!(
                "the section {name} names no property of the document: a misspelt name would count as a base member, which the writer never leaves out and the level never counts"
            ));
            continue;
        };
        if member.level <= BASE_LEVEL || member.level > levels.level {
            found.push(format!(
                "the section {name} arrives at level {}, which is not above the base level {BASE_LEVEL} and no higher than the level {} the document is read at",
                member.level, levels.level
            ));
        }
        let snake = name.len() >= 2
            && name.len() <= 64
            && name
                .chars()
                .next()
                .is_some_and(|first| first.is_ascii_lowercase())
            && name.chars().all(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
            });
        if !snake {
            found.push(format!(
                "the section {name} is not ASCII snake case, so a doctor could not always show it"
            ));
        }
        // Every other property and every name below one: a release that does not know this section
        // takes it for a misspelling of one of them when it is within the distance.
        let others: std::collections::BTreeSet<&str> = levels
            .properties
            .iter()
            .filter(|other| other.name != *name)
            .flat_map(|other| other.names.iter().map(String::as_str))
            .collect();
        for known in others {
            if kr_protocol::hostinfo::configuration::near_miss(name, known) {
                found.push(format!(
                    "the section {name} is within {NEAR_MISS} edits of the name {known}, so a release that does not know it would take it for a misspelling of that name"
                ));
            }
        }
        found.extend(shape_findings(name, property));
    }
    for (member, finding) in &levels.eligibility {
        found.push(format!("the section {member}: {finding}"));
    }
    found
}

/// The shape a section must have: an object that is not nullable, closed at every depth, whose
/// every immediate field is nullable with a null default, whose own default is none or all null,
/// and that refers to nothing outside the document's definitions.
fn shape_findings(name: &str, property: &Property) -> Vec<String> {
    let mut found = Vec::new();
    for reference in &property.unresolved {
        found.push(format!(
            "the section {name} refers to {reference}, which the document's definitions do not hold"
        ));
    }
    let schema = &property.schema;
    let is_object = schema.get("type").and_then(Value::as_str) == Some("object");
    let alternatives = ["anyOf", "oneOf", "allOf"]
        .iter()
        .any(|keyword| schema.get(keyword).is_some());
    if !is_object || alternatives {
        found.push(format!(
            "the section {name} is not an object that cannot be null: a nullable section is omitted when unused but read back as present, so the record differs from the file"
        ));
    }
    // The section itself declares its fields and refuses any other. A map is allowed as a field
    // inside it, never as the section, which would accept any key and read back differently from
    // the copy the registry keeps once it is unused.
    if schema
        .get("properties")
        .and_then(Value::as_object)
        .is_none()
        || schema.get("additionalProperties") != Some(&Value::Bool(false))
    {
        found.push(format!(
            "the section {name} does not declare its fields and refuse every other: it has to be an object with properties and additionalProperties false, and a map may only be a field inside it"
        ));
    }
    open_objects(name, schema, &mut found);
    let nullable = |field: &Value| -> bool {
        let alternatives_null = |keyword: &str| {
            field
                .get(keyword)
                .and_then(Value::as_array)
                .is_some_and(|alternatives| {
                    alternatives.iter().any(|alternative| {
                        alternative.get("type").and_then(Value::as_str) == Some("null")
                    })
                })
        };
        alternatives_null("anyOf")
            || alternatives_null("oneOf")
            || field
                .get("type")
                .and_then(Value::as_array)
                .is_some_and(|types| types.iter().any(|kind| kind.as_str() == Some("null")))
            || field.get("type").and_then(Value::as_str) == Some("null")
    };
    for (field, schema) in schema
        .get("properties")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        if !nullable(schema) {
            found.push(format!(
                "the section {name} has a field, {field}, that cannot be null, so absent would not mean not used"
            ));
        }
        if schema.get("default") != Some(&Value::Null) {
            found.push(format!(
                "the section {name} has a field, {field}, whose default is not null"
            ));
        }
    }
    if let Some(default) = schema.get("default")
        && !default
            .as_object()
            .is_some_and(|members| members.values().all(Value::is_null))
    {
        found.push(format!(
            "the section {name} has a default that is not the all-null value"
        ));
    }
    found
}

/// Reports every object that declares properties and is not closed.
fn open_objects(name: &str, schema: &Value, found: &mut Vec<String>) {
    match schema {
        Value::Object(members) => {
            if members.contains_key("properties")
                && members.get("additionalProperties") != Some(&Value::Bool(false))
            {
                found.push(format!(
                    "the section {name} has an object that declares properties and is not closed (additionalProperties is not false)"
                ));
            }
            for member in members.values() {
                open_objects(name, member, found);
            }
        }
        Value::Array(items) => {
            for item in items {
                open_objects(name, item, found);
            }
        }
        _ => {}
    }
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
        if let Some(levels) = &now.levels {
            found.extend(
                design_findings(levels)
                    .into_iter()
                    .map(|finding| format!("the store {name}: {finding}")),
            );
        }
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
        found.extend(level_findings(name, now, locked));
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

/// What differs between the code and the lock about the levels of a store's document, and what is
/// wrong with the design of its sections whatever the lock holds.
fn level_findings(name: &str, now: &Observed, locked: &Locked) -> Vec<String> {
    let mut found = Vec::new();
    let Some(levels) = &now.levels else {
        if locked.level.is_some() || locked.near_miss.is_some() || !locked.members.is_empty() {
            found.push(format!(
                "the lock records levels for the store {name} and the code does not: the levels of a store are kept, and the lock is not written without them"
            ));
        }
        return found;
    };
    if locked.level != Some(levels.level) {
        found.push(format!(
            "the store {name} is read at level {} in the code and {} in the lock: write the lock",
            levels.level,
            locked
                .level
                .map_or_else(|| "none".to_owned(), |level| level.to_string())
        ));
    }
    if locked.near_miss != Some(levels.near_miss) {
        found.push(format!(
            "the store {name} takes a name within {} edits of a known name for a misspelling in the code and {} in the lock: write the lock",
            levels.near_miss,
            locked
                .near_miss
                .map_or_else(|| "none".to_owned(), |distance| distance.to_string())
        ));
    }
    let same_version = now.entry.version == locked.entry.version;
    for member in &levels.members {
        let Some(kept) = locked
            .members
            .iter()
            .find(|kept| kept.member == member.member)
        else {
            found.push(format!(
                "the section {} of the store {name} is in the code and not in the lock: write the lock",
                member.member
            ));
            continue;
        };
        if kept.level != member.level {
            found.push(format!(
                "the section {} of the store {name} arrives at level {} in the code and {} in the lock: a section's level never changes",
                member.member, member.level, kept.level
            ));
        } else if kept.digest != member.digest {
            found.push(if same_version {
                format!(
                    "the section {} of the store {name} has changed and its version is still {}: raise the version, then write the lock",
                    member.member, now.entry.version
                )
            } else {
                format!(
                    "the section {} of the store {name} differs from the lock's: write the lock",
                    member.member
                )
            });
        }
    }
    for kept in &locked.members {
        if !levels
            .members
            .iter()
            .any(|member| member.member == kept.member)
        {
            found.push(format!(
                "the lock lists the section {} of the store {name} and the code does not",
                kept.member
            ));
        }
    }
    found
}

/// The lock that brings the committed one up to the code, or why it cannot be.
///
/// A digest that moved while its version stood still, a version that went down, and a store moved
/// to another place are refused: the lock is not brought up to the code past a version that was
/// not raised. A section that arrives with a level is held to its design whatever the lock holds,
/// and to its level against the lock's.
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
    for now in observed {
        if let Some(levels) = &now.levels {
            refused.extend(
                design_findings(levels)
                    .into_iter()
                    .map(|finding| format!("the store {}: {finding}", now.entry.store)),
            );
        }
    }
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
            match &now.levels {
                Some(levels) => refused.extend(level_refusals(name, now, levels, locked)),
                None if locked.level.is_some()
                    || locked.near_miss.is_some()
                    || !locked.members.is_empty() =>
                {
                    refused.push(format!(
                        "the levels of the store {name} would leave the lock: a store that has levels keeps them, and its level, its distance and its sections are not removed by a change that does not state them"
                    ));
                }
                None => {}
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
            level: now.levels.as_ref().map(|levels| levels.level),
            near_miss: now.levels.as_ref().map(|levels| levels.near_miss),
            members: now.levels.as_ref().map_or_else(Vec::new, |levels| {
                levels
                    .members
                    .iter()
                    .map(|member| LockedMember {
                        member: member.member.clone(),
                        level: member.level,
                        digest: member.digest.clone(),
                    })
                    .collect()
            }),
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

/// Why the levels of a store's document cannot be brought up to the lock's: a level or a distance
/// that goes down, a section whose level changes, a section dropped or changed with the version
/// standing still, and a new section whose level is not above the store's level before it and no
/// higher than the store's level now.
///
/// A raise of the version may change or drop a section: what a version stands for is anything the
/// raise says. It never lowers the level or the distance, because a release that reads the new
/// version is at or above the level of every document it reads.
fn level_refusals(
    name: &str,
    now: &Observed,
    levels: &ObservedLevels,
    locked: &Locked,
) -> Vec<String> {
    let mut refused = Vec::new();
    if let Some(level) = locked.level
        && levels.level < level
    {
        refused.push(format!(
            "the level of the store {name} would go down, from {level} to {}",
            levels.level
        ));
    }
    if let Some(distance) = locked.near_miss
        && levels.near_miss < distance
    {
        refused.push(format!(
            "the distance at which a name is taken for a misspelling in the store {name} would go down, from {distance} to {}: a release in the field keeps the distance it shipped with",
            levels.near_miss
        ));
    }
    let raised = now.entry.version > locked.entry.version;
    for kept in &locked.members {
        match levels.members.iter().find(|member| member.member == kept.member) {
            None if !raised => refused.push(format!(
                "the section {} of the store {name} would leave it with the version standing still: raise the version first",
                kept.member
            )),
            Some(member) if member.level != kept.level => refused.push(format!(
                "the level of the section {} of the store {name} would change from {} to {}",
                kept.member, kept.level, member.level
            )),
            Some(member) if member.digest != kept.digest && !raised => refused.push(format!(
                "the section {} of the store {name} has changed and its version is still {}: raise it first",
                kept.member, now.entry.version
            )),
            _ => {}
        }
    }
    let before = locked.level.unwrap_or(BASE_LEVEL);
    for member in &levels.members {
        if !locked
            .members
            .iter()
            .any(|kept| kept.member == member.member)
            && (member.level <= before || member.level > levels.level)
        {
            refused.push(format!(
                "the new section {} of the store {name} arrives at level {}, which has to be above the level {before} the store was at and no higher than the level {} it is now",
                member.member, member.level, levels.level
            ));
        }
    }
    refused
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

#[cfg(test)]
mod levels_tests;
