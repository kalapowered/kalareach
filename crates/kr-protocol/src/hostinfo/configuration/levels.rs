//! Configuration levels: how a release reads, and keeps intact, a document that holds sections it
//! does not know.
//!
//! A new section of nullable fields, where an absent section means the section is not used, costs
//! one level and no version. A release reads a document at or below its own level strictly, as it
//! always has. A document above its level has its unknown top-level members ignored and counted,
//! the members the release knows stay strict at every depth, and the release refuses to edit it,
//! so a whole-document rewrite never drops a member this release cannot see. A writer stamps the
//! highest level among the sections the document holds, so an older release can still read and
//! edit a document that holds nothing newer.
//!
//! Anything that narrows what a host may do is not a level: it stays in the ceilings and raises the
//! version.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use serde::Serialize;
use serde_json::Value;

use super::ConfigurationDocument;
use crate::hostinfo::export::{ContentClass, Sentence};

/// The level every document has unless it states a higher one.
pub const BASE_LEVEL: u64 = 1;

/// The highest level this build reads.
pub const LEVEL: u64 = 5;

/// How many edits apart a member of a document above the reader's level may be from a name this
/// build knows before it is taken for a misspelling of that name rather than a member of a newer
/// release.
///
/// A release in the field keeps the distance it shipped with, so this never goes down: a lock that
/// compared new member names at a smaller distance would admit a name that the release in the
/// field takes for a typo.
pub const NEAR_MISS: usize = 2;

/// The longest name of an ignored member that is kept for the report.
const NAME_BYTES: usize = 64;

/// How many ignored names are kept for the report.
const NAMES_KEPT: usize = 16;

/// A top-level section of the document that arrived with a level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Levelled {
    /// The member's name in the document.
    pub member: &'static str,
    /// The level at which the section arrived.
    pub level: u64,
}

/// The sections that arrived with a level.
///
/// A section is added here, with a typed field on the document, in the change that adds it, and
/// that change raises [`LEVEL`] to the section's level.
///
/// A section has one form, which the stored-format lock checks as far as a schema and a probe
/// can show:
///
/// - a struct with derived `Serialize`, `Deserialize` and `JsonSchema`, and no `flatten`,
///   `serialize_with`, `deserialize_with`, `with` or schema override, that is
///   `#[serde(deny_unknown_fields, default)]` and has only `Nullable` fields, so that absent and
///   all null are the same and mean the section is not used, and every type it holds, at any
///   depth, derives `Deserialize` and `JsonSchema` with `deny_unknown_fields` and none of those
///   attributes (a map is the one open form, and only as a field);
/// - on the document, `#[serde(default, skip_serializing_if = "is_unused")]`, and never an
///   `Option`, so that an unused section is not written and a release that reads less reads the
///   document strictly;
/// - a written statement of what a release that does not know it does without it, a test of that
///   downgrade, and a round trip of an active value through the file and the registry's copy.
///
/// A section may not restrict, redirect or reinterpret anything an older release already does:
/// what narrows a host stays in the ceilings and raises the version. A change to what a section
/// accepts, including checks the code runs that its schema does not show, raises the version.
pub const LEVELLED: &[Levelled] = &[
    Levelled {
        member: "authority",
        level: 2,
    },
    Levelled {
        member: "mailbox",
        level: 3,
    },
    Levelled {
        member: "relay",
        level: 4,
    },
    Levelled {
        member: "automation",
        level: 5,
    },
];

/// What a release reads and writes: its level and the sections that arrived with one.
///
/// The reader, the editor and the serializer take a release so that a test can stand an older or a
/// newer one in for this build; production always passes [`THIS_RELEASE`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Release {
    /// The highest level the release reads and writes.
    pub level: u64,
    /// The sections that arrived with a level, with the level of each.
    pub levelled: &'static [Levelled],
}

/// This build.
pub const THIS_RELEASE: Release = Release {
    level: LEVEL,
    levelled: LEVELLED,
};

/// The default of the document's `level` member: the base level, not this build's level, so that
/// the schema's default does not move when the level rises.
#[must_use]
pub const fn base_level() -> u64 {
    BASE_LEVEL
}

/// Whether a section's JSON form is unused: null, or an object whose every immediate member is
/// null. An empty list, map or object in a field is not null, because it can mean something.
#[must_use]
fn unused_value(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Object(members) => members.values().all(Value::is_null),
        _ => false,
    }
}

/// Whether a section is unused. It is the predicate that omits an unused section from the written
/// document and the one that decides whether a section is held, so what is written is held and
/// gets its level, whatever the section serialises to.
#[must_use]
pub fn is_unused<T: Serialize>(section: &T) -> bool {
    serde_json::to_value(section).is_ok_and(|value| unused_value(&value))
}

/// The level of a document for a release: the highest level among the sections of the release's
/// table that the document holds, and never below the base level.
#[must_use]
pub fn level_of(document: &ConfigurationDocument, release: &Release) -> u64 {
    if release.levelled.is_empty() {
        return BASE_LEVEL;
    }
    let Ok(json) = serde_json::to_value(document) else {
        return BASE_LEVEL;
    };
    release
        .levelled
        .iter()
        .filter(|entry| {
            json.get(entry.member)
                .is_some_and(|section| !unused_value(section))
        })
        .map(|entry| entry.level)
        .fold(BASE_LEVEL, u64::max)
}

// -------------------------------------------------------------------------------------------
// The names this build knows
// -------------------------------------------------------------------------------------------

/// The declared property names of the document's schema, by top-level member: each member's own
/// name and every name reachable from it through references, array items, map values and nullable
/// alternatives. Map keys are the owner's and are never names.
fn names_by_member() -> &'static BTreeMap<String, BTreeSet<String>> {
    static NAMES: OnceLock<BTreeMap<String, BTreeSet<String>>> = OnceLock::new();
    NAMES.get_or_init(|| names_by_member_of(&crate::schema::schema_for::<ConfigurationDocument>()))
}

/// The declared property names of a document schema, by top-level member: each member's own name
/// and every name reachable from it through references, array items, map values and nullable
/// alternatives. Map keys are the owner's and are never names.
///
/// This is the one computation of the names a release knows. The reader keeps its sections apart
/// from a misspelling of them by it, and the stored-format lock refuses a new section whose name a
/// release in the field would take for a misspelling, by the same function over the same schema.
#[must_use]
pub fn names_by_member_of(schema: &Value) -> BTreeMap<String, BTreeSet<String>> {
    let definitions = schema.get("$defs").cloned().unwrap_or(Value::Null);
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    properties
        .iter()
        .map(|(member, property)| {
            let mut names = BTreeSet::from([member.clone()]);
            let mut open = BTreeSet::new();
            collect_names(property, &definitions, &mut open, &mut names);
            (member.clone(), names)
        })
        .collect()
}

/// Adds to `names` every property name declared by `schema` or by a schema it reaches.
fn collect_names(
    schema: &Value,
    definitions: &Value,
    open: &mut BTreeSet<String>,
    names: &mut BTreeSet<String>,
) {
    let Value::Object(keywords) = schema else {
        return;
    };
    if let Some(reference) = keywords.get("$ref").and_then(Value::as_str)
        && let Some(name) = reference.strip_prefix("#/$defs/")
        && let Some(definition) = definitions.get(name)
        && open.insert(name.to_owned())
    {
        collect_names(definition, definitions, open, names);
    }
    if let Some(properties) = keywords.get("properties").and_then(Value::as_object) {
        for (name, property) in properties {
            names.insert(name.clone());
            collect_names(property, definitions, open, names);
        }
    }
    for keyword in ["items", "additionalProperties"] {
        if let Some(inner) = keywords.get(keyword) {
            collect_names(inner, definitions, open, names);
        }
    }
    for keyword in ["anyOf", "allOf", "oneOf"] {
        if let Some(Value::Array(alternatives)) = keywords.get(keyword) {
            for alternative in alternatives {
                collect_names(alternative, definitions, open, names);
            }
        }
    }
}

/// The names the release reads: every top-level member and every name reachable from one, except
/// the members its table lists above its level and the names reachable only from those.
fn known_names(release: &Release) -> BTreeSet<&'static str> {
    names_by_member()
        .iter()
        .filter(|(member, _)| !above(release, member))
        .flat_map(|(_, names)| names.iter().map(String::as_str))
        .collect()
}

/// Whether the release's table lists `member` at a level above the release's own.
fn above(release: &Release, member: &str) -> bool {
    release
        .levelled
        .iter()
        .any(|entry| entry.member == member && entry.level > release.level)
}

/// Whether `value` is the name of a property the document's schema declares, at any depth. These
/// are this build's own words, which is why a sentence may print one.
#[must_use]
pub fn is_schema_name(value: &str) -> bool {
    names_by_member()
        .values()
        .any(|names| names.contains(value))
}

/// A name with the differences that carry no meaning folded away: ASCII case, `_` and `-`.
#[must_use]
fn folded(name: &str) -> Vec<char> {
    name.chars()
        .filter(|character| !matches!(character, '_' | '-'))
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

/// The number of single-character edits between two folded names.
#[must_use]
fn distance(a: &[char], b: &[char]) -> usize {
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    for (row, left) in a.iter().enumerate() {
        let mut current = vec![row + 1];
        for (column, right) in b.iter().enumerate() {
            let substitution = previous[column] + usize::from(left != right);
            current.push(
                substitution
                    .min(previous[column + 1] + 1)
                    .min(current[column] + 1),
            );
        }
        previous = current;
    }
    previous[b.len()]
}

/// Whether two names are within [`NEAR_MISS`] edits of each other once the differences that carry
/// no meaning are folded away.
#[must_use]
pub fn near_miss(a: &str, b: &str) -> bool {
    distance(&folded(a), &folded(b)) <= NEAR_MISS
}

/// The name among `known` that `candidate` is within [`NEAR_MISS`] edits of, if any.
fn resembles<'a>(candidate: &str, known: &BTreeSet<&'a str>) -> Option<&'a str> {
    let folded_candidate = folded(candidate);
    known
        .iter()
        .copied()
        .find(|name| distance(&folded_candidate, &folded(name)) <= NEAR_MISS)
}

// -------------------------------------------------------------------------------------------
// Reading
// -------------------------------------------------------------------------------------------

/// What a document above the reader's level held that the reader did not read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Newer {
    /// The level the document declares.
    pub declared: u64,
    /// How many members were left out.
    pub count: u64,
    /// The names of some of them, at most sixteen: each at most 64 bytes of ASCII graphic
    /// characters, so that a terminal prints one as it is. A name that is longer, or has any
    /// other character, is counted and not kept.
    pub names: Vec<String>,
}

/// The level a document declares: absent is the base level, and anything but a whole number of at
/// least the base level is a problem. A `level` member in a document of a version before levels is
/// a problem too, as any member that version does not declare is.
///
/// # Errors
///
/// Returns the sentence that says what is wrong.
pub fn declared_level(value: &Value, version: u64) -> Result<u64, Sentence> {
    let Some(stated) = value.get("level") else {
        return Ok(BASE_LEVEL);
    };
    if version < super::VERSION {
        return Err(Sentence::new()
            .stated("version ")
            .number(version)
            .stated(" declares no level member"));
    }
    match stated.as_u64() {
        Some(level) if level >= BASE_LEVEL => Ok(level),
        _ => Err(Sentence::new()
            .stated("the level has to be a whole number of at least ")
            .number(BASE_LEVEL)),
    }
}

/// For a document at or below the reader's level: a member the release's table lists above its
/// level is refused whenever it is present, held or not, as a release that predates it refuses it.
///
/// # Errors
///
/// Returns the sentence that says which level the member needs.
pub fn refuse_listed(value: &Value, release: &Release) -> Result<(), Sentence> {
    for entry in release.levelled {
        if entry.level > release.level && value.get(entry.member).is_some() {
            return Err(Sentence::new()
                .stated("a member of level ")
                .number(entry.level)
                .stated(" is present and this build reads level ")
                .number(release.level));
        }
    }
    Ok(())
}

/// For a document above the reader's level: removes every top-level member the release does not
/// read, and reports them.
///
/// A removed member within [`NEAR_MISS`] edits of a name the release reads is a misspelling or a
/// misplaced field, not a member of a newer release, and the document is refused rather than
/// read with the owner's restriction silently gone.
///
/// # Errors
///
/// Returns the sentence that names the known name a removed member resembles.
pub fn drop_unknown(
    mut value: Value,
    declared: u64,
    release: &Release,
) -> Result<(Value, Newer), Sentence> {
    let read: BTreeSet<&str> = names_by_member()
        .keys()
        .map(String::as_str)
        .filter(|member| !above(release, member))
        .collect();
    let Value::Object(members) = &mut value else {
        return Ok((
            value,
            Newer {
                declared,
                count: 0,
                names: Vec::new(),
            },
        ));
    };
    let removed: Vec<String> = members
        .keys()
        .filter(|name| !read.contains(name.as_str()))
        .cloned()
        .collect();
    let known = known_names(release);
    for name in &removed {
        if let Some(resembled) = resembles(name, &known) {
            return Err(Sentence::new()
                .stated("a member (")
                .withheld(ContentClass::Name, name)
                .stated(") resembles the name ")
                .term(resembled)
                .stated(" and is not a member this build can ignore; correct it"));
        }
    }
    let mut names = Vec::new();
    for name in &removed {
        members.remove(name);
        if names.len() < NAMES_KEPT
            && !name.is_empty()
            && name.len() <= NAME_BYTES
            && name.chars().all(|character| character.is_ascii_graphic())
        {
            names.push(name.clone());
        }
    }
    Ok((
        value,
        Newer {
            declared,
            count: removed.len() as u64,
            names,
        },
    ))
}

#[cfg(test)]
mod tests;
