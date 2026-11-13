//! The public contract: what a client of one release reads of a host of another.
//!
//! ```text
//! kr-protocol-gen --public-contract
//! ```
//!
//! The protocol package publishes every type of the schema, and a client built from one release of
//! it talks to a host of another across a level move: the public negotiation stays at major 1
//! while the package's minor number moves. So the commit being released is compared, over the whole
//! schema and with every definition a root, with the releases a client may have been built from,
//! and what an earlier reader could not read is reported:
//!
//! * a member that was added is not a difference where the earlier release's object carries the
//!   read-only metadata marker (`x-kalareach-read-only-metadata`), which makes its reader drop a
//!   member it does not know, and the member is optional;
//! * a definition that was added is not a difference;
//! * everything else is one: a member or a variant added to a closed object, a member, a variant
//!   or a definition removed, and anything that changed.
//!
//! The check of a level (`--in-level`) also lets one more member pass: a new section of the host
//! configuration document that an earlier release ignores and counts (`compare_for_a_level`).
//! This report does not, because a validator built from an earlier package rejects a document that
//! holds a section it lacks.
//!
//! For the plugin SDK's schema the check of a level lets one more kind of member pass, from its own
//! function (`compare_sdk_for_a_level`): an optional member that the SDK's arrival table lists,
//! in a release that raises the SDK's version. The report does not read the SDK's schema.
//!
//! Until public 1.0 freezes, which is the first client release (a host, command line, desktop or
//! mobile build published for people to install), the public contract may change with a level move,
//! and this reports and does not fail: the references are every release at the commit's level.
//! From the freeze, `crates/kr-protocol/retained/PUBLIC_FREEZE` names the release the freeze was
//! made at (`release=<tag>`), the references are that release and every release after it that
//! shares a public major that is not retired with the commit, and a difference fails.
//!
//! It fails closed in both states when it cannot read what it compares: origin's tags, a release's
//! schema, the record of the freeze.

use std::collections::BTreeSet;
use std::path::Path;

use kr_protocol::method::MethodName;
use kr_protocol::retained::{Difference, DifferenceKind, differences};
use serde_json::Value;

use crate::in_level::{Head, SCHEMA_PATH, cut_over};
use crate::releases::{
    Release, agree_with_origin, git_in, inventory, is_ancestor, package_version_at,
};
use crate::retained::expected_public_majors_in;

/// Where the freeze is recorded, from the root of the repository.
pub const FREEZE: &str = "crates/kr-protocol/retained/PUBLIC_FREEZE";

/// The keyword that makes an object's reader drop a member it does not know.
const READ_ONLY_METADATA: &str = "x-kalareach-read-only-metadata";

/// The definition of the host's configuration document, a stored file read by level.
const CONFIGURATION_DOCUMENT: &str = "ConfigurationDocument";

/// What the comparison found.
#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    /// The release the freeze was made at, once public 1.0 is frozen.
    pub frozen_at: Option<String>,
    /// The releases compared.
    pub references: Vec<String>,
    /// For each release with a difference, the tag and each difference.
    pub differences: Vec<(String, Vec<String>)>,
}

/// The keys of the object that the read-only marker is written for: the shape (`type`,
/// `properties`, `required`), the marker itself and the annotations the comparison ignores.
const METADATA_OBJECT_KEYS: [&str; 6] = [
    "type",
    "properties",
    "required",
    "description",
    "title",
    READ_ONLY_METADATA,
];

/// Whether the definition is an open object of its own `properties` and nothing else that composes
/// or closes it: `type` is `object`, there is no `additionalProperties`, and every key is from
/// [`METADATA_OBJECT_KEYS`]. Its reader drops a member it does not know, so a member added to its
/// `properties` is one that an earlier reader accepts, wherever the object is used as a property,
/// an item or an `anyOf` or `allOf` branch; where it is used under a `oneOf`, a `not` or an `if`,
/// the member narrows the object and so can widen the place, which [`accepted`] checks with
/// [`is_used_only_where_it_widens`]. A `$ref`, a nullable pair or a list of branches gives a label
/// of the same form from another list, and a closed object refuses the member.
fn is_a_metadata_object(schema: &Value, definition: &str) -> bool {
    let node = &schema["$defs"][definition];
    node.get("type").and_then(Value::as_str) == Some("object")
        && node.get("additionalProperties").is_none()
        && node.as_object().is_some_and(|members| {
            members
                .keys()
                .all(|key| METADATA_OBJECT_KEYS.contains(&key.as_str()))
        })
}

/// Whether `difference` is one an earlier reader accepts: a definition that is new, or an optional
/// member that a read-only metadata object of the earlier release did not have, where every use of
/// the object is one that a narrower object only narrows.
fn accepted(old: &Value, new: &Value, difference: &Difference) -> bool {
    if difference.kind != DifferenceKind::Added {
        return false;
    }
    if difference.detail.starts_with("a root") {
        return true;
    }
    let Some((definition, member)) = difference.at.split_once('.') else {
        return false;
    };
    if difference.detail != "a member"
        || definition.contains(['#', '[', '{'])
        || member.contains(['.', '#', '[', '{'])
    {
        return false;
    }
    let marked = old["$defs"][definition]
        .get(READ_ONLY_METADATA)
        .and_then(Value::as_bool)
        == Some(true);
    let required = new["$defs"][definition]
        .get("required")
        .and_then(Value::as_array)
        .is_some_and(|required| required.iter().any(|name| name.as_str() == Some(member)));
    marked
        && !required
        && is_a_metadata_object(old, definition)
        && is_a_metadata_object(new, definition)
        && is_used_only_where_it_widens(old, definition)
        && is_used_only_where_it_widens(new, definition)
}

/// Every difference between one release's schema and the head's, with every definition a root.
fn all_differences(old: &Value, new: &Value) -> Result<Vec<Difference>, String> {
    let names = |schema: &Value| -> BTreeSet<String> {
        schema["$defs"]
            .as_object()
            .map(|definitions| definitions.keys().cloned().collect())
            .unwrap_or_default()
    };
    let roots: BTreeSet<String> = names(old).union(&names(new)).cloned().collect();
    let before = cut_over(old, &roots).map_err(|error| error.to_string())?;
    let after = cut_over(new, &roots).map_err(|error| error.to_string())?;
    Ok(differences(&before, &after))
}

/// Every difference between one release's schema and the head's, with every definition a root,
/// that an earlier reader could not read.
fn rejected(old: &Value, new: &Value) -> Result<Vec<Difference>, String> {
    Ok(all_differences(old, new)?
        .into_iter()
        .filter(|difference| !accepted(old, new, difference))
        .collect())
}

/// Compares the head's schema with one release's: each difference an earlier reader could not
/// read, as a line.
///
/// # Errors
///
/// When a schema cannot be cut.
pub fn compare(old: &Value, new: &Value) -> Result<Vec<String>, String> {
    Ok(rejected(old, new)?
        .iter()
        .map(ToString::to_string)
        .collect())
}

/// Whether `keyword` with `value` only describes a schema to its reader and decides nothing: a
/// `description` or a `title` that is a text, which is what the comparer leaves out.
fn is_an_annotation(keyword: &str, value: &Value) -> bool {
    matches!(keyword, "description" | "title") && value.is_string()
}

/// The names that the `Method` definition of `schema` accepts, when it is the definition that the
/// rule for a new method is written for, and none otherwise. That is a `oneOf` list and nothing
/// else (annotations aside), every branch of it a plain text constant (`const` a text, `type`
/// "string", annotations aside), every name a method's name as the protocol writes it
/// ([`MethodName`]) and every name once. Such a definition accepts exactly its names. For any other
/// shape the rule does not say what the definition accepts, so it reads no names.
fn plain_method_names(schema: &Value) -> Option<BTreeSet<&str>> {
    let definition = schema["$defs"]["Method"].as_object()?;
    if !definition
        .iter()
        .all(|(keyword, value)| keyword == "oneOf" || is_an_annotation(keyword, value))
    {
        return None;
    }
    let mut names = BTreeSet::new();
    for branch in definition.get("oneOf")?.as_array()? {
        let branch = branch.as_object()?;
        if !branch.iter().all(|(keyword, value)| {
            matches!(keyword.as_str(), "const" | "type") || is_an_annotation(keyword, value)
        }) {
            return None;
        }
        let name = branch.get("const")?.as_str()?;
        if branch.get("type")?.as_str()? != "string" {
            return None;
        }
        if MethodName::new(name).is_err() || !names.insert(name) {
            return None;
        }
    }
    Some(names)
}

/// Whether every use of the definition `name` in `schema` is one where a wider definition makes the
/// place that uses it accept at least what it accepted: a use as a property, an item (`items`,
/// `prefixItems`), an additional or pattern property, in an `anyOf` or an `allOf`, or as a whole
/// definition, through any chain of definitions that reach it. A use under any other keyword is not
/// counted: under some of them (a `oneOf`, a `not`, an `if`, a `contains` with `maxContains`) a
/// wider definition can make the place refuse a value that it accepted, and the walk does not tell
/// those from the rest. A schema that has an `unevaluatedItems` or an `unevaluatedProperties`
/// anywhere is refused whole: they read what the keywords beside them evaluated, which a
/// definition changes both ways. The walk reads every definition and the keywords of the schema beside
/// `$defs` (the root must name the dialect of [`DIALECT`], and nothing below it may name another),
/// and it refuses any form that it cannot read (see [`widens_at`]).
fn is_used_only_where_it_widens(schema: &Value, name: &str) -> bool {
    // A root that names no dialect is read in whatever dialect the reader defaults to, and an older
    // one has no `const` and ignores what stands beside a `$ref`: the walk reads neither.
    if schema.get("$schema").and_then(Value::as_str) != Some(DIALECT) {
        return false;
    }
    let Some(definitions) = schema["$defs"].as_object() else {
        return true;
    };
    let mut reaching: BTreeSet<&str> = BTreeSet::from([name]);
    loop {
        let known = reaching.len();
        for (definition, node) in definitions {
            let mut found = Vec::new();
            references(node, "", &mut found);
            if found.iter().any(|(_, target)| {
                target
                    .strip_prefix("#/$defs/")
                    .is_some_and(|target| reaching.contains(target))
            }) {
                reaching.insert(definition);
            }
        }
        if reaching.len() == known {
            break;
        }
    }
    schemas_widen(definitions, &reaching, true)
        && schema
            .as_object()
            .into_iter()
            .flatten()
            .all(|(keyword, member)| match keyword.as_str() {
                "$defs" => true,
                // The dialect is the walk's own, as checked above.
                "$schema" => true,
                _ => widens_at(keyword, member, &reaching, true),
            })
}

/// The dialect that the walk is written for: the one that the root of a schema must name, and the
/// only one that a schema may name.
pub(crate) const DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

/// Whether every member of `named`, a map from names to schemas, is a schema that stands where it
/// may (see [`widens_at`]). A member must be an object, a boolean or a list (under `dependencies`,
/// a list of names): any other member is no schema, and a text under a name is a keyword
/// to a resolver that reads every object for the keywords `$id`, `id`, `$anchor` and
/// `$dynamicAnchor`, and it takes any text under one of them for an address or a name, so a text
/// under a name is refused.
fn schemas_widen(
    named: &serde_json::Map<String, Value>,
    reaching: &BTreeSet<&str>,
    widening: bool,
) -> bool {
    named.values().all(|schema| {
        (schema.is_object() || schema.is_boolean() || schema.is_array())
            && widens_with(schema, reaching, widening)
    })
}

/// Whether every `$ref` under `node` to a definition of `reaching` stands where a wider definition
/// widens the place: `widening` says that the path to `node` has only such places.
fn widens_with(node: &Value, reaching: &BTreeSet<&str>, widening: bool) -> bool {
    match node {
        Value::Object(members) => members
            .iter()
            .all(|(keyword, member)| widens_at(keyword, member, reaching, widening)),
        Value::Array(items) => items
            .iter()
            .all(|item| widens_with(item, reaching, widening)),
        _ => true,
    }
}

/// The keywords that give a place an address of its own (`$id`, and draft-04's `id`), a name that
/// a reference can find (`$anchor`, `$dynamicAnchor`), a mark that lets a `$recursiveRef` select
/// the place (`$recursiveAnchor`), a target that depends on the place that evaluates it
/// (`$dynamicRef`, `$recursiveRef`), or another dialect for the place (`$schema`, which only the
/// root of a schema may have, and only with [`DIALECT`]).
const SCOPE_KEYWORDS: [&str; 8] = [
    "$id",
    "id",
    "$anchor",
    "$dynamicAnchor",
    "$recursiveAnchor",
    "$dynamicRef",
    "$recursiveRef",
    "$schema",
];

/// Whether a `$ref` to `member` stands where a wider definition of `reaching` widens the place
/// (`widening`), or does not reach one. The walk follows a `$ref` only when it is `#/$defs/` and a
/// name of one or more ASCII letters, digits and `_`. That is a fragment of two pointer segments
/// with no character that a validator decodes (`%`, `~`) or removes (a trailing `#`, a tab, a line
/// feed, a carriage return, a space at the end) and no `/` that starts a third segment, so every
/// validator reads the same two segments. Any other `$ref` (`#`, `#name`, an address,
/// `#/definitions/NAME`, an empty name) is refused.
fn reference_widens(member: &Value, reaching: &BTreeSet<&str>, widening: bool) -> bool {
    match member
        .as_str()
        .and_then(|target| target.strip_prefix("#/$defs/"))
    {
        Some(target)
            if !target.is_empty()
                && target
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') =>
        {
            widening || !reaching.contains(target)
        }
        _ => false,
    }
}

/// Whether `member`, the value of `keyword` in a schema, stands where a wider definition of
/// `reaching` widens the place (see [`widens_with`]).
///
/// A reference that [`reference_widens`] follows has no scheme, host or path, so it is resolved
/// against the base address of the resource that holds it, and it reaches the member of the one
/// `$defs` that its name says (a generated file holds a key once; a name that `$defs` lacks
/// reaches nothing, which is an error and never another place). Only a [`SCOPE_KEYWORDS`] keyword
/// can change that, and the walk refuses each of them wherever it stands (`$schema` may stand
/// only at the root, and there only with [`DIALECT`]). It reads a key as a name
/// only in a map from names to schemas (`properties`, `patternProperties`, `$defs`,
/// `definitions`, `dependentSchemas`, `dependencies`), and only where the member under the name
/// is an object, a boolean or a list ([`schemas_widen`]); every key of a value that it does not
/// read as a schema (a constant, a default, an example, a keyword that it does not know) is read
/// as a keyword, so no keyword hides among names. A schema that the walk accepts then holds no
/// place with an address, a name or a dialect of its own and no reference that it cannot read.
fn widens_at(keyword: &str, member: &Value, reaching: &BTreeSet<&str>, widening: bool) -> bool {
    match keyword {
        "$ref" => reference_widens(member, reaching, widening),
        _ if SCOPE_KEYWORDS.contains(&keyword) => false,
        "properties" | "patternProperties" if member.is_object() => member
            .as_object()
            .is_some_and(|named| schemas_widen(named, reaching, widening)),
        "$defs" | "definitions" | "dependentSchemas" | "dependencies" if member.is_object() => {
            member
                .as_object()
                .is_some_and(|named| schemas_widen(named, reaching, false))
        }
        "items" | "additionalProperties" | "anyOf" | "allOf" | "prefixItems" => {
            widens_with(member, reaching, widening)
        }
        // They read what the keywords beside them evaluated, so a definition that evaluates more or
        // fewer members changes the place both ways: the walk reads no place that has one.
        "unevaluatedItems" | "unevaluatedProperties" => false,
        "oneOf" | "not" | "if" | "then" | "else" | "contains" | "propertyNames"
        | "additionalItems" | "contentSchema" => widens_with(member, reaching, false),
        _ => is_plain_data(member, reaching),
    }
}

/// Whether `node`, a value that the walk does not read as a schema, holds no keyword that the walk
/// refuses: every key is read as a keyword, none as a name, and no place widens.
fn is_plain_data(node: &Value, reaching: &BTreeSet<&str>) -> bool {
    match node {
        Value::Object(members) => members.iter().all(|(key, member)| match key.as_str() {
            "$ref" => reference_widens(member, reaching, false),
            key if SCOPE_KEYWORDS.contains(&key) => false,
            _ => is_plain_data(member, reaching),
        }),
        Value::Array(items) => items.iter().all(|item| is_plain_data(item, reaching)),
        _ => true,
    }
}

/// Whether `difference` is one new method: the addition of a variant that `Method` gains. Every one
/// of these holds, or it is a difference like any other:
///
/// * `Method` is, in both schemas, the list of plain text constants that [`plain_method_names`]
///   describes, so it accepts exactly its names;
/// * every name of the earlier list is in the new one;
/// * the line is about a name that the new list adds;
/// * every use of `Method` in both schemas is one where a wider `Method` only widens the place that
///   uses it ([`is_used_only_where_it_widens`]).
///
/// Then every place that uses `Method` accepts what it accepted, and a value that it accepts anew
/// holds a new name at a use of `Method`.
///
/// The label of a line says where it is and not which list it came from: other lists have the
/// place `Method` as its `oneOf` does (its `anyOf`, the inner list of a nullable pair, a
/// definition that an old reference to `Method` is compared with), and two lines of them can be
/// one. So the label only says which name the line is about, and the shape of `Method` and the
/// uses of it decide. Where they do not hold, this rule excuses no line under `Method`, and each
/// is reported as it is.
fn is_an_added_method(old: &Value, new: &Value, difference: &Difference) -> bool {
    if difference.kind != DifferenceKind::Added || difference.detail != "a variant" {
        return false;
    }
    let Some(name) = difference.at.strip_prefix("Method#const:") else {
        return false;
    };
    let (Some(before), Some(after)) = (plain_method_names(old), plain_method_names(new)) else {
        return false;
    };
    before.is_subset(&after)
        && after.difference(&before).any(|added| *added == name)
        && is_used_only_where_it_widens(old, "Method")
        && is_used_only_where_it_widens(new, "Method")
}

/// The name of the member that `difference` adds directly to the configuration document: the only
/// kind of difference that a new section can be.
fn member_added_to_the_configuration_document(difference: &Difference) -> Option<&str> {
    if difference.kind != DifferenceKind::Added || difference.detail != "a member" {
        return None;
    }
    difference
        .at
        .strip_prefix(CONFIGURATION_DOCUMENT)
        .and_then(|rest| rest.strip_prefix('.'))
        .filter(|member| !member.contains(['.', '#', '[', '{']))
}

/// Whether a reference (`$ref` or `$dynamicRef`) to the definition `name` occurs anywhere in a
/// definition of `schema` or in a keyword of its own root. An entry of the root's `properties` that
/// is a bare `$ref` is the bundle's own (the schema lists its messages there, and a use as a
/// property widens with its target) and is not read; any other entry is.
fn is_referred_to(schema: &Value, name: &str) -> bool {
    fn refers(node: &Value, reference: &str) -> bool {
        match node {
            Value::Object(members) => {
                ["$ref", "$dynamicRef"]
                    .iter()
                    .any(|keyword| members.get(*keyword).and_then(Value::as_str) == Some(reference))
                    || members.values().any(|member| refers(member, reference))
            }
            Value::Array(items) => items.iter().any(|item| refers(item, reference)),
            _ => false,
        }
    }
    fn is_a_bare_reference(entry: &Value) -> bool {
        entry.as_object().is_some_and(|members| {
            members.len() == 1 && members.get("$ref").is_some_and(Value::is_string)
        })
    }
    let reference = format!("#/$defs/{name}");
    let root: serde_json::Map<String, Value> = schema
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(keyword, _)| keyword.as_str() != "$defs")
        .map(
            |(keyword, member)| match (keyword.as_str(), member.as_object()) {
                ("properties", Some(entries)) => (
                    keyword.clone(),
                    Value::Object(
                        entries
                            .iter()
                            .filter(|(_, entry)| !is_a_bare_reference(entry))
                            .map(|(entry_name, entry)| (entry_name.clone(), entry.clone()))
                            .collect(),
                    ),
                ),
                _ => (keyword.clone(), member.clone()),
            },
        )
        .collect();
    refers(&Value::Object(root), &reference)
        || schema["$defs"].as_object().is_some_and(|definitions| {
            definitions
                .values()
                .any(|definition| refers(definition, &reference))
        })
}

/// Whether `difference` is a new section of the configuration document that an earlier release
/// ignores and counts: a stored file read by level, which records the level of the sections it
/// holds, so an earlier release applies the rest and refuses to edit it.
///
/// Every one of these holds, or it is a difference like any other:
///
/// * it is a member added directly to `ConfigurationDocument`;
/// * `sections` lists it: the build's table of sections lists it at a level above the level the
///   earlier release's stored-format lock records for the document;
/// * it is not required;
/// * the document is a plain closed object in both schemas ([`plain_closed_object`]), so its own
///   `properties` are the only list that gives the label `ConfigurationDocument.member`, and the
///   added member is a key that the earlier schema refused (an open document, a nullable pair or
///   a `$ref` with `properties` beside it gives the same label from a list where the member
///   restricts a value that the earlier schema accepted);
/// * no definition of either schema, and no keyword of either root (but a bare reference among the
///   root's `properties`, the bundle's own entry), refers to `ConfigurationDocument`, so no answer a
///   host gives carries the document, and a reference that moved to a copy of it cannot hide the
///   add: only the file and the registry's copy of it are read by a release that lacks the
///   section.
///
/// Anything else about the document is compared as it is for every definition, so a change to an
/// existing member, a default, `required`, a ceiling or a section the table does not list still
/// fails. What this cannot tell is a section from a restriction filed as one: a restriction is
/// never a level (`docs/host/updates.md`, "Configuration levels"), and only a review of the change
/// that adds the section sees that it is not one.
fn is_a_new_section(
    old: &Value,
    new: &Value,
    difference: &Difference,
    sections: &BTreeSet<String>,
) -> bool {
    let Some(section) = member_added_to_the_configuration_document(difference) else {
        return false;
    };
    let required = new["$defs"][CONFIGURATION_DOCUMENT]
        .get("required")
        .and_then(Value::as_array)
        .is_some_and(|required| required.iter().any(|name| name.as_str() == Some(section)));
    sections.contains(section)
        && !required
        && plain_closed_object(CONFIGURATION_DOCUMENT, old, "the earlier release's").is_ok()
        && plain_closed_object(CONFIGURATION_DOCUMENT, new, "this commit's").is_ok()
        && !is_referred_to(old, CONFIGURATION_DOCUMENT)
        && !is_referred_to(new, CONFIGURATION_DOCUMENT)
}

/// As [`compare`], for the check of a level: the differences that fail a commit that stays at the
/// level. A method a daemon serves keeps the level, because a host of the same level answers a
/// method it does not list with `PERMISSION_DENIED` and a client that meets that refusal for a
/// method that is new tells it from a lack of rights, so a new variant of `Method` is not a
/// difference here, where the rule of `is_an_added_method` holds. It is one for
/// `--public-contract`, which reports it.
///
/// A new section of the configuration document passes too, where `sections` (called once, and only
/// when the schemas differ by a member added to the document) names it: the sections the build
/// lists above the level the earlier release's lock records. Each section passed is added to
/// `passed`. Where `sections` cannot say what they are, the member stays a difference and says
/// why, so the check fails and the difference is not hidden by the failure to read.
///
/// # Errors
///
/// When a schema cannot be cut.
pub fn compare_for_a_level(
    old: &Value,
    new: &Value,
    sections: &dyn Fn() -> Result<BTreeSet<String>, String>,
    passed: &mut Vec<String>,
) -> Result<Vec<String>, String> {
    let mut sections_above: Option<Result<BTreeSet<String>, String>> = None;
    let mut lines = Vec::new();
    for difference in rejected(old, new)? {
        if is_an_added_method(old, new, &difference) {
            continue;
        }
        if let Some(section) = member_added_to_the_configuration_document(&difference) {
            match sections_above.get_or_insert_with(sections) {
                Ok(above) if is_a_new_section(old, new, &difference, above) => {
                    passed.push(section.to_owned());
                    continue;
                }
                Ok(_) => {}
                Err(unread) => {
                    lines.push(format!("{difference}; {unread}"));
                    continue;
                }
            }
        }
        lines.push(difference.to_string());
    }
    Ok(lines)
}

/// A version of the plugin SDK as its contract states it: three whole numbers, compared as numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SdkVersion(u64, u64, u64);

impl SdkVersion {
    /// Reads `major.minor.patch`: three whole numbers made of digits, and nothing else (a
    /// pre-release, a build or a sign is not one this check reads).
    ///
    /// # Errors
    ///
    /// When the text is not that.
    pub fn parse(text: &str) -> Result<Self, String> {
        let number = |part: &str| -> Result<u64, String> {
            let plain = part == "0" || !part.starts_with('0');
            if part.is_empty() || !plain || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(format!(
                    "{text} is not three whole numbers with dots between"
                ));
            }
            part.parse()
                .map_err(|_| format!("{text} holds a number that is too large"))
        };
        match text.split('.').collect::<Vec<_>>().as_slice() {
            [major, minor, patch] => Ok(Self(number(major)?, number(minor)?, number(patch)?)),
            _ => Err(format!(
                "{text} is not three whole numbers with dots between"
            )),
        }
    }
}

impl std::fmt::Display for SdkVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// One member that arrived in a definition of the SDK's schema, as a contract lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SdkArrival {
    /// The definition of the SDK's schema.
    pub definition: String,
    /// The member's name.
    pub member: String,
    /// The SDK version it arrived at.
    pub version: SdkVersion,
}

/// What a release's committed package contract says about the SDK: its version, and the members
/// that arrived inside a level. A contract from before the table has an empty one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SdkContract {
    /// The SDK version the release implements.
    pub version: SdkVersion,
    /// The table of arrivals.
    pub arrivals: Vec<SdkArrival>,
}

impl SdkContract {
    /// Reads the committed `package-contract.json`.
    ///
    /// # Errors
    ///
    /// When it is not JSON, has no `sdk_version` that is text of three numbers, or its
    /// `arrivals` is not a list of entries that each hold a definition, a member and an SDK
    /// version and nothing else, with no member listed twice. A contract with no `arrivals` at all
    /// is one from before the table, and its table is empty.
    pub fn parse(text: &str) -> Result<Self, String> {
        let document: Value = serde_json::from_str(text).map_err(|error| error.to_string())?;
        let version = document
            .get("sdk_version")
            .and_then(Value::as_str)
            .ok_or("no sdk_version")?;
        let version =
            SdkVersion::parse(version).map_err(|error| format!("sdk_version: {error}"))?;
        let mut arrivals: Vec<SdkArrival> = Vec::new();
        if let Some(table) = document.get("arrivals") {
            for entry in table.as_array().ok_or("arrivals is not a list")? {
                let entry = entry
                    .as_object()
                    .ok_or("an entry of arrivals is not an object")?;
                if let Some(other) = entry
                    .keys()
                    .find(|key| !["definition", "member", "sdk_version"].contains(&key.as_str()))
                {
                    return Err(format!(
                        "an entry of arrivals has the member {other}, which this check does not read"
                    ));
                }
                let text_of = |name: &str| -> Result<String, String> {
                    entry
                        .get(name)
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .ok_or_else(|| format!("an entry of arrivals has no {name} as text"))
                };
                let (definition, member) = (text_of("definition")?, text_of("member")?);
                let at = SdkVersion::parse(&text_of("sdk_version")?)
                    .map_err(|error| format!("the entry {definition}.{member}: {error}"))?;
                if arrivals
                    .iter()
                    .any(|listed| listed.definition == definition && listed.member == member)
                {
                    return Err(format!("{definition}.{member} is listed twice"));
                }
                arrivals.push(SdkArrival {
                    definition,
                    member,
                    version: at,
                });
            }
        }
        Ok(Self { version, arrivals })
    }

    fn listing(&self, definition: &str, member: &str) -> Option<&SdkArrival> {
        self.arrivals
            .iter()
            .find(|listed| listed.definition == definition && listed.member == member)
    }
}

/// A member of the SDK's schema that the comparison passed because the SDK lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassedMember {
    /// `Definition.member`.
    pub member: String,
    /// The SDK version the head's table lists it at.
    pub arrived: SdkVersion,
    /// The SDK version of the release it is new to.
    pub earlier: SdkVersion,
}

/// Whether `difference` is a member that arrived in a definition of the SDK's schema in a way the
/// SDK's table allows. Every one of these holds, or it is a difference like any other:
///
/// * it is a member added to a definition, with no nesting: not a member of a variant, an item or
///   a value, and not a variant;
/// * both SDK schemas have the definition, the earlier one without the member and the head's with
///   it, and the head's does not require it;
/// * the definition is a plain closed object in both ([`plain_closed_object`]);
/// * neither release's protocol schema has a definition of that name, because the protocol's own
///   rule holds what a client of the protocol reads;
/// * the head's table lists the member at an SDK version above the earlier release's;
/// * the head's SDK version is above the earlier release's;
/// * every use of the definition, in both schemas, is one where a wider definition only widens
///   the place ([`is_used_only_where_it_widens`]);
/// * its definition is reached from the connector table's root and not from the package manifest's,
///   in both SDK schemas: a host reads `connector.json` after it has tested the package's
///   `sdk_range`, and parses all of `plugin.json` before it can, so a new member there would stop
///   an earlier host before it read the range.
///
/// A member that meets all of these but the last is returned as an error that says why, since it
/// is the SDK's table that lists it in the wrong place.
fn is_a_listed_arrival(
    old: &Value,
    new: &Value,
    protocols: (&Value, &Value),
    earlier: &SdkContract,
    head: &SdkContract,
    difference: &Difference,
) -> Result<Option<PassedMember>, String> {
    if difference.kind != DifferenceKind::Added || difference.detail != "a member" {
        return Ok(None);
    }
    let Some((definition, member)) = difference.at.split_once('.') else {
        return Ok(None);
    };
    if definition.contains(['.', '#', '[', '{']) || member.contains(['.', '#', '[', '{']) {
        return Ok(None);
    }
    // The earlier definition exists, and has no such member: a definition that has no members at all
    // has no `properties` either.
    let has_no_member = old["$defs"].get(definition).is_some_and(|earlier| {
        earlier
            .get("properties")
            .and_then(Value::as_object)
            .is_none_or(|members| !members.contains_key(member))
    });
    let has_member = new["$defs"][definition]["properties"]
        .as_object()
        .is_some_and(|members| members.contains_key(member));
    let required = new["$defs"][definition]
        .get("required")
        .and_then(Value::as_array)
        .is_some_and(|required| required.iter().any(|name| name.as_str() == Some(member)));
    let shared = [protocols.0, protocols.1]
        .iter()
        .any(|protocol| protocol["$defs"].get(definition).is_some());
    let Some(listed) = head.listing(definition, member) else {
        return Ok(None);
    };
    let arrived = listed.version;
    if !(has_no_member
        && has_member
        && !required
        && !shared
        && arrived > earlier.version
        && head.version > earlier.version)
    {
        return Ok(None);
    }
    for (name, schema) in [("the earlier release's", old), ("this commit's", new)] {
        for root in [CONNECTOR_ROOT, MANIFEST_ROOT] {
            if schema["$defs"].get(root).is_none() {
                return Err(format!(
                    "{name} SDK schema has no {root} definition, so where {definition} is reached \
                     from cannot be told"
                ));
            }
        }
        if !reached(schema, CONNECTOR_ROOT).contains(definition) {
            return Err(format!(
                "{definition} is not reached from {CONNECTOR_ROOT} in {name} SDK schema, and a \
                 member listed in the arrival table has to be one the connector table carries"
            ));
        }
        if reached(schema, MANIFEST_ROOT).contains(definition) {
            return Err(format!(
                "{definition} is reached from {MANIFEST_ROOT} in {name} SDK schema, which a host \
                 parses whole before it tests the package's sdk_range, so a member listed in the \
                 arrival table cannot be in it"
            ));
        }
        plain_closed_object(definition, schema, name)?;
    }
    // A closed object that gains a member accepts more, so a place that uses it must gain values
    // when it does: in a `oneOf` beside a branch that accepts the member, or a `not`, the earlier
    // schema accepts a value that the new one refuses, and the difference is not an arrival.
    if ![old, new]
        .iter()
        .all(|schema| is_used_only_where_it_widens(schema, definition))
    {
        return Ok(None);
    }
    Ok(Some(PassedMember {
        member: format!("{definition}.{member}"),
        arrived,
        earlier: earlier.version,
    }))
}

/// The keys a plain closed object's definition may have at its top, as the generator writes them:
/// the shape (`type`, `properties`, `required`, `additionalProperties`) and the annotations the
/// comparison ignores (`description`, `title`).
const PLAIN_OBJECT_KEYS: [&str; 6] = [
    "type",
    "properties",
    "required",
    "additionalProperties",
    "description",
    "title",
];

/// Fails unless the definition is a plain closed object in `schema`: `type` is `object`,
/// `additionalProperties` is `false`, and the definition's own keys are from
/// [`PLAIN_OBJECT_KEYS`]. Any other key at its top (`allOf`, `anyOf`, `oneOf`, `not`, `if`, `$ref`,
/// `patternProperties`, `unevaluatedProperties`, a marker of the protocol) composes or loosens the
/// object, so a name that appears in its `properties` may restrict a member the definition has
/// another way, and a member added to it is not one an earlier reader meets as a new member.
fn plain_closed_object(definition: &str, schema: &Value, name: &str) -> Result<(), String> {
    let node = &schema["$defs"][definition];
    if node.get("type").and_then(Value::as_str) != Some("object") {
        return Err(format!(
            "{definition} is not an object in {name} SDK schema, and a member listed in the \
             arrival table has to be a member of a plain closed object"
        ));
    }
    if let Some(key) = node
        .as_object()
        .into_iter()
        .flat_map(|members| members.keys())
        .find(|key| !PLAIN_OBJECT_KEYS.contains(&key.as_str()))
    {
        return Err(format!(
            "{definition} has {key} at its top in {name} SDK schema, and a member listed in the \
             arrival table has to be a member of a plain closed object"
        ));
    }
    if node.get("additionalProperties") != Some(&Value::Bool(false)) {
        return Err(format!(
            "{definition} is not closed in {name} SDK schema (additionalProperties is not false), \
             and a member listed in the arrival table has to be a member of a plain closed object"
        ));
    }
    Ok(())
}

/// The root of the connector table in the SDK's schema: a host reads `connector.json` after it
/// has tested the package's `sdk_range`.
const CONNECTOR_ROOT: &str = "ConnectorManifest";

/// The root of the package manifest in the SDK's schema: a host parses `plugin.json` whole before
/// it can test the range it states.
const MANIFEST_ROOT: &str = "PluginManifest";

/// The definitions reached from `root`, itself among them, by following every `$ref`.
fn reached(schema: &Value, root: &str) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut pending = vec![root.to_owned()];
    while let Some(name) = pending.pop() {
        if !seen.insert(name.clone()) {
            continue;
        }
        let mut found = Vec::new();
        references(&schema["$defs"][name.as_str()], "", &mut found);
        pending.extend(
            found
                .into_iter()
                .filter_map(|(_, target)| target.strip_prefix("#/$defs/").map(str::to_owned)),
        );
    }
    seen
}

/// Every `$ref` under `node`, each with the path that leads to it.
fn references(node: &Value, path: &str, found: &mut Vec<(String, String)>) {
    match node {
        Value::Object(members) => {
            for (key, member) in members {
                match (key.as_str(), member.as_str()) {
                    ("$ref", Some(target)) => found.push((path.to_owned(), target.to_owned())),
                    _ => references(member, &format!("{path}/{key}"), found),
                }
            }
        }
        Value::Array(items) => {
            for (position, item) in items.iter().enumerate() {
                references(item, &format!("{path}/{position}"), found);
            }
        }
        _ => {}
    }
}

/// The first definition both schemas have that refers to other definitions than it did, leaving
/// out the members of the head's that are arrivals.
fn moved_reference(old: &Value, new: &Value, arrived: &[PassedMember]) -> Option<String> {
    for (name, before) in old["$defs"].as_object()? {
        let Some(after) = new["$defs"].get(name) else {
            continue;
        };
        let mut after = after.clone();
        for member in arrived {
            if let Some((definition, member)) = member.member.split_once('.')
                && definition == name
                && let Some(members) = after.get_mut("properties").and_then(Value::as_object_mut)
            {
                members.remove(member);
            }
        }
        let (mut was, mut is) = (Vec::new(), Vec::new());
        references(before, "", &mut was);
        references(&after, "", &mut is);
        was.sort();
        is.sort();
        if was != is {
            return Some(name.clone());
        }
    }
    None
}

/// As [`compare_for_a_level`], for the plugin SDK's schema, which has its own function so that the
/// protocol's comparison does not change. A difference passes only when it is a new definition or
/// the SDK's own arrival table lists it ([`is_a_listed_arrival`]); every other difference fails.
/// The protocol's read-only metadata marker (`x-kalareach-read-only-metadata`) has no meaning in
/// the SDK's schema: an optional member added to an SDK definition that carries it is a member like
/// any other, and fails unless it is listed. A new definition is a difference that no reader of an
/// earlier release meets, as it is for the protocol schema. An entry of the earlier release's table that the head's table
/// changed or lacks, since a member that passed once is not one the table may take back. A head
/// whose SDK version is below the release's fails, and so does a head in which a definition refers
/// to another definition than it did (the comparison goes by where a definition is used and not by
/// its name, so a member could otherwise be taken for an arrival of a definition that is not the
/// one it was added to). Each member that passes is added to `passed`.
///
/// `old` and `new` are the SDK schemas of the earlier release and the head, `protocols` the
/// protocol schemas of the two, and `earlier` and `head` what their contracts say.
///
/// # Errors
///
/// When a schema cannot be cut.
pub fn compare_sdk_for_a_level(
    old: &Value,
    new: &Value,
    protocols: (&Value, &Value),
    earlier: &SdkContract,
    head: &SdkContract,
    passed: &mut Vec<PassedMember>,
) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    let mut arrived = Vec::new();
    // The protocol's read-only metadata marker has no meaning in the SDK's schema, so this does not
    // go through `accepted`: a new definition passes, a listed member passes, and nothing else.
    for difference in all_differences(old, new)? {
        if difference.kind == DifferenceKind::Added && difference.detail.starts_with("a root") {
            continue;
        }
        match is_a_listed_arrival(old, new, protocols, earlier, head, &difference) {
            Ok(Some(member)) => arrived.push(member),
            Ok(None) => lines.push(difference.to_string()),
            Err(why) => lines.push(format!("{difference}; {why}")),
        }
    }
    if !arrived.is_empty()
        && let Some(definition) = moved_reference(old, new, &arrived)
    {
        lines.push(format!(
            "{definition} refers to other definitions than it did there, so a member listed in \
             the arrival table cannot be told from one added to another definition"
        ));
        lines.extend(
            arrived
                .drain(..)
                .map(|member| format!("{} added: a member", member.member)),
        );
    }
    passed.extend(arrived);
    if head.version < earlier.version {
        lines.push(format!(
            "the SDK version is {} there and {} here, which is lower",
            earlier.version, head.version
        ));
    }
    for listed in &earlier.arrivals {
        let (definition, member) = (&listed.definition, &listed.member);
        match head.listing(definition, member) {
            Some(now) if now.version == listed.version => {}
            Some(now) => lines.push(format!(
                "{definition}.{member} is listed in the arrival table at {} there and at {} here",
                listed.version, now.version
            )),
            None => lines.push(format!(
                "{definition}.{member} is listed in the arrival table at {} there and is not \
                 listed here",
                listed.version
            )),
        }
    }
    Ok(lines)
}

/// The non-retired public majors a record of the table lists.
fn live_majors(record: &str) -> BTreeSet<String> {
    record
        .lines()
        .filter(|line| line.starts_with("major=") && line.ends_with("retired=false"))
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

/// The release the freeze names, when there is a record of one.
///
/// # Errors
///
/// When the record is not `release=<tag>`, names a tag that is not a release here, or one that is
/// not in the history of `head`.
pub fn freeze(
    repository: &Path,
    head: &str,
    inventory: &[Release],
) -> Result<Option<Release>, String> {
    let path = repository.join(FREEZE);
    if !path.exists() {
        return Ok(None);
    }
    let text =
        std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let tag = text
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| line.strip_prefix("release="))
        .collect::<Option<Vec<&str>>>()
        .filter(|lines| lines.len() == 1)
        .map(|lines| lines[0].trim())
        .ok_or_else(|| format!("{FREEZE} is not a single `release=<tag>` line"))?;
    let release = inventory
        .iter()
        .find(|release| release.tag == tag)
        .ok_or_else(|| format!("{FREEZE} names {tag}, which is not a release tag here"))?;
    if !is_ancestor(repository, &release.commit, head)? {
        return Err(format!(
            "{FREEZE} names {tag}, which is not in the history of {head}"
        ));
    }
    Ok(Some(release.clone()))
}

/// Compares `head` with the releases that make its public contract.
///
/// # Errors
///
/// When a record or a tree cannot be read.
pub fn report(
    repository: &Path,
    head: &Head,
    inventory: &[Release],
    frozen: Option<&Release>,
) -> Result<Report, String> {
    let head_majors = live_majors(&head.public_majors);
    let mut references = Vec::new();
    for release in inventory
        .iter()
        .filter(|release| release.commit != head.commit)
    {
        let referenced = match frozen {
            None => release.level() == head.level,
            Some(frozen) => {
                (release.commit == frozen.commit
                    || is_ancestor(repository, &frozen.commit, &release.commit)?)
                    && !live_majors(&expected_public_majors_in(repository, &release.commit)?)
                        .is_disjoint(&head_majors)
            }
        };
        if referenced {
            references.push(release);
        }
    }
    let mut found = Vec::new();
    for release in &references {
        let stated = package_version_at(repository, &release.commit)?;
        if stated != release.version {
            return Err(format!(
                "{} states {} and its commit's package is {stated}",
                release.tag, release.version
            ));
        }
        let text = git_in(
            repository,
            &["show", &format!("{}:{SCHEMA_PATH}", release.commit)],
        )
        .map_err(|error| format!("the schema of {} cannot be read: {error}", release.tag))?;
        let schema: Value = serde_json::from_str(&text)
            .map_err(|error| format!("the schema of {}: {error}", release.tag))?;
        let lines = compare(&schema, &head.schema)
            .map_err(|error| format!("the schema of {}: {error}", release.tag))?;
        if !lines.is_empty() {
            found.push((release.tag.clone(), lines));
        }
    }
    Ok(Report {
        frozen_at: frozen.map(|release| release.tag.clone()),
        references: references
            .iter()
            .map(|release| release.tag.clone())
            .collect(),
        differences: found,
    })
}

/// Runs the check for the commit at `HEAD` of the checkout at `repository`.
///
/// # Errors
///
/// When it cannot read what it compares, and, once public 1.0 is frozen, on a difference.
pub fn run(repository: &Path) -> Result<(), String> {
    let commit = git_in(repository, &["rev-parse", "--verify", "HEAD^{commit}"])?
        .trim()
        .to_owned();
    let releases = inventory(repository)?;
    agree_with_origin(repository, &releases, &commit)?;
    let head = Head::of_this_build(repository, &commit)?;
    let frozen = freeze(repository, &commit, &releases)?;
    let report = report(repository, &head, &releases, frozen.as_ref())?;
    conclude(&report)
}

/// What the report comes to: printed, and a failure from the freeze on.
///
/// # Errors
///
/// When public 1.0 is frozen and a release's reader cannot read what the commit writes.
pub fn conclude(report: &Report) -> Result<(), String> {
    for (tag, lines) in &report.differences {
        println!(
            "{tag}: a client built from it cannot read what this commit writes:\n  {}",
            lines.join("\n  ")
        );
    }
    match (&report.frozen_at, report.differences.is_empty()) {
        (_, true) => {
            println!(
                "the public contract holds against {} release(s)",
                report.references.len()
            );
            Ok(())
        }
        (None, false) => {
            println!(
                "{} release(s) differ; public 1.0 is not frozen until the first client release, \
                 so this reports and does not fail",
                report.differences.len()
            );
            Ok(())
        }
        (Some(tag), false) => Err(format!(
            "public 1.0 is frozen at {tag} and {} release(s) differ",
            report.differences.len()
        )),
    }
}
