//! Values of the protocol's types with the marker planted in every leaf of free text, and the checks
//! that say where an output let such text through.
//!
//! A value is built from its type's JSON schema: every property, one element of every list, and
//! each alternative of every choice in turn, so each variant is built at least once. A string leaf
//! with no format or pattern holds the marker, with a colon and a space after it so that no
//! identifier grammar a validator checks accepts it. A leaf with a format or a pattern holds an
//! example of it, and a type whose own checks go further than its schema has an example here.

use std::collections::{BTreeSet, HashSet};

use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::output::{Document, Line};
use crate::shown::marker::MARKER;

/// What a leaf of free text holds.
pub(crate) fn planted_text() -> String {
    format!("{MARKER}: planted")
}

/// Every value of `T` this builds: one for each alternative of the widest choice in its schema.
///
/// # Panics
///
/// Panics when a built value does not read back as a `T`, naming the type and the value, so a type
/// whose own checks go further than its schema can be given an example.
pub(crate) fn planted<T: JsonSchema + DeserializeOwned>() -> Vec<T> {
    let schema = schemars::generate::SchemaSettings::draft2020_12()
        .into_generator()
        .into_root_schema_for::<T>();
    let root = schema.as_value().clone();
    let definitions = root.get("$defs").cloned().unwrap_or(Value::Null);
    let widest = widest(&root, &definitions, &mut HashSet::new()).max(1);
    (0..widest)
        .map(|pick| {
            let value = built(&root, &definitions, pick, 0);
            serde_json::from_value::<T>(value.clone()).unwrap_or_else(|error| {
                panic!(
                    "a planted {} does not read back: {error}\n{value:#}",
                    std::any::type_name::<T>()
                )
            })
        })
        .collect()
}

/// The widest choice anywhere in a schema.
fn widest(schema: &Value, definitions: &Value, seen: &mut HashSet<String>) -> usize {
    let mut widest = 1;
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let name = reference.trim_start_matches("#/$defs/").to_owned();
        if seen.insert(name.clone()) {
            widest = widest.max(self::widest(&definitions[&name], definitions, seen));
        }
        return widest;
    }
    for key in ["oneOf", "anyOf"] {
        if let Some(choices) = schema.get(key).and_then(Value::as_array) {
            widest = widest.max(choices.len());
        }
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        widest = widest.max(values.len());
    }
    match schema {
        Value::Object(map) => {
            for value in map.values() {
                widest = widest.max(self::widest(value, definitions, seen));
            }
        }
        Value::Array(values) => {
            for value in values {
                widest = widest.max(self::widest(value, definitions, seen));
            }
        }
        _ => {}
    }
    widest
}

/// A value of `schema`, taking alternative `pick` of every choice.
fn built(schema: &Value, definitions: &Value, pick: usize, depth: usize) -> Value {
    assert!(
        depth < 96,
        "the schema nests deeper than any protocol type does"
    );
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let name = reference.trim_start_matches("#/$defs/");
        if let Some(example) = example(name) {
            return example;
        }
        let mut value = built(&definitions[name], definitions, pick, depth + 1);
        // A reference with properties beside it adds them.
        if let (Value::Object(object), Some(Value::Object(properties))) =
            (&mut value, schema.get("properties"))
        {
            for (key, property) in properties {
                object.insert(key.clone(), built(property, definitions, pick, depth + 1));
            }
        }
        return value;
    }
    if let Some(value) = schema.get("const") {
        return value.clone();
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        return values[pick % values.len()].clone();
    }
    for key in ["oneOf", "anyOf"] {
        if let Some(choices) = schema.get(key).and_then(Value::as_array) {
            // Null is taken only where nothing else can be: a leaf that can hold text holds it.
            let real = choices
                .iter()
                .filter(|choice| choice.get("type").and_then(Value::as_str) != Some("null"))
                .collect::<Vec<_>>();
            let Some(choice) = real.get(pick % real.len().max(1)) else {
                return Value::Null;
            };
            let mut value = built(choice, definitions, pick, depth + 1);
            // An internally tagged enum puts the fields every variant shares beside its choices.
            if let (Value::Object(object), Some(Value::Object(properties))) =
                (&mut value, schema.get("properties"))
            {
                for (key, property) in properties {
                    object
                        .entry(key.clone())
                        .or_insert_with(|| built(property, definitions, pick, depth + 1));
                }
            }
            return value;
        }
    }
    if let Some(parts) = schema.get("allOf").and_then(Value::as_array) {
        let mut merged = Map::new();
        for part in parts {
            if let Value::Object(object) = built(part, definitions, pick, depth + 1) {
                merged.extend(object);
            }
        }
        return Value::Object(merged);
    }
    let kind = match schema.get("type") {
        Some(Value::String(kind)) => kind.as_str(),
        Some(Value::Array(kinds)) => kinds
            .iter()
            .filter_map(Value::as_str)
            .find(|kind| *kind != "null")
            .unwrap_or("null"),
        _ if schema.get("properties").is_some() => "object",
        _ => "null",
    };
    match kind {
        "object" => {
            let mut object = Map::new();
            if let Some(Value::Object(properties)) = schema.get("properties") {
                for (key, property) in properties {
                    object.insert(key.clone(), built(property, definitions, pick, depth + 1));
                }
            }
            if let Some(entry) = schema
                .get("additionalProperties")
                .filter(|entry| entry.is_object())
            {
                object.insert(
                    planted_key(schema),
                    built(entry, definitions, pick, depth + 1),
                );
            }
            Value::Object(object)
        }
        "array" => {
            if let Some(Value::Array(items)) = schema.get("prefixItems") {
                return Value::Array(
                    items
                        .iter()
                        .map(|item| built(item, definitions, pick, depth + 1))
                        .collect(),
                );
            }
            let count = schema
                .get("minItems")
                .and_then(Value::as_u64)
                .unwrap_or(1)
                .max(1);
            let item = schema.get("items").cloned().unwrap_or(Value::Null);
            Value::Array(
                (0..count)
                    .map(|index| {
                        built(
                            &item,
                            definitions,
                            pick + usize::try_from(index).unwrap_or(0),
                            depth + 1,
                        )
                    })
                    .collect(),
            )
        }
        "string" => text(schema),
        "integer" => {
            let minimum = schema.get("minimum").and_then(Value::as_i64).unwrap_or(0);
            let maximum = schema
                .get("maximum")
                .and_then(Value::as_i64)
                .unwrap_or(i64::MAX);
            Value::from(7_i64.clamp(minimum, maximum))
        }
        "number" => Value::from(1.5_f64),
        "boolean" => Value::Bool(true),
        _ => Value::Null,
    }
}

/// The key a planted map holds its one entry under.
fn planted_key(schema: &Value) -> String {
    match schema
        .get("propertyNames")
        .and_then(|names| names.get("pattern"))
    {
        Some(pattern) => pattern_example(pattern.as_str().unwrap_or_default())
            .as_str()
            .unwrap_or("key")
            .to_owned(),
        None => planted_text(),
    }
}

/// A string leaf: an example of its format or its pattern, or the planted text.
fn text(schema: &Value) -> Value {
    if schema.get("format").and_then(Value::as_str) == Some("uuid") {
        return Value::from("0e1f9a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b");
    }
    if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
        return pattern_example(pattern);
    }
    let maximum = schema
        .get("maxLength")
        .and_then(Value::as_u64)
        .map_or(usize::MAX, |maximum| {
            usize::try_from(maximum).unwrap_or(usize::MAX)
        });
    let planted = planted_text();
    if planted.len() <= maximum {
        Value::from(planted)
    } else if MARKER.len() <= maximum {
        Value::from(MARKER)
    } else {
        Value::from("x".repeat(maximum.max(1)))
    }
}

/// An example of each pattern the protocol's schema uses. A pattern that admits the marker holds it,
/// with a colon after it where the pattern admits no space: such a field can hold text that
/// arrived. Every other pattern is an identifier's, a digest's or an origin's, and holds an example.
fn pattern_example(pattern: &str) -> Value {
    let example = match pattern {
        "^[^\\u0000-\\u001f\\u007f]{1,128}$" | "^[^\\u0000-\\u001f\\u007f-\\u009f]+$" => {
            return Value::from(planted_text());
        }
        "^[!-~]{1,253}$" | "^[!#-\\[\\]-~]+$" => return Value::from(format!("{MARKER}:planted")),
        "^[A-Za-z0-9_-]+$" => MARKER,
        "^(0|[1-9][0-9]*)$" => "7",
        "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" => {
            "0e1f9a2b-3c4d-4e5f-8a9b-0c1d2e3f4a5b"
        }
        "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$" => "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "^([A-Za-z0-9_-]{4})*([A-Za-z0-9_-][AQgw]|[A-Za-z0-9_-]{2}[AEIMQUYcgkosw048])?$" => "AAAA",
        "^[A-Za-z0-9_-]{32}$" => "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "^[A-Za-z0-9_-]{85}[AQgw]$" => {
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        }
        "^[a-z0-9_]+(\\.[a-z0-9_]+)*$" => "desktop.screen_capture",
        "^https://([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*|\\[[0-9a-f:]+\\])(:[1-9][0-9]{0,4})?$" => {
            "https://rendezvous.example"
        }
        "^[1-9A-HJ-NP-Za-km-z]{4}-[1-9A-HJ-NP-Za-km-z]{3}-[1-9A-HJ-NP-Za-km-z]{3}$" => {
            "4XkP-Qm7-Zr2"
        }
        other => panic!("the planted values have no example of the pattern {other}"),
    };
    Value::from(example)
}

/// A value for a type whose own checks go further than its schema.
fn example(name: &str) -> Option<Value> {
    let _ = name;
    None
}

/// Holds a claim that `T` is closed: no value of it this builds holds the marker anywhere.
///
/// # Panics
///
/// Panics, naming the type and the path, where one does.
pub(crate) fn assert_closed<T: JsonSchema + DeserializeOwned + serde::Serialize>() {
    for value in planted::<T>() {
        let encoded = serde_json::to_value(&value).unwrap_or(Value::Null);
        let found = marked(&encoded);
        assert!(
            found.is_empty(),
            "{} is claimed closed and holds text at {found:?}",
            std::any::type_name::<T>()
        );
    }
}

/// Every place in `value` whose text holds the marker, as a path of keys and `[]` for list elements.
pub(crate) fn marked(value: &Value) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    walk(value, "", &mut found);
    found
}

fn walk(value: &Value, path: &str, found: &mut BTreeSet<String>) {
    match value {
        Value::String(text) if text.contains(MARKER) => {
            found.insert(path.to_owned());
        }
        Value::Array(values) => {
            for value in values {
                walk(value, &format!("{path}[]"), found);
            }
        }
        Value::Object(object) => {
            for (key, value) in object {
                if key.contains(MARKER) {
                    found.insert(format!("{path}{{key}}"));
                }
                let inner = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                walk(value, &inner, found);
            }
        }
        _ => {}
    }
}

/// Holds a document to its rule: the marker shows only where it holds asked content. Returns where
/// the marker showed.
///
/// # Panics
///
/// Panics, naming the path, where the marker shows anywhere else.
pub(crate) fn only_asked(label: &str, document: &Document) -> BTreeSet<String> {
    only_asked_or_host_text(label, document, &[])
}

/// Holds a document to its rule where some of its fields say the host's own export text through
/// the door for it ([`crate::shown::host_text`]): the marker shows only where the document holds
/// asked content or at one of `doors`. The schema a value is planted from cannot tell a field of
/// that text from any other string, so the fields are named here. Returns where the marker showed.
///
/// # Panics
///
/// Panics, naming the path, where the marker shows anywhere else.
pub(crate) fn only_asked_or_host_text(
    label: &str,
    document: &Document,
    doors: &[&str],
) -> BTreeSet<String> {
    let json = document.json();
    let found = marked(&json);
    for path in &found {
        assert!(
            document.asked().contains(path) || doors.contains(&path.as_str()),
            "{label}: the planted text shows at {path}, which holds no asked content\n{json:#}"
        );
    }
    found
}

/// Holds a document to the protocol's encoding of the value it renders: the same keys and the same
/// leaves everywhere, but at `reduced`, the leaves a reducer, a validator or a path's spelling says
/// in its own words, which only have to be there, and at `added`, the keys the document adds.
///
/// # Panics
///
/// Panics, naming the path, where the document and the encoding part.
pub(crate) fn same_encoding(
    label: &str,
    document: &Document,
    encoded: &Value,
    reduced: &[&str],
    added: &[&str],
) {
    fn compare(
        label: &str,
        written: &Value,
        encoded: &Value,
        path: &str,
        reduced: &[&str],
        added: &[&str],
    ) {
        if reduced.contains(&path) {
            return;
        }
        match (written, encoded) {
            (Value::Object(written), Value::Object(encoded)) => {
                for key in written.keys() {
                    let inner = joined(path, key);
                    assert!(
                        encoded.contains_key(key) || added.contains(&inner.as_str()),
                        "{label}: the document adds {inner}, which the protocol does not encode"
                    );
                }
                for (key, value) in encoded {
                    let inner = joined(path, key);
                    let Some(held) = written.get(key) else {
                        panic!("{label}: the document leaves out {inner}");
                    };
                    compare(label, held, value, &inner, reduced, added);
                }
            }
            (Value::Array(written), Value::Array(encoded)) => {
                assert_eq!(
                    written.len(),
                    encoded.len(),
                    "{label}: {path} has another length"
                );
                let inner = format!("{path}[]");
                for (held, value) in written.iter().zip(encoded) {
                    compare(label, held, value, &inner, reduced, added);
                }
            }
            _ => assert_eq!(
                written, encoded,
                "{label}: {path} is not what the protocol encodes"
            ),
        }
    }

    fn joined(path: &str, key: &str) -> String {
        if path.is_empty() {
            key.to_owned()
        } else {
            format!("{path}.{key}")
        }
    }

    compare(label, &document.json(), encoded, "", reduced, added);
}

/// Holds a document to the protocol's encoding of the value it renders wherever it says the value
/// as it is: the same keys, and the same leaves but where the document holds asked content or where
/// a reducer or a validator put its own words (`[...]`). Keys in `added` are the document's own.
///
/// # Panics
///
/// Panics, naming the path, where the document and the encoding part anywhere else.
pub(crate) fn differs_only_where_said(
    label: &str,
    document: &Document,
    encoded: &Value,
    added: &[&str],
) {
    fn compare(
        label: &str,
        asked: &BTreeSet<String>,
        written: &Value,
        encoded: &Value,
        path: &str,
        added: &[&str],
    ) {
        match (written, encoded) {
            (Value::Object(written), Value::Object(encoded)) => {
                for key in written.keys() {
                    let inner = joined(path, key);
                    assert!(
                        encoded.contains_key(key) || added.contains(&inner.as_str()),
                        "{label}: the document adds {inner}, which the protocol does not encode"
                    );
                }
                for (key, value) in encoded {
                    let inner = joined(path, key);
                    let Some(held) = written.get(key) else {
                        panic!("{label}: the document leaves out {inner}");
                    };
                    compare(label, asked, held, value, &inner, added);
                }
            }
            (Value::Array(written), Value::Array(encoded)) => {
                assert_eq!(
                    written.len(),
                    encoded.len(),
                    "{label}: {path} has another length"
                );
                let inner = format!("{path}[]");
                for (held, value) in written.iter().zip(encoded) {
                    compare(label, asked, held, value, &inner, added);
                }
            }
            (Value::String(said), _) if written != encoded => assert!(
                asked.contains(path) || (said.starts_with('[') && said.ends_with(']')),
                "{label}: {path} says {said:?}, which is neither asked content, a reducer's words \
                 nor what the protocol encodes ({encoded})"
            ),
            _ => assert_eq!(
                written, encoded,
                "{label}: {path} is not what the protocol encodes"
            ),
        }
    }

    fn joined(path: &str, key: &str) -> String {
        if path.is_empty() {
            key.to_owned()
        } else {
            format!("{path}.{key}")
        }
    }

    compare(
        label,
        document.asked(),
        &document.json(),
        encoded,
        "",
        added,
    );
}

/// Holds lines to their rule: the marker shows only inside asked content.
///
/// # Panics
///
/// Panics, naming the line, where the marker shows anywhere else.
pub(crate) fn only_asked_lines(label: &str, lines: &[Line]) {
    for line in lines {
        assert_eq!(
            line.unasked(MARKER),
            0,
            "{label}: the planted text shows outside asked content in {:?}",
            line.text()
        );
    }
}
