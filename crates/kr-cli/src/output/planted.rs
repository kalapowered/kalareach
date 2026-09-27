//! Values of the protocol's types with the marker planted in every leaf of free text, and the checks
//! that say where an output let such text through.
//!
//! A value is built from its type's JSON schema: every property and one element of every list. A
//! choice (an enumeration, `oneOf` or `anyOf`) takes its first alternative unless a build holds it
//! to another, and the builds go on until every alternative of every choice met has been taken at
//! least once, each reached along the choices that led to it the first time, so a choice nested in
//! one variant of another is built in each of its own alternatives. A string leaf with no format or
//! pattern holds the marker, with a colon and a space after it so that no identifier grammar a
//! validator checks accepts it. A leaf with a format or a pattern holds an example of it, and a type
//! whose own checks go further than its schema has an example here.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::output::{Document, Line};
use crate::shown::marker::MARKER;

/// What a leaf of free text holds.
pub(crate) fn planted_text() -> String {
    format!("{MARKER}: planted")
}

/// Every value of `T` this builds: enough for every alternative of every choice in its schema to
/// be taken at least once.
///
/// # Panics
///
/// Panics when a built value does not read back as a `T`, naming the type and the value, so a type
/// whose own checks go further than its schema can be given an example; and when a choice met is
/// left with an alternative no build took.
pub(crate) fn planted<T: JsonSchema + DeserializeOwned>() -> Vec<T> {
    let schema = schemars::generate::SchemaSettings::draft2020_12()
        .into_generator()
        .into_root_schema_for::<T>();
    let root = schema.as_value().clone();
    let definitions = root.get("$defs").cloned().unwrap_or(Value::Null);
    // The choices met, each with its number of alternatives and the alternatives taken.
    let mut met: BTreeMap<String, (usize, BTreeSet<usize>)> = BTreeMap::new();
    // The choices taken on the way to each choice the first time it was met.
    let mut routes: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    let mut queued: BTreeSet<(String, usize)> = BTreeSet::new();
    let mut builds = VecDeque::from([BTreeMap::new()]);
    let mut values = Vec::new();
    while let Some(held) = builds.pop_front() {
        let mut build = Build {
            definitions: &definitions,
            held,
            taken: Vec::new(),
            route: Vec::new(),
            routes: BTreeMap::new(),
        };
        let value = build.built(&root, "#", 0);
        values.push(
            serde_json::from_value::<T>(value.clone()).unwrap_or_else(|error| {
                panic!(
                    "a planted {} does not read back: {error}\n{value:#}",
                    std::any::type_name::<T>()
                )
            }),
        );
        for (choice, count, taken) in build.taken {
            met.entry(choice)
                .or_insert_with(|| (count, BTreeSet::new()))
                .1
                .insert(taken);
        }
        for (choice, route) in build.routes {
            routes.entry(choice).or_insert(route);
        }
        for (choice, (count, taken)) in &met {
            for alternative in (0..*count).filter(|alternative| !taken.contains(alternative)) {
                if queued.insert((choice.clone(), alternative)) {
                    let mut held = routes.get(choice).cloned().unwrap_or_default();
                    held.insert(choice.clone(), alternative);
                    builds.push_back(held);
                }
            }
        }
    }
    for (choice, (count, taken)) in &met {
        assert_eq!(
            taken.len(),
            *count,
            "{}: the choice at {choice} was not built in every alternative",
            std::any::type_name::<T>()
        );
    }
    values
}

/// One build of a value: which alternative each choice is held to, and what it met.
struct Build<'a> {
    definitions: &'a Value,
    /// The alternative each choice is held to, by where the choice is in the schema; any other
    /// takes its first.
    held: BTreeMap<String, usize>,
    /// Each choice met, with its number of alternatives and the one taken.
    taken: Vec<(String, usize, usize)>,
    /// The choices taken on the way to where the build is.
    route: Vec<(String, usize)>,
    /// The route to each choice met, as a build holds it to reach that choice again.
    routes: BTreeMap<String, BTreeMap<String, usize>>,
}

impl Build<'_> {
    /// The alternative the choice at `choice` takes, of `count`.
    fn choose(&mut self, choice: &str, count: usize) -> usize {
        let taken = self
            .held
            .get(choice)
            .copied()
            .unwrap_or(0)
            .min(count.saturating_sub(1));
        self.taken.push((choice.to_owned(), count, taken));
        self.routes
            .entry(choice.to_owned())
            .or_insert_with(|| self.route.iter().cloned().collect());
        taken
    }

    /// A value of `schema`, which is at `at` in the schema.
    fn built(&mut self, schema: &Value, at: &str, depth: usize) -> Value {
        assert!(
            depth < 96,
            "the schema nests deeper than any protocol type does"
        );
        if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
            let name = reference.trim_start_matches("#/$defs/");
            if let Some(example) = example(name) {
                return example;
            }
            let definition = &self.definitions[name];
            let mut value = self.built(definition, name, depth + 1);
            // A reference with properties beside it adds them.
            if let (Value::Object(object), Some(Value::Object(properties))) =
                (&mut value, schema.get("properties"))
            {
                for (key, property) in properties {
                    let inner = self.built(property, &format!("{at}/properties/{key}"), depth + 1);
                    object.insert(key.clone(), inner);
                }
            }
            return value;
        }
        if let Some(value) = schema.get("const") {
            return value.clone();
        }
        if let Some(values) = schema.get("enum").and_then(Value::as_array) {
            let taken = self.choose(&format!("{at}/enum"), values.len());
            return values.get(taken).cloned().unwrap_or(Value::Null);
        }
        for key in ["oneOf", "anyOf"] {
            if let Some(choices) = schema.get(key).and_then(Value::as_array) {
                // Null is taken only where nothing else can be: a leaf that can hold text holds it.
                let real = choices
                    .iter()
                    .enumerate()
                    .filter(|(_, choice)| {
                        choice.get("type").and_then(Value::as_str) != Some("null")
                    })
                    .collect::<Vec<_>>();
                if real.is_empty() {
                    return Value::Null;
                }
                let choice = format!("{at}/{key}");
                let taken = self.choose(&choice, real.len());
                let (index, alternative) = real[taken];
                self.route.push((choice, taken));
                let mut value = self.built(alternative, &format!("{at}/{key}/{index}"), depth + 1);
                self.route.pop();
                // An internally tagged enum puts the fields every variant shares beside its choices.
                if let (Value::Object(object), Some(Value::Object(properties))) =
                    (&mut value, schema.get("properties"))
                {
                    for (name, property) in properties {
                        if !object.contains_key(name) {
                            let inner =
                                self.built(property, &format!("{at}/properties/{name}"), depth + 1);
                            object.insert(name.clone(), inner);
                        }
                    }
                }
                return value;
            }
        }
        if let Some(parts) = schema.get("allOf").and_then(Value::as_array) {
            let mut merged = Map::new();
            for (index, part) in parts.iter().enumerate() {
                if let Value::Object(object) =
                    self.built(part, &format!("{at}/allOf/{index}"), depth + 1)
                {
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
                        let inner =
                            self.built(property, &format!("{at}/properties/{key}"), depth + 1);
                        object.insert(key.clone(), inner);
                    }
                }
                if let Some(entry) = schema
                    .get("additionalProperties")
                    .filter(|entry| entry.is_object())
                {
                    let inner = self.built(entry, &format!("{at}/additionalProperties"), depth + 1);
                    object.insert(planted_key(schema), inner);
                }
                Value::Object(object)
            }
            "array" => {
                if let Some(Value::Array(items)) = schema.get("prefixItems") {
                    let mut built = Vec::new();
                    for (index, item) in items.iter().enumerate() {
                        built.push(self.built(
                            item,
                            &format!("{at}/prefixItems/{index}"),
                            depth + 1,
                        ));
                    }
                    return Value::Array(built);
                }
                let count = schema
                    .get("minItems")
                    .and_then(Value::as_u64)
                    .unwrap_or(1)
                    .max(1);
                let item = schema.get("items").cloned().unwrap_or(Value::Null);
                let mut built = Vec::new();
                for _ in 0..count {
                    built.push(self.built(&item, &format!("{at}/items"), depth + 1));
                }
                Value::Array(built)
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

/// Every place in `value` whose text holds the marker, as a path of keys and `[n]` for the list
/// element at `n`.
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
            for (index, value) in values.iter().enumerate() {
                walk(value, &format!("{path}[{index}]"), found);
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
/// asked content, element by element, or at one of `doors`, written with `[]` for every element
/// of a list. The schema a value is planted from cannot tell a field of that text from any other
/// string, so the fields are named here. Returns where the marker showed, each list element's
/// place written `[]`.
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
            document.asked().contains(path) || doors.contains(&any_element(path).as_str()),
            "{label}: the planted text shows at {path}, which holds no asked content\n{json:#}"
        );
    }
    found.iter().map(|path| any_element(path)).collect()
}

/// A path with every list element's place written `[]`, as a rule names the fields of every
/// element at once.
pub(crate) fn any_element(path: &str) -> String {
    let mut written = String::with_capacity(path.len());
    let mut rest = path;
    while let Some(open) = rest.find('[') {
        written.push_str(&rest[..=open]);
        rest = &rest[open + 1..];
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0 && rest[digits..].starts_with(']') {
            rest = &rest[digits..];
        }
    }
    written.push_str(rest);
    written
}

/// Whether `said` is a reducer's or a validator's own words in place of a string: a class and a
/// length in the host's wording, or the placeholder for text that is not an identifier.
fn reducers_words(said: &str) -> bool {
    if said == "[not an identifier]" {
        return true;
    }
    said.strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(" bytes]"))
        .and_then(|inner| inner.split_once(" withheld, "))
        .is_some_and(|(class, length)| {
            !class.is_empty()
                && class
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
                && length.parse::<u64>().is_ok()
        })
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
/// as it is: the same keys, and the same leaves but where the document holds asked content, element
/// by element, or where a reducer or a validator put its own words in place of a string the
/// protocol encodes (a class and a length, or `[not an identifier]`). Keys in `added` are the
/// document's own.
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
                for (index, (held, value)) in written.iter().zip(encoded).enumerate() {
                    compare(
                        label,
                        asked,
                        held,
                        value,
                        &format!("{path}[{index}]"),
                        added,
                    );
                }
            }
            (Value::String(said), _) if written != encoded => assert!(
                asked.contains(path) || (encoded.is_string() && reducers_words(said)),
                "{label}: {path} says {said:?}, which is neither asked content, a reducer's words \
                 in place of a string nor what the protocol encodes ({encoded})"
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
