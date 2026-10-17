//! The part of the generated schema that a control daemon and a worker of two releases meet.
//!
//! A [`Surface`] is the set of definitions reachable from some root types in a generated schema,
//! kept as the generator wrote them. A release keeps the surface of the release before it, and
//! compares it with its own: [`differences`] lists what is not the same, by walking both from the
//! roots through the references between definitions, so a definition that was renamed is not a
//! difference and a member that was added is.
//!
//! [`Surface::walk`] reads a value against a surface. It refuses a member the surface does not
//! have, a member it requires and the value lacks, a variant or a text constant it does not list,
//! and it lets a visitor see (and change) the value of every definition it passes through. That
//! is the shape check [`kr_cbor::check`] does not do: that one is about structure only, and leaves
//! text constants and required members to the typed layer, which checks the current type and not
//! the retained one. Scalar branches are not looked into here either: the JSON form a schema
//! describes is not the CBOR form on the wire (an integer is a decimal string in JSON, an
//! identifier is a byte string in CBOR), so their kinds and ranges stay with the typed layer, and
//! the golden frames and the real previous release are what cover them.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use kr_cbor::{CanonicalMap, CanonicalValue};
use serde_json::Value;

/// Keywords that describe a schema to its reader and decide nothing.
const IGNORED: [&str; 2] = ["description", "title"];

/// Why a surface could not be made.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SurfaceError {
    /// A root names no definition.
    #[error("the schema has no definition named {0}")]
    UnknownRoot(String),
    /// A reference does not name a definition of the schema.
    #[error("{0} is not a reference to a definition")]
    BadReference(String),
    /// The text is not a surface document.
    #[error("not a surface document: {0}")]
    NotASurface(String),
}

/// The definitions reachable from some roots in a generated schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Surface {
    roots: Vec<String>,
    definitions: BTreeMap<String, Value>,
}

impl Surface {
    /// Cuts the surface of `roots` out of a generated schema bundle.
    ///
    /// # Errors
    ///
    /// Returns [`SurfaceError::UnknownRoot`] for a root the bundle lacks, and
    /// [`SurfaceError::BadReference`] for a reference that is not to one of its definitions.
    pub fn cut(schema: &Value, roots: &[&str]) -> Result<Self, SurfaceError> {
        let all = schema
            .get("$defs")
            .and_then(Value::as_object)
            .ok_or_else(|| SurfaceError::NotASurface("no $defs".to_owned()))?;
        let mut definitions = BTreeMap::new();
        let mut todo: Vec<String> = Vec::new();
        for root in roots {
            if !all.contains_key(*root) {
                return Err(SurfaceError::UnknownRoot((*root).to_owned()));
            }
            todo.push((*root).to_owned());
        }
        while let Some(name) = todo.pop() {
            if definitions.contains_key(&name) {
                continue;
            }
            let definition = all
                .get(&name)
                .ok_or_else(|| SurfaceError::UnknownRoot(name.clone()))?;
            for reference in references(definition) {
                todo.push(reference_name(&reference)?);
            }
            definitions.insert(name, without_annotations(definition));
        }
        let mut roots: Vec<String> = roots.iter().map(|root| (*root).to_owned()).collect();
        roots.sort();
        roots.dedup();
        Ok(Self { roots, definitions })
    }

    /// Reads a surface document, as [`Surface::render`] writes it.
    ///
    /// # Errors
    ///
    /// Returns [`SurfaceError::NotASurface`] for text that is not one, and the errors of
    /// [`Surface::cut`] for one whose roots or references do not hold together.
    pub fn parse(text: &str) -> Result<Self, SurfaceError> {
        let document: Value = serde_json::from_str(text)
            .map_err(|error| SurfaceError::NotASurface(error.to_string()))?;
        let roots: Vec<String> = document
            .get("roots")
            .and_then(Value::as_array)
            .ok_or_else(|| SurfaceError::NotASurface("no roots".to_owned()))?
            .iter()
            .map(|root| {
                root.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| SurfaceError::NotASurface("a root is not text".to_owned()))
            })
            .collect::<Result<_, _>>()?;
        let roots: Vec<&str> = roots.iter().map(String::as_str).collect();
        let surface = Self::cut(&document, &roots)?;
        let declared = document
            .get("$defs")
            .and_then(Value::as_object)
            .map_or(0, serde_json::Map::len);
        if declared != surface.definitions.len() {
            return Err(SurfaceError::NotASurface(
                "the document holds a definition no root reaches".to_owned(),
            ));
        }
        Ok(surface)
    }

    /// Writes the surface as the document [`Surface::parse`] reads: sorted, indented, ending in a
    /// newline.
    ///
    /// # Panics
    ///
    /// Never in practice: a schema value is always serialisable.
    #[must_use]
    pub fn render(&self) -> String {
        let definitions: serde_json::Map<String, Value> = self
            .definitions
            .iter()
            .map(|(name, definition)| (name.clone(), definition.clone()))
            .collect();
        let mut document = serde_json::Map::new();
        document.insert(
            "roots".to_owned(),
            Value::Array(self.roots.iter().cloned().map(Value::String).collect()),
        );
        document.insert("$defs".to_owned(), Value::Object(definitions));
        let mut text = serde_json::to_string_pretty(&Value::Object(document))
            .expect("a surface is serialisable");
        text.push('\n');
        text
    }

    /// The root definitions, by name.
    #[must_use]
    pub fn roots(&self) -> &[String] {
        &self.roots
    }

    /// The names of every definition this surface holds.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.definitions.keys().map(String::as_str)
    }

    /// One definition, as the generator wrote it.
    #[must_use]
    pub fn definition(&self, name: &str) -> Option<&Value> {
        self.definitions.get(name)
    }

    /// The names of the definitions reachable from `roots` in this surface, the roots included.
    ///
    /// # Errors
    ///
    /// Returns [`SurfaceError::UnknownRoot`] for a name the surface lacks.
    pub fn closure(&self, roots: &[&str]) -> Result<BTreeSet<String>, SurfaceError> {
        let mut seen = BTreeSet::new();
        let mut todo: Vec<String> = roots.iter().map(|root| (*root).to_owned()).collect();
        while let Some(name) = todo.pop() {
            if !seen.insert(name.clone()) {
                continue;
            }
            let definition = self
                .definitions
                .get(&name)
                .ok_or_else(|| SurfaceError::UnknownRoot(name.clone()))?;
            for reference in references(definition) {
                todo.push(reference_name(&reference)?);
            }
        }
        Ok(seen)
    }
}

/// A schema without its descriptions and titles, which decide nothing and make a surface large.
///
/// Only a keyword whose value is text is an annotation: a member that happens to be named
/// `description` has a schema for its value.
fn without_annotations(node: &Value) -> Value {
    match node {
        Value::Object(members) => Value::Object(
            members
                .iter()
                .filter(|(key, value)| !(IGNORED.contains(&key.as_str()) && value.is_string()))
                .map(|(key, value)| (key.clone(), without_annotations(value)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(without_annotations).collect()),
        other => other.clone(),
    }
}

fn references(node: &Value) -> Vec<String> {
    let mut found = Vec::new();
    collect_references(node, &mut found);
    found
}

fn collect_references(node: &Value, found: &mut Vec<String>) {
    match node {
        Value::Object(members) => {
            if let Some(Value::String(reference)) = members.get("$ref") {
                found.push(reference.clone());
            }
            for member in members.values() {
                collect_references(member, found);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_references(item, found);
            }
        }
        _ => {}
    }
}

fn reference_name(reference: &str) -> Result<String, SurfaceError> {
    reference
        .strip_prefix("#/$defs/")
        .map(str::to_owned)
        .ok_or_else(|| SurfaceError::BadReference(reference.to_owned()))
}

/* -------------------------------------------------------------------------------------------- */
/* Differences                                                                                  */
/* -------------------------------------------------------------------------------------------- */

/// What is not the same between two surfaces.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Difference {
    /// Where, by the old surface's names: `Definition`, `Definition.member`, `Definition#variant`,
    /// and these nested (`Definition#variant.member[]`).
    pub at: String,
    /// What kind of difference.
    pub kind: DifferenceKind,
    /// What exactly, for a reader.
    pub detail: String,
}

/// The kinds of difference between two surfaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DifferenceKind {
    /// The new surface has a member, variant, constant or root the old one lacks.
    Added,
    /// The old surface has one the new one lacks.
    Removed,
    /// Both have it and a keyword of it differs.
    Changed,
}

impl Difference {
    /// The definition the difference is in: the part of [`Difference::at`] before its first `.`,
    /// `#` or `[`.
    #[must_use]
    pub fn definition(&self) -> &str {
        self.at
            .find(['.', '#', '['])
            .map_or(self.at.as_str(), |end| &self.at[..end])
    }
}

impl fmt::Display for Difference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.kind {
            DifferenceKind::Added => "added",
            DifferenceKind::Removed => "removed",
            DifferenceKind::Changed => "changed",
        };
        write!(formatter, "{} {kind}: {}", self.at, self.detail)
    }
}

/// Lists what differs between an old surface and a new one.
///
/// Both are walked from the roots they share through the references between definitions, so the
/// name a definition has on either side does not matter; only where it is used. Every keyword of
/// a schema is compared but its description and its title.
#[must_use]
pub fn differences(old: &Surface, new: &Surface) -> Vec<Difference> {
    let mut comparer = Comparer {
        old,
        new,
        seen: BTreeSet::new(),
        found: Vec::new(),
    };
    let mut names: BTreeSet<&str> = BTreeSet::new();
    names.extend(old.roots.iter().map(String::as_str));
    names.extend(new.roots.iter().map(String::as_str));
    for name in names {
        match (
            old.definitions.contains_key(name),
            new.definitions.contains_key(name),
        ) {
            (true, true) => comparer.definition(name, name),
            (true, false) => comparer.report(
                name,
                DifferenceKind::Removed,
                "a root the new surface lacks",
            ),
            (false, true) => {
                comparer.report(name, DifferenceKind::Added, "a root the old surface lacks")
            }
            (false, false) => {}
        }
    }
    comparer.found.sort();
    comparer.found.dedup();
    comparer.found
}

struct Comparer<'a> {
    old: &'a Surface,
    new: &'a Surface,
    seen: BTreeSet<(String, String)>,
    found: Vec<Difference>,
}

impl Comparer<'_> {
    fn report(&mut self, at: &str, kind: DifferenceKind, detail: &str) {
        self.found.push(Difference {
            at: at.to_owned(),
            kind,
            detail: detail.to_owned(),
        });
    }

    fn definition(&mut self, old: &str, new: &str) {
        if !self.seen.insert((old.to_owned(), new.to_owned())) {
            return;
        }
        let (Some(old_node), Some(new_node)) =
            (self.old.definitions.get(old), self.new.definitions.get(new))
        else {
            return;
        };
        self.node(old_node, new_node, old);
    }

    fn node(&mut self, old: &Value, new: &Value, at: &str) {
        match (reference_of(old), reference_of(new)) {
            (Some(old_name), Some(new_name)) => {
                self.definition(&old_name, &new_name);
                return;
            }
            (Some(_), None) | (None, Some(_)) => {
                self.report(
                    at,
                    DifferenceKind::Changed,
                    "a reference against an inline schema",
                );
                return;
            }
            (None, None) => {}
        }
        let (Value::Object(old_members), Value::Object(new_members)) = (old, new) else {
            if old != new {
                self.report(at, DifferenceKind::Changed, "the schema");
            }
            return;
        };
        let mut keywords: BTreeSet<&str> = BTreeSet::new();
        keywords.extend(old_members.keys().map(String::as_str));
        keywords.extend(new_members.keys().map(String::as_str));
        for keyword in keywords {
            if IGNORED.contains(&keyword) {
                continue;
            }
            let (before, after) = (old_members.get(keyword), new_members.get(keyword));
            match keyword {
                "properties" => self.properties(before, after, at),
                "required" => self.required(before, after, at),
                "oneOf" | "anyOf" => self.branches(keyword, before, after, at),
                "items" | "additionalProperties" => match (before, after) {
                    (Some(before @ Value::Object(_)), Some(after @ Value::Object(_))) => {
                        let nested = if keyword == "items" {
                            format!("{at}[]")
                        } else {
                            format!("{at}{{}}")
                        };
                        self.node(before, after, &nested);
                    }
                    _ if before != after => {
                        self.report(at, DifferenceKind::Changed, keyword);
                    }
                    _ => {}
                },
                _ if before != after => {
                    self.report(at, DifferenceKind::Changed, keyword);
                }
                _ => {}
            }
        }
    }

    fn properties(&mut self, before: Option<&Value>, after: Option<&Value>, at: &str) {
        let empty = serde_json::Map::new();
        let before = before.and_then(Value::as_object).unwrap_or(&empty);
        let after = after.and_then(Value::as_object).unwrap_or(&empty);
        let mut names: BTreeSet<&str> = BTreeSet::new();
        names.extend(before.keys().map(String::as_str));
        names.extend(after.keys().map(String::as_str));
        for name in names {
            let nested = format!("{at}.{name}");
            match (before.get(name), after.get(name)) {
                (Some(old), Some(new)) => self.node(old, new, &nested),
                (Some(_), None) => self.report(&nested, DifferenceKind::Removed, "a member"),
                (None, Some(_)) => self.report(&nested, DifferenceKind::Added, "a member"),
                (None, None) => {}
            }
        }
    }

    fn required(&mut self, before: Option<&Value>, after: Option<&Value>, at: &str) {
        let names = |value: Option<&Value>| -> BTreeSet<String> {
            value
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|name| name.as_str().map(str::to_owned))
                .collect()
        };
        let (before, after) = (names(before), names(after));
        for name in before.difference(&after) {
            self.report(
                &format!("{at}.{name}"),
                DifferenceKind::Changed,
                "no longer required",
            );
        }
        for name in after.difference(&before) {
            self.report(
                &format!("{at}.{name}"),
                DifferenceKind::Changed,
                "now required",
            );
        }
    }

    fn branches(&mut self, keyword: &str, before: Option<&Value>, after: Option<&Value>, at: &str) {
        let (Some(Value::Array(old)), Some(Value::Array(new))) = (before, after) else {
            if before != after {
                self.report(at, DifferenceKind::Changed, keyword);
            }
            return;
        };
        // A nullable value is a choice of one schema and null: it is the schema's, and the choice
        // adds no part to the place.
        if let (Some(old_inner), Some(new_inner)) = (nullable(old), nullable(new)) {
            self.node(old_inner, new_inner, at);
            return;
        }
        let old_heads = heads(old);
        let new_heads = heads(new);
        let mut names: BTreeSet<&String> = BTreeSet::new();
        names.extend(old_heads.keys());
        names.extend(new_heads.keys());
        for head in names {
            let nested = format!("{at}#{head}");
            match (old_heads.get(head), new_heads.get(head)) {
                (Some(old), Some(new)) => self.node(old, new, &nested),
                (Some(_), None) => self.report(&nested, DifferenceKind::Removed, "a variant"),
                (None, Some(_)) => self.report(&nested, DifferenceKind::Added, "a variant"),
                (None, None) => {}
            }
        }
    }
}

fn reference_of(node: &Value) -> Option<String> {
    node.get("$ref")
        .and_then(Value::as_str)
        .and_then(|reference| reference.strip_prefix("#/$defs/"))
        .map(str::to_owned)
}

/// The one non-null schema of a nullable value, when the branches are exactly that and null.
fn nullable(branches: &[Value]) -> Option<&Value> {
    if branches.len() != 2 {
        return None;
    }
    let is_null = |branch: &Value| branch.get("type").and_then(Value::as_str) == Some("null");
    match (is_null(&branches[0]), is_null(&branches[1])) {
        (false, true) => Some(&branches[0]),
        (true, false) => Some(&branches[1]),
        _ => None,
    }
}

/// What tells one branch of a choice from the others: a text constant, a reference, the one key of
/// a variant carried by name, the constant member of a variant carried with a tag, or else the
/// names of its members.
fn head(branch: &Value) -> String {
    if let Some(constant) = branch.get("const") {
        return format!(
            "const:{}",
            constant
                .as_str()
                .map_or_else(|| constant.to_string(), str::to_owned)
        );
    }
    if let Some(name) = reference_of(branch) {
        return format!("ref:{name}");
    }
    if let Some(Value::Object(members)) = branch.get("properties") {
        let required: Vec<&str> = branch
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        for (name, member) in members {
            if let Some(Value::String(constant)) = member.get("const") {
                return format!("tag:{name}={constant}");
            }
        }
        if let [only] = required.as_slice() {
            return format!("key:{only}");
        }
        let names: Vec<&str> = members.keys().map(String::as_str).collect();
        return format!("object:{}", names.join(","));
    }
    branch
        .get("type")
        .and_then(Value::as_str)
        .map_or_else(|| "any".to_owned(), |kind| format!("type:{kind}"))
}

fn heads(branches: &[Value]) -> BTreeMap<String, &Value> {
    let mut found = BTreeMap::new();
    for (position, branch) in branches.iter().enumerate() {
        let mut name = head(branch);
        if found.contains_key(&name) {
            name = format!("{name}@{position}");
        }
        found.insert(name, branch);
    }
    found
}

/* -------------------------------------------------------------------------------------------- */
/* Reading a value against a surface                                                            */
/* -------------------------------------------------------------------------------------------- */

/// Why a value does not fit a surface.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The value has a member the definition does not have.
    #[error("{definition} has no member {member}")]
    UnknownMember {
        /// The definition.
        definition: String,
        /// The member.
        member: String,
    },
    /// The definition requires a member the value lacks.
    #[error("{definition} requires {member}")]
    MissingMember {
        /// The definition.
        definition: String,
        /// The member.
        member: String,
    },
    /// The value names a variant the definition does not list.
    #[error("{definition} has no variant {found}")]
    UnknownVariant {
        /// The definition.
        definition: String,
        /// What the value names.
        found: String,
    },
    /// The value is a text the definition does not list.
    #[error("{definition} has no value {found}")]
    UnknownConstant {
        /// The definition.
        definition: String,
        /// The text.
        found: String,
    },
    /// The value is not of the kind the definition describes.
    #[error("{definition} is {expected}")]
    WrongKind {
        /// The definition.
        definition: String,
        /// The kind it describes.
        expected: &'static str,
    },
    /// A rewrite declared for the definition could not be applied.
    #[error("{definition} could not be rewritten: {why}")]
    Rewrite {
        /// The definition.
        definition: String,
        /// Why.
        why: String,
    },
}

/// Sees every value of a definition that [`Surface::walk`] has read, and may change it.
///
/// The value is shown after its content was read and found to fit the surface, innermost first, so
/// a change a visitor makes to a value is a change to something already known to be well formed,
/// and the surface's reading of the value around it is not disturbed.
pub trait Visit {
    /// Called with the definition's name and the value that stands for it.
    ///
    /// # Errors
    ///
    /// Returns a refusal to stop the walk.
    fn leave(&mut self, definition: &str, value: &mut CanonicalValue) -> Result<(), Refusal>;
}

/// A visitor that looks and changes nothing.
#[derive(Debug, Default)]
pub struct Plain;

impl Visit for Plain {
    fn leave(&mut self, _definition: &str, _value: &mut CanonicalValue) -> Result<(), Refusal> {
        Ok(())
    }
}

impl Surface {
    /// Reads `value` as the definition `root`: refuses what the surface does not admit, and shows
    /// `visitor` the value of every definition once it was read, innermost first.
    ///
    /// # Errors
    ///
    /// Returns the first [`Refusal`], or a refusal of the visitor.
    pub fn walk(
        &self,
        root: &str,
        value: &mut CanonicalValue,
        visitor: &mut dyn Visit,
    ) -> Result<(), Refusal> {
        let Some(definition) = self.definitions.get(root) else {
            return Err(Refusal::UnknownVariant {
                definition: "the surface".to_owned(),
                found: root.to_owned(),
            });
        };
        self.descend(definition, value, root, visitor)?;
        visitor.leave(root, value)
    }

    fn descend(
        &self,
        node: &Value,
        value: &mut CanonicalValue,
        definition: &str,
        visitor: &mut dyn Visit,
    ) -> Result<(), Refusal> {
        if let Some(name) = reference_of(node) {
            return self.walk(&name, value, visitor);
        }
        if let Some(Value::String(constant)) = node.get("const") {
            return match value {
                CanonicalValue::Text(text) if text == constant => Ok(()),
                CanonicalValue::Text(text) => Err(Refusal::UnknownConstant {
                    definition: definition.to_owned(),
                    found: text.clone(),
                }),
                _ => Err(wrong_kind(definition, "text")),
            };
        }
        if let Some(Value::Array(branches)) = node.get("oneOf").or_else(|| node.get("anyOf")) {
            return self.choose(branches, value, definition, visitor);
        }
        match node.get("type").and_then(Value::as_str) {
            Some("object") => self.object(node, value, definition, visitor),
            Some("array") => {
                let CanonicalValue::Array(items) = value else {
                    return Err(wrong_kind(definition, "an array"));
                };
                if let Some(schema) = node.get("items") {
                    for item in items {
                        self.descend(schema, item, definition, visitor)?;
                    }
                }
                Ok(())
            }
            // A scalar: its kind and range are the typed layer's.
            _ => Ok(()),
        }
    }

    fn choose(
        &self,
        branches: &[Value],
        value: &mut CanonicalValue,
        definition: &str,
        visitor: &mut dyn Visit,
    ) -> Result<(), Refusal> {
        if matches!(value, CanonicalValue::Null) {
            return if branches.iter().any(|branch| self.admits_null(branch)) {
                Ok(())
            } else {
                Err(wrong_kind(definition, "not null"))
            };
        }
        for branch in branches {
            if self.matches(branch, value) {
                return self.descend(branch, value, definition, visitor);
            }
        }
        Err(Refusal::UnknownVariant {
            definition: definition.to_owned(),
            found: describe(value),
        })
    }

    fn admits_null(&self, branch: &Value) -> bool {
        match reference_of(branch) {
            Some(name) => self
                .definitions
                .get(&name)
                .is_some_and(|inner| self.admits_null(inner)),
            None => branch.get("type").and_then(Value::as_str) == Some("null"),
        }
    }

    /// Whether `value` is the sort of value `branch` describes, as far as telling the branches of
    /// a choice apart goes.
    fn matches(&self, branch: &Value, value: &CanonicalValue) -> bool {
        if let Some(name) = reference_of(branch) {
            return self
                .definitions
                .get(&name)
                .is_some_and(|inner| self.matches(inner, value));
        }
        if let Some(constant) = branch.get("const") {
            return matches!((constant, value), (Value::String(constant), CanonicalValue::Text(text)) if constant == text);
        }
        if let Some(Value::Array(branches)) = branch.get("oneOf").or_else(|| branch.get("anyOf")) {
            return branches.iter().any(|inner| self.matches(inner, value));
        }
        match branch.get("type").and_then(Value::as_str) {
            Some("object") => {
                let CanonicalValue::Map(map) = value else {
                    return false;
                };
                let required: Vec<&str> = branch
                    .get("required")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect();
                if let Some(Value::Object(members)) = branch.get("properties") {
                    for (name, member) in members {
                        if let Some(Value::String(constant)) = member.get("const") {
                            return matches!(map.get(name), Some(CanonicalValue::Text(text)) if text == constant);
                        }
                    }
                }
                if let [only] = required.as_slice() {
                    return map.get(only).is_some();
                }
                true
            }
            Some("array") => matches!(value, CanonicalValue::Array(_)),
            Some("null") => matches!(value, CanonicalValue::Null),
            _ => !matches!(
                value,
                CanonicalValue::Map(_) | CanonicalValue::Array(_) | CanonicalValue::Null
            ),
        }
    }

    fn object(
        &self,
        node: &Value,
        value: &mut CanonicalValue,
        definition: &str,
        visitor: &mut dyn Visit,
    ) -> Result<(), Refusal> {
        let CanonicalValue::Map(map) = value else {
            return Err(wrong_kind(definition, "a map"));
        };
        let properties = node.get("properties").and_then(Value::as_object);
        let keyed = node
            .get("additionalProperties")
            .filter(|schema| schema.is_object());
        let closed = node.get("additionalProperties") == Some(&Value::Bool(false));
        let entries = std::mem::take(map).into_entries();
        let mut kept: Vec<(String, CanonicalValue)> = Vec::with_capacity(entries.len());
        let mut outcome = Ok(());
        for (key, mut member) in entries {
            if outcome.is_ok() {
                outcome = match (properties.and_then(|members| members.get(&key)), keyed) {
                    (Some(schema), _) | (None, Some(schema)) => {
                        self.descend(schema, &mut member, definition, visitor)
                    }
                    (None, None) if closed || properties.is_some() => Err(Refusal::UnknownMember {
                        definition: definition.to_owned(),
                        member: key.clone(),
                    }),
                    (None, None) => Ok(()),
                };
            }
            kept.push((key, member));
        }
        // Whatever the walk did, the value is put back as it was found or as the visitor left it.
        *value = CanonicalValue::Map(
            CanonicalMap::from_sorted_entries(kept).unwrap_or_else(|_| CanonicalMap::new()),
        );
        outcome?;
        let CanonicalValue::Map(map) = value else {
            return Ok(());
        };
        if let Some(Value::Array(required)) = node.get("required") {
            for name in required.iter().filter_map(Value::as_str) {
                if map.get(name).is_none() {
                    return Err(Refusal::MissingMember {
                        definition: definition.to_owned(),
                        member: name.to_owned(),
                    });
                }
            }
        }
        Ok(())
    }
}

fn wrong_kind(definition: &str, expected: &'static str) -> Refusal {
    Refusal::WrongKind {
        definition: definition.to_owned(),
        expected,
    }
}

fn describe(value: &CanonicalValue) -> String {
    match value {
        CanonicalValue::Text(text) => text.clone(),
        CanonicalValue::Map(map) => map
            .entries()
            .first()
            .map_or_else(|| "an empty map".to_owned(), |(key, _)| key.clone()),
        CanonicalValue::Array(_) => "an array".to_owned(),
        CanonicalValue::Null => "null".to_owned(),
        CanonicalValue::Bool(_) => "a boolean".to_owned(),
        CanonicalValue::Integer(_) => "an integer".to_owned(),
        CanonicalValue::Bytes(_) => "a byte string".to_owned(),
    }
}
