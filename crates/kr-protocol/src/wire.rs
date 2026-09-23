//! Reading a protocol message: its bytes, then its schema, then its type.
//!
//! Section 9 has a receiver refuse duplicate keys, invalid UTF-8 and unrecognised fields before
//! ordinary deserialisation. Every protocol message is read here, in that order:
//!
//! 1. [`kr_cbor::decode`] applies every byte rule, duplicate keys and invalid UTF-8 among them,
//!    before it builds a value;
//! 2. [`kr_cbor::check`] reads the value against the structure the message's type publishes and
//!    refuses a key the schema does not declare;
//! 3. serde builds the typed value, and the round trip in [`kr_cbor::from_canonical_value`] holds
//!    it to the one encoding the type writes.
//!
//! A message refused at the first or second step never reaches the third.
//!
//! # Where the structure comes from
//!
//! The structure is compiled from the type's JSON Schema, the one `packages/protocol` publishes and
//! generates its TypeScript from, so the check enforces the contract other implementations read.
//! Each type is compiled once per process and kept. Every object is closed unless its schema
//! carries [`READ_ONLY_METADATA`]; an object that says nothing is closed whatever serde would
//! tolerate.

use std::any::TypeId;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, LazyLock, PoisonError, RwLock};

use kr_cbor::{
    AdmittedMember, CanonicalValue, CborError, Limits, ObjectShape, Shape, TaggedShape, Undeclared,
};
use schemars::JsonSchema;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::error::ErrorCode;
use crate::extension::NegotiatedExtensions;

/// The schema keyword that marks an object as read-only metadata.
///
/// Section 23 lets read-only metadata add explicitly optional fields that a receiver ignores. An
/// object whose schema carries this keyword set to `true` is one: a field it does not declare is
/// removed before typed decoding and never delivered. Every other object refuses such a field.
pub const READ_ONLY_METADATA: &str = "x-kalareach-read-only-metadata";

/// A type this module reads: a protocol message that publishes its schema.
pub trait WireMessage: DeserializeOwned + Serialize + JsonSchema + 'static {}

impl<T> WireMessage for T where T: DeserializeOwned + Serialize + JsonSchema + 'static {}

/// Reads one protocol message from canonical bytes, admitting no extension member.
///
/// # Errors
///
/// Returns the first broken byte rule, then [`CborError::UnknownField`],
/// [`CborError::UnknownVariant`] or [`CborError::UnnegotiatedExtension`] for what the schema does
/// not admit, and only then a typed decoding failure.
pub fn decode<T: WireMessage>(bytes: &[u8], limits: &Limits) -> Result<T, CborError> {
    from_value(&kr_cbor::decode(bytes, limits)?)
}

/// Reads one protocol message from a value that already passed the byte rules, admitting no
/// extension member.
///
/// This is how an opaque value inside a message, a method's parameters or result, is read into its
/// own schema.
///
/// # Errors
///
/// As [`decode`], without the byte rules.
pub fn from_value<T: WireMessage>(value: &CanonicalValue) -> Result<T, CborError> {
    from_value_extended(value, &NegotiatedExtensions::none()).map(|extended| extended.message)
}

/// A message and the members of the negotiated extensions it carried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extended<T> {
    /// The message, typed without its extension members.
    pub message: T,
    /// Each extension member, checked against its extension's schema, with where it was.
    pub members: Vec<AdmittedMember>,
}

/// Reads one protocol message from canonical bytes on a connection that negotiated `extensions`.
///
/// # Errors
///
/// As [`decode`]; a member of an extension that is not negotiated, or that does not extend the
/// object carrying it, is [`CborError::UnnegotiatedExtension`].
pub fn decode_extended<T: WireMessage>(
    bytes: &[u8],
    limits: &Limits,
    extensions: &NegotiatedExtensions,
) -> Result<Extended<T>, CborError> {
    from_value_extended(&kr_cbor::decode(bytes, limits)?, extensions)
}

/// Reads one protocol message from a value on a connection that negotiated `extensions`.
///
/// # Errors
///
/// As [`decode_extended`], without the byte rules.
pub fn from_value_extended<T: WireMessage>(
    value: &CanonicalValue,
    extensions: &NegotiatedExtensions,
) -> Result<Extended<T>, CborError> {
    let checked = kr_cbor::check(value, &shape_of::<T>(), extensions)?;
    Ok(Extended {
        message: kr_cbor::from_canonical_value(&checked.value)?,
        members: checked.members,
    })
}

/// Returns the error code a message refused while it was read answers with.
///
/// What the schema does not admit, a field, a variant or an extension member, is a schema the
/// receiver does not support: `UNSUPPORTED_SCHEMA`. Every byte rule, duplicate keys and invalid
/// UTF-8 included, is a malformed message: `INVALID_ARGUMENT`. So is a typed decoding failure, which
/// is a field of the wrong kind or out of its range.
#[must_use]
pub const fn refusal_code(error: &CborError) -> ErrorCode {
    match error {
        CborError::UnknownField { .. }
        | CborError::UnknownVariant { .. }
        | CborError::UnnegotiatedExtension { .. } => ErrorCode::UnsupportedSchema,
        _ => ErrorCode::InvalidArgument,
    }
}

/// Every compiled structure, by type.
static SHAPES: LazyLock<RwLock<HashMap<TypeId, Arc<Shape>>>> = LazyLock::new(RwLock::default);

/// Returns the structure `T` publishes, compiling it on first use.
#[must_use]
pub fn shape_of<T: JsonSchema + 'static>() -> Arc<Shape> {
    let key = TypeId::of::<T>();
    if let Some(shape) = SHAPES
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&key)
    {
        return Arc::clone(shape);
    }
    let shape = Arc::new(compile(&crate::schema::schema_for::<T>()));
    Arc::clone(
        SHAPES
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(key)
            .or_insert(shape),
    )
}

/// Compiles a root JSON Schema, with its `$defs`, into the structure the check reads.
///
/// The compiler reads the forms the schema generator writes for this crate's types: references
/// into `$defs`, `oneOf` for enum variants, `anyOf` for nullable values, objects with `properties`,
/// objects with only `additionalProperties` or `patternProperties` (maps keyed by data), arrays
/// with `items`, and scalars.
/// Variants that are objects sharing a field whose value is a different constant in each are
/// selected by that field, the way the typed decoder selects them ([`Shape::Tagged`]). A schema
/// that carries no structural keyword, such as an opaque value's, is [`Shape::Any`], and so is a
/// recursive reference, which no protocol type has.
#[must_use]
pub fn compile(root: &Value) -> Shape {
    let mut compiler = Compiler {
        definitions: root.get("$defs").and_then(Value::as_object),
        compiled: HashMap::new(),
        compiling: Vec::new(),
    };
    compiler.schema(root, root.get("title").and_then(Value::as_str))
}

struct Compiler<'s> {
    definitions: Option<&'s Map<String, Value>>,
    compiled: HashMap<&'s str, Shape>,
    compiling: Vec<&'s str>,
}

impl<'s> Compiler<'s> {
    fn schema(&mut self, schema: &'s Value, name: Option<&str>) -> Shape {
        // `true` admits anything and `false` nothing; neither describes a structure.
        let Value::Object(keywords) = schema else {
            return Shape::Any;
        };
        if let Some(Value::String(reference)) = keywords.get("$ref") {
            return self.reference(reference);
        }
        for combinator in ["oneOf", "anyOf"] {
            if let Some(Value::Array(branches)) = keywords.get(combinator) {
                if let Some(tagged) = self.tagged(branches, name) {
                    return tagged;
                }
                let shapes = branches
                    .iter()
                    .map(|branch| self.schema(branch, name))
                    .collect();
                return one_of(shapes);
            }
        }
        match keywords.get("type") {
            Some(Value::String(kind)) => self.typed(kind, keywords, name),
            Some(Value::Array(kinds)) => {
                let shapes = kinds
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|kind| self.typed(kind, keywords, name))
                    .collect();
                one_of(shapes)
            }
            _ if keywords.contains_key("const") || keywords.contains_key("enum") => Shape::Scalar,
            _ => Shape::Any,
        }
    }

    fn typed(&mut self, kind: &str, keywords: &'s Map<String, Value>, name: Option<&str>) -> Shape {
        match kind {
            "object" => self.object(keywords, name),
            "array" => Shape::Array(Arc::new(
                keywords
                    .get("items")
                    .map_or(Shape::Any, |items| self.schema(items, None)),
            )),
            _ => Shape::Scalar,
        }
    }

    fn object(&mut self, keywords: &'s Map<String, Value>, name: Option<&str>) -> Shape {
        let properties = keywords.get("properties").and_then(Value::as_object);
        if properties.is_none() {
            // No declared field and a schema for the values: a map keyed by data. A key type with
            // a pattern gives its value schema under `patternProperties` instead; the key itself
            // is the typed layer's to validate.
            let mut members: Vec<Shape> = keywords
                .get("patternProperties")
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
                .map(|(_, member)| self.schema(member, None))
                .collect();
            if let Some(member @ Value::Object(_)) = keywords.get("additionalProperties") {
                members.push(self.schema(member, None));
            }
            if !members.is_empty() {
                return Shape::Map(Arc::new(one_of(members)));
            }
        }
        let fields = properties
            .into_iter()
            .flatten()
            .map(|(field, schema)| (field.clone(), self.schema(schema, None)))
            .collect();
        let undeclared = if keywords.get(READ_ONLY_METADATA) == Some(&Value::Bool(true)) {
            Undeclared::Ignore
        } else {
            Undeclared::Refuse
        };
        Shape::Object(Arc::new(ObjectShape {
            name: name.map(str::to_owned),
            fields,
            undeclared,
        }))
    }

    /// Compiles variants told apart by a tag field, when these branches are such variants.
    ///
    /// The tag is a field every branch declares with a text constant, a different one in each.
    fn tagged(&mut self, branches: &'s [Value], name: Option<&str>) -> Option<Shape> {
        let properties: Vec<&'s Map<String, Value>> = branches
            .iter()
            .map(|branch| {
                self.resolve(branch)?
                    .get("properties")
                    .and_then(Value::as_object)
            })
            .collect::<Option<_>>()?;
        if properties.len() < 2 {
            return None;
        }
        let constant = |properties: &'s Map<String, Value>, field: &str| {
            properties
                .get(field)
                .and_then(|schema| schema.get("const"))
                .and_then(Value::as_str)
        };
        let tag = properties[0].keys().find(|field| {
            let mut seen = BTreeSet::new();
            properties
                .iter()
                .all(|branch| constant(branch, field).is_some_and(|value| seen.insert(value)))
        })?;
        let mut variants = BTreeMap::new();
        for (branch, fields) in branches.iter().zip(&properties) {
            let Shape::Object(object) = self.schema(branch, name) else {
                return None;
            };
            variants.insert(constant(fields, tag)?.to_owned(), object);
        }
        Some(Shape::Tagged(Arc::new(TaggedShape::new(
            name.map(str::to_owned),
            tag.clone(),
            variants,
        ))))
    }

    /// Follows a reference into `$defs`, or returns the schema itself.
    fn resolve(&self, schema: &'s Value) -> Option<&'s Value> {
        match schema.get("$ref").and_then(Value::as_str) {
            Some(reference) => self.definitions?.get(reference.strip_prefix("#/$defs/")?),
            None => Some(schema),
        }
    }

    fn reference(&mut self, reference: &str) -> Shape {
        let Some(name) = reference.strip_prefix("#/$defs/") else {
            return Shape::Any;
        };
        let Some((name, definition)) = self
            .definitions
            .and_then(|definitions| definitions.get_key_value(name))
        else {
            return Shape::Any;
        };
        if let Some(shape) = self.compiled.get(name.as_str()) {
            return shape.clone();
        }
        if self.compiling.contains(&name.as_str()) {
            return Shape::Any;
        }
        self.compiling.push(name);
        let shape = self.schema(definition, Some(name));
        self.compiling.pop();
        self.compiled.insert(name, shape.clone());
        shape
    }
}

/// Joins alternative shapes, flattening nested alternatives and dropping repeats.
fn one_of(shapes: Vec<Shape>) -> Shape {
    let mut alternatives: Vec<Shape> = Vec::new();
    for shape in shapes {
        let members = match shape {
            Shape::OneOf(members) => members.to_vec(),
            other => vec![other],
        };
        for member in members {
            if !alternatives.contains(&member) {
                alternatives.push(member);
            }
        }
    }
    if alternatives.contains(&Shape::Any) {
        return Shape::Any;
    }
    if alternatives.iter().all(|shape| *shape == Shape::Scalar) {
        return Shape::Scalar;
    }
    if alternatives.len() == 1 {
        return alternatives.remove(0);
    }
    Shape::OneOf(alternatives.into())
}
