//! Protocol extensions, negotiated by identifier and schema hash.
//!
//! Section 23 closes every mutation schema for the negotiated version and lets read-only metadata
//! add explicitly optional fields a receiver ignores. Anything more needs an extension, and an
//! extension needs a negotiated identifier and schema hash.
//!
//! # Negotiation
//!
//! `hello` carries it. The client offers every extension it implements, each by identifier and the
//! hash of the schema it holds ([`ClientOffer::extensions`](crate::hello::ClientOffer)). The host
//! selects exactly the offered extensions it implements with the identical hash ([`select`]) and
//! says so in its selection. A host that does not implement an offered extension leaves it out; the
//! offer is not refused for it. The client refuses a selection that names an extension it did not
//! offer with that hash ([`check_selection`]). The `kr-connect/1` transcript covers the complete
//! offer and selection, so both lists are bound by the connection proof.
//!
//! # What the hash covers
//!
//! [`schema_hash`] is SHA-256 of the KR-CBOR-1 encoding of
//! `["kr-extension/1", identifier, {type name: member schema, ...}]`: the identifier, every type the
//! extension extends and the exact JSON Schema of the member it adds there. Two peers negotiate an
//! extension only when they hold the identical schema.
//!
//! # Using one
//!
//! An extension adds one member to each object it extends: an entry whose key is the extension's
//! identifier and whose value its schema describes. An identifier always contains a dot and no
//! declared field name does, so a receiver can tell an extension member from an unknown field
//! without knowing the extension. Extensions extend read-only metadata only: such an object is
//! never signed, never covered by a mutation digest and never a mutation's parameters, so a member
//! taken out before typed decoding is never left out of anything a signature or a digest covers.
//!
//! A message that carries a member of an extension its connection did not negotiate, or in an
//! object that extension does not extend, is refused before typed decoding
//! (`unnegotiated_extension`, `UNSUPPORTED_SCHEMA`). A member of a negotiated extension is checked
//! against its schema, taken out, and returned beside the message by
//! [`crate::wire::decode_extended`].
//!
//! This build implements no extension ([`implemented`]), so it offers and selects none, and every
//! extension member it receives is refused.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, LazyLock};

use kr_cbor::{CanonicalMap, CanonicalValue, Extensions, Member, ObjectShape, Shape, Undeclared};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::scalars::Digest256;
use crate::wire::READ_ONLY_METADATA;

/// The domain the schema hash is separated by.
pub const SCHEMA_DOMAIN: &str = "kr-extension/1";

/// The longest extension identifier, in bytes.
pub const MAX_EXTENSION_ID_LEN: usize = 64;

/// Extensions by identifier, each with the hash of the schema one side holds for it.
///
/// A client's offer and a host's selection are both this. On the wire it is a map from identifier
/// to the 32-byte hash, left out of the message when it is empty.
pub type ExtensionOffers = BTreeMap<ExtensionId, Digest256>;

/// An extension identifier: two or more dot-separated segments of lower-case ASCII letters, digits,
/// `_` and `-`, such as `org.example.thermal`.
///
/// The dot is what tells an extension member from a field: no declared field name has one.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ExtensionId(String);

impl ExtensionId {
    /// Validates and wraps an identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionError::InvalidId`] when the text is not two or more non-empty segments of
    /// `[a-z0-9_-]` joined by dots, or is longer than [`MAX_EXTENSION_ID_LEN`] bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, ExtensionError> {
        let value = value.into();
        let segments: Vec<&str> = value.split('.').collect();
        let valid = value.len() <= MAX_EXTENSION_ID_LEN
            && segments.len() >= 2
            && segments.iter().all(|segment| {
                !segment.is_empty()
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'_' | b'-')
                    })
            });
        if valid {
            Ok(Self(value))
        } else {
            Err(ExtensionError::InvalidId)
        }
    }

    /// Returns the identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for ExtensionId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl JsonSchema for ExtensionId {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ExtensionId".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::ExtensionId".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "minLength": 3,
            "maxLength": MAX_EXTENSION_ID_LEN,
            "pattern": "^[a-z0-9_-]+(\\.[a-z0-9_-]+)+$",
            "description": "An extension identifier: two or more dot-separated segments of lower-case letters, digits, '_' and '-'. No declared field name has a dot, so an extension member is told apart from a field by its key."
        })
    }
}

impl<'de> Deserialize<'de> for ExtensionId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(text).map_err(serde::de::Error::custom)
    }
}

/// A refused extension identifier, definition or selection.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExtensionError {
    /// The identifier is not two or more dot-separated segments of `[a-z0-9_-]`.
    #[error(
        "an extension identifier is two or more dot-separated segments of lower-case letters, \
         digits, '_' and '-', at most 64 bytes"
    )]
    InvalidId,
    /// The definition extends a type that is not read-only metadata.
    #[error("an extension extends read-only metadata only, and {target} is not")]
    NotReadOnlyMetadata {
        /// The type the definition named.
        target: String,
    },
    /// A member schema holds a value KR-CBOR-1 cannot carry, such as a fraction.
    #[error("an extension's schema cannot be hashed: {reason}")]
    UnrepresentableSchema {
        /// What could not be represented.
        reason: String,
    },
    /// The host selected an extension the client did not offer with that hash.
    #[error("the host selected the extension {extension}, which was not offered with that schema")]
    NotOffered {
        /// The extension the host named.
        extension: String,
    },
}

/// An extension this build implements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionDefinition {
    id: ExtensionId,
    members: BTreeMap<String, Value>,
    schema_hash: Digest256,
    shapes: BTreeMap<String, Arc<Shape>>,
}

impl ExtensionDefinition {
    /// Defines an extension by its identifier and the member it adds to each type it extends.
    ///
    /// `members` maps a type's schema name, as `packages/protocol/schema` publishes it, to the JSON
    /// Schema of the member the extension adds there.
    ///
    /// # Errors
    ///
    /// Returns [`ExtensionError::NotReadOnlyMetadata`] when a type is not read-only metadata, and
    /// [`ExtensionError::UnrepresentableSchema`] when a schema holds a value that cannot be hashed.
    pub fn new(id: ExtensionId, members: BTreeMap<String, Value>) -> Result<Self, ExtensionError> {
        if let Some(target) = members
            .keys()
            .find(|target| !READ_ONLY_METADATA_TYPES.contains(target.as_str()))
        {
            return Err(ExtensionError::NotReadOnlyMetadata {
                target: target.clone(),
            });
        }
        let schema_hash = schema_hash(&id, &members)?;
        let shapes = members
            .iter()
            .map(|(target, schema)| (target.clone(), Arc::new(crate::wire::compile(schema))))
            .collect();
        Ok(Self {
            id,
            members,
            schema_hash,
            shapes,
        })
    }

    /// Returns the identifier.
    #[must_use]
    pub const fn id(&self) -> &ExtensionId {
        &self.id
    }

    /// Returns the hash of the schema, which the negotiation compares.
    #[must_use]
    pub const fn schema_hash(&self) -> Digest256 {
        self.schema_hash
    }

    /// Returns the member schema for each type the extension extends.
    #[must_use]
    pub const fn members(&self) -> &BTreeMap<String, Value> {
        &self.members
    }
}

/// Every type the published schema marks as read-only metadata.
static READ_ONLY_METADATA_TYPES: LazyLock<BTreeSet<String>> = LazyLock::new(|| {
    crate::schema::protocol_schema()["$defs"]
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(_, schema)| schema.get(READ_ONLY_METADATA) == Some(&Value::Bool(true)))
        .map(|(name, _)| name.clone())
        .collect()
});

/// Returns the hash of an extension's schema.
///
/// SHA-256 of the KR-CBOR-1 encoding of `["kr-extension/1", identifier, members]`, where `members`
/// maps each extended type's name to its member schema written as KR-CBOR-1.
///
/// # Errors
///
/// Returns [`ExtensionError::UnrepresentableSchema`] when a schema holds a number that is not an
/// integer in the 64-bit range.
pub fn schema_hash(
    id: &ExtensionId,
    members: &BTreeMap<String, Value>,
) -> Result<Digest256, ExtensionError> {
    let mut map = CanonicalMap::new();
    for (target, schema) in members {
        map.insert(target.clone(), canonical(schema)?)
            .map_err(|error| ExtensionError::UnrepresentableSchema {
                reason: error.to_string(),
            })?;
    }
    let input = kr_cbor::signing_input(
        SCHEMA_DOMAIN,
        vec![CanonicalValue::text(id.as_str()), CanonicalValue::Map(map)],
    )
    .map_err(|error| ExtensionError::UnrepresentableSchema {
        reason: error.to_string(),
    })?;
    Ok(Digest256::from_bytes(kr_cbor::sha256(&input)))
}

/// Writes a JSON Schema document as a KR-CBOR-1 value.
fn canonical(value: &Value) -> Result<CanonicalValue, ExtensionError> {
    let unrepresentable = |reason: String| ExtensionError::UnrepresentableSchema { reason };
    Ok(match value {
        Value::Null => CanonicalValue::Null,
        Value::Bool(value) => CanonicalValue::Bool(*value),
        Value::Number(number) => {
            let integer = number
                .as_u64()
                .map(i128::from)
                .or_else(|| number.as_i64().map(i128::from))
                .ok_or_else(|| unrepresentable(format!("{number} is not an integer")))?;
            CanonicalValue::integer(integer).map_err(|error| unrepresentable(error.to_string()))?
        }
        Value::String(text) => CanonicalValue::text(text.as_str()),
        Value::Array(items) => {
            CanonicalValue::Array(items.iter().map(canonical).collect::<Result<Vec<_>, _>>()?)
        }
        Value::Object(fields) => {
            let mut map = CanonicalMap::new();
            for (key, field) in fields {
                map.insert(key.clone(), canonical(field)?)
                    .map_err(|error| unrepresentable(error.to_string()))?;
            }
            CanonicalValue::Map(map)
        }
    })
}

/// Every extension this build implements.
///
/// None: this protocol version defines no extension, so a connection this build makes or accepts
/// negotiates none and every extension member it receives is refused.
#[must_use]
pub const fn implemented() -> Vec<ExtensionDefinition> {
    Vec::new()
}

/// Returns what a client offers for these definitions.
#[must_use]
pub fn offer(definitions: &[ExtensionDefinition]) -> ExtensionOffers {
    definitions
        .iter()
        .map(|definition| (definition.id.clone(), definition.schema_hash))
        .collect()
}

/// Returns the host's selection: every offered extension it implements with the identical hash.
///
/// An offered extension the host does not implement, or holds a different schema for, is left out
/// rather than refused, so the connection goes on without it.
#[must_use]
pub fn select(offered: &ExtensionOffers, implemented: &[ExtensionDefinition]) -> ExtensionOffers {
    implemented
        .iter()
        .filter(|definition| offered.get(&definition.id) == Some(&definition.schema_hash))
        .map(|definition| (definition.id.clone(), definition.schema_hash))
        .collect()
}

/// Checks a host's selection against the offer it answers.
///
/// # Errors
///
/// Returns [`ExtensionError::NotOffered`] for the first selected extension the offer did not name
/// with the same hash.
pub fn check_selection(
    offered: &ExtensionOffers,
    selected: &ExtensionOffers,
) -> Result<(), ExtensionError> {
    match selected
        .iter()
        .find(|(id, hash)| offered.get(*id) != Some(*hash))
    {
        Some((id, _)) => Err(ExtensionError::NotOffered {
            extension: id.to_string(),
        }),
        None => Ok(()),
    }
}

/// The extensions one connection negotiated, which decide the extension members its messages may
/// carry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NegotiatedExtensions {
    definitions: Vec<ExtensionDefinition>,
}

impl NegotiatedExtensions {
    /// No extension: every extension member is refused.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            definitions: Vec::new(),
        }
    }

    /// The definitions a selection names, with the hash each was selected with.
    #[must_use]
    pub fn from_selection(selected: &ExtensionOffers, implemented: &[ExtensionDefinition]) -> Self {
        Self {
            definitions: implemented
                .iter()
                .filter(|definition| selected.get(&definition.id) == Some(&definition.schema_hash))
                .cloned()
                .collect(),
        }
    }

    /// Returns true when nothing was negotiated.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.definitions.is_empty()
    }
}

impl Extensions for NegotiatedExtensions {
    fn classify(&self, object: &ObjectShape, key: &str) -> Member {
        // A declared field never has a dot, so an undeclared key without one is an ordinary field
        // and the object's own rule decides it.
        if !key.contains('.') {
            return Member::Field;
        }
        // Only read-only metadata is ever extended.
        if object.undeclared != Undeclared::Ignore {
            return Member::Refused;
        }
        let Some(name) = object.name.as_deref() else {
            return Member::Refused;
        };
        self.definitions
            .iter()
            .find(|definition| definition.id.as_str() == key)
            .and_then(|definition| definition.shapes.get(name))
            .map_or(Member::Refused, |shape| Member::Admitted(Arc::clone(shape)))
    }
}
