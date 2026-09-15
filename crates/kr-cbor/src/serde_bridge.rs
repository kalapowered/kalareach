//! serde integration through the maintained `ciborium` implementation.
//!
//! Outbound: serde serialises into a `ciborium` value, this module validates that value against
//! the profile and the canonical encoder produces the bytes.
//!
//! Inbound: the strict decoder validates the bytes and produces a [`CanonicalValue`], which this
//! module converts into a `ciborium` value for serde deserialisation. Nothing reaches serde before
//! wire order, duplicate keys and every byte rule have been checked.

use ciborium::value::Value;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::decode::decode;
use crate::encode::encode;
use crate::error::{CborError, Result};
use crate::limits::Limits;
use crate::value::{CanonicalMap, CanonicalValue, Integer};

/// Converts a `ciborium` value into a validated canonical value.
///
/// # Errors
///
/// Returns [`CborError::Unrepresentable`] for floats, tags and non-text map keys,
/// [`CborError::IntegerOutOfRange`] for integers outside the 64-bit argument range and
/// [`CborError::DuplicateKey`] when a map repeats a key.
pub fn from_ciborium(value: &Value) -> Result<CanonicalValue> {
    match value {
        Value::Null => Ok(CanonicalValue::Null),
        Value::Bool(value) => Ok(CanonicalValue::Bool(*value)),
        Value::Integer(value) => Ok(CanonicalValue::Integer(Integer::new(i128::from(*value))?)),
        Value::Bytes(bytes) => Ok(CanonicalValue::Bytes(bytes.clone())),
        Value::Text(text) => Ok(CanonicalValue::Text(text.clone())),
        Value::Array(items) => items
            .iter()
            .map(from_ciborium)
            .collect::<Result<Vec<_>>>()
            .map(CanonicalValue::Array),
        Value::Map(entries) => {
            let mut converted = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                let Value::Text(key) = key else {
                    return Err(CborError::Unrepresentable {
                        reason: "map keys must be text strings",
                    });
                };
                converted.push((key.clone(), from_ciborium(value)?));
            }
            CanonicalMap::from_entries(converted).map(CanonicalValue::Map)
        }
        Value::Float(_) => Err(CborError::Unrepresentable {
            reason: "floats are forbidden; use a schema-defined integer or text representation",
        }),
        Value::Tag(..) => Err(CborError::Unrepresentable {
            reason: "tags are forbidden; timestamps are integer UTC milliseconds",
        }),
        _ => Err(CborError::Unrepresentable {
            reason: "value is outside the KR-CBOR-1 profile",
        }),
    }
}

/// Converts a canonical value into a `ciborium` value for serde deserialisation.
#[must_use]
pub fn to_ciborium(value: &CanonicalValue) -> Value {
    match value {
        CanonicalValue::Null => Value::Null,
        CanonicalValue::Bool(value) => Value::Bool(*value),
        CanonicalValue::Integer(value) => Value::Integer(
            ciborium::value::Integer::try_from(value.get()).expect("checked 64-bit argument range"),
        ),
        CanonicalValue::Bytes(bytes) => Value::Bytes(bytes.clone()),
        CanonicalValue::Text(text) => Value::Text(text.clone()),
        CanonicalValue::Array(items) => Value::Array(items.iter().map(to_ciborium).collect()),
        CanonicalValue::Map(map) => Value::Map(
            map.entries()
                .iter()
                .map(|(key, value)| (Value::Text(key.clone()), to_ciborium(value)))
                .collect(),
        ),
    }
}

/// Serialises a value and validates it against the profile.
///
/// # Errors
///
/// Returns [`CborError::Serialize`] when serde fails and a profile error when the resulting value
/// is outside KR-CBOR-1.
pub fn to_canonical_value<T>(value: &T) -> Result<CanonicalValue>
where
    T: Serialize + ?Sized,
{
    let intermediate = Value::serialized(value).map_err(|error| CborError::Serialize {
        message: error.to_string(),
    })?;
    from_ciborium(&intermediate)
}

/// Serialises a value to canonical KR-CBOR-1 bytes.
///
/// # Errors
///
/// Returns a profile error when the value cannot be represented.
pub fn to_canonical_vec<T>(value: &T) -> Result<Vec<u8>>
where
    T: Serialize + ?Sized,
{
    Ok(encode(&to_canonical_value(value)?))
}

/// Serialises a value to canonical bytes and checks it against `limits` first.
///
/// # Errors
///
/// Returns a profile error, a limit error, or [`CborError::InputTooLarge`] when the encoding is
/// longer than `limits.max_message_len`.
pub fn to_canonical_vec_within<T>(value: &T, limits: &Limits) -> Result<Vec<u8>>
where
    T: Serialize + ?Sized,
{
    let value = to_canonical_value(value)?;
    value.check_limits(limits)?;
    let bytes = encode(&value);
    if bytes.len() > limits.max_message_len {
        return Err(CborError::InputTooLarge {
            len: bytes.len(),
            limit: limits.max_message_len,
        });
    }
    Ok(bytes)
}

/// Deserialises a validated canonical value.
///
/// The value is canonical, but that is not enough on its own: serde accepts more than one
/// representation of the same typed value. A unit enum variant, for example, arrives either as its
/// name or as a single-entry map holding null, and both produce the same Rust value while only one
/// of them is what the type serialises back to. A signed object that arrived in the other form
/// would re-serialise to different bytes than the ones its signature covers.
///
/// So the typed value is serialised again here and has to equal the value it came from. That makes
/// one representation of each type reachable, which is what lets a later stage re-encode a decoded
/// object and still get the bytes the signature was taken over.
///
/// # Errors
///
/// Returns [`CborError::Deserialize`] when the value does not match the target schema, or
/// [`CborError::NonCanonical`] when the typed value does not serialise back to the same value.
pub fn from_canonical_value<T>(value: &CanonicalValue) -> Result<T>
where
    T: DeserializeOwned + Serialize,
{
    let typed: T = to_ciborium(value)
        .deserialized()
        .map_err(|error| CborError::Deserialize {
            message: error.to_string(),
        })?;
    if &to_canonical_value(&typed)? != value {
        return Err(CborError::NonCanonical);
    }
    Ok(typed)
}

/// Strictly decodes canonical bytes and deserialises them.
///
/// # Errors
///
/// Returns the first broken byte rule, [`CborError::Deserialize`] when the validated value does
/// not match the target schema, or [`CborError::NonCanonical`] when the typed value does not
/// serialise back to the bytes it came from.
pub fn from_canonical_slice<T>(bytes: &[u8], limits: &Limits) -> Result<T>
where
    T: DeserializeOwned + Serialize,
{
    from_canonical_value(&decode(bytes, limits)?)
}
