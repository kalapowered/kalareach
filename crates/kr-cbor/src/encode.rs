//! The canonical encoder.
//!
//! Encoding is total: a [`CanonicalValue`] already satisfies every profile rule, so the encoder
//! only has to choose the shortest head for each argument and walk the tree in key order.

use crate::value::{CanonicalMap, CanonicalValue, Integer};

const MAJOR_UNSIGNED: u8 = 0;
const MAJOR_NEGATIVE: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_SIMPLE: u8 = 7;

const SIMPLE_FALSE: u8 = 20;
const SIMPLE_TRUE: u8 = 21;
const SIMPLE_NULL: u8 = 22;

/// Encodes one value as canonical KR-CBOR-1 bytes.
#[must_use]
pub fn encode(value: &CanonicalValue) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

/// Appends the canonical encoding of `value` to `out`.
pub fn encode_into(value: &CanonicalValue, out: &mut Vec<u8>) {
    match value {
        CanonicalValue::Null => out.push((MAJOR_SIMPLE << 5) | SIMPLE_NULL),
        CanonicalValue::Bool(false) => out.push((MAJOR_SIMPLE << 5) | SIMPLE_FALSE),
        CanonicalValue::Bool(true) => out.push((MAJOR_SIMPLE << 5) | SIMPLE_TRUE),
        CanonicalValue::Integer(value) => encode_integer(*value, out),
        CanonicalValue::Bytes(bytes) => {
            write_head(MAJOR_BYTES, bytes.len() as u64, out);
            out.extend_from_slice(bytes);
        }
        CanonicalValue::Text(text) => {
            write_head(MAJOR_TEXT, text.len() as u64, out);
            out.extend_from_slice(text.as_bytes());
        }
        CanonicalValue::Array(items) => {
            write_head(MAJOR_ARRAY, items.len() as u64, out);
            for item in items {
                encode_into(item, out);
            }
        }
        CanonicalValue::Map(map) => encode_map(map, out),
    }
}

fn encode_map(map: &CanonicalMap, out: &mut Vec<u8>) {
    write_head(MAJOR_MAP, map.len() as u64, out);
    for (key, value) in map.entries() {
        write_head(MAJOR_TEXT, key.len() as u64, out);
        out.extend_from_slice(key.as_bytes());
        encode_into(value, out);
    }
}

fn encode_integer(value: Integer, out: &mut Vec<u8>) {
    let raw = value.get();
    if raw >= 0 {
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        write_head(MAJOR_UNSIGNED, raw as u64, out);
    } else {
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        write_head(MAJOR_NEGATIVE, (-1 - raw) as u64, out);
    }
}

/// Writes a major type and argument using the shortest permitted head.
fn write_head(major: u8, argument: u64, out: &mut Vec<u8>) {
    let major = major << 5;
    if argument < 24 {
        #[allow(clippy::cast_possible_truncation)]
        out.push(major | argument as u8);
    } else if argument <= u64::from(u8::MAX) {
        #[allow(clippy::cast_possible_truncation)]
        out.extend_from_slice(&[major | 24, argument as u8]);
    } else if argument <= u64::from(u16::MAX) {
        out.push(major | 25);
        #[allow(clippy::cast_possible_truncation)]
        out.extend_from_slice(&(argument as u16).to_be_bytes());
    } else if argument <= u64::from(u32::MAX) {
        out.push(major | 26);
        #[allow(clippy::cast_possible_truncation)]
        out.extend_from_slice(&(argument as u32).to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend_from_slice(&argument.to_be_bytes());
    }
}
