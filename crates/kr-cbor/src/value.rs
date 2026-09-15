//! The validated KR-CBOR-1 value tree.
//!
//! A [`CanonicalValue`] can only hold shapes the profile permits: integers inside CBOR's 64-bit
//! argument range, byte strings, valid UTF-8 text, arrays, text-keyed maps, booleans and null.
//! A [`CanonicalMap`] keeps its entries in canonical key order and rejects duplicates, so encoding
//! a `CanonicalValue` cannot produce a non-canonical byte string.

use core::cmp::Ordering;

use crate::error::{CborError, Result};
use crate::limits::Limits;

/// An integer inside CBOR's 64-bit argument range.
///
/// The range is `-2^64 ..= 2^64 - 1`: major type 0 carries `0 ..= 2^64 - 1` and major type 1
/// carries `-2^64 ..= -1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Integer(i128);

impl Integer {
    /// Smallest representable value, `-2^64`.
    pub const MIN: i128 = -(1i128 << 64);
    /// Largest representable value, `2^64 - 1`.
    pub const MAX: i128 = (1i128 << 64) - 1;

    /// Creates an integer, rejecting values outside the 64-bit argument range.
    ///
    /// # Errors
    ///
    /// Returns [`CborError::IntegerOutOfRange`] when `value` is outside `MIN ..= MAX`.
    pub const fn new(value: i128) -> Result<Self> {
        if value < Self::MIN || value > Self::MAX {
            return Err(CborError::IntegerOutOfRange { value });
        }
        Ok(Self(value))
    }

    /// Returns the value.
    #[must_use]
    pub const fn get(self) -> i128 {
        self.0
    }

    /// Returns the value when it fits in a `u64`.
    #[must_use]
    pub const fn as_u64(self) -> Option<u64> {
        if self.0 >= 0 && self.0 <= u64::MAX as i128 {
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            Some(self.0 as u64)
        } else {
            None
        }
    }

    /// Returns the value when it fits in an `i64`.
    #[must_use]
    pub const fn as_i64(self) -> Option<i64> {
        if self.0 >= i64::MIN as i128 && self.0 <= i64::MAX as i128 {
            #[allow(clippy::cast_possible_truncation)]
            Some(self.0 as i64)
        } else {
            None
        }
    }
}

impl From<u64> for Integer {
    fn from(value: u64) -> Self {
        Self(i128::from(value))
    }
}

impl From<i64> for Integer {
    fn from(value: i64) -> Self {
        Self(i128::from(value))
    }
}

impl From<u32> for Integer {
    fn from(value: u32) -> Self {
        Self(i128::from(value))
    }
}

/// A value in the KR-CBOR-1 profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalValue {
    /// Schema-declared `null`. Null is a value, never an omitted field.
    Null,
    /// A boolean.
    Bool(bool),
    /// An integer in the 64-bit argument range.
    Integer(Integer),
    /// A byte string. Raw terminal bytes need not be valid UTF-8 and travel here.
    Bytes(Vec<u8>),
    /// A text string. Always valid UTF-8, never normalised or case folded.
    Text(String),
    /// An array.
    Array(Vec<CanonicalValue>),
    /// A text-keyed map in canonical key order.
    Map(CanonicalMap),
}

impl CanonicalValue {
    /// Creates an integer value.
    ///
    /// # Errors
    ///
    /// Returns [`CborError::IntegerOutOfRange`] when `value` is outside the 64-bit argument range.
    pub fn integer(value: i128) -> Result<Self> {
        Integer::new(value).map(Self::Integer)
    }

    /// Creates a text value.
    #[must_use]
    pub fn text(value: impl Into<String>) -> Self {
        Self::Text(value.into())
    }

    /// Creates a byte-string value.
    #[must_use]
    pub fn bytes(value: impl Into<Vec<u8>>) -> Self {
        Self::Bytes(value.into())
    }

    /// Returns the map when this value is a map.
    #[must_use]
    pub const fn as_map(&self) -> Option<&CanonicalMap> {
        match self {
            Self::Map(map) => Some(map),
            _ => None,
        }
    }

    /// Returns the text when this value is a text string.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            _ => None,
        }
    }

    /// Returns the integer when this value is an integer.
    #[must_use]
    pub const fn as_integer(&self) -> Option<Integer> {
        match self {
            Self::Integer(value) => Some(*value),
            _ => None,
        }
    }

    /// Checks depth, item-count, collection and string bounds against `limits`.
    ///
    /// The decoder applies these bounds while reading. This method applies the same bounds to a
    /// value built in memory, so an outbound message cannot exceed the peer's declared limits.
    ///
    /// # Errors
    ///
    /// Returns the first bound that the value exceeds.
    pub fn check_limits(&self, limits: &Limits) -> Result<()> {
        let mut items = 0usize;
        self.check_limits_inner(limits, 1, &mut items)
    }

    fn check_limits_inner(&self, limits: &Limits, depth: usize, items: &mut usize) -> Result<()> {
        if depth > limits.max_depth {
            return Err(CborError::DepthLimit {
                limit: limits.max_depth,
            });
        }
        *items += 1;
        if *items > limits.max_items {
            return Err(CborError::CountLimit {
                limit: limits.max_items,
            });
        }
        match self {
            Self::Null | Self::Bool(_) | Self::Integer(_) => Ok(()),
            Self::Bytes(bytes) => {
                if bytes.len() > limits.max_bytes_len {
                    return Err(CborError::LengthLimit {
                        len: bytes.len() as u64,
                        limit: limits.max_bytes_len,
                    });
                }
                Ok(())
            }
            Self::Text(text) => {
                if text.len() > limits.max_text_len {
                    return Err(CborError::LengthLimit {
                        len: text.len() as u64,
                        limit: limits.max_text_len,
                    });
                }
                Ok(())
            }
            Self::Array(items_vec) => {
                if items_vec.len() > limits.max_collection_len {
                    return Err(CborError::CollectionLimit {
                        len: items_vec.len() as u64,
                        limit: limits.max_collection_len,
                    });
                }
                for item in items_vec {
                    item.check_limits_inner(limits, depth + 1, items)?;
                }
                Ok(())
            }
            Self::Map(map) => {
                if map.len() > limits.max_collection_len {
                    return Err(CborError::CollectionLimit {
                        len: map.len() as u64,
                        limit: limits.max_collection_len,
                    });
                }
                for (key, value) in map.entries() {
                    if key.len() > limits.max_text_len {
                        return Err(CborError::LengthLimit {
                            len: key.len() as u64,
                            limit: limits.max_text_len,
                        });
                    }
                    *items += 1;
                    if *items > limits.max_items {
                        return Err(CborError::CountLimit {
                            limit: limits.max_items,
                        });
                    }
                    value.check_limits_inner(limits, depth + 1, items)?;
                }
                Ok(())
            }
        }
    }
}

/// A text-keyed map whose entries are in canonical key order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CanonicalMap {
    entries: Vec<(String, CanonicalValue)>,
}

impl CanonicalMap {
    /// Creates an empty map.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Builds a map from entries in any order.
    ///
    /// # Errors
    ///
    /// Returns [`CborError::DuplicateKey`] when two entries share a key. Byte-distinct keys are
    /// distinct: no Unicode normalisation or case folding happens here.
    pub fn from_entries<I>(entries: I) -> Result<Self>
    where
        I: IntoIterator<Item = (String, CanonicalValue)>,
    {
        let mut map = Self::new();
        for (key, value) in entries {
            map.insert(key, value)?;
        }
        Ok(map)
    }

    /// Inserts one entry, keeping canonical order.
    ///
    /// # Errors
    ///
    /// Returns [`CborError::DuplicateKey`] when the key is already present.
    pub fn insert(&mut self, key: String, value: CanonicalValue) -> Result<()> {
        match self
            .entries
            .binary_search_by(|(existing, _)| compare_keys(existing, &key))
        {
            Ok(_) => Err(CborError::DuplicateKey { key }),
            Err(position) => {
                self.entries.insert(position, (key, value));
                Ok(())
            }
        }
    }

    /// Builds a map from entries that must already be in canonical order.
    ///
    /// The decoder uses this so a re-sort cannot hide a non-canonical wire order.
    ///
    /// # Errors
    ///
    /// Returns [`CborError::UnsortedMapKeys`] or [`CborError::DuplicateKey`] for the first pair
    /// that breaks the order.
    pub fn from_sorted_entries(entries: Vec<(String, CanonicalValue)>) -> Result<Self> {
        for window in entries.windows(2) {
            let previous = &window[0].0;
            let current = &window[1].0;
            match compare_keys(previous, current) {
                Ordering::Less => {}
                Ordering::Equal => {
                    return Err(CborError::DuplicateKey {
                        key: current.clone(),
                    });
                }
                Ordering::Greater => {
                    return Err(CborError::UnsortedMapKeys {
                        previous: previous.clone(),
                        current: current.clone(),
                    });
                }
            }
        }
        Ok(Self { entries })
    }

    /// Returns the entries in canonical order.
    #[must_use]
    pub fn entries(&self) -> &[(String, CanonicalValue)] {
        &self.entries
    }

    /// Returns the value stored under `key`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&CanonicalValue> {
        self.entries
            .binary_search_by(|(existing, _)| compare_keys(existing, key))
            .ok()
            .map(|position| &self.entries[position].1)
    }

    /// Returns the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true when the map has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Consumes the map and returns its entries in canonical order.
    #[must_use]
    pub fn into_entries(self) -> Vec<(String, CanonicalValue)> {
        self.entries
    }
}

/// Orders two map keys the way section 23 requires.
///
/// The rule is the bytewise lexicographic order of the *complete encoded key*, which for a text
/// string is `head(len) || utf8`. The first head byte rises strictly with the length class
/// (`0x60..=0x77` for lengths 0..=23, then `0x78`, `0x79`, `0x7a`, `0x7b`) and inside a class the
/// big-endian length bytes compare in numeric order, so comparing the encoded heads is exactly
/// comparing the lengths. Comparing head-then-body is therefore comparing `(len, bytes)`.
/// `encoded_key_order_matches_length_then_bytes` in the tests checks this against real encodings
/// across every length boundary.
///
/// Note that this is *not* the bytewise order of the key text: `"z"` sorts before `"aa"` because
/// its encoded key is shorter.
#[must_use]
pub fn compare_keys(left: &str, right: &str) -> Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}
