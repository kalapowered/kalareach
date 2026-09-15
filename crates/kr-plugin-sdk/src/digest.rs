//! Payload digests and declared sizes.
//!
//! Every byte a package carries is named by its SHA-256 digest and its exact length. The host
//! checks the declared length before it downloads and both the length and the digest after, so a
//! payload cannot grow past its declared size during processing and cannot change content while
//! keeping its name.

use core::fmt;
use core::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};

pub use kr_protocol::scalars::U64;

/// Length in bytes of a SHA-256 digest.
pub const DIGEST_LEN: usize = 32;

/// Text that is not a lower-case hexadecimal SHA-256 digest.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DigestParseError {
    /// The text was not 64 hexadecimal characters.
    #[error("a SHA-256 digest is 64 lower-case hexadecimal characters, not {len}")]
    Length {
        /// The length of the supplied text.
        len: usize,
    },
    /// The text carried a character outside lower-case hexadecimal.
    #[error("a SHA-256 digest contains only 0-9 and a-f, not {character:?}")]
    Character {
        /// The offending character.
        character: char,
    },
}

/// A SHA-256 digest of one payload.
///
/// The JSON form is lower-case hexadecimal. Upper case is rejected rather than folded: two
/// spellings of one digest mean two index entries that compare unequal while naming the same
/// bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct PayloadDigest(#[serde(with = "hex_bytes")] [u8; DIGEST_LEN]);

impl PayloadDigest {
    /// Computes the digest of `bytes`.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self(hasher.finalize().into())
    }

    /// Wraps raw digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; DIGEST_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DIGEST_LEN] {
        &self.0
    }

    /// Parses a lower-case hexadecimal digest.
    ///
    /// # Errors
    ///
    /// Returns [`DigestParseError`] when the text is the wrong length or is not lower-case
    /// hexadecimal.
    pub fn parse(text: &str) -> Result<Self, DigestParseError> {
        if text.len() != DIGEST_LEN * 2 {
            return Err(DigestParseError::Length { len: text.len() });
        }
        if let Some(character) = text
            .chars()
            .find(|c| !c.is_ascii_digit() && !matches!(c, 'a'..='f'))
        {
            return Err(DigestParseError::Character { character });
        }
        let mut bytes = [0u8; DIGEST_LEN];
        hex::decode_to_slice(text, &mut bytes)
            .map_err(|_| DigestParseError::Length { len: text.len() })?;
        Ok(Self(bytes))
    }
}

impl fmt::Display for PayloadDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for PayloadDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "PayloadDigest({self})")
    }
}

impl FromStr for PayloadDigest {
    type Err = DigestParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

impl<'de> Deserialize<'de> for PayloadDigest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for PayloadDigest {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "PayloadDigest".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::PayloadDigest".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "pattern": "^[0-9a-f]{64}$",
            "description": "A SHA-256 digest as 64 lower-case hexadecimal characters."
        })
    }
}

mod hex_bytes {
    use serde::Serializer;

    pub(super) fn serialize<S: Serializer>(
        bytes: &[u8; super::DIGEST_LEN],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut text = String::with_capacity(super::DIGEST_LEN * 2);
        for byte in bytes {
            text.push_str(&format!("{byte:02x}"));
        }
        serializer.serialize_str(&text)
    }
}

/// A size in bytes.
///
/// Sizes travel as decimal strings in JSON for the same reason counters do: a JavaScript number
/// cannot carry a `u64` exactly, and a size that loses precision is a size check that passes when
/// it should not.
pub type ByteSize = U64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_the_empty_input() {
        assert_eq!(
            PayloadDigest::of(b"").to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn round_trips_through_json() {
        let digest = PayloadDigest::of(b"kalareach");
        let text = serde_json::to_string(&digest).expect("serialisable");
        let parsed: PayloadDigest = serde_json::from_str(&text).expect("deserialisable");
        assert_eq!(digest, parsed);
        assert_eq!(text, format!("\"{digest}\""));
    }

    #[test]
    fn rejects_upper_case_and_short_digests() {
        let upper = PayloadDigest::of(b"kalareach").to_string().to_uppercase();
        assert!(matches!(
            PayloadDigest::parse(&upper),
            Err(DigestParseError::Character { .. })
        ));
        assert!(matches!(
            PayloadDigest::parse("abcd"),
            Err(DigestParseError::Length { len: 4 })
        ));
    }
}
