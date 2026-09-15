//! Wire scalars and their two representations.
//!
//! Every scalar has exactly one canonical wire form and one JSON form:
//!
//! | Scalar | KR-CBOR-1 wire form | JSON representation |
//! | --- | --- | --- |
//! | [`Uuid`] and the identifier newtypes | 16-byte string | canonical hyphenated text |
//! | [`U64`], [`TimestampMs`], [`DurationMs`] | unsigned 64-bit integer | decimal string |
//! | [`Bytes`] and the fixed-width byte types | byte string | unpadded base64url |
//!
//! Section 4 makes JSON the managed HTTP representation, with opaque bytes base64url-encoded and
//! unsigned 64-bit counters as decimal strings, because JavaScript numbers cannot carry a `u64`
//! exactly. Reading a JSON number into a `u64` field is still accepted so a hand-written
//! diagnostic document parses, but everything this crate emits uses the decimal string.
//!
//! JSON is never a signing representation. Signatures and digests always cover canonical
//! KR-CBOR-1 bytes.

use core::fmt;
use core::marker::PhantomData;
use core::str::FromStr;
use std::collections::BTreeSet;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize as _;

/// Length of a UUID in bytes.
pub const UUID_LEN: usize = 16;

/// A 128-bit identifier.
///
/// Section 23 puts UUIDs on the wire as 16-byte strings. The JSON representation is the canonical
/// hyphenated lower-case text form, which is what the specification's own diagnostic examples use.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uuid([u8; UUID_LEN]);

impl Uuid {
    /// The all-zero identifier.
    pub const NIL: Self = Self([0; UUID_LEN]);

    /// Wraps 16 raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; UUID_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; UUID_LEN] {
        &self.0
    }

    /// Returns the UUID version nibble.
    ///
    /// Section 9 requires a cryptographically generated UUIDv4 for `action_id`. Identifiers that
    /// are simply 128 random bits, such as a pairing invitation ID, do not carry a version.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.0[6] >> 4
    }
}

/// A UUID text form that is not a canonical hyphenated identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UuidParseError;

impl fmt::Display for UuidParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("expected a hyphenated 36-character UUID")
    }
}

impl std::error::Error for UuidParseError {}

impl FromStr for Uuid {
    type Err = UuidParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bytes = text.as_bytes();
        if bytes.len() != 36 {
            return Err(UuidParseError);
        }
        let mut out = [0u8; UUID_LEN];
        let mut index = 0;
        let mut position = 0;
        while position < bytes.len() {
            if matches!(position, 8 | 13 | 18 | 23) {
                if bytes[position] != b'-' {
                    return Err(UuidParseError);
                }
                position += 1;
                continue;
            }
            let high = hex_nibble(bytes[position])?;
            let low = hex_nibble(*bytes.get(position + 1).ok_or(UuidParseError)?)?;
            out[index] = (high << 4) | low;
            index += 1;
            position += 2;
        }
        if index != UUID_LEN {
            return Err(UuidParseError);
        }
        Ok(Self(out))
    }
}

fn hex_nibble(byte: u8) -> Result<u8, UuidParseError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(UuidParseError),
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                formatter.write_str("-")?;
            }
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Uuid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Uuid({self})")
    }
}

impl Serialize for Uuid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Uuid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let text = String::deserialize(deserializer)?;
            text.parse().map_err(de::Error::custom)
        } else {
            let bytes = deserializer.deserialize_bytes(FixedBytesVisitor::<UUID_LEN>)?;
            Ok(Self(bytes))
        }
    }
}

impl JsonSchema for Uuid {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Uuid".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::Uuid".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "format": "uuid",
            "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            "description": "A 128-bit identifier. On the wire it is a 16-byte string; in JSON it is the canonical hyphenated lower-case text form."
        })
    }
}

struct FixedBytesVisitor<const N: usize>;

impl<'de, const N: usize> Visitor<'de> for FixedBytesVisitor<N> {
    type Value = [u8; N];

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a byte string of exactly {N} bytes")
    }

    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
        <[u8; N]>::try_from(value)
            .map_err(|_| E::invalid_length(value.len(), &format!("{N} bytes").as_str()))
    }

    fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
        self.visit_bytes(&value)
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = [0u8; N];
        for slot in &mut out {
            *slot = seq
                .next_element::<u8>()?
                .ok_or_else(|| de::Error::invalid_length(N, &self))?;
        }
        if seq.next_element::<u8>()?.is_some() {
            return Err(de::Error::invalid_length(N + 1, &self));
        }
        Ok(out)
    }
}

/// An unsigned 64-bit counter.
///
/// Epochs, sequences, revisions and generations all use this type. The wire form is a CBOR
/// unsigned integer; the JSON form is a decimal string so a JavaScript consumer cannot lose
/// precision.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct U64(u64);

impl U64 {
    /// Zero.
    pub const ZERO: Self = Self(0);

    /// Wraps a raw counter.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw counter.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl From<u64> for U64 {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<U64> for u64 {
    fn from(value: U64) -> Self {
        value.0
    }
}

impl fmt::Display for U64 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl Serialize for U64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.0.to_string())
        } else {
            serializer.serialize_u64(self.0)
        }
    }
}

impl<'de> Deserialize<'de> for U64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            deserializer.deserialize_any(U64Visitor).map(Self)
        } else {
            u64::deserialize(deserializer).map(Self)
        }
    }
}

struct U64Visitor;

impl Visitor<'_> for U64Visitor {
    type Value = u64;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an unsigned 64-bit counter as a decimal string")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
            return Err(E::custom("expected a decimal string without leading zeros"));
        }
        value.parse().map_err(E::custom)
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        Ok(value)
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        u64::try_from(value).map_err(|_| E::custom("expected an unsigned counter"))
    }
}

fn u64_schema(description: &str) -> Schema {
    json_schema!({
        "type": "string",
        "pattern": "^(0|[1-9][0-9]*)$",
        "description": description
    })
}

impl JsonSchema for U64 {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "U64".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::U64".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        u64_schema(
            "An unsigned 64-bit counter. On the wire it is a CBOR unsigned integer; in JSON it is a decimal string.",
        )
    }
}

/// A point in time as unsigned UTC milliseconds.
///
/// Timestamps are schema-declared integers, never tagged dates and never floating point.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct TimestampMs(U64);

impl TimestampMs {
    /// Wraps a raw millisecond value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(U64::new(value))
    }

    /// Returns the raw millisecond value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl<'de> Deserialize<'de> for TimestampMs {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        U64::deserialize(deserializer).map(Self)
    }
}

impl JsonSchema for TimestampMs {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "TimestampMs".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::TimestampMs".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        u64_schema("A UTC timestamp in milliseconds, as a decimal string in JSON.")
    }
}

/// A duration in milliseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct DurationMs(U64);

impl DurationMs {
    /// Wraps a raw millisecond value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(U64::new(value))
    }

    /// Returns the raw millisecond value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl<'de> Deserialize<'de> for DurationMs {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        U64::deserialize(deserializer).map(Self)
    }
}

impl JsonSchema for DurationMs {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "DurationMs".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::DurationMs".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        u64_schema("A duration in milliseconds, as a decimal string in JSON.")
    }
}

/// An opaque byte string.
///
/// Raw terminal output, ciphertext, nonces and signatures travel here. The wire form is a CBOR
/// byte string; the JSON form is unpadded base64url.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bytes(Vec<u8>);

impl Bytes {
    /// Wraps raw bytes.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the wrapper and returns the raw bytes.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    /// Returns the length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true when there are no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl fmt::Debug for Bytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Bytes({} bytes)", self.0.len())
    }
}

/// Encodes bytes the way the JSON representation does.
#[must_use]
pub fn to_base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes unpadded base64url text.
///
/// # Errors
///
/// Returns a message describing the first invalid character or length.
pub fn from_base64url(text: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|error| error.to_string())
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&to_base64url(&self.0))
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let text = String::deserialize(deserializer)?;
            from_base64url(&text).map(Self).map_err(de::Error::custom)
        } else {
            deserializer
                .deserialize_byte_buf(VariableBytesVisitor)
                .map(Self)
        }
    }
}

struct VariableBytesVisitor;

impl<'de> Visitor<'de> for VariableBytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a byte string")
    }

    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
        Ok(value.to_vec())
    }

    fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
        Ok(value)
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = Vec::with_capacity(seq.size_hint().unwrap_or_default().min(1024));
        while let Some(byte) = seq.next_element::<u8>()? {
            out.push(byte);
        }
        Ok(out)
    }
}

fn base64url_schema(description: &str, length: Option<usize>) -> Schema {
    let pattern = match length {
        // base64url without padding encodes N bytes in ceil(N / 3) * 4 - padding characters.
        Some(len) => format!(
            "^[A-Za-z0-9_-]{{{}}}$",
            len.div_ceil(3) * 4 - (3 - len % 3) % 3
        ),
        None => "^[A-Za-z0-9_-]*$".to_owned(),
    };
    json_schema!({
        "type": "string",
        "contentEncoding": "base64url",
        "pattern": pattern,
        "description": description
    })
}

impl JsonSchema for Bytes {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Bytes".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::Bytes".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        base64url_schema(
            "An opaque byte string. On the wire it is a CBOR byte string; in JSON it is unpadded base64url.",
            None,
        )
    }
}

/// Declares a fixed-width byte string with the same two representations as [`Bytes`].
macro_rules! fixed_bytes {
    ($(#[$meta:meta])* $name:ident, $len:expr, $description:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Length in bytes.
            pub const LEN: usize = $len;

            /// Wraps raw bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// Returns the raw bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, concat!(stringify!($name), "({})"), to_base64url(&self.0))
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                if serializer.is_human_readable() {
                    serializer.serialize_str(&to_base64url(&self.0))
                } else {
                    serializer.serialize_bytes(&self.0)
                }
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                if deserializer.is_human_readable() {
                    let text = String::deserialize(deserializer)?;
                    let bytes = from_base64url(&text).map_err(de::Error::custom)?;
                    <[u8; $len]>::try_from(bytes.as_slice())
                        .map(Self)
                        .map_err(|_| {
                            de::Error::invalid_length(bytes.len(), &concat!(stringify!($len), " bytes"))
                        })
                } else {
                    deserializer
                        .deserialize_bytes(FixedBytesVisitor::<$len>)
                        .map(Self)
                }
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                stringify!($name).into()
            }

            fn schema_id() -> std::borrow::Cow<'static, str> {
                concat!("kalareach::", stringify!($name)).into()
            }

            fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
                base64url_schema($description, Some($len))
            }
        }
    };
}

fixed_bytes!(
    /// A SHA-256 digest.
    Digest256,
    32,
    "A 32-byte SHA-256 digest. On the wire it is a CBOR byte string; in JSON it is unpadded base64url."
);

fixed_bytes!(
    /// A 256-bit nonce or challenge.
    Nonce256,
    32,
    "A 32-byte nonce. On the wire it is a CBOR byte string; in JSON it is unpadded base64url."
);

fixed_bytes!(
    /// An iroh endpoint public key.
    EndpointKey,
    32,
    "A 32-byte iroh endpoint public key. On the wire it is a CBOR byte string; in JSON it is unpadded base64url."
);

fixed_bytes!(
    /// An Ed25519 authorisation public key.
    ///
    /// Section 10 keeps the four device key purposes separate and forbids converting or reusing
    /// one private key across purposes. Each purpose therefore has its own type here, so a
    /// transport key cannot be passed where an authorisation key is expected.
    AuthorisationKey,
    32,
    "A 32-byte Ed25519 authorisation public key. On the wire it is a CBOR byte string; in JSON it is unpadded base64url."
);

fixed_bytes!(
    /// An X25519 stored-envelope public key.
    StoredEnvelopeKey,
    32,
    "A 32-byte X25519 stored-envelope public key. On the wire it is a CBOR byte string; in JSON it is unpadded base64url."
);

fixed_bytes!(
    /// An X25519 notification-preview public key.
    ///
    /// The notification extension receives only this private key and paired sender public keys.
    NotificationPreviewKey,
    32,
    "A 32-byte X25519 notification-preview public key. On the wire it is a CBOR byte string; in JSON it is unpadded base64url."
);

fixed_bytes!(
    /// A stable identifier for one purpose-separated public key.
    ///
    /// It is the SHA-256 of the domain-separated encoding of the purpose and the key, so two
    /// devices name the same key identically and a key of one purpose never shares an identifier
    /// with a key of another.
    KeyId,
    32,
    "A 32-byte key identifier: the SHA-256 of the domain-separated encoding of a key purpose and public key."
);

fixed_bytes!(
    /// An Ed25519 detached signature.
    Signature64,
    64,
    "A 64-byte Ed25519 detached signature. On the wire it is a CBOR byte string; in JSON it is unpadded base64url."
);

/// Thirty-two secret bytes.
///
/// It is the type of a value that must not reach a log, an analytics event or a debug rendering:
/// a pairing invitation's secret, a printed recovery seed. It zeroises when it is dropped and
/// redacts itself in debug output, and it is deliberately not `Copy`, because a `Copy` secret
/// leaves a duplicate behind on every move and a duplicate cannot be zeroised.
///
/// It has the same two wire representations as every other fixed-width byte string.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes32([u8; 32]);

impl SecretBytes32 {
    /// Length in bytes.
    pub const LEN: usize = 32;

    /// Wraps raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    ///
    /// The name is deliberate: every call site that reads the secret is one a reviewer can find.
    #[must_use]
    pub const fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for SecretBytes32 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretBytes32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes32(redacted)")
    }
}

impl Serialize for SecretBytes32 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&to_base64url(&self.0))
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for SecretBytes32 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let text = String::deserialize(deserializer)?;
            let bytes = from_base64url(&text).map_err(de::Error::custom)?;
            <[u8; 32]>::try_from(bytes.as_slice())
                .map(Self)
                .map_err(|_| de::Error::invalid_length(bytes.len(), &"32 bytes"))
        } else {
            deserializer
                .deserialize_bytes(FixedBytesVisitor::<32>)
                .map(Self)
        }
    }
}

impl JsonSchema for SecretBytes32 {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "SecretBytes32".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::SecretBytes32".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        base64url_schema(
            "Thirty-two secret bytes. The Rust representation clears them when it is dropped and redacts them in diagnostics; a consumer in another language must apply its own handling, because a JSON string carries no such guarantee.",
            Some(32),
        )
    }
}

fixed_bytes!(
    /// A 192-bit nonce, as used by XChaCha20-Poly1305 and `crypto_box_easy`.
    Nonce192,
    24,
    "A 24-byte nonce. On the wire it is a CBOR byte string; in JSON it is unpadded base64url."
);

fixed_bytes!(
    /// A 256-bit message authentication tag, as produced by HMAC-SHA-256.
    Mac256,
    32,
    "A 32-byte HMAC-SHA-256 tag. On the wire it is a CBOR byte string; in JSON it is unpadded base64url."
);

/// A field that must be present and may be null.
///
/// Section 23 states that `null` is not omission. A closed schema therefore cannot use
/// `Option<T>`: serde lets any field whose `Deserialize` accepts `deserialize_option` be missing,
/// so an omitted field and an explicit `null` would be indistinguishable to the receiver.
///
/// `Nullable<T>` deserialises through `deserialize_newtype_struct` instead. A self-describing
/// format passes the original deserializer straight through to `Option<T>`, which keeps the
/// human-readable flag and therefore the correct representation of the inner scalar. serde's
/// missing-field deserializer supports only `deserialize_option`, so a missing field fails.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Nullable<T>(pub Option<T>);

impl<T> Nullable<T> {
    /// A present value.
    pub const fn some(value: T) -> Self {
        Self(Some(value))
    }

    /// An explicit null.
    pub const fn null() -> Self {
        Self(None)
    }

    /// Returns a reference to the value when present.
    pub const fn as_ref(&self) -> Option<&T> {
        self.0.as_ref()
    }

    /// Returns true when the field carries a value.
    pub const fn is_present(&self) -> bool {
        self.0.is_some()
    }
}

impl<T> From<Option<T>> for Nullable<T> {
    fn from(value: Option<T>) -> Self {
        Self(value)
    }
}

impl<T: Serialize> Serialize for Nullable<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            Some(value) => serializer.serialize_some(value),
            None => serializer.serialize_none(),
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Nullable<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_newtype_struct("Nullable", NullableVisitor(PhantomData))
    }
}

struct NullableVisitor<T>(PhantomData<T>);

impl<'de, T: Deserialize<'de>> Visitor<'de> for NullableVisitor<T> {
    type Value = Nullable<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a present field that may be null")
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        Option::<T>::deserialize(deserializer).map(Nullable)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Nullable(None))
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Nullable(None))
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        T::deserialize(deserializer).map(|value| Nullable(Some(value)))
    }
}

impl<T: JsonSchema> JsonSchema for Nullable<T> {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        format!("Nullable_{}", T::schema_name()).into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        format!("kalareach::Nullable<{}>", T::schema_id()).into()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "anyOf": [generator.subschema_for::<T>(), { "type": "null" }]
        })
    }
}

/// A set that keeps one exact encoding.
///
/// A signed object is verified against the bytes it arrived in, so a collection inside one cannot
/// normalise on the way through. `BTreeSet` would: decoding `["z", "a"]` gives `{"a", "z"}`, and
/// re-serialising it for a transcript would cover bytes the peer never sent.
///
/// `CanonicalSet` closes that by making the schema order part of the contract. It serialises in
/// ascending element order and rejects an incoming sequence that is not already strictly
/// ascending, so a received value always re-encodes to the bytes it came from. Section 23 permits
/// exactly this: a schema may validate a canonical form, as long as it does so *before* encoding.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalSet<T: Ord>(BTreeSet<T>);

impl<T: Ord> CanonicalSet<T> {
    /// An empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self(BTreeSet::new())
    }

    /// Returns true when `value` is a member.
    pub fn contains<Q>(&self, value: &Q) -> bool
    where
        T: core::borrow::Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.0.contains(value)
    }

    /// Adds a member, returning true when it was not already present.
    pub fn insert(&mut self, value: T) -> bool {
        self.0.insert(value)
    }

    /// Iterates the members in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.0.iter()
    }

    /// Returns the number of members.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true when the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns true when every member of `self` is also a member of `other`.
    #[must_use]
    pub fn is_subset(&self, other: &Self) -> bool {
        self.0.is_subset(&other.0)
    }
}

impl<T: Ord> FromIterator<T> for CanonicalSet<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<'a, T: Ord> IntoIterator for &'a CanonicalSet<T> {
    type Item = &'a T;
    type IntoIter = std::collections::btree_set::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T: Ord + Serialize> Serialize for CanonicalSet<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter())
    }
}

impl<'de, T: Ord + Deserialize<'de>> Deserialize<'de> for CanonicalSet<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_seq(CanonicalSetVisitor(PhantomData))
    }
}

struct CanonicalSetVisitor<T>(PhantomData<T>);

impl<'de, T: Ord + Deserialize<'de>> Visitor<'de> for CanonicalSetVisitor<T> {
    type Value = CanonicalSet<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a sequence in strictly ascending order")
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
        let mut members: Vec<T> = Vec::new();
        while let Some(member) = sequence.next_element::<T>()? {
            if let Some(previous) = members.last() {
                match previous.cmp(&member) {
                    core::cmp::Ordering::Less => {}
                    core::cmp::Ordering::Equal => {
                        return Err(de::Error::custom("duplicate member in a canonical set"));
                    }
                    core::cmp::Ordering::Greater => {
                        return Err(de::Error::custom(
                            "members of a canonical set must be in ascending order",
                        ));
                    }
                }
            }
            members.push(member);
        }
        Ok(CanonicalSet(members.into_iter().collect()))
    }
}

impl<T: Ord + JsonSchema> JsonSchema for CanonicalSet<T> {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        format!("CanonicalSet_{}", T::schema_name()).into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        format!("kalareach::CanonicalSet<{}>", T::schema_id()).into()
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "array",
            "items": generator.subschema_for::<T>(),
            "uniqueItems": true,
            "description": "A set encoded as a sequence in strictly ascending order. A sequence that is unsorted or repeats a member is rejected."
        })
    }
}
