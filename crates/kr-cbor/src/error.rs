//! Typed decoding and validation errors.
//!
//! Every variant names the rule it enforces: a KR-CBOR-1 byte rule, or a schema rule the check
//! before typed decoding applies. [`CborError::rule`] returns the stable rule identifier that the
//! cross-language fixtures use, so the Rust and TypeScript implementations can assert the same
//! error class for the same bytes.

use core::fmt;

/// A KR-CBOR-1 validation, encoding or decoding failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CborError {
    /// The input was empty; a KR-CBOR-1 message is exactly one object.
    #[error("empty input: a KR-CBOR-1 message is exactly one object")]
    EmptyInput,

    /// The input ended inside a head, a string body or a collection.
    #[error("unexpected end of input at offset {offset}")]
    UnexpectedEnd {
        /// Byte offset at which more input was required.
        offset: usize,
    },

    /// Bytes remained after the single top-level object.
    #[error("{count} trailing byte(s) after the top-level object")]
    TrailingBytes {
        /// Number of bytes left over.
        count: usize,
    },

    /// The whole input exceeded the configured maximum message length.
    #[error("input of {len} bytes exceeds the {limit}-byte message limit")]
    InputTooLarge {
        /// Length of the supplied input.
        len: usize,
        /// Configured maximum.
        limit: usize,
    },

    /// An integer used a longer argument encoding than necessary.
    #[error("integer at offset {offset} is not encoded in the shortest form")]
    NonShortestInteger {
        /// Byte offset of the offending head.
        offset: usize,
    },

    /// A string, array or map length used a longer argument encoding than necessary.
    #[error("length at offset {offset} is not encoded in the shortest form")]
    NonShortestLength {
        /// Byte offset of the offending head.
        offset: usize,
    },

    /// An indefinite-length string, array or map was found.
    #[error("indefinite length at offset {offset} is forbidden")]
    IndefiniteLength {
        /// Byte offset of the offending head.
        offset: usize,
    },

    /// A break code was found outside any indefinite-length item.
    #[error("break code at offset {offset} is forbidden")]
    BreakOutsideIndefinite {
        /// Byte offset of the break code.
        offset: usize,
    },

    /// Additional information 28, 29 or 30 is reserved.
    #[error("reserved additional information {value} at offset {offset}")]
    ReservedAdditionalInfo {
        /// The reserved additional-information value.
        value: u8,
        /// Byte offset of the offending head.
        offset: usize,
    },

    /// A tag was found. The profile forbids every tag.
    #[error("tag {tag} at offset {offset} is forbidden")]
    Tag {
        /// The tag number.
        tag: u64,
        /// Byte offset of the tag head.
        offset: usize,
    },

    /// A half, single or double precision float was found.
    #[error("float at offset {offset} is forbidden")]
    Float {
        /// Byte offset of the float head.
        offset: usize,
    },

    /// The `undefined` simple value was found.
    #[error("undefined at offset {offset} is forbidden")]
    Undefined {
        /// Byte offset of the simple value.
        offset: usize,
    },

    /// A simple value other than `false`, `true` and `null` was found.
    #[error("simple value {value} at offset {offset} is forbidden")]
    SimpleValue {
        /// The simple-value number.
        value: u8,
        /// Byte offset of the simple value.
        offset: usize,
    },

    /// A map key was not a text string.
    #[error("map key at offset {offset} is not a text string")]
    NonTextMapKey {
        /// Byte offset of the offending key.
        offset: usize,
    },

    /// Two map keys were equal.
    #[error("duplicate map key {key:?}")]
    DuplicateKey {
        /// The repeated key.
        key: String,
    },

    /// Map keys were not in ascending bytewise order of their complete encoded keys.
    #[error("map keys {previous:?} and {current:?} are not in canonical order")]
    UnsortedMapKeys {
        /// The key that appeared first.
        previous: String,
        /// The key that appeared after it.
        current: String,
    },

    /// A text string was not valid UTF-8.
    #[error("text string at offset {offset} is not valid UTF-8")]
    InvalidUtf8 {
        /// Byte offset of the string body.
        offset: usize,
    },

    /// Nesting exceeded the configured depth limit.
    #[error("nesting depth exceeds the limit of {limit}")]
    DepthLimit {
        /// Configured maximum nesting depth.
        limit: usize,
    },

    /// The object contained more items than the configured limit allows.
    #[error("item count exceeds the limit of {limit}")]
    CountLimit {
        /// Configured maximum item count.
        limit: usize,
    },

    /// A collection declared more members than the configured limit allows.
    #[error("collection of {len} members exceeds the limit of {limit}")]
    CollectionLimit {
        /// Declared member count.
        len: u64,
        /// Configured maximum.
        limit: usize,
    },

    /// A byte or text string declared a length above the configured limit.
    #[error("string of {len} bytes exceeds the limit of {limit}")]
    LengthLimit {
        /// Declared string length.
        len: u64,
        /// Configured maximum.
        limit: usize,
    },

    /// An integer fell outside CBOR's 64-bit argument range.
    #[error("integer {value} is outside the 64-bit argument range")]
    IntegerOutOfRange {
        /// The offending value.
        value: i128,
    },

    /// The decoded value does not re-encode to the bytes it came from.
    ///
    /// Every rule is checked while reading, so this is unreachable in a correct decoder. It exists
    /// because canonicity is what signatures rest on.
    #[error("the decoded value does not re-encode to the input bytes")]
    NonCanonical,

    /// A closed object carries a key its schema does not declare.
    ///
    /// Found by [`crate::check`] before typed decoding runs, never by the typed decoder.
    #[error("{at} does not declare the field {field:?}")]
    UnknownField {
        /// The object, by schema name where it has one, and where it is in the message.
        at: String,
        /// The undeclared key.
        field: String,
    },

    /// An object carries a member of an extension that is not admitted there.
    ///
    /// Found by [`crate::check`] before typed decoding runs, never by the typed decoder.
    #[error("{at} carries a member of the extension {extension:?}, which is not negotiated there")]
    UnnegotiatedExtension {
        /// The object, by schema name where it has one, and where it is in the message.
        at: String,
        /// The key naming the extension.
        extension: String,
    },

    /// A serde value could not be represented in the KR-CBOR-1 profile.
    #[error("value cannot be represented in KR-CBOR-1: {reason}")]
    Unrepresentable {
        /// Why the value is outside the profile.
        reason: &'static str,
    },

    /// The serde serializer failed before validation could run.
    #[error("serialization failed: {message}")]
    Serialize {
        /// Message from the serde implementation.
        message: String,
    },

    /// The serde deserializer rejected a validated value.
    #[error("deserialization failed: {message}")]
    Deserialize {
        /// Message from the serde implementation.
        message: String,
    },
}

impl CborError {
    /// Returns the stable rule identifier for this failure.
    ///
    /// The cross-language fixtures under `fixtures/cbor/` name the expected rule with these
    /// strings, so the Rust and TypeScript decoders must agree on the byte rules. `unknown_field`
    /// and `unnegotiated_extension` come from [`crate::check`], which reads a message against its
    /// schema rather than its bytes.
    #[must_use]
    pub fn rule(&self) -> &'static str {
        match self {
            Self::EmptyInput => "empty_input",
            Self::UnexpectedEnd { .. } => "unexpected_end",
            Self::TrailingBytes { .. } => "trailing_bytes",
            Self::InputTooLarge { .. } => "input_too_large",
            Self::NonShortestInteger { .. } => "non_shortest_integer",
            Self::NonShortestLength { .. } => "non_shortest_length",
            Self::IndefiniteLength { .. } => "indefinite_length",
            Self::BreakOutsideIndefinite { .. } => "break_outside_indefinite",
            Self::ReservedAdditionalInfo { .. } => "reserved_additional_info",
            Self::Tag { .. } => "tag",
            Self::Float { .. } => "float",
            Self::Undefined { .. } => "undefined",
            Self::SimpleValue { .. } => "simple_value",
            Self::NonTextMapKey { .. } => "non_text_map_key",
            Self::DuplicateKey { .. } => "duplicate_key",
            Self::UnsortedMapKeys { .. } => "unsorted_map_keys",
            Self::InvalidUtf8 { .. } => "invalid_utf8",
            Self::DepthLimit { .. } => "depth_limit",
            Self::CountLimit { .. } => "count_limit",
            Self::CollectionLimit { .. } => "collection_limit",
            Self::LengthLimit { .. } => "length_limit",
            Self::IntegerOutOfRange { .. } => "integer_out_of_range",
            Self::NonCanonical => "non_canonical",
            Self::UnknownField { .. } => "unknown_field",
            Self::UnnegotiatedExtension { .. } => "unnegotiated_extension",
            Self::Unrepresentable { .. } => "unrepresentable",
            Self::Serialize { .. } => "serialize_failed",
            Self::Deserialize { .. } => "deserialize_failed",
        }
    }
}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, CborError>;

impl serde::de::Error for CborError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Self::Deserialize {
            message: msg.to_string(),
        }
    }
}

impl serde::ser::Error for CborError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Self::Serialize {
            message: msg.to_string(),
        }
    }
}
