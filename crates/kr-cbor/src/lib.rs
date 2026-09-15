//! KR-CBOR-1: the canonical encoding KalaReach signs, hashes and frames.
//!
//! # The profile
//!
//! KR-CBOR-1 is RFC 8949 section 4.2.1 core deterministic encoding — definite lengths, shortest
//! integer and length encodings, and map keys sorted by the bytewise lexicographic order of their
//! complete encoded keys — narrowed by an application profile. It is *not* the differently named
//! length-first variant in RFC 8949 section 4.2.3.
//!
//! Permitted: integers in CBOR's 64-bit argument range, byte strings, valid UTF-8 text, arrays,
//! text-keyed maps, booleans and schema-declared `null`.
//!
//! Forbidden: tags, floats, indefinite lengths, `undefined` and other simple values, duplicate
//! keys, non-shortest encodings and trailing bytes.
//!
//! No Unicode normalisation or case folding happens here. Byte-distinct strings stay distinct;
//! a schema that needs a canonical identifier validates it *before* encoding. `null` is a value,
//! never an omitted field. Decimal and scaled numbers use schema-defined integer or text
//! representations. UUIDs are 16-byte strings and timestamps are integer UTC milliseconds, never
//! tagged dates.
//!
//! # Why a maintained encoder plus a strict layer
//!
//! The specification requires maintained encoders plus a strict validator and adaptation layer,
//! and forbids a new handwritten cryptographic implementation. This crate follows that split:
//!
//! * `ciborium`, the maintained implementation, owns the serde work and writes the bytes. It turns
//!   Rust types into a value tree and back, and [`encode`] hands it a validated, key-ordered tree
//!   to serialise. That is the part that benefits from an upstream maintainer: derive support,
//!   enum representations, borrowed data and the long tail of serde behaviour.
//! * This crate owns the byte rules on the way in. A value tree cannot answer the questions the
//!   profile asks: whether a length was indefinite, whether an argument used a longer head than
//!   necessary, whether two keys collided, what order the keys arrived in, whether bytes followed
//!   the object. A decoder that answers those questions has to read the bytes, so [`decode`] does,
//!   and it names the broken rule in a typed error.
//! * Encoding needs no such reader. [`CanonicalValue`] admits only permitted shapes and keeps maps
//!   in canonical key order, so a validated tree serialises to canonical bytes. The conformance
//!   tests check that against the fixture bytes rather than assuming it.
//!
//! Neither half re-implements the other. `ciborium` never sees unvalidated bytes and this crate
//! never re-implements serde or the CBOR writer.
//!
//! # Flow
//!
//! ```text
//! outbound: T -> ciborium value -> validate -> CanonicalValue -> canonical bytes
//! inbound:  bytes -> strict decode (every rule) -> CanonicalValue -> ciborium value -> T
//! ```
//!
//! # Example
//!
//! ```
//! use kr_cbor::{CanonicalMap, CanonicalValue, Limits, decode, encode};
//!
//! let mut map = CanonicalMap::new();
//! map.insert("aa".to_owned(), CanonicalValue::integer(2)?)?;
//! map.insert("z".to_owned(), CanonicalValue::integer(1)?)?;
//!
//! // "z" sorts first: its complete encoded key is shorter.
//! let bytes = encode(&CanonicalValue::Map(map));
//! assert_eq!(bytes, [0xa2, 0x61, 0x7a, 0x01, 0x62, 0x61, 0x61, 0x02]);
//! assert_eq!(decode(&bytes, &Limits::DEFAULT)?, decode(&bytes, &Limits::DEFAULT)?);
//! # Ok::<(), kr_cbor::CborError>(())
//! ```

mod decode;
mod digest;
mod encode;
mod error;
mod limits;
mod serde_bridge;
mod value;

pub use crate::decode::decode;
pub use crate::digest::{
    SHA256_LEN, sha256, sha256_of_canonical, signing_digest, signing_input, signing_value,
};
pub use crate::encode::{encode, encode_into};
pub use crate::error::{CborError, Result};
pub use crate::limits::Limits;
pub use crate::serde_bridge::{
    from_canonical_slice, from_canonical_value, from_ciborium, to_canonical_value,
    to_canonical_vec, to_canonical_vec_within, to_ciborium,
};
pub use crate::value::{CanonicalMap, CanonicalValue, Integer, compare_keys};
