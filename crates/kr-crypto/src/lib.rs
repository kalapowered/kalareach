//! KalaReach cryptography.
//!
//! Nothing here implements a cipher, a hash, a signature scheme or a PAKE. Section 20 forbids it,
//! and this crate exists to make the maintained implementations safe and hard to misuse rather
//! than to replace them:
//!
//! | What | Where it comes from |
//! | --- | --- |
//! | `crypto_box_easy`, Ed25519, `secretstream`, the pairing AEAD, `crypto_kdf`, the CSPRNG | libsodium, through the pinned `libsodium-sys-stable` binding |
//! | HKDF-SHA256, HMAC-SHA256, SHA-256 | the maintained RustCrypto crates |
//! | Canonical encoding and digests | `kr-cbor` |
//! | Wire shapes | `kr-protocol` |
//!
//! # What the wrapper adds
//!
//! * **One unsafe boundary.** The `sodium` module is the only one that calls the C library and the
//!   only one allowed to use `unsafe`. It is private, so the raw primitives are not part of this
//!   crate's interface: a caller cannot reach a nonce-accepting encryption function or a
//!   `secretstream` without the final-record rule. It checks every length constant against the
//!   linked library at initialisation, so a build that links a different libsodium fails before it
//!   allocates a buffer.
//! * **Purpose separation.** [`keys`] gives the four device key purposes four types that cannot be
//!   converted into each other, and keeps their private material out of reach of code outside this
//!   crate.
//! * **Zeroising secrets.** [`secret::Secret`] and [`secret::SecretVec`] zeroise on drop and
//!   redact themselves in debug output.
//! * **Nonces the caller cannot repeat.** Every sealing function generates its own nonce from
//!   libsodium's random generator and returns it. There is no function that accepts one.
//! * **Domain separation by construction.** [`sign`] has no way to sign a bare message. Signing
//!   takes a [`sign::SigningTranscript`], which is either built from a domain and its elements or
//!   checked against the domain it claims.
//!
//! # Modules
//!
//! | Module | What it does |
//! | --- | --- |
//! | [`secret`] | Zeroising secret buffers |
//! | [`keys`] | The four purpose-separated device keys and key identifiers |
//! | [`sign`] | Ed25519 authorisation signatures over domain-separated transcripts |
//! | [`sealed`] | `crypto_box_easy` between two paired devices |
//! | [`aead`] | The XChaCha20-Poly1305 AEAD the pairing bundle exchange uses |
//! | [`stream`] | `secretstream` in 1 MiB records, with the final record required |
//! | [`kdf`] | HKDF-SHA256, HMAC-SHA256 and the `KRRECOV1` recovery derivations |
//! | [`store`] | Platform secret storage and the documented Unix fallback |
//! | [`connect`] | The `kr-connect/1` mutual proof |
//! | [`envelope`] | Mailbox envelopes |
//! | [`archive`] | Backup objects, key wraps, signed manifests and recovery bundles |
//!
//! # Example
//!
//! ```
//! use kr_crypto::keys::DeviceKeys;
//! use kr_crypto::{sealed, sign};
//! use kr_cbor::CanonicalValue;
//!
//! let host = DeviceKeys::generate()?;
//! let client = DeviceKeys::generate()?;
//!
//! // The four purposes are four independent keys.
//! assert!(host.public_keys().purposes_are_distinct());
//!
//! // A signature covers a domain-separated transcript, never a bare message.
//! let signature = sign::sign_elements(
//!     &host.authorisation,
//!     "kr-pair/host-bundle/1",
//!     vec![CanonicalValue::text("the bundle")],
//! )?;
//! assert!(
//!     sign::verify_elements(
//!         host.authorisation.public(),
//!         "kr-pair/host-bundle/1",
//!         vec![CanonicalValue::text("the bundle")],
//!         &signature,
//!     )
//!     .is_ok()
//! );
//!
//! // Sealing generates its own nonce; the caller cannot repeat one.
//! let (nonce, ciphertext) = sealed::seal_stored_envelope(
//!     &host.stored_envelope,
//!     client.stored_envelope.public(),
//!     b"an envelope",
//! )?;
//! let opened = sealed::open_stored_envelope(
//!     &client.stored_envelope,
//!     host.stored_envelope.public(),
//!     &nonce,
//!     &ciphertext,
//! )?;
//! assert_eq!(opened.expose(), b"an envelope");
//! # Ok::<(), kr_crypto::CryptoError>(())
//! ```

pub mod aead;
pub mod archive;
pub mod connect;
pub mod envelope;
mod error;
pub mod kdf;
pub mod keys;
pub mod sealed;
pub mod secret;
pub mod sign;
mod sodium;
pub mod store;
pub mod stream;
pub mod vectors;

pub use crate::error::{CryptoError, Result};

/// Initialises libsodium and verifies that the linked library matches this wrapper.
///
/// Every operation calls this first, so an application does not have to. It is public so a host
/// can fail at startup rather than at its first cryptographic operation.
///
/// # Errors
///
/// Returns [`CryptoError::LibraryUnavailable`] or [`CryptoError::LibraryMismatch`].
pub fn initialise() -> Result<()> {
    sodium::initialise()
}
