//! Typed cryptography failures.
//!
//! Every variant names what failed rather than why, because an authentication failure must not
//! tell an attacker which part of the input was wrong. Section 10 says the same thing about
//! pairing: an ambiguous authentication failure stays ambiguous.

use kr_cbor::CborError;

/// The result of a cryptographic operation.
pub type Result<T> = core::result::Result<T, CryptoError>;

/// A cryptographic failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// libsodium could not initialise.
    #[error("libsodium could not initialise (sodium_init returned {code})")]
    LibraryUnavailable {
        /// The return code.
        code: std::os::raw::c_int,
    },

    /// A libsodium call reported a failure.
    #[error("{name} returned {code}")]
    Library {
        /// The function that failed.
        name: &'static str,
        /// The return code.
        code: std::os::raw::c_int,
    },

    /// The linked libsodium reports a length the wrapper does not expect.
    ///
    /// The wrapper sizes its buffers from its own constants, so a mismatch has to stop the process
    /// before any buffer is allocated rather than after.
    #[error("{name} is {actual} bytes in the linked libsodium, not {expected}")]
    LibraryMismatch {
        /// The accessor that disagreed.
        name: &'static str,
        /// The length the wrapper expects.
        expected: usize,
        /// The length the library reports.
        actual: usize,
    },

    /// Something did not authenticate.
    ///
    /// The variant names the object, never the reason. A tampered ciphertext, a wrong key and a
    /// replayed nonce all look the same from outside.
    #[error("{what} did not authenticate")]
    Authentication {
        /// What failed to authenticate.
        what: &'static str,
    },

    /// An input was shorter than the minimum its format requires.
    #[error("{what} is {actual} bytes, under the {minimum}-byte minimum")]
    Truncated {
        /// What was too short.
        what: &'static str,
        /// The minimum length.
        minimum: usize,
        /// The actual length.
        actual: usize,
    },

    /// An input was longer than the limit its format sets.
    #[error("{what} is {actual} bytes, over the {limit}-byte limit")]
    TooLarge {
        /// What was too long.
        what: &'static str,
        /// The limit.
        limit: usize,
        /// The actual length.
        actual: usize,
    },

    /// An encrypted object ended without its final authenticated record.
    ///
    /// Section 20 requires the final record before a complete object is accepted, so a truncated
    /// upload cannot pass for a complete one.
    #[error("the encrypted object ended without its final authenticated record")]
    MissingFinalRecord,

    /// An encrypted object carried records after its final one.
    #[error("the encrypted object carries records after its final one")]
    RecordsAfterFinal,

    /// A stored object did not match the hash the manifest or descriptor declared.
    #[error("{what} does not match the declared hash")]
    HashMismatch {
        /// What did not match.
        what: &'static str,
    },

    /// A field inside an authenticated plaintext did not match the value it was checked against.
    #[error("{what} does not match the authenticated value")]
    BindingMismatch {
        /// Which binding failed.
        what: &'static str,
    },

    /// A value could not be represented in KR-CBOR-1.
    #[error(transparent)]
    Encoding(#[from] CborError),

    /// The secret store could not be reached or the operation failed.
    #[error("the secret store failed: {message}")]
    SecretStore {
        /// What the store reported.
        message: String,
    },

    /// A stored secret was not the length its purpose requires.
    #[error("the stored secret for {name} is {actual} bytes, not {expected}")]
    StoredSecretLength {
        /// The item name.
        name: String,
        /// The expected length.
        expected: usize,
        /// The stored length.
        actual: usize,
    },
}
