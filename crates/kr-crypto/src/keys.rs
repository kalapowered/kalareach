//! The four purpose-separated device keys of section 10.
//!
//! Each installed device creates independent keys for iroh transport, Ed25519 authorisation
//! signatures, X25519 stored-envelope encryption and X25519 notification previews. One private key
//! is never converted or reused across purposes, and this module makes that structural rather than
//! a convention:
//!
//! * The four keypairs are four types with no conversion between them and no shared trait that
//!   would let one stand in for another.
//! * Their private material lives in per-purpose seed types whose bytes are visible only inside
//!   this crate, so code outside it cannot take one purpose's seed and build another purpose's key
//!   from it. The one deliberate exception is
//!   [`TransportIdentityKeyPair::export_endpoint_seed`], because iroh owns the transport handshake
//!   and needs the seed to build its own endpoint identity.
//! * [`DeviceKeys::public_keys`] produces a bundle that fails
//!   [`DevicePublicKeys::purposes_are_distinct`] if two purposes ever share a key.

use kr_protocol::pairing::{DevicePublicKeys, KeyPurpose};
use kr_protocol::scalars::{
    AuthorisationKey, EndpointKey, KeyId, NotificationPreviewKey, StoredEnvelopeKey,
};

use crate::error::Result;
use crate::secret::Secret;
use crate::sodium;

/// Returns the identifier of one public key: `SHA256(CBOR(["kr-key-id/1", purpose, key]))`.
///
/// The derivation belongs to the wire contract, so it is `kr_protocol::pairing::key_id` and this is
/// the name the key types here reach it by. One implementation, one set of bytes: a second one
/// would be a second answer to a question the protocol has already settled.
#[must_use]
pub fn key_id(purpose: KeyPurpose, public_key: &[u8; 32]) -> KeyId {
    kr_protocol::pairing::key_id(purpose, public_key)
}

/// Declares one purpose's private seed.
///
/// The bytes are crate-private. Outside this crate a seed can be generated, stored and loaded, but
/// never read, so it cannot be handed to another purpose's constructor.
macro_rules! purpose_seed {
    ($(#[$meta:meta])* $name:ident, $purpose:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone)]
        pub struct $name(Secret<32>);

        impl $name {
            /// The purpose this seed belongs to.
            pub const PURPOSE: KeyPurpose = $purpose;

            /// Generates a fresh seed from libsodium's random generator.
            ///
            /// # Errors
            ///
            /// Returns an error when libsodium is unavailable.
            pub fn generate() -> Result<Self> {
                Ok(Self(Secret::random()?))
            }

            /// Reads a seed back from this purpose's own stored item.
            ///
            /// It is crate-private. If a caller outside this crate could build a seed from raw
            /// bytes, it could take one purpose's seed and construct another purpose's key from
            /// it, which section 10 forbids. Restoring a device's keys goes through
            /// [`crate::store::load_device_keys`], which reads one item per purpose.
            ///
            /// # Errors
            ///
            /// Returns an error when the stored value is not 32 bytes.
            pub(crate) fn from_stored_bytes(bytes: &[u8]) -> Result<Self> {
                Ok(Self(Secret::from_slice(
                    concat!("the stored ", stringify!($name)),
                    bytes,
                )?))
            }

            pub(crate) const fn expose(&self) -> &[u8; 32] {
                self.0.expose()
            }
        }
    };
}

purpose_seed!(
    /// The seed of a device's iroh transport identity.
    TransportSeed,
    KeyPurpose::Transport
);
purpose_seed!(
    /// The seed of a device's Ed25519 authorisation key.
    AuthorisationSeed,
    KeyPurpose::Authorisation
);
purpose_seed!(
    /// The seed of a device's X25519 stored-envelope key.
    StoredEnvelopeSeed,
    KeyPurpose::StoredEnvelope
);
purpose_seed!(
    /// The seed of a device's X25519 notification-preview key.
    NotificationPreviewSeed,
    KeyPurpose::NotificationPreview
);

/// A device's iroh transport identity.
///
/// KalaReach never signs application data with this key. It exists so the device has a stable
/// endpoint identity that pairing can pin, and the transport layer builds iroh's own endpoint from
/// its seed.
#[derive(Debug, Clone)]
pub struct TransportIdentityKeyPair {
    seed: TransportSeed,
    public: EndpointKey,
}

impl TransportIdentityKeyPair {
    /// Generates a fresh transport identity.
    ///
    /// # Errors
    ///
    /// Returns an error when libsodium is unavailable or reports a failure.
    pub fn generate() -> Result<Self> {
        Self::from_seed(TransportSeed::generate()?)
    }

    /// Derives the identity from a seed read back from its own stored item.
    ///
    /// # Errors
    ///
    /// Returns an error when libsodium is unavailable or reports a failure.
    pub fn from_seed(seed: TransportSeed) -> Result<Self> {
        let (public, mut expanded) = sodium::sign_seed_keypair(seed.expose())?;
        // The expanded secret key is not kept: this key signs nothing here.
        sodium::memzero(&mut expanded);
        Ok(Self {
            seed,
            public: EndpointKey::from_bytes(public),
        })
    }

    /// Returns the endpoint identity.
    #[must_use]
    pub const fn public(&self) -> &EndpointKey {
        &self.public
    }

    /// Returns the key identifier.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        key_id(KeyPurpose::Transport, self.public.as_bytes())
    }

    /// Exports the seed so the transport layer can build iroh's endpoint from it.
    ///
    /// This is the only private key material this crate hands out, and it exists because iroh owns
    /// the transport handshake. It cannot be fed back into another purpose: the seed types take
    /// raw bytes only inside this crate, so there is no constructor outside it that would accept
    /// the result. The transport crate passes it straight to iroh and drops it.
    #[must_use]
    pub fn export_endpoint_seed(&self) -> Secret<32> {
        Secret::from_bytes(*self.seed.expose())
    }

    pub(crate) const fn seed(&self) -> &TransportSeed {
        &self.seed
    }
}

/// A device's Ed25519 authorisation keypair.
///
/// It signs pairing bundles, connection proofs, grants, revocation requests, owner-confirmation
/// proofs and archive manifests. It never encrypts and it is never an endpoint identity.
#[derive(Debug, Clone)]
pub struct AuthorisationKeyPair {
    seed: AuthorisationSeed,
    expanded: Secret<64>,
    public: AuthorisationKey,
}

impl AuthorisationKeyPair {
    /// Generates a fresh authorisation keypair.
    ///
    /// # Errors
    ///
    /// Returns an error when libsodium is unavailable or reports a failure.
    pub fn generate() -> Result<Self> {
        Self::from_seed(AuthorisationSeed::generate()?)
    }

    /// Derives the keypair from a seed read back from its own stored item.
    ///
    /// # Errors
    ///
    /// Returns an error when libsodium is unavailable or reports a failure.
    pub fn from_seed(seed: AuthorisationSeed) -> Result<Self> {
        let (public, mut expanded) = sodium::sign_seed_keypair(seed.expose())?;
        let held = Secret::from_bytes(expanded);
        // `expanded` is an array, so wrapping it copied it. Wipe the library's own copy.
        sodium::memzero(&mut expanded);
        Ok(Self {
            seed,
            expanded: held,
            public: AuthorisationKey::from_bytes(public),
        })
    }

    /// Returns the public key.
    #[must_use]
    pub const fn public(&self) -> &AuthorisationKey {
        &self.public
    }

    /// Returns the key identifier.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        key_id(KeyPurpose::Authorisation, self.public.as_bytes())
    }

    pub(crate) const fn expanded(&self) -> &Secret<64> {
        &self.expanded
    }

    pub(crate) const fn seed(&self) -> &AuthorisationSeed {
        &self.seed
    }
}

/// Declares one X25519 `crypto_box` keypair type.
macro_rules! box_keypair {
    ($(#[$meta:meta])* $name:ident, $seed:ty, $public:ty, $purpose:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone)]
        pub struct $name {
            seed: $seed,
            secret: Secret<32>,
            public: $public,
        }

        impl $name {
            /// Generates a fresh keypair.
            ///
            /// # Errors
            ///
            /// Returns an error when libsodium is unavailable or reports a failure.
            pub fn generate() -> Result<Self> {
                Self::from_seed(<$seed>::generate()?)
            }

            /// Derives the keypair from a seed read back from its own stored item.
            ///
            /// # Errors
            ///
            /// Returns an error when libsodium is unavailable or reports a failure.
            pub fn from_seed(seed: $seed) -> Result<Self> {
                let (public, mut secret) = sodium::box_seed_keypair(seed.expose())?;
                let held = Secret::from_bytes(secret);
                // `secret` is an array, so wrapping it copied it. Wipe the library's own copy.
                sodium::memzero(&mut secret);
                Ok(Self {
                    seed,
                    secret: held,
                    public: <$public>::from_bytes(public),
                })
            }

            /// Returns the public key.
            #[must_use]
            pub const fn public(&self) -> &$public {
                &self.public
            }

            /// Returns the key identifier.
            #[must_use]
            pub fn key_id(&self) -> KeyId {
                key_id($purpose, self.public.as_bytes())
            }

            pub(crate) const fn secret(&self) -> &Secret<32> {
                &self.secret
            }

            pub(crate) const fn seed(&self) -> &$seed {
                &self.seed
            }
        }
    };
}

box_keypair!(
    /// A device's X25519 stored-envelope keypair.
    ///
    /// It opens mailbox envelopes and backup key wraps. The notification extension never receives
    /// it.
    StoredEnvelopeKeyPair,
    StoredEnvelopeSeed,
    StoredEnvelopeKey,
    KeyPurpose::StoredEnvelope
);

box_keypair!(
    /// A device's X25519 notification-preview keypair.
    ///
    /// The notification extension receives this private key and paired sender public keys, and no
    /// general stored-envelope, archive, recovery or control-signing private key.
    NotificationPreviewKeyPair,
    NotificationPreviewSeed,
    NotificationPreviewKey,
    KeyPurpose::NotificationPreview
);

/// One device's complete set of independent keys.
#[derive(Debug, Clone)]
pub struct DeviceKeys {
    /// The iroh transport identity.
    pub transport: TransportIdentityKeyPair,
    /// The Ed25519 authorisation keypair.
    pub authorisation: AuthorisationKeyPair,
    /// The X25519 stored-envelope keypair.
    pub stored_envelope: StoredEnvelopeKeyPair,
    /// The X25519 notification-preview keypair.
    pub notification_preview: NotificationPreviewKeyPair,
}

impl DeviceKeys {
    /// Generates four independent keys.
    ///
    /// # Errors
    ///
    /// Returns an error when libsodium is unavailable or reports a failure.
    pub fn generate() -> Result<Self> {
        Ok(Self {
            transport: TransportIdentityKeyPair::generate()?,
            authorisation: AuthorisationKeyPair::generate()?,
            stored_envelope: StoredEnvelopeKeyPair::generate()?,
            notification_preview: NotificationPreviewKeyPair::generate()?,
        })
    }

    /// Returns the public bundle a pairing exchange binds to a device record.
    #[must_use]
    pub const fn public_keys(&self) -> DevicePublicKeys {
        DevicePublicKeys {
            transport: *self.transport.public(),
            authorisation: *self.authorisation.public(),
            stored_envelope: *self.stored_envelope.public(),
            notification_preview: *self.notification_preview.public(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_four_purposes_produce_four_different_keys() {
        let keys = DeviceKeys::generate().expect("libsodium is available");
        let public = keys.public_keys();
        assert!(public.purposes_are_distinct());
    }

    #[test]
    fn a_key_identifier_covers_the_purpose() {
        let bytes = [9u8; 32];
        assert_ne!(
            key_id(KeyPurpose::StoredEnvelope, &bytes),
            key_id(KeyPurpose::NotificationPreview, &bytes)
        );
    }

    #[test]
    fn a_seed_reproduces_the_same_public_key() {
        let seed = AuthorisationSeed::generate().expect("libsodium is available");
        let first = AuthorisationKeyPair::from_seed(seed.clone()).expect("a keypair");
        let second = AuthorisationKeyPair::from_seed(seed).expect("a keypair");
        assert_eq!(first.public(), second.public());
    }

    #[test]
    fn the_same_seed_bytes_under_two_purposes_still_give_two_public_keys() {
        // The seed types are separate, so this is only reachable by deliberately storing the same
        // bytes under two items. Even then, the two algorithms give two different public keys, and
        // the key identifiers differ because the purpose is inside the hash.
        let raw = [3u8; 32];
        let signing = AuthorisationKeyPair::from_seed(
            AuthorisationSeed::from_stored_bytes(&raw).expect("32 bytes"),
        )
        .expect("a keypair");
        let boxed = StoredEnvelopeKeyPair::from_seed(
            StoredEnvelopeSeed::from_stored_bytes(&raw).expect("32 bytes"),
        )
        .expect("a keypair");
        assert_ne!(signing.public().as_bytes(), boxed.public().as_bytes());
        assert_ne!(signing.key_id(), boxed.key_id());
    }

    #[test]
    fn an_exported_transport_seed_cannot_become_another_purpose() {
        // `export_endpoint_seed` is the one export, and the only constructors that take raw bytes
        // are crate-private, so this is a compile-time property rather than a runtime check. The
        // test records what the export is for.
        let keys = TransportIdentityKeyPair::generate().expect("a keypair");
        let exported = keys.export_endpoint_seed();
        let rebuilt = TransportIdentityKeyPair::from_seed(
            TransportSeed::from_stored_bytes(exported.expose()).expect("32 bytes"),
        )
        .expect("a keypair");
        assert_eq!(rebuilt.public(), keys.public());
    }

    #[test]
    fn a_stored_seed_of_the_wrong_length_is_rejected() {
        assert!(TransportSeed::from_stored_bytes(&[0; 31]).is_err());
        assert!(TransportSeed::from_stored_bytes(&[0; 32]).is_ok());
    }
}
