//! Key derivation: HKDF-SHA256 and HMAC-SHA256 for pairing, `crypto_kdf` for recovery.
//!
//! Two different libraries, because the specification names two different things. Section 10's
//! pairing derivations use maintained RustCrypto HKDF-SHA256 and HMAC-SHA256; section 20's
//! recovery seed uses libsodium's own KDF with context `KRRECOV1`. Neither is implemented here.

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use kr_protocol::archive::{
    RECOVERY_BUNDLE_DOMAIN, RECOVERY_BUNDLE_SUBKEY_ID, RECOVERY_KDF_CONTEXT,
    RECOVERY_RECIPIENT_SUBKEY_ID, RecoveryContext, RecoveryKit,
};
use kr_protocol::scalars::{Bytes, Mac256, StoredEnvelopeKey, U64};
use sha2::Sha256;

use crate::error::{CryptoError, Result};
use crate::secret::{Secret, SymmetricKey};
use crate::sodium;

/// The eight-byte `crypto_kdf` context of the recovery seed.
pub const RECOVERY_CONTEXT: [u8; sodium::KDF_CONTEXT_LEN] = {
    let bytes = RECOVERY_KDF_CONTEXT.as_bytes();
    assert!(
        bytes.len() == sodium::KDF_CONTEXT_LEN,
        "a crypto_kdf context is exactly eight bytes"
    );
    [
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]
};

/// Derives a 32-byte key with HKDF-SHA256.
///
/// The salt is the pairing transcript and the information string is one of the five literals
/// section 10 lists, so the five keys of one attempt are independent and none of them is reachable
/// from another attempt.
///
/// # Errors
///
/// Returns an error only when the requested length is outside HKDF's output range, which a
/// 32-byte key never is.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<SymmetricKey> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hkdf.expand(info, &mut okm)
        .map_err(|_| CryptoError::TooLarge {
            what: "an HKDF-SHA256 output",
            limit: 255 * 32,
            actual: okm.len(),
        })?;
    let key = Secret::from_bytes(okm);
    sodium::memzero(&mut okm);
    Ok(key)
}

/// Computes `HMAC-SHA256(key, message)`.
#[must_use]
pub fn hmac_sha256(key: &SymmetricKey, message: &[u8]) -> Mac256 {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.expose()).expect("HMAC accepts any key length");
    mac.update(message);
    Mac256::from_bytes(mac.finalize().into_bytes().into())
}

/// Verifies `HMAC-SHA256(key, message)` against `tag` in constant time.
///
/// # Errors
///
/// Returns [`CryptoError::Authentication`] when the tag does not match.
pub fn verify_hmac_sha256(key: &SymmetricKey, message: &[u8], tag: &Mac256) -> Result<()> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.expose()).expect("HMAC accepts any key length");
    mac.update(message);
    mac.verify_slice(tag.as_bytes())
        .map_err(|_| CryptoError::Authentication {
            what: "an HMAC-SHA256 tag",
        })
}

/// The 256-bit recovery seed, and the material it derives.
///
/// The seed lives in the owner's secure store and in the printed recovery kit. Everything a
/// restore needs comes out of it: the bundle key under subkey 1 and the recovery recipient's
/// `crypto_box` keypair under subkey 2. Backup producers hold only the recipient's public key, so
/// every new archive stays recoverable without copying a device private key.
#[derive(Debug, Clone)]
pub struct RecoverySeed(Secret<32>);

impl RecoverySeed {
    /// Generates a fresh seed.
    ///
    /// # Errors
    ///
    /// Returns an error when libsodium is unavailable.
    pub fn generate() -> Result<Self> {
        Ok(Self(Secret::random()?))
    }

    /// Reads a seed back from its stored item or from a recovery kit.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not 32 bytes.
    pub fn from_stored_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(Secret::from_slice("a recovery seed", bytes)?))
    }

    /// Returns the seed's checksum, so a mistyped kit fails before anything is decrypted.
    ///
    /// It is the first four bytes of the SHA-256 of the seed, which is enough to catch a
    /// transcription error and carries no secret.
    #[must_use]
    pub fn checksum(&self) -> [u8; 4] {
        let digest = kr_cbor::sha256(self.0.expose());
        [digest[0], digest[1], digest[2], digest[3]]
    }

    /// Returns true when `checksum` is this seed's checksum.
    #[must_use]
    pub fn checksum_matches(&self, checksum: &[u8]) -> bool {
        sodium::constant_time_eq(&self.checksum(), checksum)
    }

    /// Derives the recovery-bundle encryption key, subkey 1 of context `KRRECOV1`.
    ///
    /// # Errors
    ///
    /// Returns an error when libsodium is unavailable or reports a failure.
    pub fn bundle_key(&self) -> Result<SymmetricKey> {
        let mut subkey = [0u8; 32];
        sodium::kdf_derive(
            &mut subkey,
            RECOVERY_BUNDLE_SUBKEY_ID,
            &RECOVERY_CONTEXT,
            self.0.expose(),
        )?;
        let key = Secret::from_bytes(subkey);
        sodium::memzero(&mut subkey);
        Ok(key)
    }

    /// Exports the kit the user keeps: the seed, its checksum, the configured service origins and
    /// the stable bundle locator.
    ///
    /// A seed without a way to find the encrypted bundle is not a complete kit, so the locator and
    /// the origins travel with it.
    #[must_use]
    pub fn to_kit(
        &self,
        profile_version: u64,
        service_origins: Vec<String>,
        bundle_locator: String,
    ) -> RecoveryKit {
        RecoveryKit {
            profile_version: U64::new(profile_version),
            seed: Bytes::new(self.0.expose().to_vec()),
            seed_checksum: Bytes::new(self.checksum().to_vec()),
            service_origins,
            bundle_locator,
        }
    }

    /// Reads the seed out of a kit, checking its checksum first.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Authentication`] when the checksum does not match the seed, which is
    /// what a mistyped printed kit looks like, and a length error when the seed is not 32 bytes.
    pub fn from_kit(kit: &RecoveryKit) -> Result<Self> {
        let seed = Self::from_stored_bytes(kit.seed.as_slice())?;
        if !seed.checksum_matches(kit.seed_checksum.as_slice()) {
            return Err(CryptoError::Authentication {
                what: "a recovery kit checksum",
            });
        }
        Ok(seed)
    }

    /// Derives the encryption key of the recovery bundle at one retrieval context.
    ///
    /// The bundle key from subkey 1 is mixed with the origin and locator the bundle is being read
    /// from, so a bundle served from another origin or under another locator does not authenticate.
    /// Origin or locator substitution therefore fails authentication instead of causing trust in
    /// archive-supplied writer keys.
    ///
    /// # Errors
    ///
    /// Returns an error when libsodium is unavailable or the context is outside KR-CBOR-1.
    pub fn bundle_key_for(&self, context: &RecoveryContext) -> Result<SymmetricKey> {
        let salt = context.to_canonical_bytes()?;
        let master = self.bundle_key()?;
        hkdf_sha256(master.expose(), &salt, RECOVERY_BUNDLE_DOMAIN.as_bytes())
    }

    /// Derives the recovery recipient's `crypto_box` keypair, from subkey 2 of context `KRRECOV1`.
    ///
    /// # Errors
    ///
    /// Returns an error when libsodium is unavailable or reports a failure.
    pub fn recipient(&self) -> Result<RecoveryRecipient> {
        let mut seed = [0u8; 32];
        sodium::kdf_derive(
            &mut seed,
            RECOVERY_RECIPIENT_SUBKEY_ID,
            &RECOVERY_CONTEXT,
            self.0.expose(),
        )?;
        let result = sodium::box_seed_keypair(&seed);
        sodium::memzero(&mut seed);
        let (public, mut secret) = result?;
        let held = Secret::from_bytes(secret);
        sodium::memzero(&mut secret);
        Ok(RecoveryRecipient {
            secret: held,
            public: StoredEnvelopeKey::from_bytes(public),
        })
    }

    pub(crate) const fn expose(&self) -> &[u8; 32] {
        self.0.expose()
    }
}

/// The `crypto_box` recipient a recovery-enabled collection wraps its manifest keys for.
///
/// It is an ordinary stored-envelope recipient: it opens key wraps and nothing else. It is not a
/// device key, so it carries no fifth key purpose; what makes it different is that it is derived
/// from the recovery seed rather than generated on a device.
#[derive(Debug, Clone)]
pub struct RecoveryRecipient {
    secret: Secret<32>,
    public: StoredEnvelopeKey,
}

impl RecoveryRecipient {
    /// Returns the public key a backup producer registers and wraps for.
    #[must_use]
    pub const fn public(&self) -> &StoredEnvelopeKey {
        &self.public
    }

    pub(crate) const fn secret(&self) -> &Secret<32> {
        &self.secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_recovery_context_is_the_specified_literal() {
        assert_eq!(&RECOVERY_CONTEXT, b"KRRECOV1");
    }

    #[test]
    fn hkdf_separates_the_information_strings() {
        let first = hkdf_sha256(b"ikm", b"salt", b"kr-pair/1/client-confirm").expect("a key");
        let second = hkdf_sha256(b"ikm", b"salt", b"kr-pair/1/host-confirm").expect("a key");
        assert!(!first.constant_time_eq(&second));
    }

    #[test]
    fn hkdf_separates_the_salts() {
        let first = hkdf_sha256(b"ikm", b"salt-a", b"info").expect("a key");
        let second = hkdf_sha256(b"ikm", b"salt-b", b"info").expect("a key");
        assert!(!first.constant_time_eq(&second));
    }

    #[test]
    fn hkdf_matches_rfc_5869_test_case_one() {
        // RFC 5869 appendix A.1: SHA-256, 22-byte IKM of 0x0b, 13-byte salt 0x000102..0c,
        // 10-byte info 0xf0f1..f9. The first 32 bytes of the 42-byte OKM are checked here.
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0u8..=0x0c).collect();
        let info: Vec<u8> = (0xf0u8..=0xf9).collect();
        let key = hkdf_sha256(&ikm, &salt, &info).expect("a key");
        assert_eq!(
            hex::encode(key.expose()),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        );
    }

    #[test]
    fn hmac_matches_rfc_4231_test_case_two() {
        // RFC 4231 section 4.3: key "Jefe", data "what do ya want for nothing?".
        let mut key_bytes = [0u8; 32];
        key_bytes[..4].copy_from_slice(b"Jefe");
        // The RFC key is four bytes; this wrapper takes a 32-byte key, so the vector is checked
        // through the raw HMAC the wrapper calls rather than through the key type.
        let mut mac = Hmac::<Sha256>::new_from_slice(b"Jefe").expect("any key length");
        mac.update(b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(mac.finalize().into_bytes()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn an_hmac_tag_verifies_and_a_changed_message_does_not() {
        let key = SymmetricKey::random().expect("a key");
        let tag = hmac_sha256(&key, b"message");
        assert!(verify_hmac_sha256(&key, b"message", &tag).is_ok());
        assert!(matches!(
            verify_hmac_sha256(&key, b"other", &tag),
            Err(CryptoError::Authentication { .. })
        ));
    }

    #[test]
    fn the_two_recovery_subkeys_differ_and_are_deterministic() {
        let seed = RecoverySeed::generate().expect("a seed");
        let bundle = seed.bundle_key().expect("a bundle key");
        let recipient = seed.recipient().expect("a recipient");
        assert!(!bundle.constant_time_eq(&Secret::from_bytes(*recipient.secret().expose())));

        let fixed = RecoverySeed::from_stored_bytes(&[5; 32]).expect("a seed");
        let again = RecoverySeed::from_stored_bytes(&[5; 32]).expect("a seed");
        assert!(
            fixed
                .bundle_key()
                .expect("a bundle key")
                .constant_time_eq(&again.bundle_key().expect("a bundle key"))
        );
        assert_eq!(
            fixed.recipient().expect("a recipient").public(),
            again.recipient().expect("a recipient").public()
        );
    }

    #[test]
    fn a_kit_round_trips_and_a_mistyped_checksum_fails() {
        let seed = RecoverySeed::generate().expect("a seed");
        let kit = seed.to_kit(
            1,
            vec!["https://reach.kala.to".to_owned()],
            "opaque-locator".to_owned(),
        );
        let restored = RecoverySeed::from_kit(&kit).expect("the seed");
        assert_eq!(restored.checksum(), seed.checksum());

        let mut mistyped = kit;
        mistyped.seed_checksum = Bytes::new(vec![0; 4]);
        assert!(matches!(
            RecoverySeed::from_kit(&mistyped),
            Err(CryptoError::Authentication { .. })
        ));
    }

    #[test]
    fn the_bundle_key_is_bound_to_the_origin_and_locator() {
        let seed = RecoverySeed::generate().expect("a seed");
        let here = RecoveryContext {
            service_origin: "https://reach.kala.to".to_owned(),
            bundle_locator: "opaque-locator".to_owned(),
        };
        let other_origin = RecoveryContext {
            service_origin: "https://elsewhere.example".to_owned(),
            ..here.clone()
        };
        let other_locator = RecoveryContext {
            bundle_locator: "another-locator".to_owned(),
            ..here.clone()
        };
        let key = seed.bundle_key_for(&here).expect("a key");
        assert!(!key.constant_time_eq(&seed.bundle_key_for(&other_origin).expect("a key")));
        assert!(!key.constant_time_eq(&seed.bundle_key_for(&other_locator).expect("a key")));
        assert!(key.constant_time_eq(&seed.bundle_key_for(&here).expect("a key")));
    }

    #[test]
    fn a_seed_checksum_catches_a_transcription_error() {
        let seed = RecoverySeed::from_stored_bytes(&[1; 32]).expect("a seed");
        let checksum = seed.checksum();
        assert!(seed.checksum_matches(&checksum));
        let mistyped = RecoverySeed::from_stored_bytes(&[2; 32]).expect("a seed");
        assert!(!mistyped.checksum_matches(&checksum));
    }
}
