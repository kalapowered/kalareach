//! The short-code transcript and the five keys derived from it.
//!
//! Section 10 fixes every step of this, and the fixtures under `fixtures/pairing/` freeze the
//! bytes:
//!
//! 1. both devices build the deterministic-CBOR context `C` themselves and reject an inconsistent
//!    one, and `CH = SHA256(C)`;
//! 2. the host is role A with identity `CBOR(["kr-pair/host", CH])` and the client is role B with
//!    `CBOR(["kr-pair/client", CH])`, and both pass the same two identities in that order;
//! 3. `T = SHA256(CBOR([C, message_A, message_B]))`;
//! 4. HKDF-SHA256 with input key material `K` and salt `T` derives five independent 32-byte keys
//!    under five literal information strings;
//! 5. the client sends `HMAC-SHA256(client-confirm-key, T)`, the host verifies it in constant time
//!    and answers with `HMAC-SHA256(host-confirm-key, T)`, and the client verifies that before it
//!    trusts any host metadata.
//!
//! The confirmation step is not decoration. Receiving a key from `finish` does not establish that
//! the peer entered the same password; the tags do.

use kr_crypto::kdf;
use kr_crypto::secret::{Secret, SymmetricKey};
use kr_protocol::pairing::{
    INFO_CLIENT_CONFIRM, INFO_CLIENT_TO_HOST, INFO_HOST_CONFIRM, INFO_HOST_TO_CLIENT,
    INFO_IROH_BIND, PairingContext,
};
use kr_protocol::scalars::{Digest256, Mac256};

use crate::error::{PairingError, Result};

/// The five keys one attempt derives.
///
/// They are independent: each comes from HKDF under its own information string, so a confirmation
/// tag cannot be replayed as a bundle key and the iroh binding tag cannot be produced by anything
/// that only saw a confirmation.
pub struct AttemptKeys {
    /// Keys the client's confirmation tag.
    pub client_confirm: SymmetricKey,
    /// Keys the host's confirmation tag.
    pub host_confirm: SymmetricKey,
    /// Encrypts the candidate's messages to the host.
    pub client_to_host: SymmetricKey,
    /// Encrypts the host's messages to the candidate.
    pub host_to_client: SymmetricKey,
    /// Keys the `pair.finish` tag that binds the transcript to the two iroh endpoints.
    pub iroh_bind: SymmetricKey,
}

impl core::fmt::Debug for AttemptKeys {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AttemptKeys(5 keys, redacted)")
    }
}

impl AttemptKeys {
    /// Derives the five keys from the shared key and the transcript.
    ///
    /// # Errors
    ///
    /// Returns an error only when HKDF rejects the output length, which a 32-byte key never is.
    pub fn derive(shared_key: &[u8], transcript: Digest256) -> Result<Self> {
        let salt = transcript.as_bytes();
        Ok(Self {
            client_confirm: kdf::hkdf_sha256(shared_key, salt, INFO_CLIENT_CONFIRM.as_bytes())?,
            host_confirm: kdf::hkdf_sha256(shared_key, salt, INFO_HOST_CONFIRM.as_bytes())?,
            client_to_host: kdf::hkdf_sha256(shared_key, salt, INFO_CLIENT_TO_HOST.as_bytes())?,
            host_to_client: kdf::hkdf_sha256(shared_key, salt, INFO_HOST_TO_CLIENT.as_bytes())?,
            iroh_bind: kdf::hkdf_sha256(shared_key, salt, INFO_IROH_BIND.as_bytes())?,
        })
    }

    /// Returns the client's confirmation tag over the transcript.
    #[must_use]
    pub fn client_confirmation(&self, transcript: Digest256) -> Mac256 {
        kdf::hmac_sha256(&self.client_confirm, transcript.as_bytes())
    }

    /// Returns the host's confirmation tag over the transcript.
    #[must_use]
    pub fn host_confirmation(&self, transcript: Digest256) -> Mac256 {
        kdf::hmac_sha256(&self.host_confirm, transcript.as_bytes())
    }

    /// Verifies the client's confirmation tag in constant time.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::AuthenticationFailed`], which says nothing about why.
    pub fn verify_client_confirmation(&self, transcript: Digest256, tag: &Mac256) -> Result<()> {
        kdf::verify_hmac_sha256(&self.client_confirm, transcript.as_bytes(), tag)
            .map_err(|_| PairingError::AuthenticationFailed)
    }

    /// Verifies the host's confirmation tag in constant time.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::AuthenticationFailed`].
    pub fn verify_host_confirmation(&self, transcript: Digest256, tag: &Mac256) -> Result<()> {
        kdf::verify_hmac_sha256(&self.host_confirm, transcript.as_bytes(), tag)
            .map_err(|_| PairingError::AuthenticationFailed)
    }

    /// Returns the `pair.finish` tag over the message section 10 specifies.
    #[must_use]
    pub fn binding_tag(&self, message: &[u8]) -> Mac256 {
        kdf::hmac_sha256(&self.iroh_bind, message)
    }

    /// Verifies the `pair.finish` tag in constant time.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::AuthenticationFailed`].
    pub fn verify_binding_tag(&self, message: &[u8], tag: &Mac256) -> Result<()> {
        kdf::verify_hmac_sha256(&self.iroh_bind, message, tag)
            .map_err(|_| PairingError::AuthenticationFailed)
    }
}

/// The shared key the PAKE returned, held so it clears when the attempt ends.
pub struct SharedKey(Secret<32>);

impl SharedKey {
    /// Wraps the key `finish` returned.
    ///
    /// # Errors
    ///
    /// Returns an error when the library returned a key of another length, which would mean the
    /// profile is not the one this build pinned.
    pub fn from_library(bytes: &[u8]) -> Result<Self> {
        Ok(Self(Secret::from_slice("a SPAKE2 shared key", bytes)?))
    }

    /// Returns the key, for the one caller that derives from it.
    #[must_use]
    pub fn expose(&self) -> &[u8; 32] {
        self.0.expose()
    }
}

impl core::fmt::Debug for SharedKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SharedKey(redacted)")
    }
}

/// Checks that two devices built the same context.
///
/// Both construct `C` themselves, from their own configured origin and their own random values, so
/// this compares the digests rather than trusting either side's copy.
///
/// # Errors
///
/// Returns [`PairingError::ContextMismatch`] when they differ.
pub fn require_same_context(ours: &PairingContext, theirs: &PairingContext) -> Result<()> {
    if ours.context_hash() != theirs.context_hash() {
        return Err(PairingError::ContextMismatch {
            what: "the pairing context",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::ids::{AttemptId, InvitationId};
    use kr_protocol::pairing::{HKDF_INFO_STRINGS, Locator, RendezvousOrigin};
    use kr_protocol::scalars::{Nonce256, Uuid};

    fn context() -> PairingContext {
        PairingContext {
            rendezvous_origin: RendezvousOrigin::new("https://reach.kala.to").expect("an origin"),
            locator: Locator::new("aB3x").expect("a locator"),
            invitation_id: InvitationId::new(Uuid::from_bytes([1; 16])),
            attempt_id: AttemptId::new(Uuid::from_bytes([2; 16])),
            host_nonce: Nonce256::from_bytes([3; 32]),
            client_nonce: Nonce256::from_bytes([4; 32]),
        }
    }

    #[test]
    fn the_five_keys_are_independent() {
        let transcript = context().transcript(b"message-a", b"message-b");
        let keys = AttemptKeys::derive(b"shared key", transcript).expect("five keys");
        let derived = [
            &keys.client_confirm,
            &keys.host_confirm,
            &keys.client_to_host,
            &keys.host_to_client,
            &keys.iroh_bind,
        ];
        for (index, left) in derived.iter().enumerate() {
            for right in &derived[index + 1..] {
                assert!(!left.constant_time_eq(right));
            }
        }
        assert_eq!(HKDF_INFO_STRINGS.len(), derived.len());
    }

    #[test]
    fn a_confirmation_tag_verifies_only_over_its_own_transcript() {
        let context = context();
        let transcript = context.transcript(b"a", b"b");
        let other = context.transcript(b"a", b"c");
        let keys = AttemptKeys::derive(b"shared key", transcript).expect("keys");

        let client_tag = keys.client_confirmation(transcript);
        assert!(
            keys.verify_client_confirmation(transcript, &client_tag)
                .is_ok()
        );
        assert!(matches!(
            keys.verify_client_confirmation(other, &client_tag),
            Err(PairingError::AuthenticationFailed)
        ));

        // The host's tag is a different tag: one does not verify as the other.
        let host_tag = keys.host_confirmation(transcript);
        assert_ne!(client_tag, host_tag);
        assert!(keys.verify_host_confirmation(transcript, &host_tag).is_ok());
        assert!(
            keys.verify_host_confirmation(transcript, &client_tag)
                .is_err()
        );
        assert!(
            keys.verify_client_confirmation(transcript, &host_tag)
                .is_err()
        );
    }

    #[test]
    fn another_shared_key_gives_another_set_of_tags() {
        let transcript = context().transcript(b"a", b"b");
        let ours = AttemptKeys::derive(b"shared key", transcript).expect("keys");
        let theirs = AttemptKeys::derive(b"another key", transcript).expect("keys");
        let tag = theirs.client_confirmation(transcript);
        assert!(matches!(
            ours.verify_client_confirmation(transcript, &tag),
            Err(PairingError::AuthenticationFailed)
        ));
    }

    #[test]
    fn a_binding_tag_is_not_a_confirmation_tag() {
        let transcript = context().transcript(b"a", b"b");
        let keys = AttemptKeys::derive(b"shared key", transcript).expect("keys");
        let binding = keys.binding_tag(transcript.as_bytes());
        assert_ne!(binding, keys.client_confirmation(transcript));
        assert!(
            keys.verify_binding_tag(transcript.as_bytes(), &binding)
                .is_ok()
        );
        assert!(keys.verify_binding_tag(b"other", &binding).is_err());
    }

    #[test]
    fn the_transcript_covers_both_library_messages_in_order() {
        let context = context();
        assert_ne!(
            context.transcript(b"a", b"b"),
            context.transcript(b"b", b"a"),
            "the host message comes first"
        );
        assert_ne!(
            context.transcript(b"a", b"b"),
            context.transcript(b"a", b"c")
        );
    }

    #[test]
    fn a_different_context_gives_a_different_transcript_and_identities() {
        let ours = context();
        let mut theirs = context();
        theirs.attempt_id = AttemptId::new(Uuid::from_bytes([9; 16]));
        assert!(require_same_context(&ours, &ours).is_ok());
        assert!(matches!(
            require_same_context(&ours, &theirs),
            Err(PairingError::ContextMismatch { .. })
        ));
        assert_ne!(ours.transcript(b"a", b"b"), theirs.transcript(b"a", b"b"));
        assert_ne!(ours.host_identity(), theirs.host_identity());
    }

    #[test]
    fn a_shared_key_of_another_length_is_refused() {
        assert!(SharedKey::from_library(&[0; 32]).is_ok());
        assert!(SharedKey::from_library(&[0; 31]).is_err());
        assert!(SharedKey::from_library(&[0; 64]).is_err());
        assert_eq!(
            format!("{:?}", SharedKey::from_library(&[0; 32]).expect("a key")),
            "SharedKey(redacted)"
        );
    }
}
