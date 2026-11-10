//! The device's half of an unlocked-screen voice confirmation: the signature over the host's
//! challenge.
//!
//! Section 15 ¶8: a confirmation is a signature over the exact action by the paired device's
//! identity key, never a statement in the conversation. The host issues the challenge and verifies
//! the answer; the device that was asked to confirm makes the answer here, once its person has
//! completed the platform's ceremony. Nothing in this module asks the person or decides whether the
//! challenge is one to put to them: that is the caller's, and a signature made over a challenge the
//! caller did not check is a signature for whatever the host chose to ask.

use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign::{self, SigningTranscript};
use kr_protocol::voice::{VOICE_CONFIRM_DOMAIN, VoiceConfirmationProof, VoiceConfirmationRequest};

use crate::error::{ClientError, Result};
use crate::shown::Shown;

/// Signs a challenge the way a paired device does after its person has confirmed.
///
/// The signature covers `CBOR(["kr-voice/confirm/1", request])`, the whole challenge: a field the
/// host could change beside it would be the signer's unauthenticated claim, so none sits beside it.
///
/// # Errors
///
/// Returns [`ClientError::Cbor`] when the challenge cannot be encoded as KR-CBOR-1 or the
/// signature cannot be made.
pub fn sign_voice_confirmation(
    key: &AuthorisationKeyPair,
    request: &VoiceConfirmationRequest,
) -> Result<VoiceConfirmationProof> {
    let transcript =
        SigningTranscript::from_canonical_bytes(VOICE_CONFIRM_DOMAIN, request.signing_input()?)
            .map_err(|error| ClientError::Cbor(Shown::crypto(&error)))?;
    let signature =
        sign::sign(key, &transcript).map_err(|error| ClientError::Cbor(Shown::crypto(&error)))?;
    Ok(VoiceConfirmationProof {
        request: request.clone(),
        signer_key_id: key.key_id(),
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::ids::{ActionId, ConfirmationId, DeviceId, VoiceSessionId};
    use kr_protocol::scalars::{Digest256, Nonce256, TimestampMs, Uuid};
    use kr_protocol::voice::VoiceAction;

    /// The challenge `voice_confirmation_vectors` in kr-protocol holds to fixed bytes.
    fn challenge() -> VoiceConfirmationRequest {
        VoiceConfirmationRequest {
            confirmation_id: ConfirmationId::new(Uuid::from_bytes([0x11; 16])),
            voice_session_id: VoiceSessionId::new(Uuid::from_bytes([0x22; 16])),
            action: VoiceAction::ApplyDiff,
            action_digest: Digest256::from_bytes([0x33; 32]),
            action_id: ActionId::new(Uuid::from_bytes([0x44; 16])),
            host_device_id: DeviceId::new(Uuid::from_bytes([0x55; 16])),
            device_id: DeviceId::new(Uuid::from_bytes([0x66; 16])),
            nonce: Nonce256::from_bytes([0x77; 32]),
            expires_at_ms: TimestampMs::new(1_700_000_000_000),
        }
    }

    /// A proof made here is the signature of the published signing input by the device's own key,
    /// under the identifier the host derives from that key: what the host's verifier checks.
    #[test]
    fn a_proof_is_the_devices_signature_of_the_published_signing_input() {
        let key = AuthorisationKeyPair::generate().expect("a device key");
        let request = challenge();

        let proof = sign_voice_confirmation(&key, &request).expect("a proof");

        assert_eq!(proof.request, request);
        assert_eq!(
            proof.signer_key_id,
            kr_protocol::pairing::key_id(
                kr_protocol::pairing::KeyPurpose::Authorisation,
                key.public().as_bytes()
            )
        );
        let transcript = SigningTranscript::from_canonical_bytes(
            VOICE_CONFIRM_DOMAIN,
            request.signing_input().expect("the challenge encodes"),
        )
        .expect("a transcript");
        sign::verify(key.public(), &transcript, &proof.signature)
            .expect("the signature covers the challenge");
    }
}
