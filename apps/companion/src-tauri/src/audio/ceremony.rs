//! The desktop unlocked-screen ceremony.
//!
//! Section 15 paragraph 8 and section 10 require that the five sensitive action classes
//! (running commands, applying diffs, answering approvals, closing sessions, and external delivery)
//! cannot be authorized by provider speech alone. A statement from the model that the user
//! confirmed something is content, never authority.
//!
//! The ceremony requires user-presence verification on the unlocked screen of the paired device:
//! on macOS, through Apple's LocalAuthentication (`LAContext`); on non-macOS desktop, by refusing
//! `UNAVAILABLE`. Once presence is verified, the client signs `VoiceConfirmationProof` over
//! `CBOR(["kr-voice/confirm/1", request])` using the paired device's `authorisation` key.

use kr_crypto::keys::AuthorisationKeyPair;
use kr_protocol::voice::{VoiceConfirmationProof, VoiceConfirmationRequest};

use crate::error::{CommandError, Result};
use crate::verify::verify_owner_presence;

/// Prompts the user on the device's unlocked screen and signs a confirmation challenge upon approval.
///
/// # Errors
///
/// Returns `PERMISSION_DENIED` if the user declines or fails verification,
/// `UNAVAILABLE` on platforms without a native verification ceremony, or an error if signing fails.
pub fn confirm_voice_action(
    authorisation_key: &AuthorisationKeyPair,
    request: &VoiceConfirmationRequest,
) -> Result<VoiceConfirmationProof> {
    let reason = format!("Authorise voice action: {}", request.action.as_str());
    let presence = verify_owner_presence(&reason)?;

    if !presence.verified {
        return Err(CommandError::refused(
            "the unlocked-screen ceremony was not completed",
        ));
    }

    sign_voice_confirmation(authorisation_key, request)
}

/// Signs a voice confirmation request with the paired device's authorization key.
///
/// Present so both the ceremony path and cryptographic verification tests sign through the
/// identical algorithm.
///
/// # Errors
///
/// Returns an error if signing fails.
pub fn sign_voice_confirmation(
    authorisation_key: &AuthorisationKeyPair,
    request: &VoiceConfirmationRequest,
) -> Result<VoiceConfirmationProof> {
    kr_voice::confirm::sign_confirmation(authorisation_key, request).map_err(|error| {
        CommandError::local_failure(format!("failed to sign confirmation: {error}"))
    })
}

/// One fixed challenge, and the exact bytes every client must sign for it.
///
/// The three clients sign on three platforms in three languages, and a client that encodes the
/// challenge its own way produces a proof the host rejects without any client-side test noticing.
/// This module is where the three are held to one encoding: the desktop test below asserts the
/// bytes the shared protocol produces, and the iOS and Android ceremony tests assert their own
/// encoders against the same two constants.
#[cfg(test)]
pub(crate) mod vector {
    /// The fixed challenge, field by field, as every language's test builds it.
    pub const CONFIRMATION_ID: [u8; 16] = [0x11; 16];
    pub const VOICE_SESSION_ID: [u8; 16] = [0x22; 16];
    pub const ACTION: &str = "apply_diff";
    pub const ACTION_DIGEST: [u8; 32] = [0x33; 32];
    pub const ACTION_ID: [u8; 16] = [0x44; 16];
    pub const HOST_DEVICE_ID: [u8; 16] = [0x55; 16];
    pub const DEVICE_ID: [u8; 16] = [0x66; 16];
    pub const NONCE: [u8; 32] = [0x77; 32];
    pub const EXPIRES_AT_MS: u64 = 1_700_000_000_000;

    /// A fixed Ed25519 public key, for the signer identifier vector.
    pub const PUBLIC_KEY: [u8; 32] = [0x88; 32];

    /// `CBOR(["kr-voice/confirm/1", request])` for that challenge, hex encoded.
    pub const SIGNING_INPUT_HEX: &str = "82726b722d766f6963652f636f6e6669726d2f31a9656e6f6e63655820777777777777777777777777777777777777777777777777777777777777777766616374696f6e6a6170706c795f6469666669616374696f6e5f69645044444444444444444444444444444444696465766963655f696450666666666666666666666666666666666d616374696f6e5f646967657374582033333333333333333333333333333333333333333333333333333333333333336d657870697265735f61745f6d731b0000018bcfe568006e686f73745f6465766963655f696450555555555555555555555555555555556f636f6e6669726d6174696f6e5f6964501111111111111111111111111111111170766f6963655f73657373696f6e5f69645022222222222222222222222222222222";

    /// `SHA256(CBOR(["kr-key-id/1", "authorisation", key]))` for that key, hex encoded.
    pub const SIGNER_KEY_ID_HEX: &str =
        "a1e1283a5a7d9396772f55cfbd0867b9836c583a4381dd3f70a7a78afd9dec7f";

    /// Unsigned integers at every point the head changes size, with the bytes the shared protocol
    /// writes for each. The phone encoders assert the same list.
    pub const UNSIGNED_BOUNDARIES: &[(u64, &str)] = &[
        (0, "00"),
        (23, "17"),
        (24, "1818"),
        (255, "18ff"),
        (256, "190100"),
        (65_535, "19ffff"),
        (65_536, "1a00010000"),
        (4_294_967_295, "1affffffff"),
        (4_294_967_296, "1b0000000100000000"),
        (u64::MAX, "1bffffffffffffffff"),
    ];

    /// For a string of this many bytes: the head of a byte string and of a text string.
    pub const LENGTH_HEADS: &[(usize, &str, &str)] = &[
        (0, "40", "60"),
        (23, "57", "77"),
        (24, "5818", "7818"),
        (255, "58ff", "78ff"),
        (256, "590100", "790100"),
    ];

    /// Text whose characters are more than one byte each: the head counts bytes, not characters.
    pub const MULTIBYTE_TEXT: &[(&str, &str)] = &[("é", "62c3a9"), ("日本", "66e697a5e69cac")];

    /// Maps with one unsigned value per key, and their bytes: shortest encoded key first, then by
    /// the key's bytes, which puts "z" before "aa" and "ab" before "é".
    pub const MAP_ORDER: &[(&[(&str, u64)], &str)] = &[
        (&[("b", 1), ("a", 2)], "a2616102616201"),
        (&[("aa", 1), ("b", 2)], "a261620262616101"),
        (&[("é", 1), ("z", 2)], "a2617a0262c3a901"),
        (&[("é", 1), ("ab", 2)], "a26261620262c3a901"),
    ];
}

#[cfg(test)]
mod boundaries {
    use super::vector;
    use kr_cbor::CanonicalValue;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// The boundary list the phone encoders are held to is the host encoder's own output. A
    /// constant typed out by hand in three languages would agree with itself and nothing else.
    #[test]
    fn the_boundary_vectors_are_what_the_host_encodes() {
        for (value, expected) in vector::UNSIGNED_BOUNDARIES {
            let encoded = kr_cbor::to_canonical_vec(value).expect("an unsigned integer encodes");
            assert_eq!(hex(&encoded), *expected, "{value}");
        }
        for (length, bytes_head, text_head) in vector::LENGTH_HEADS {
            let bytes = kr_cbor::encode(&CanonicalValue::Bytes(vec![1; *length]));
            assert_eq!(hex(&bytes), format!("{bytes_head}{}", "01".repeat(*length)));
            let text = kr_cbor::to_canonical_vec(&"a".repeat(*length)).expect("text encodes");
            assert_eq!(hex(&text), format!("{text_head}{}", "61".repeat(*length)));
        }
        for (text, expected) in vector::MULTIBYTE_TEXT {
            let encoded = kr_cbor::to_canonical_vec(text).expect("text encodes");
            assert_eq!(hex(&encoded), *expected, "{text}");
        }
        for (entries, expected) in vector::MAP_ORDER {
            let map: std::collections::BTreeMap<String, u64> = entries
                .iter()
                .map(|(key, value)| ((*key).to_owned(), *value))
                .collect();
            let encoded = kr_cbor::to_canonical_vec(&map).expect("a map encodes");
            assert_eq!(hex(&encoded), *expected, "{entries:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_crypto::keys::AuthorisationKeyPair;
    use kr_protocol::ids::{ActionId, DeviceId, SessionId, VoiceSessionId};
    use kr_protocol::scalars::{Digest256, Nullable, Uuid};
    use kr_protocol::voice::{VoiceAction, VoiceActionPlan, VoiceRefusal};
    use kr_voice::confirm::{ConfirmationLedger, issue_confirmation, verify_confirmation};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// The cross-language vector: the exact bytes a voice confirmation is signed over.
    #[test]
    fn confirmation_signing_input_matches_the_cross_language_vector() {
        use super::vector;
        use kr_protocol::ids::ConfirmationId;
        use kr_protocol::scalars::{Nonce256, TimestampMs};
        use kr_protocol::voice::VoiceConfirmationRequest;

        let request = VoiceConfirmationRequest {
            confirmation_id: ConfirmationId::new(Uuid::from_bytes(vector::CONFIRMATION_ID)),
            voice_session_id: VoiceSessionId::new(Uuid::from_bytes(vector::VOICE_SESSION_ID)),
            action: VoiceAction::ApplyDiff,
            action_digest: Digest256::from_bytes(vector::ACTION_DIGEST),
            action_id: ActionId::new(Uuid::from_bytes(vector::ACTION_ID)),
            host_device_id: DeviceId::new(Uuid::from_bytes(vector::HOST_DEVICE_ID)),
            device_id: DeviceId::new(Uuid::from_bytes(vector::DEVICE_ID)),
            nonce: Nonce256::from_bytes(vector::NONCE),
            expires_at_ms: TimestampMs::new(vector::EXPIRES_AT_MS),
        };

        assert_eq!(request.action.as_str(), vector::ACTION);
        let input = request.signing_input().expect("the challenge encodes");
        assert_eq!(hex(&input), vector::SIGNING_INPUT_HEX);
    }

    /// The cross-language vector: the identifier of the key that signs it.
    #[test]
    fn signer_key_id_matches_the_cross_language_vector() {
        use super::vector;
        use kr_protocol::pairing::{KeyPurpose, key_id};

        let derived = key_id(KeyPurpose::Authorisation, &vector::PUBLIC_KEY);
        assert_eq!(hex(derived.as_bytes()), vector::SIGNER_KEY_ID_HEX);
    }

    fn test_device_id(seed: u8) -> DeviceId {
        DeviceId::new(Uuid::from_bytes([seed; 16]))
    }

    fn test_action_id(seed: u8) -> ActionId {
        ActionId::new(Uuid::from_bytes([seed; 16]))
    }

    fn test_voice_session_id() -> VoiceSessionId {
        VoiceSessionId::new(Uuid::from_bytes([0x42; 16]))
    }

    fn test_plan(action: VoiceAction, payload: u8) -> VoiceActionPlan {
        VoiceActionPlan {
            voice_session_id: test_voice_session_id(),
            action,
            session_id: Nullable::some(SessionId::new(Uuid::from_bytes([2; 16]))),
            delegation_id: Nullable::null(),
            payload_digest: Digest256::from_bytes([payload; 32]),
        }
    }

    #[test]
    fn signature_covers_action_hash_and_tampering_is_refused() {
        let key = AuthorisationKeyPair::generate().expect("keypair");
        let plan = test_plan(VoiceAction::ApplyDiff, 0x11);

        let now_ms = 1_000_000u64;
        let action_id = test_action_id(9);
        let host_device = test_device_id(1);
        let client_device = test_device_id(2);

        let request = issue_confirmation(&plan, action_id, host_device, client_device, now_ms)
            .expect("challenge");

        let proof = sign_voice_confirmation(&key, &request).expect("proof");

        let mut ledger = ConfirmationLedger::new();
        ledger.issue(&request);
        let verified = verify_confirmation(
            &mut ledger,
            &plan,
            action_id,
            client_device,
            &proof,
            key.public(),
            now_ms + 100,
        );
        assert!(verified.is_ok(), "valid proof must verify: {verified:?}");

        // Tampering with the action digest in request invalidates the proof.
        let mut tampered_request = request.clone();
        let mut bad_digest = [0u8; 32];
        bad_digest[0] = 0xff;
        tampered_request.action_digest = Digest256::from_bytes(bad_digest);

        let mut tampered_proof = proof.clone();
        tampered_proof.request = tampered_request;

        let mut ledger2 = ConfirmationLedger::new();
        ledger2.issue(&request);
        let tampered_result = verify_confirmation(
            &mut ledger2,
            &plan,
            action_id,
            client_device,
            &tampered_proof,
            key.public(),
            now_ms + 100,
        );
        assert!(
            tampered_result.is_err(),
            "tampered action digest must be refused"
        );
    }

    #[test]
    fn confirmation_for_one_action_does_not_authorize_another() {
        let key = AuthorisationKeyPair::generate().expect("keypair");
        let plan_a = test_plan(VoiceAction::ApplyDiff, 0xaa);
        let plan_b = test_plan(VoiceAction::ShellInput, 0xbb);

        let now_ms = 1_000_000u64;
        let action_id = test_action_id(9);
        let host_device = test_device_id(1);
        let client_device = test_device_id(2);

        let request = issue_confirmation(&plan_a, action_id, host_device, client_device, now_ms)
            .expect("challenge for plan A");

        let proof = sign_voice_confirmation(&key, &request).expect("proof for plan A");

        let mut ledger = ConfirmationLedger::new();
        ledger.issue(&request);
        let result = verify_confirmation(
            &mut ledger,
            &plan_b, // Attempting to authorize plan B with confirmation for plan A
            action_id,
            client_device,
            &proof,
            key.public(),
            now_ms + 100,
        );
        assert_eq!(
            result.err().and_then(|e| e.reason()),
            Some(VoiceRefusal::ConfirmationMismatch),
            "confirmation for plan A must not authorize plan B"
        );
    }

    #[test]
    fn provider_text_cannot_produce_confirmation() {
        let key = AuthorisationKeyPair::generate().expect("keypair");
        let imposter_key = AuthorisationKeyPair::generate().expect("imposter keypair");

        let plan = test_plan(VoiceAction::CloseSession, 0xcc);

        let now_ms = 1_000_000u64;
        let action_id = test_action_id(9);
        let host_device = test_device_id(1);
        let client_device = test_device_id(2);

        let request = issue_confirmation(&plan, action_id, host_device, client_device, now_ms)
            .expect("challenge");

        // An imposter signing the challenge (such as a simulated confirmation from provider text)
        let imposter_proof = sign_voice_confirmation(&imposter_key, &request).expect("proof");

        let mut ledger = ConfirmationLedger::new();
        ledger.issue(&request);
        let result = verify_confirmation(
            &mut ledger,
            &plan,
            action_id,
            client_device,
            &imposter_proof,
            key.public(), // Checked against the paired device's key
            now_ms + 100,
        );
        assert_eq!(
            result.err().and_then(|e| e.reason()),
            Some(VoiceRefusal::ConfirmationMismatch),
            "signature by non-paired key must be rejected"
        );
    }
}
