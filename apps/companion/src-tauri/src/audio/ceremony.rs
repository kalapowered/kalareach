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

#[cfg(test)]
mod tests {
    use super::*;
    use kr_crypto::keys::AuthorisationKeyPair;
    use kr_protocol::ids::{ActionId, DeviceId, SessionId, VoiceSessionId};
    use kr_protocol::scalars::{Digest256, Nullable, Uuid};
    use kr_protocol::voice::{VoiceAction, VoiceActionPlan, VoiceRefusal};
    use kr_voice::confirm::{ConfirmationLedger, issue_confirmation, verify_confirmation};

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
