//! The voice confirmation's signing input and its signer's key identifier, held to fixed bytes.
//!
//! The paired phones sign the host's challenge in Swift and in Kotlin. A phone that encodes the
//! challenge its own way produces a proof the host rejects, and no test on the phone can see that
//! without this side's bytes. The phones' ceremony tests (`VoiceCeremonyTests.swift`,
//! `VoiceCeremonyTest.kt`) hold the same two constants, so a change to either encoding fails here
//! and on both phones together.
//!
//! The confirmation is a signature over the exact action, so these bytes are what a confirmation
//! covers.

use kr_protocol::ids::{ActionId, ConfirmationId, DeviceId, VoiceSessionId};
use kr_protocol::pairing::{KeyPurpose, key_id};
use kr_protocol::scalars::{Digest256, Nonce256, TimestampMs, Uuid};
use kr_protocol::voice::{VoiceAction, VoiceConfirmationRequest};

/// `CBOR(["kr-voice/confirm/1", request])` for the fixed challenge below, hex encoded.
const SIGNING_INPUT_HEX: &str = "82726b722d766f6963652f636f6e6669726d2f31a9656e6f6e63655820777777777777777777777777777777777777777777777777777777777777777766616374696f6e6a6170706c795f6469666669616374696f6e5f69645044444444444444444444444444444444696465766963655f696450666666666666666666666666666666666d616374696f6e5f646967657374582033333333333333333333333333333333333333333333333333333333333333336d657870697265735f61745f6d731b0000018bcfe568006e686f73745f6465766963655f696450555555555555555555555555555555556f636f6e6669726d6174696f6e5f6964501111111111111111111111111111111170766f6963655f73657373696f6e5f69645022222222222222222222222222222222";

/// `SHA256(CBOR(["kr-key-id/1", "authorisation", key]))` for the fixed public key, hex encoded.
const SIGNER_KEY_ID_HEX: &str = "a1e1283a5a7d9396772f55cfbd0867b9836c583a4381dd3f70a7a78afd9dec7f";

/// The fixed challenge, field by field, as every language's test builds it.
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

#[test]
fn the_confirmation_signing_input_is_the_published_bytes() {
    let input = challenge().signing_input().expect("the challenge encodes");
    assert_eq!(hex::encode(input), SIGNING_INPUT_HEX);
}

#[test]
fn the_signer_key_identifier_is_the_published_bytes() {
    let derived = key_id(KeyPurpose::Authorisation, &[0x88; 32]);
    assert_eq!(hex::encode(derived.as_bytes()), SIGNER_KEY_ID_HEX);
}
