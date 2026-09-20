//! The unlocked-screen confirmation: issued by the host, signed by the paired device, verified
//! here.
//!
//! Section 15 ¶8 is precise about what this is for. The provider and the managed operator are
//! inside the trust boundary for interpreting speech, so they can influence what the model says,
//! and a model statement that the user confirmed an operation is **not** a native-screen
//! confirmation. The five action classes of section 15 ¶13 therefore need a separate client-signed
//! confirmation bound to the exact action hash and the current request, and provider text cannot
//! create one.
//!
//! What makes that true here is the key. The signature is checked against the paired device's
//! identity key — the one that already signs its authority-bearing requests — and never against a
//! session key, a provider credential or anything a transcript could carry.
//!
//! The ceremony that produces the signature is the native client's: device-owner authentication on
//! an unlocked screen. This module issues the challenge, consumes it exactly once, and checks the
//! answer.

use std::collections::BTreeMap;

use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign::{self, SigningTranscript};
use kr_protocol::ids::{ActionId, ConfirmationId, DeviceId, VoiceSessionId};
use kr_protocol::scalars::{AuthorisationKey, Digest256, Nonce256, TimestampMs, Uuid};
use kr_protocol::voice::{
    VOICE_CONFIRM_DOMAIN, VOICE_CONFIRMATION_LIFETIME_MS, VoiceActionPlan, VoiceConfirmationProof,
    VoiceConfirmationRequest, VoiceRefusal,
};

use crate::error::{Result, VoiceError};

/// Issues a challenge for one action the device must confirm on an unlocked screen.
///
/// The digest comes from the plan rather than from anything the device sent: a challenge built
/// from what the caller claims it wants would be a challenge the caller could rewrite.
///
/// # Errors
///
/// Returns an error when the plan cannot be encoded or the random generator is unavailable.
pub fn issue_confirmation(
    plan: &VoiceActionPlan,
    action_id: ActionId,
    host_device_id: DeviceId,
    device_id: DeviceId,
    now_ms: u64,
) -> Result<VoiceConfirmationRequest> {
    let mut identity = [0u8; 16];
    kr_crypto::random_bytes(&mut identity)?;
    let mut nonce = [0u8; 32];
    kr_crypto::random_bytes(&mut nonce)?;
    Ok(VoiceConfirmationRequest {
        confirmation_id: ConfirmationId::new(Uuid::from_bytes(identity)),
        voice_session_id: plan.voice_session_id,
        action: plan.action,
        action_digest: plan.digest()?,
        action_id,
        host_device_id,
        device_id,
        nonce: Nonce256::from_bytes(nonce),
        expires_at_ms: TimestampMs::new(now_ms.saturating_add(VOICE_CONFIRMATION_LIFETIME_MS)),
    })
}

/// Signs a challenge the way a paired device's ceremony does.
///
/// Present so a test and a native client sign the same bytes. A host never calls it: a host that
/// could produce a confirmation would be a host whose confirmations prove nothing.
///
/// # Errors
///
/// Returns an encoding error, or a library error when the signature cannot be made.
pub fn sign_confirmation(
    key: &AuthorisationKeyPair,
    request: &VoiceConfirmationRequest,
) -> Result<VoiceConfirmationProof> {
    let signature = sign::sign(
        key,
        &SigningTranscript::from_canonical_bytes(VOICE_CONFIRM_DOMAIN, request.signing_input()?)?,
    )?;
    Ok(VoiceConfirmationProof {
        request: request.clone(),
        signer_key_id: key.key_id(),
        signature,
    })
}

/// Checks a proof against the exact action it is supposed to authorise.
///
/// The checks, in order, and each one is a way a confirmation could otherwise be reused:
///
/// 1. the challenge is one this host issued and has not consumed;
/// 2. the proof answers that challenge byte for byte;
/// 3. the challenge names the action this request is about, and the digest of this exact plan;
/// 4. the challenge names this request, so a confirmation for one action does not authorise the
///    next one;
/// 5. the challenge has not expired, on the host's own reading of the clock;
/// 6. the signer is this device's identity key;
/// 7. the signature covers the whole challenge.
///
/// Only then is the challenge consumed, so a failed check leaves it usable by the real answer.
///
/// # Errors
///
/// Returns a refusal naming which of those is missing.
pub fn verify_confirmation(
    ledger: &mut ConfirmationLedger,
    plan: &VoiceActionPlan,
    action_id: ActionId,
    device_id: DeviceId,
    proof: &VoiceConfirmationProof,
    signer: &AuthorisationKey,
    now_ms: u64,
) -> Result<()> {
    let Some(issued) = ledger.outstanding(proof.request.confirmation_id) else {
        return Err(VoiceError::refused(
            VoiceRefusal::ConfirmationSpent,
            "this confirmation is not one this host is waiting for; it has been used or it has \
             run out",
        ));
    };
    if &proof.request != issued {
        return Err(VoiceError::refused(
            VoiceRefusal::ConfirmationMismatch,
            "this proof answers a different challenge from the one this host issued",
        ));
    }
    if proof.request.action != plan.action
        || proof.request.voice_session_id != plan.voice_session_id
    {
        return Err(VoiceError::refused(
            VoiceRefusal::ConfirmationMismatch,
            "this confirmation was given for a different action",
        ));
    }
    if proof.request.action_digest != plan.digest()? {
        return Err(VoiceError::refused(
            VoiceRefusal::ConfirmationMismatch,
            "this confirmation was given for different details of the same action",
        ));
    }
    if proof.request.action_id != action_id {
        return Err(VoiceError::refused(
            VoiceRefusal::ConfirmationMismatch,
            "this confirmation was given for a different request",
        ));
    }
    if proof.request.device_id != device_id {
        return Err(VoiceError::refused(
            VoiceRefusal::ConfirmationMismatch,
            "this confirmation was given for a different device",
        ));
    }
    if now_ms >= proof.request.expires_at_ms.get() {
        return Err(VoiceError::refused(
            VoiceRefusal::ConfirmationSpent,
            "this confirmation has run out; ask for it again on the unlocked screen",
        ));
    }
    if proof.signer_key_id
        != kr_crypto::keys::key_id(
            kr_protocol::pairing::KeyPurpose::Authorisation,
            signer.as_bytes(),
        )
    {
        return Err(VoiceError::refused(
            VoiceRefusal::ConfirmationMismatch,
            "this confirmation was not signed by this device's identity key",
        ));
    }
    sign::verify(
        signer,
        &SigningTranscript::from_canonical_bytes(
            VOICE_CONFIRM_DOMAIN,
            proof.request.signing_input()?,
        )?,
        &proof.signature,
    )
    .map_err(|_| {
        VoiceError::refused(
            VoiceRefusal::ConfirmationMismatch,
            "this confirmation's signature does not cover the challenge this host issued",
        )
    })?;

    ledger.consume(proof.request.confirmation_id);
    Ok(())
}

/// The challenges this host has issued and not yet consumed.
///
/// The whole challenge is kept, not only its identity. A ledger that kept only the identity would
/// let anything that could influence what the caller presents substitute a challenge with the same
/// identity and different contents, and the signature check would then pass against the
/// substitution.
#[derive(Debug, Default)]
pub struct ConfirmationLedger {
    outstanding: BTreeMap<[u8; 16], VoiceConfirmationRequest>,
}

impl ConfirmationLedger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a challenge this host has just issued.
    pub fn issue(&mut self, request: &VoiceConfirmationRequest) {
        self.outstanding
            .insert(*request.confirmation_id.get().as_bytes(), request.clone());
    }

    /// The challenge already outstanding for one exact action and request, when there is one.
    ///
    /// A device that asks twice for the same confirmation is asking for the same thing, and
    /// answering with the challenge it already has keeps one action to one challenge. Without it
    /// a caller could fill this ledger by resubmitting a delegation it never intends to sign.
    #[must_use]
    pub fn outstanding_for(
        &self,
        action_digest: Digest256,
        action_id: ActionId,
        device_id: DeviceId,
        now_ms: u64,
    ) -> Option<&VoiceConfirmationRequest> {
        self.outstanding.values().find(|request| {
            request.action_digest == action_digest
                && request.action_id == action_id
                && request.device_id == device_id
                && now_ms < request.expires_at_ms.get()
        })
    }

    /// The challenge with this identity, when this host is still waiting for it.
    #[must_use]
    pub fn outstanding(&self, id: ConfirmationId) -> Option<&VoiceConfirmationRequest> {
        self.outstanding.get(id.get().as_bytes())
    }

    /// Consumes one challenge. Single use: a second presentation finds nothing.
    pub fn consume(&mut self, id: ConfirmationId) {
        self.outstanding.remove(id.get().as_bytes());
    }

    /// Drops every challenge that has run out, and returns how many went.
    pub fn sweep(&mut self, now_ms: u64) -> usize {
        let before = self.outstanding.len();
        self.outstanding
            .retain(|_, request| now_ms < request.expires_at_ms.get());
        before - self.outstanding.len()
    }

    /// Drops every challenge belonging to one voice session.
    ///
    /// Ending a voice session ends what it was waiting for. A challenge that outlived its session
    /// would be a confirmation for a call that is over.
    pub fn forget_session(&mut self, voice_session_id: VoiceSessionId) {
        self.outstanding
            .retain(|_, request| request.voice_session_id != voice_session_id);
    }

    /// How many challenges are outstanding.
    #[must_use]
    pub fn len(&self) -> usize {
        self.outstanding.len()
    }

    /// Returns true when nothing is outstanding.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.outstanding.is_empty()
    }
}

/// The digest of an action plan, for a caller that needs it beside the challenge.
///
/// # Errors
///
/// Returns a CBOR error when the plan cannot be represented in KR-CBOR-1.
pub fn plan_digest(plan: &VoiceActionPlan) -> Result<Digest256> {
    Ok(plan.digest()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::ids::SessionId;
    use kr_protocol::scalars::Nullable;
    use kr_protocol::voice::VoiceAction;

    fn plan(action: VoiceAction, payload: u8) -> VoiceActionPlan {
        VoiceActionPlan {
            voice_session_id: VoiceSessionId::new(Uuid::from_bytes([7; 16])),
            action,
            session_id: Nullable::some(SessionId::new(Uuid::from_bytes([2; 16]))),
            delegation_id: Nullable::null(),
            payload_digest: Digest256::from_bytes([payload; 32]),
        }
    }

    fn device(byte: u8) -> DeviceId {
        DeviceId::new(Uuid::from_bytes([byte; 16]))
    }

    fn action_id(byte: u8) -> ActionId {
        ActionId::new(Uuid::from_bytes([byte; 16]))
    }

    #[test]
    fn a_signed_confirmation_authorises_exactly_its_own_action_and_request() {
        let key = AuthorisationKeyPair::generate().expect("a device key");
        let mut ledger = ConfirmationLedger::new();
        let plan = plan(VoiceAction::ShellInput, 3);
        let request = issue_confirmation(&plan, action_id(9), device(0xf0), device(0xf1), 1_000)
            .expect("a challenge");
        ledger.issue(&request);
        let proof = sign_confirmation(&key, &request).expect("a proof");

        verify_confirmation(
            &mut ledger,
            &plan,
            action_id(9),
            device(0xf1),
            &proof,
            key.public(),
            1_100,
        )
        .expect("the confirmation answers this action");
        assert!(ledger.is_empty(), "a confirmation is single use");
    }

    #[test]
    fn a_confirmation_for_one_action_does_not_authorise_another() {
        let key = AuthorisationKeyPair::generate().expect("a device key");
        let mut ledger = ConfirmationLedger::new();
        let confirmed = plan(VoiceAction::ApplyDiff, 3);
        let request =
            issue_confirmation(&confirmed, action_id(9), device(0xf0), device(0xf1), 1_000)
                .expect("a challenge");
        ledger.issue(&request);
        let proof = sign_confirmation(&key, &request).expect("a proof");

        let other = plan(VoiceAction::ShellInput, 3);
        let error = verify_confirmation(
            &mut ledger,
            &other,
            action_id(9),
            device(0xf1),
            &proof,
            key.public(),
            1_100,
        )
        .expect_err("a different action is refused");
        assert_eq!(error.reason(), Some(VoiceRefusal::ConfirmationMismatch));

        // The same action with different details is refused too: the digest is over the plan.
        let same_action_other_details = plan(VoiceAction::ApplyDiff, 4);
        let error = verify_confirmation(
            &mut ledger,
            &same_action_other_details,
            action_id(9),
            device(0xf1),
            &proof,
            key.public(),
            1_100,
        )
        .expect_err("different details are refused");
        assert_eq!(error.reason(), Some(VoiceRefusal::ConfirmationMismatch));
        assert!(!ledger.is_empty(), "a failed check does not spend it");
    }

    #[test]
    fn a_confirmation_does_not_carry_to_the_next_request() {
        let key = AuthorisationKeyPair::generate().expect("a device key");
        let mut ledger = ConfirmationLedger::new();
        let plan = plan(VoiceAction::CloseSession, 3);
        let request = issue_confirmation(&plan, action_id(9), device(0xf0), device(0xf1), 1_000)
            .expect("a challenge");
        ledger.issue(&request);
        let proof = sign_confirmation(&key, &request).expect("a proof");

        let error = verify_confirmation(
            &mut ledger,
            &plan,
            action_id(10),
            device(0xf1),
            &proof,
            key.public(),
            1_100,
        )
        .expect_err("another request is refused");
        assert_eq!(error.reason(), Some(VoiceRefusal::ConfirmationMismatch));
    }

    #[test]
    fn a_confirmation_signed_by_another_key_is_refused() {
        let device_key = AuthorisationKeyPair::generate().expect("a device key");
        let imposter = AuthorisationKeyPair::generate().expect("another key");
        let mut ledger = ConfirmationLedger::new();
        let plan = plan(VoiceAction::ChangeGrant, 3);
        let request = issue_confirmation(&plan, action_id(9), device(0xf0), device(0xf1), 1_000)
            .expect("a challenge");
        ledger.issue(&request);
        let proof = sign_confirmation(&imposter, &request).expect("a proof");

        let error = verify_confirmation(
            &mut ledger,
            &plan,
            action_id(9),
            device(0xf1),
            &proof,
            device_key.public(),
            1_100,
        )
        .expect_err("another key is refused");
        assert_eq!(error.reason(), Some(VoiceRefusal::ConfirmationMismatch));
    }

    #[test]
    fn a_confirmation_that_ran_out_is_refused_and_swept() {
        let key = AuthorisationKeyPair::generate().expect("a device key");
        let mut ledger = ConfirmationLedger::new();
        let plan = plan(VoiceAction::ShellInput, 3);
        let request = issue_confirmation(&plan, action_id(9), device(0xf0), device(0xf1), 1_000)
            .expect("a challenge");
        ledger.issue(&request);
        let proof = sign_confirmation(&key, &request).expect("a proof");

        let late = request.expires_at_ms.get();
        let error = verify_confirmation(
            &mut ledger,
            &plan,
            action_id(9),
            device(0xf1),
            &proof,
            key.public(),
            late,
        )
        .expect_err("an expired confirmation is refused");
        assert_eq!(error.reason(), Some(VoiceRefusal::ConfirmationSpent));
        assert_eq!(ledger.sweep(late), 1);
    }

    #[test]
    fn a_confirmation_this_host_never_issued_is_refused() {
        let key = AuthorisationKeyPair::generate().expect("a device key");
        let mut ledger = ConfirmationLedger::new();
        let plan = plan(VoiceAction::ShellInput, 3);
        // Issued but never recorded: what a caller that made its own challenge would present.
        let request = issue_confirmation(&plan, action_id(9), device(0xf0), device(0xf1), 1_000)
            .expect("a challenge");
        let proof = sign_confirmation(&key, &request).expect("a proof");

        let error = verify_confirmation(
            &mut ledger,
            &plan,
            action_id(9),
            device(0xf1),
            &proof,
            key.public(),
            1_100,
        )
        .expect_err("a challenge this host did not issue is refused");
        assert_eq!(error.reason(), Some(VoiceRefusal::ConfirmationSpent));
    }

    #[test]
    fn ending_a_voice_session_ends_what_it_was_waiting_for() {
        let mut ledger = ConfirmationLedger::new();
        let plan = plan(VoiceAction::ShellInput, 3);
        let request = issue_confirmation(&plan, action_id(9), device(0xf0), device(0xf1), 1_000)
            .expect("a challenge");
        ledger.issue(&request);
        ledger.forget_session(plan.voice_session_id);
        assert!(ledger.is_empty());
    }
}
