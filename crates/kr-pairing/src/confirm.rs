//! Sensitive owner confirmation.
//!
//! Section 10 names six actions that need a fresh owner confirmation bound to the exact action
//! digest, destination keys and rights, host, nonce and short expiry: issuing a persistent pairing
//! invitation, confirming a new device, enlarging persistent grants, trusting a new repository
//! root, granting executable or native-bridge capabilities, and changing host-management
//! authority. It is equally explicit about what is *not* a confirmation: an agent's process label,
//! operating-system peer credentials, terminal output and a newly created invitation context.
//!
//! The ceremony itself is platform code, injected as [`OwnerConfirmation`]. What lives here is
//! the challenge, the proof and the checks: the channel is inside the signature, the challenge is
//! single use, and a proof is accepted only against the exact challenge it answers.
//!
//! Already-authorised restriction, revocation and emergency session stop need no new
//! rights-enlarging confirmation. [`SensitiveAction`] lists only the actions that do, so a caller
//! cannot ask for a confirmation of something that should never have needed one.

use std::collections::BTreeSet;

use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign::{self, SigningTranscript};
use kr_protocol::ids::{ConfirmationId, DeviceId};
use kr_protocol::pairing::{
    ConfirmationChannel, DevicePublicKeys, OWNER_CONFIRM_DOMAIN, OwnerConfirmationProof,
    OwnerConfirmationRequest, SensitiveAction,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{
    AuthorisationKey, CanonicalSet, Digest256, EndpointKey, Nonce256, Nullable, TimestampMs, Uuid,
};

use crate::error::{PairingError, Result};
use crate::platform::{OwnerConfirmation, PairingClock};

/// How long a confirmation challenge stays open, in milliseconds.
///
/// Section 10 says "short expiry" without a number. Two minutes is long enough for a native
/// ceremony on an unlocked device and short enough that a challenge captured now is useless later.
/// It is a profile decision, recorded in `docs/pairing/README.md`.
pub const CONFIRMATION_LIFETIME_MS: u64 = 2 * 60 * 1000;

/// Whether a host has an owner yet.
///
/// The interactive controlling terminal is the initial local bootstrap exception and nothing more.
/// Afterwards a headless host with no enrolled user-presence-capable signer and no separately
/// paired owner refuses the confirmation rather than downgrading it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostEnrolment {
    /// No owner yet: the bootstrap exception applies.
    InitialBootstrap,
    /// An owner exists, so only a real ceremony or a paired owner device will do.
    Enrolled,
}

/// Issues a challenge for one sensitive action.
///
/// # Errors
///
/// Returns a crypto error when libsodium is unavailable.
pub fn request_confirmation(
    clock: &dyn PairingClock,
    action: SensitiveAction,
    action_digest: Digest256,
    destination_keys: Option<DevicePublicKeys>,
    destination_rights: BTreeSet<ActionRight>,
    host_device_id: DeviceId,
    host_endpoint_id: EndpointKey,
) -> Result<OwnerConfirmationRequest> {
    let mut identity = [0u8; 16];
    kr_crypto::random_bytes(&mut identity)?;
    let mut nonce = [0u8; 32];
    kr_crypto::random_bytes(&mut nonce)?;
    Ok(OwnerConfirmationRequest {
        confirmation_id: ConfirmationId::new(Uuid::from_bytes(identity)),
        action,
        action_digest,
        destination_keys: destination_keys.map_or_else(Nullable::null, Nullable::some),
        destination_rights: destination_rights.into_iter().collect::<CanonicalSet<_>>(),
        host_device_id,
        host_endpoint_id,
        nonce: Nonce256::from_bytes(nonce),
        expires_at_ms: TimestampMs::new(
            clock
                .wall_clock_ms()
                .saturating_add(CONFIRMATION_LIFETIME_MS),
        ),
    })
}

/// Signs a proof for one challenge, as an owner signer or a paired owner device does.
///
/// # Errors
///
/// Returns an encoding error, or a library error when libsodium fails.
pub fn sign_confirmation(
    key: &AuthorisationKeyPair,
    request: &OwnerConfirmationRequest,
    channel: ConfirmationChannel,
) -> Result<OwnerConfirmationProof> {
    let signature = sign::sign(
        key,
        &SigningTranscript::from_canonical_bytes(
            OWNER_CONFIRM_DOMAIN,
            request.signing_input(channel)?,
        )?,
    )?;
    Ok(OwnerConfirmationProof {
        request: request.clone(),
        channel,
        signer_key_id: key.key_id(),
        signature,
    })
}

/// Runs the ceremony and checks what it returned.
///
/// # Errors
///
/// Returns whatever [`verify_confirmation`] returns, and
/// [`PairingError::OwnerConfirmationRequired`] when the ceremony declined.
pub fn obtain_confirmation(
    ceremony: &dyn OwnerConfirmation,
    clock: &dyn PairingClock,
    request: &OwnerConfirmationRequest,
    signer: &AuthorisationKey,
    enrolment: HostEnrolment,
) -> Result<OwnerConfirmationProof> {
    let proof = ceremony.confirm(request)?;
    verify_confirmation(clock, request, &proof, signer, enrolment)?;
    Ok(proof)
}

/// Checks a proof against the exact challenge it answers.
///
/// The checks, in order: the proof answers *this* challenge, byte for byte; the channel can carry
/// a confirmation at all; the challenge has not expired; the signer is the enrolled one; and the
/// signature covers the request and the channel together.
///
/// # Errors
///
/// Returns [`PairingError::OwnerConfirmationRequired`] when the proof answers another challenge,
/// arrived through a channel that cannot carry one, or has expired, and
/// [`PairingError::AuthenticationFailed`] when the signature fails.
pub fn verify_confirmation(
    clock: &dyn PairingClock,
    request: &OwnerConfirmationRequest,
    proof: &OwnerConfirmationProof,
    signer: &AuthorisationKey,
    enrolment: HostEnrolment,
) -> Result<()> {
    if &proof.request != request {
        // One confirmation authorises one digest. A proof for another action, another
        // destination, another host or another nonce is not this one.
        return Err(PairingError::OwnerConfirmationRequired);
    }
    if !proof
        .channel
        .is_acceptable(enrolment == HostEnrolment::InitialBootstrap)
    {
        return Err(PairingError::OwnerConfirmationRequired);
    }
    if clock.wall_clock_ms() >= request.expires_at_ms.get() {
        return Err(PairingError::OwnerConfirmationRequired);
    }
    if proof.signer_key_id
        != kr_crypto::keys::key_id(
            kr_protocol::pairing::KeyPurpose::Authorisation,
            signer.as_bytes(),
        )
    {
        return Err(PairingError::OwnerConfirmationRequired);
    }
    sign::verify(
        signer,
        &SigningTranscript::from_canonical_bytes(
            OWNER_CONFIRM_DOMAIN,
            request.signing_input(proof.channel)?,
        )?,
        &proof.signature,
    )
    .map_err(|_| PairingError::AuthenticationFailed)
}

/// The challenges a host has issued and not yet consumed.
///
/// User-presence verification and the challenge-consumption transition are both part of the host's
/// acceptance record, so consumption happens here and exactly once.
#[derive(Debug, Default)]
pub struct ConfirmationLedger {
    outstanding: BTreeSet<[u8; 16]>,
}

impl ConfirmationLedger {
    /// Creates an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a challenge the host has just issued.
    pub fn issue(&mut self, request: &OwnerConfirmationRequest) {
        self.outstanding
            .insert(*request.confirmation_id.get().as_bytes());
    }

    /// Consumes a challenge, which succeeds exactly once.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::OwnerConfirmationRequired`] when the challenge was never issued or
    /// has already been used.
    pub fn consume(&mut self, request: &OwnerConfirmationRequest) -> Result<()> {
        if self
            .outstanding
            .remove(request.confirmation_id.get().as_bytes())
        {
            Ok(())
        } else {
            Err(PairingError::OwnerConfirmationRequired)
        }
    }

    /// Returns how many challenges are outstanding.
    #[must_use]
    pub fn len(&self) -> usize {
        self.outstanding.len()
    }

    /// Returns true when none is outstanding.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.outstanding.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::TestClock;
    use kr_crypto::keys::DeviceKeys;

    struct SigningCeremony {
        key: AuthorisationKeyPair,
        channel: ConfirmationChannel,
    }

    impl OwnerConfirmation for SigningCeremony {
        fn confirm(&self, request: &OwnerConfirmationRequest) -> Result<OwnerConfirmationProof> {
            sign_confirmation(&self.key, request, self.channel)
        }
    }

    struct DecliningCeremony;

    impl OwnerConfirmation for DecliningCeremony {
        fn confirm(&self, _request: &OwnerConfirmationRequest) -> Result<OwnerConfirmationProof> {
            Err(PairingError::OwnerConfirmationRequired)
        }
    }

    fn request(clock: &TestClock) -> OwnerConfirmationRequest {
        request_confirmation(
            clock,
            SensitiveAction::ConfirmDevice,
            Digest256::from_bytes([1; 32]),
            None,
            BTreeSet::new(),
            DeviceId::new(Uuid::from_bytes([2; 16])),
            EndpointKey::from_bytes([3; 32]),
        )
        .expect("a challenge")
    }

    #[test]
    fn a_proof_answers_the_exact_challenge_and_nothing_else() {
        let clock = TestClock::new();
        let owner = DeviceKeys::generate().expect("keys");
        let ceremony = SigningCeremony {
            key: owner.authorisation.clone(),
            channel: ConfirmationChannel::OwnerDevicePresence,
        };
        let challenge = request(&clock);
        let proof = obtain_confirmation(
            &ceremony,
            &clock,
            &challenge,
            owner.authorisation.public(),
            HostEnrolment::Enrolled,
        )
        .expect("a proof");

        // Another challenge, even one that differs only in its nonce, is not this one.
        let other = request(&clock);
        assert!(matches!(
            verify_confirmation(
                &clock,
                &other,
                &proof,
                owner.authorisation.public(),
                HostEnrolment::Enrolled,
            ),
            Err(PairingError::OwnerConfirmationRequired)
        ));

        // And a proof whose action digest was rewritten does not verify.
        let mut tampered = proof;
        tampered.request.action_digest = Digest256::from_bytes([9; 32]);
        assert!(matches!(
            verify_confirmation(
                &clock,
                &tampered.request.clone(),
                &tampered,
                owner.authorisation.public(),
                HostEnrolment::Enrolled,
            ),
            Err(PairingError::AuthenticationFailed)
        ));
    }

    #[test]
    fn a_session_plugin_or_contact_tool_channel_is_refused() {
        let clock = TestClock::new();
        let owner = DeviceKeys::generate().expect("keys");
        let challenge = request(&clock);
        for channel in [
            ConfirmationChannel::Session,
            ConfirmationChannel::Plugin,
            ConfirmationChannel::ContactTool,
        ] {
            let proof =
                sign_confirmation(&owner.authorisation, &challenge, channel).expect("a proof");
            assert!(matches!(
                verify_confirmation(
                    &clock,
                    &challenge,
                    &proof,
                    owner.authorisation.public(),
                    HostEnrolment::Enrolled,
                ),
                Err(PairingError::OwnerConfirmationRequired)
            ));
        }
    }

    #[test]
    fn the_controlling_terminal_is_the_bootstrap_exception_only() {
        let clock = TestClock::new();
        let owner = DeviceKeys::generate().expect("keys");
        let challenge = request(&clock);
        let proof = sign_confirmation(
            &owner.authorisation,
            &challenge,
            ConfirmationChannel::LocalBootstrapTerminal,
        )
        .expect("a proof");
        assert!(
            verify_confirmation(
                &clock,
                &challenge,
                &proof,
                owner.authorisation.public(),
                HostEnrolment::InitialBootstrap,
            )
            .is_ok()
        );
        assert!(matches!(
            verify_confirmation(
                &clock,
                &challenge,
                &proof,
                owner.authorisation.public(),
                HostEnrolment::Enrolled,
            ),
            Err(PairingError::OwnerConfirmationRequired)
        ));
    }

    #[test]
    fn a_channel_cannot_be_rewritten_after_the_ceremony() {
        let clock = TestClock::new();
        let owner = DeviceKeys::generate().expect("keys");
        let challenge = request(&clock);
        let mut proof = sign_confirmation(
            &owner.authorisation,
            &challenge,
            ConfirmationChannel::LocalBootstrapTerminal,
        )
        .expect("a proof");
        // Claiming a stronger channel breaks the signature, because the channel is inside it.
        proof.channel = ConfirmationChannel::OwnerDevicePresence;
        assert!(matches!(
            verify_confirmation(
                &clock,
                &challenge,
                &proof,
                owner.authorisation.public(),
                HostEnrolment::Enrolled,
            ),
            Err(PairingError::AuthenticationFailed)
        ));
    }

    #[test]
    fn a_challenge_expires() {
        let clock = TestClock::new();
        let owner = DeviceKeys::generate().expect("keys");
        let challenge = request(&clock);
        let proof = sign_confirmation(
            &owner.authorisation,
            &challenge,
            ConfirmationChannel::OwnerDevicePresence,
        )
        .expect("a proof");
        clock.advance(CONFIRMATION_LIFETIME_MS);
        assert!(matches!(
            verify_confirmation(
                &clock,
                &challenge,
                &proof,
                owner.authorisation.public(),
                HostEnrolment::Enrolled,
            ),
            Err(PairingError::OwnerConfirmationRequired)
        ));
    }

    #[test]
    fn another_signer_is_not_the_owner() {
        let clock = TestClock::new();
        let owner = DeviceKeys::generate().expect("keys");
        let impostor = DeviceKeys::generate().expect("keys");
        let challenge = request(&clock);
        let proof = sign_confirmation(
            &impostor.authorisation,
            &challenge,
            ConfirmationChannel::OwnerDevicePresence,
        )
        .expect("a proof");
        assert!(matches!(
            verify_confirmation(
                &clock,
                &challenge,
                &proof,
                owner.authorisation.public(),
                HostEnrolment::Enrolled,
            ),
            Err(PairingError::OwnerConfirmationRequired)
        ));
    }

    #[test]
    fn a_declining_ceremony_is_a_refusal_rather_than_a_downgrade() {
        let clock = TestClock::new();
        let owner = DeviceKeys::generate().expect("keys");
        let challenge = request(&clock);
        assert!(matches!(
            obtain_confirmation(
                &DecliningCeremony,
                &clock,
                &challenge,
                owner.authorisation.public(),
                HostEnrolment::Enrolled,
            ),
            Err(PairingError::OwnerConfirmationRequired)
        ));
    }

    #[test]
    fn a_challenge_is_consumed_once() {
        let clock = TestClock::new();
        let mut ledger = ConfirmationLedger::new();
        let challenge = request(&clock);
        assert!(ledger.is_empty());
        ledger.issue(&challenge);
        assert_eq!(ledger.len(), 1);
        assert!(ledger.consume(&challenge).is_ok());
        assert!(matches!(
            ledger.consume(&challenge),
            Err(PairingError::OwnerConfirmationRequired)
        ));
        assert!(ledger.is_empty());
    }

    #[test]
    fn every_action_that_needs_a_confirmation_can_ask_for_one() {
        let clock = TestClock::new();
        for action in [
            SensitiveAction::IssueInvitation,
            SensitiveAction::ConfirmDevice,
            SensitiveAction::EnlargeGrant,
            SensitiveAction::TrustRepositoryRoot,
            SensitiveAction::GrantExecutableCapability,
            SensitiveAction::ChangeHostAuthority,
        ] {
            let request = request_confirmation(
                &clock,
                action,
                Digest256::from_bytes([1; 32]),
                None,
                BTreeSet::new(),
                DeviceId::new(Uuid::from_bytes([2; 16])),
                EndpointKey::from_bytes([3; 32]),
            )
            .expect("a challenge");
            assert_eq!(request.action, action);
            assert_eq!(
                request.expires_at_ms.get(),
                clock.wall_clock_ms() + CONFIRMATION_LIFETIME_MS
            );
        }
    }
}
