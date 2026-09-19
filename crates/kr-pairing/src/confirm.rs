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

use std::collections::{BTreeMap, BTreeSet};

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
use crate::platform::{BootIdentity, OwnerConfirmation, PairingClock};

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
///
/// The ledger keeps the whole challenge, not just its identity. A caller presents a challenge and
/// a proof; if it kept only the identity, an attacker who could influence what the caller presents
/// could hand over a challenge with the same identity and different contents, and the signature
/// check would pass against the substituted text. Comparing the retained challenge with the
/// presented one closes that, and it is also what makes the retained copy the host's own record of
/// what the owner was asked.
///
/// The deadline this enforces is the host's own, on the monotonic clock and tied to the boot it
/// was issued in. The `expires_at_ms` inside the request is the same interval expressed on the
/// wall clock, which is what a signer and a paired owner device can read; it is not what the host
/// trusts, because moving the wall clock backwards would otherwise reopen every challenge that
/// had run out. A reboot ends every outstanding challenge, which is also correct: nothing resumes
/// a ceremony across one.
#[derive(Debug, Default)]
pub struct ConfirmationLedger {
    outstanding: BTreeMap<[u8; 16], OutstandingChallenge>,
}

/// One challenge the host issued, as the host recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct OutstandingChallenge {
    request: OwnerConfirmationRequest,
    deadline_monotonic_ms: u64,
    boot_identity: BootIdentity,
}

impl ConfirmationLedger {
    /// Creates an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a challenge the host has just issued, with the deadline the host will enforce.
    pub fn issue(&mut self, request: &OwnerConfirmationRequest, clock: &dyn PairingClock) {
        self.outstanding.insert(
            *request.confirmation_id.get().as_bytes(),
            OutstandingChallenge {
                request: request.clone(),
                deadline_monotonic_ms: clock
                    .monotonic_ms()
                    .saturating_add(CONFIRMATION_LIFETIME_MS),
                boot_identity: clock.boot_identity(),
            },
        );
    }

    /// Returns the challenge the host issued under this identity, while it is still outstanding.
    #[must_use]
    pub fn outstanding(
        &self,
        confirmation_id: ConfirmationId,
    ) -> Option<&OwnerConfirmationRequest> {
        self.outstanding
            .get(confirmation_id.get().as_bytes())
            .map(|challenge| &challenge.request)
    }

    /// Returns the deadline this host will enforce for an outstanding challenge, and its boot.
    ///
    /// The deadline is monotonic and belongs to one boot, which is what makes it a deadline a
    /// moving wall clock cannot lengthen. A caller that carries the acceptance forward carries
    /// *these* values rather than recomputing anything from the wall clock, because the wall clock
    /// may have moved between the moment the challenge was issued and the moment it was answered.
    #[must_use]
    pub fn deadline(&self, confirmation_id: ConfirmationId) -> Option<(BootIdentity, u64)> {
        self.outstanding
            .get(confirmation_id.get().as_bytes())
            .map(|challenge| (challenge.boot_identity, challenge.deadline_monotonic_ms))
    }

    /// Consumes a challenge, which succeeds exactly once and only before its deadline.
    ///
    /// The presented challenge must equal the one the host issued, member for member.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::OwnerConfirmationRequired`] when the challenge was never issued,
    /// differs from the one issued, has already been used, has run out, or belongs to an earlier
    /// boot.
    pub fn consume(
        &mut self,
        request: &OwnerConfirmationRequest,
        clock: &dyn PairingClock,
    ) -> Result<()> {
        let Some(challenge) = self
            .outstanding
            .remove(request.confirmation_id.get().as_bytes())
        else {
            return Err(PairingError::OwnerConfirmationRequired);
        };
        if &challenge.request != request {
            // Removed either way: something presented an identity the host issued with contents it
            // did not, and the honest challenge is not left open beside that.
            return Err(PairingError::OwnerConfirmationRequired);
        }
        if challenge.boot_identity != clock.boot_identity()
            || clock.monotonic_ms() >= challenge.deadline_monotonic_ms
        {
            // An expired challenge is spent, not retryable.
            return Err(PairingError::OwnerConfirmationRequired);
        }
        Ok(())
    }

    /// Drops every challenge that has run out, which a host does periodically.
    pub fn expire(&mut self, clock: &dyn PairingClock) {
        let now = clock.monotonic_ms();
        let boot = clock.boot_identity();
        self.outstanding.retain(|_, challenge| {
            challenge.boot_identity == boot && now < challenge.deadline_monotonic_ms
        });
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

/// Verifies a proof and consumes the challenge it answers, in that order.
///
/// This is the only way the pairing flows accept a confirmation. Verifying first means a caller
/// cannot burn an owner's outstanding challenge by submitting rubbish, and consuming second means
/// one ceremony authorises exactly one action: a proof replayed at the next sensitive step finds
/// nothing outstanding.
///
/// A confirmation of *something* is not a confirmation of *this*, so the challenge is compared
/// with [`ConfirmationExpectation`] first: the action, the digest, the host, the destination keys
/// and the rights all have to be the ones the caller is about to act on.
///
/// # Errors
///
/// Returns [`PairingError::OwnerConfirmationRequired`] or [`PairingError::AuthenticationFailed`].
pub fn accept_confirmation(
    ledger: &mut ConfirmationLedger,
    clock: &dyn PairingClock,
    request: &OwnerConfirmationRequest,
    proof: &OwnerConfirmationProof,
    signer: &AuthorisationKey,
    enrolment: HostEnrolment,
    expectation: &ConfirmationExpectation<'_>,
) -> Result<()> {
    expectation.require(request)?;
    verify_confirmation(clock, request, proof, signer, enrolment)?;
    ledger.consume(request, clock)
}

/// What a caller is about to do, as the challenge must describe it.
///
/// Section 10 binds a confirmation to the exact action digest, destination keys and rights, host
/// and nonce. Checking the digest alone is not that: the owner is shown the destination and the
/// rights, and a host that ignored those fields would accept a challenge answered for a different
/// device or a different set of permissions than the one it is about to write.
#[derive(Clone, Copy, Debug)]
pub struct ConfirmationExpectation<'a> {
    /// The action.
    pub action: SensitiveAction,
    /// The digest of what is being authorised.
    pub action_digest: Digest256,
    /// The host doing it.
    pub host_device_id: DeviceId,
    /// That host's endpoint.
    pub host_endpoint_id: EndpointKey,
    /// The device the action is about, when it is about one.
    pub destination_keys: Option<&'a DevicePublicKeys>,
    /// The rights it carries.
    pub destination_rights: &'a CanonicalSet<ActionRight>,
}

impl ConfirmationExpectation<'_> {
    /// Checks that a challenge describes exactly this.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::OwnerConfirmationRequired`] when any member differs.
    pub fn require(&self, request: &OwnerConfirmationRequest) -> Result<()> {
        let destination = self
            .destination_keys
            .map_or_else(Nullable::null, |keys| Nullable::some(*keys));
        if request.action != self.action
            || request.action_digest != self.action_digest
            || request.host_device_id != self.host_device_id
            || request.host_endpoint_id != self.host_endpoint_id
            || request.destination_keys != destination
            || &request.destination_rights != self.destination_rights
        {
            return Err(PairingError::OwnerConfirmationRequired);
        }
        Ok(())
    }
}

/// Returns the digest of any canonical-CBOR value, which a challenge names as its action digest.
///
/// # Errors
///
/// Returns an encoding error when the value is outside KR-CBOR-1.
pub fn action_digest<T: serde::Serialize>(value: &T) -> Result<Digest256> {
    Ok(Digest256::from_bytes(kr_cbor::sha256(
        &kr_cbor::to_canonical_vec(value)?,
    )))
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

    const HOST_DEVICE: [u8; 16] = [2; 16];
    const HOST_ENDPOINT: [u8; 32] = [3; 32];

    /// A destination bundle the challenges below never name.
    fn destination() -> DevicePublicKeys {
        DeviceKeys::generate().expect("keys").public_keys()
    }

    /// A right the challenges below never carry.
    fn other_rights() -> CanonicalSet<ActionRight> {
        [ActionRight::SessionView].into_iter().collect()
    }

    /// The expectation `request` below answers.
    fn expectation<'a>(
        action: SensitiveAction,
        digest: Digest256,
        rights: &'a CanonicalSet<ActionRight>,
    ) -> ConfirmationExpectation<'a> {
        ConfirmationExpectation {
            action,
            action_digest: digest,
            host_device_id: DeviceId::new(Uuid::from_bytes(HOST_DEVICE)),
            host_endpoint_id: EndpointKey::from_bytes(HOST_ENDPOINT),
            destination_keys: None,
            destination_rights: rights,
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
        ledger.issue(&challenge, &clock);
        assert_eq!(ledger.len(), 1);
        assert!(ledger.consume(&challenge, &clock).is_ok());
        assert!(matches!(
            ledger.consume(&challenge, &clock),
            Err(PairingError::OwnerConfirmationRequired)
        ));
        assert!(ledger.is_empty());
    }

    #[test]
    fn a_challenge_runs_out_on_the_monotonic_clock() {
        let clock = TestClock::new();
        let mut ledger = ConfirmationLedger::new();
        let challenge = request(&clock);
        ledger.issue(&challenge, &clock);

        // Winding the wall clock back does not reopen it: the host's deadline is monotonic.
        clock.skew_wall_clock(-(2 * CONFIRMATION_LIFETIME_MS as i64));
        clock.advance(CONFIRMATION_LIFETIME_MS);
        assert!(matches!(
            ledger.consume(&challenge, &clock),
            Err(PairingError::OwnerConfirmationRequired)
        ));
        assert!(ledger.is_empty(), "an expired challenge is spent, not held");
    }

    #[test]
    fn a_reboot_ends_every_outstanding_challenge() {
        let clock = TestClock::new();
        let mut ledger = ConfirmationLedger::new();
        let challenge = request(&clock);
        ledger.issue(&challenge, &clock);
        clock.reboot(4);
        assert!(matches!(
            ledger.consume(&challenge, &clock),
            Err(PairingError::OwnerConfirmationRequired)
        ));
    }

    #[test]
    fn expiring_drops_only_what_has_run_out() {
        let clock = TestClock::new();
        let mut ledger = ConfirmationLedger::new();
        let early = request(&clock);
        ledger.issue(&early, &clock);
        clock.advance(CONFIRMATION_LIFETIME_MS - 1);
        let late = request(&clock);
        ledger.issue(&late, &clock);
        clock.advance(1);
        ledger.expire(&clock);
        assert_eq!(ledger.len(), 1);
        assert!(ledger.consume(&late, &clock).is_ok());
    }

    #[test]
    fn a_proof_is_accepted_once_and_the_action_must_match() {
        let clock = TestClock::new();
        let owner = DeviceKeys::generate().expect("keys");
        let mut ledger = ConfirmationLedger::new();
        let challenge = request(&clock);
        ledger.issue(&challenge, &clock);
        let proof = sign_confirmation(
            &owner.authorisation,
            &challenge,
            ConfirmationChannel::OwnerDevicePresence,
        )
        .expect("a proof");

        // The challenge is for ConfirmDevice over digest [1; 32], from this host, with no
        // destination device and no rights. Each member is checked.
        let rights = CanonicalSet::new();
        let elsewhere = destination();
        let more_rights = other_rights();
        let digest = Digest256::from_bytes([1; 32]);
        let good = expectation(SensitiveAction::ConfirmDevice, digest, &rights);
        assert!(good.require(&challenge).is_ok());
        for wrong in [
            ConfirmationExpectation {
                action: SensitiveAction::EnlargeGrant,
                ..good
            },
            ConfirmationExpectation {
                action_digest: Digest256::from_bytes([2; 32]),
                ..good
            },
            ConfirmationExpectation {
                host_device_id: DeviceId::new(Uuid::from_bytes([9; 16])),
                ..good
            },
            ConfirmationExpectation {
                host_endpoint_id: EndpointKey::from_bytes([9; 32]),
                ..good
            },
            ConfirmationExpectation {
                destination_keys: Some(&elsewhere),
                ..good
            },
            ConfirmationExpectation {
                destination_rights: &more_rights,
                ..good
            },
        ] {
            assert!(matches!(
                wrong.require(&challenge),
                Err(PairingError::OwnerConfirmationRequired)
            ));
        }

        assert!(
            accept_confirmation(
                &mut ledger,
                &clock,
                &challenge,
                &proof,
                owner.authorisation.public(),
                HostEnrolment::Enrolled,
                &good,
            )
            .is_ok()
        );
        // Replaying the same proof at the next sensitive step finds nothing outstanding.
        assert!(matches!(
            accept_confirmation(
                &mut ledger,
                &clock,
                &challenge,
                &proof,
                owner.authorisation.public(),
                HostEnrolment::Enrolled,
                &good,
            ),
            Err(PairingError::OwnerConfirmationRequired)
        ));
    }

    #[test]
    fn a_challenge_with_substituted_contents_is_not_the_one_the_host_issued() {
        let clock = TestClock::new();
        let owner = DeviceKeys::generate().expect("keys");
        let mut ledger = ConfirmationLedger::new();
        let issued = request(&clock);
        ledger.issue(&issued, &clock);

        // Same identity, different rights. A ledger that kept only the identity would check the
        // signature against this text and accept it.
        let mut substituted = issued.clone();
        substituted.destination_rights = other_rights();
        let proof = sign_confirmation(
            &owner.authorisation,
            &substituted,
            ConfirmationChannel::OwnerDevicePresence,
        )
        .expect("a proof");
        let rights = other_rights();
        let expectation = expectation(
            SensitiveAction::ConfirmDevice,
            Digest256::from_bytes([1; 32]),
            &rights,
        );
        assert!(matches!(
            accept_confirmation(
                &mut ledger,
                &clock,
                &substituted,
                &proof,
                owner.authorisation.public(),
                HostEnrolment::Enrolled,
                &expectation,
            ),
            Err(PairingError::OwnerConfirmationRequired)
        ));
    }

    #[test]
    fn a_rubbish_proof_does_not_burn_an_outstanding_challenge() {
        let clock = TestClock::new();
        let owner = DeviceKeys::generate().expect("keys");
        let impostor = DeviceKeys::generate().expect("keys");
        let mut ledger = ConfirmationLedger::new();
        let challenge = request(&clock);
        ledger.issue(&challenge, &clock);
        let forged = sign_confirmation(
            &impostor.authorisation,
            &challenge,
            ConfirmationChannel::OwnerDevicePresence,
        )
        .expect("a proof");
        let rights = CanonicalSet::new();
        assert!(
            accept_confirmation(
                &mut ledger,
                &clock,
                &challenge,
                &forged,
                owner.authorisation.public(),
                HostEnrolment::Enrolled,
                &expectation(
                    SensitiveAction::ConfirmDevice,
                    Digest256::from_bytes([1; 32]),
                    &rights
                ),
            )
            .is_err()
        );
        assert_eq!(ledger.len(), 1, "the owner's challenge is still answerable");
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
