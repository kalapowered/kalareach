//! The host's short-code state machine.
//!
//! One invitation, at most four candidates, and one serial path through every decision that could
//! consume the password-guess allowance. Section 10's budget rules are the reason this is one type
//! rather than one per candidate: "count and verify guesses in one serial path so concurrent
//! candidates cannot exceed the remaining allowance". A candidate that holds a `&mut` borrow of
//! the invitation is the only candidate being served at that instant, and the count it reads is
//! the count every other candidate will read next.
//!
//! What consumes the allowance is narrow. A confirmation tag that verified and did not match
//! consumes one. A malformed message, an unreachable service, a candidate that walks away and a
//! local configuration error consume bounded rate and slot budgets instead, because none of them
//! produced a password confirmation result.
//!
//! Three rules shape the rest of this file:
//!
//! * **The lock is at the PAKE, not at `pair.finish`.** A successful key confirmation locks the
//!   invitation to that candidate and cancels the others there and then. Leaving the invitation
//!   open until `finish` would let a second candidate keep guessing against an invitation someone
//!   had already proved.
//! * **The store is the authority.** Every transition reloads the record before it decides and
//!   persists before it reports, so a host that crashed between deciding and persisting comes back
//!   with the decision it persisted, and an invitation that offers both entry modes has one
//!   candidate and one consumption whichever route reaches it first.
//! * **A write that fails fences the invitation.** If the host cannot record a spent guess, it
//!   refuses to serve the invitation at all rather than hand the guess back.

use std::collections::BTreeMap;

use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::secret::SymmetricKey;
use kr_protocol::actor::ActorIngress;
use kr_protocol::ids::{ActorId, AttemptId, DeviceId, DeviceKeyRevision, GrantId, InvitationId};
use kr_protocol::pairing::{
    BundleMessageType, DevicePublicKeys, HostBundle, INVITATION_LIFETIME_MS,
    MAX_CONFIRMATION_FAILURES, NetworkConfig, OwnerConfirmationProof, OwnerConfirmationRequest,
    PairFinishRequest, PairStatus, PairingConsumedReason, PairingContext, ProposedGrant,
    RendezvousOrigin, SensitiveAction, SignedClientBundle, finish_mac_input, verification_value,
};
use kr_protocol::scalars::{
    AuthorisationKey, Digest256, EndpointKey, Mac256, Nonce256, TimestampMs, Uuid,
};

use crate::bundles::{self, BundleFrame, ExchangeBudget};
use crate::code::{CodeSecret, GeneratedCode, generate_code};
use crate::confirm::{self, ConfirmationLedger, HostEnrolment};
use crate::error::{PairingError, Result};
use crate::platform::{
    InvitationRecord, InvitationState, InvitationStore, LivePeer, LocatorReservation, PairingClock,
    PairingCommitment, RendezvousHost, require_completed_handshake,
};
use crate::spake::{Role, SpakeState};
use crate::transcript::AttemptKeys;

/// The most candidates one invitation serves at a time.
///
/// The rendezvous room holds one host connection and at most four candidate slots. The host keeps
/// the same bound, so a room that misbehaves cannot make it hold more.
pub const MAX_CANDIDATES: usize = 4;

/// How long one candidate has to finish its handshake, in milliseconds.
///
/// Section 10 gives the invitation five minutes and does not give the individual handshake a
/// number. Ten seconds is a profile decision, recorded in `docs/pairing/README.md`: it is far more
/// than a PAKE and two bundles need over any working link, and short enough that four candidates
/// cannot hold the four slots shut for the invitation's whole life. The deadline is monotonic and
/// tied to the boot, and no message extends it.
pub const HANDSHAKE_DEADLINE_MS: u64 = 10_000;

/// How many locators a host tries before it gives up on the service.
///
/// A collision makes the host generate another locator. Four collisions in a row out of `58^4`
/// possibilities means the service is not reserving anything.
const MAX_LOCATOR_ATTEMPTS: usize = 4;

/// The owner context that issued an invitation.
///
/// `pair.confirm` and `pair.cancel` require the *original* issuing owner. A newly created
/// invitation context is not that: section 10 says so explicitly, which is why this is captured at
/// issue and compared later rather than re-derived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerContext {
    /// The host-issued principal of the verified actor. A caller cannot assert its own.
    pub actor_id: ActorId,
    /// How that actor reached the host.
    pub ingress: ActorIngress,
}

/// Everything the host declares about itself.
///
/// The host bundle is built from this rather than handed in, so a caller cannot make the host
/// sign a bundle naming another device's keys, another endpoint or a larger grant than the
/// invitation proposed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostIdentity {
    /// The host's device identity.
    pub device_id: DeviceId,
    /// The host's iroh endpoint identity.
    pub endpoint_id: EndpointKey,
    /// The host's purpose-separated public keys.
    pub keys: DevicePublicKeys,
    /// The revision of those keys.
    pub device_key_revision: DeviceKeyRevision,
    /// The selected discovery and relay configuration, with current hints.
    pub network_config: NetworkConfig,
}

/// What an owner asks the host to issue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvitationProposal {
    /// The locally configured rendezvous origin. A service cannot name its own.
    pub origin: RendezvousOrigin,
    /// The host's own identity, which its bundle declares.
    pub host: HostIdentity,
    /// The rights the invitation proposes.
    pub proposed_grant: ProposedGrant,
}

/// One owner confirmation, as the host receives it.
///
/// Issuing a persistent pairing invitation and confirming a new device are two of the six actions
/// section 10 requires a fresh owner confirmation for. The challenge, the proof and the enrolled
/// signer travel together because they are only meaningful together: a proof without the exact
/// challenge it answers proves nothing.
#[derive(Clone, Copy, Debug)]
pub struct OwnerApproval<'a> {
    /// The owner acting.
    pub owner: &'a OwnerContext,
    /// The enrolled signer whose signature the proof must carry.
    pub signer: &'a AuthorisationKey,
    /// Whether the host has an owner yet.
    pub enrolment: HostEnrolment,
    /// The challenge the host issued.
    pub request: &'a OwnerConfirmationRequest,
    /// The proof that answers it.
    pub proof: &'a OwnerConfirmationProof,
}

impl OwnerApproval<'_> {
    /// Checks the challenge describes this action, verifies the proof and consumes the challenge.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::OwnerConfirmationRequired`] or
    /// [`PairingError::AuthenticationFailed`].
    fn accept(
        &self,
        ledger: &mut ConfirmationLedger,
        clock: &dyn PairingClock,
        action: SensitiveAction,
        action_digest: Digest256,
    ) -> Result<()> {
        confirm::require_action(self.request, action, action_digest)?;
        confirm::accept_confirmation(
            ledger,
            clock,
            self.request,
            self.proof,
            self.signer,
            self.enrolment,
        )
    }

    /// Accepts a confirmation to issue an invitation proposing exactly these rights.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::OwnerConfirmationRequired`] or
    /// [`PairingError::AuthenticationFailed`].
    pub fn accept_issue(
        &self,
        ledger: &mut ConfirmationLedger,
        clock: &dyn PairingClock,
        proposed_grant: &ProposedGrant,
    ) -> Result<()> {
        self.accept(
            ledger,
            clock,
            SensitiveAction::IssueInvitation,
            confirm::action_digest(proposed_grant)?,
        )
    }

    /// Accepts a confirmation to add exactly the device this digest names.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::OwnerConfirmationRequired`] or
    /// [`PairingError::AuthenticationFailed`].
    pub fn accept_confirm_device(
        &self,
        ledger: &mut ConfirmationLedger,
        clock: &dyn PairingClock,
        action_digest: Digest256,
    ) -> Result<()> {
        self.accept(ledger, clock, SensitiveAction::ConfirmDevice, action_digest)
    }
}

/// Where one candidate's attempt has reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AttemptPhase {
    /// The host has sent its PAKE message and is waiting for the candidate's.
    AwaitingClientPake,
    /// Both messages are in and the host is waiting for the client confirmation tag.
    AwaitingClientConfirmation,
    /// The tags matched; the invitation is locked and the bundle exchange is open.
    Confirmed,
    /// The candidate's bundle is in and `pair.finish` is expected.
    AwaitingFinish,
    /// The candidate holds the invitation and the owner is deciding.
    AwaitingApproval,
}

impl AttemptPhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingClientPake => "the candidate's PAKE message",
            Self::AwaitingClientConfirmation => "the candidate's confirmation tag",
            Self::Confirmed => "the bundle exchange",
            Self::AwaitingFinish => "pair.finish",
            Self::AwaitingApproval => "owner approval",
        }
    }
}

/// One candidate's live attempt. It exists only in memory: nothing resumes it after a restart.
struct HostAttempt {
    context: PairingContext,
    phase: AttemptPhase,
    spake: Option<SpakeState>,
    transcript: Option<Digest256>,
    keys: Option<AttemptKeys>,
    budget: ExchangeBudget,
    host_bundle_hash: Option<Digest256>,
    client_bundle: Option<SignedClientBundle>,
    deadline_monotonic_ms: u64,
}

/// What a successful key confirmation produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostConfirmation {
    /// The host's confirmation tag, which the candidate verifies before it trusts anything.
    pub host_tag: Mac256,
    /// The competing candidates this lock cancelled.
    pub cancelled: Vec<AttemptId>,
}

/// What a successful `pair.finish` produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockedCandidate {
    /// The candidate that holds the invitation.
    pub attempt_id: AttemptId,
    /// The transcript both devices confirmed.
    pub transcript: Digest256,
    /// The candidate's signed bundle.
    pub client_bundle: SignedClientBundle,
    /// The eight hexadecimal characters both devices display.
    pub verification_value: String,
}

/// The host's side of one short-code invitation.
pub struct HostInvitation<S: InvitationStore, C: PairingClock> {
    store: S,
    clock: C,
    record: InvitationRecord,
    code: GeneratedCode,
    reservation: LocatorReservation,
    proposal: InvitationProposal,
    issuing_owner: OwnerContext,
    advertised_expires_at_ms: TimestampMs,
    attempts: BTreeMap<AttemptId, HostAttempt>,
    /// Set when a durable write failed. The invitation serves nobody afterwards.
    fenced: bool,
}

impl<S: InvitationStore, C: PairingClock> HostInvitation<S, C> {
    /// Issues an invitation: a fresh code, a reserved locator and a persisted record.
    ///
    /// Issuing a persistent pairing invitation is one of the six actions that need a fresh owner
    /// confirmation bound to the exact rights being proposed, so the challenge must name
    /// [`SensitiveAction::IssueInvitation`] and carry the digest of this proposed grant. The
    /// challenge is consumed here and works exactly once.
    ///
    /// The identity is 128 random bits, the deadline is five minutes on the monotonic clock, and
    /// the record-control token is a separate random 256-bit value the service only ever sees
    /// hashed.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::OwnerConfirmationRequired`] without a valid single-use
    /// confirmation, [`PairingError::RendezvousUnavailable`] when the service cannot reserve a
    /// locator, [`PairingError::Store`] when the record cannot be persisted, and a crypto error
    /// when libsodium is unavailable.
    pub fn issue(
        store: S,
        clock: C,
        rendezvous: &dyn RendezvousHost,
        proposal: InvitationProposal,
        approval: &OwnerApproval<'_>,
        ledger: &mut ConfirmationLedger,
    ) -> Result<Self> {
        approval.accept_issue(ledger, &clock, &proposal.proposed_grant)?;
        bundles::require_consistent_keys(
            &proposal.host.keys,
            &proposal.host.endpoint_id,
            "the endpoint a host declares, which is not its own transport key",
        )?;

        let invitation_id = InvitationId::new(random_uuid()?);
        let control_token = SymmetricKey::random()?;
        // The deadline is the host's, on the monotonic clock. The absolute time below is only what
        // the service advertises to a candidate; a lie about it changes nothing here.
        let deadline_monotonic_ms = clock.monotonic_ms().saturating_add(INVITATION_LIFETIME_MS);
        let advertised_expires_at_ms =
            TimestampMs::new(clock.wall_clock_ms().saturating_add(INVITATION_LIFETIME_MS));

        let mut code = generate_code()?;
        let mut reserved = None;
        for _ in 0..MAX_LOCATOR_ATTEMPTS {
            let reservation = LocatorReservation {
                locator: code.locator().clone(),
                control_token: control_token.clone(),
            };
            if rendezvous.reserve_locator(
                &proposal.origin,
                &reservation.locator,
                invitation_id,
                advertised_expires_at_ms,
                reservation.control_token_hash(),
            )? {
                reserved = Some(reservation);
                break;
            }
            // A collision makes the host generate another locator, which also gives the invitation
            // another secret: the two halves are drawn together and never mixed between codes.
            code = generate_code()?;
        }
        let Some(reservation) = reserved else {
            return Err(PairingError::RendezvousUnavailable {
                reason: "no locator could be reserved".to_owned(),
            });
        };

        let record = InvitationRecord {
            invitation_id,
            locator: Some(reservation.locator.clone()),
            state: InvitationState::Open,
            failed_confirmations: 0,
            deadline_monotonic_ms,
            boot_identity: clock.boot_identity(),
        };
        store.save(&record)?;
        let issuing_owner = approval.owner.clone();
        Ok(Self {
            store,
            clock,
            record,
            code,
            reservation,
            proposal,
            issuing_owner,
            advertised_expires_at_ms,
            attempts: BTreeMap::new(),
            fenced: false,
        })
    }

    /// Returns the code to display. The six secret characters go no further than the screen.
    #[must_use]
    pub const fn code(&self) -> &GeneratedCode {
        &self.code
    }

    /// Returns the invitation identity.
    #[must_use]
    pub const fn invitation_id(&self) -> InvitationId {
        self.record.invitation_id
    }

    /// Returns the host's own device identity, which its bundle declares.
    #[must_use]
    pub const fn host_device_id(&self) -> DeviceId {
        self.proposal.host.device_id
    }

    /// Returns how many failed confirmations the invitation has left.
    ///
    /// The issuing device shows this, so an owner watching a pairing can see the allowance fall.
    #[must_use]
    pub const fn remaining_confirmations(&self) -> u32 {
        MAX_CONFIRMATION_FAILURES.saturating_sub(self.record.failed_confirmations)
    }

    /// Returns the record as this host last read or wrote it.
    #[must_use]
    pub const fn record(&self) -> &InvitationRecord {
        &self.record
    }

    /// Returns the candidate that holds the invitation, when one does.
    #[must_use]
    pub fn locked_attempt(&self) -> Option<AttemptId> {
        self.record.state.locked_attempt()
    }

    /// Returns the transcript of the candidate that holds the invitation.
    ///
    /// The issuing device shows the owner what this candidate proved; the owner then names that
    /// transcript back in `pair.confirm`, which is what stops an approval being applied to a
    /// candidate the owner was not shown.
    #[must_use]
    pub fn locked_transcript(&self) -> Option<Digest256> {
        let attempt_id = self.record.state.locked_attempt()?;
        self.attempts
            .get(&attempt_id)
            .and_then(|attempt| attempt.transcript)
    }

    /// Returns the bundle hash of the candidate that holds the invitation.
    ///
    /// # Errors
    ///
    /// Returns an encoding error when the bundle is outside KR-CBOR-1.
    pub fn locked_client_bundle_hash(&self) -> Result<Option<Digest256>> {
        let Some(attempt_id) = self.record.state.locked_attempt() else {
            return Ok(None);
        };
        self.attempts
            .get(&attempt_id)
            .and_then(|attempt| attempt.client_bundle.as_ref())
            .map(|signed| bundles::bundle_hash(&signed.bundle))
            .transpose()
    }

    /// Admits a candidate and returns the host's PAKE message.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Expired`], [`PairingError::Consumed`],
    /// [`PairingError::CandidateLocked`] once a candidate has proved the code,
    /// [`PairingError::AttemptsExhausted`] or [`PairingError::TooLarge`] when the room is full.
    pub fn admit(&mut self, attempt_id: AttemptId, client_nonce: Nonce256) -> Result<Vec<u8>> {
        self.require_open()?;
        if self.record.state.locked_attempt().is_some() {
            // A candidate has proved the code. No further guessing happens against this
            // invitation, by this route or the other one.
            return Err(PairingError::CandidateLocked);
        }
        if self.attempts.len() >= MAX_CANDIDATES {
            return Err(PairingError::TooLarge {
                what: "the candidate slots of one invitation",
                limit: MAX_CANDIDATES,
                actual: self.attempts.len() + 1,
            });
        }
        if self.attempts.contains_key(&attempt_id) {
            return Err(PairingError::ReplayedSequence { sequence: 0 });
        }
        let context = PairingContext {
            rendezvous_origin: self.proposal.origin.clone(),
            locator: self.code.locator().clone(),
            invitation_id: self.record.invitation_id,
            attempt_id,
            host_nonce: Nonce256::from_bytes(random_bytes32()?),
            client_nonce,
        };
        // A fresh state per attempt: nothing is reused after a timeout, a failure or a reconnect.
        let spake = SpakeState::start(Role::Host, &context, self.code.secret());
        let message = spake.message().to_vec();
        self.attempts.insert(
            attempt_id,
            HostAttempt {
                context,
                phase: AttemptPhase::AwaitingClientPake,
                spake: Some(spake),
                transcript: None,
                keys: None,
                budget: ExchangeBudget::new(),
                host_bundle_hash: None,
                client_bundle: None,
                deadline_monotonic_ms: self
                    .clock
                    .monotonic_ms()
                    .saturating_add(HANDSHAKE_DEADLINE_MS),
            },
        );
        Ok(message)
    }

    /// Drops one candidate's attempt and frees its slot, charging no guess.
    ///
    /// A candidate that disconnects or gives up has produced no confirmation result, so the
    /// password-guess allowance is untouched. A candidate that already holds the invitation cannot
    /// be dropped this way: releasing the lock is the owner's decision, through `pair.cancel`.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::CandidateLocked`] for the candidate holding the invitation.
    pub fn abort(&mut self, attempt_id: AttemptId) -> Result<()> {
        if self.record.state.locked_attempt() == Some(attempt_id) {
            return Err(PairingError::CandidateLocked);
        }
        self.attempts.remove(&attempt_id);
        Ok(())
    }

    /// Returns how many candidate slots are in use.
    #[must_use]
    pub fn live_candidates(&self) -> usize {
        self.attempts.len()
    }

    /// Returns the context the host built for one candidate.
    ///
    /// Both devices build `C` themselves; this is the host's copy, which a caller compares with
    /// the candidate's rather than adopting it.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::WrongPhase`] when there is no such attempt.
    pub fn context(&self, attempt_id: AttemptId) -> Result<&PairingContext> {
        Ok(&self.attempt(attempt_id)?.context)
    }

    /// Takes the candidate's PAKE message and derives the attempt's five keys.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::WrongPhase`], and [`PairingError::AuthenticationFailed`] for a
    /// malformed message, a wrong role or an invalid element. None of those consumes the
    /// password-guess allowance: no confirmation result was produced.
    pub fn receive_client_pake(&mut self, attempt_id: AttemptId, message: &[u8]) -> Result<()> {
        self.require_open()?;
        let attempt = self.attempt_mut(attempt_id)?;
        require_phase(attempt, AttemptPhase::AwaitingClientPake)?;
        let spake = attempt.spake.take().ok_or(PairingError::WrongPhase {
            expected: AttemptPhase::AwaitingClientPake.as_str(),
            actual: "an attempt with no message of its own",
        })?;
        let host_message = spake.message().to_vec();
        let shared = spake.finish(message)?;
        let transcript = attempt.context.transcript(&host_message, message);
        attempt.keys = Some(AttemptKeys::derive(shared.expose(), transcript)?);
        attempt.transcript = Some(transcript);
        attempt.phase = AttemptPhase::AwaitingClientConfirmation;
        Ok(())
    }

    /// Verifies the candidate's confirmation tag, locks the invitation and returns the host's tag.
    ///
    /// This is the serial path, and it is where the invitation is locked. A tag that matches locks
    /// the invitation to that candidate and cancels every competitor *before* the host answers. A
    /// tag that verifies and does not match consumes one of the five guesses, the count is
    /// persisted before the failure is returned, and the fifth failure consumes the invitation.
    ///
    /// Both outcomes persist first and change memory second. If the write fails the invitation is
    /// fenced: it serves nobody until the host restarts and cancels it, which is the only
    /// behaviour that cannot hand a spent guess back.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::AuthenticationFailed`] for a wrong tag,
    /// [`PairingError::AttemptsExhausted`] once the allowance is gone, and
    /// [`PairingError::Store`] when the outcome cannot be persisted.
    pub fn verify_client_confirmation(
        &mut self,
        attempt_id: AttemptId,
        tag: &Mac256,
    ) -> Result<HostConfirmation> {
        self.require_open()?;
        if self.remaining_confirmations() == 0 {
            return Err(PairingError::AttemptsExhausted);
        }
        let attempt = self.attempt_mut(attempt_id)?;
        require_phase(attempt, AttemptPhase::AwaitingClientConfirmation)?;
        let (Some(keys), Some(transcript)) = (attempt.keys.as_ref(), attempt.transcript) else {
            return Err(PairingError::WrongPhase {
                expected: AttemptPhase::AwaitingClientConfirmation.as_str(),
                actual: "an attempt with no derived keys",
            });
        };
        match keys.verify_client_confirmation(transcript, tag) {
            Ok(()) => {
                let host_tag = keys.host_confirmation(transcript);
                // The lock is persisted before the host answers. A candidate that receives the
                // host tag is a candidate this invitation is already committed to serving.
                let mut locked = self.record.clone();
                locked.state = InvitationState::Locked { attempt_id };
                self.persist(locked)?;
                let attempt = self.attempt_mut(attempt_id)?;
                attempt.phase = AttemptPhase::Confirmed;
                let cancelled: Vec<AttemptId> = self
                    .attempts
                    .keys()
                    .copied()
                    .filter(|id| *id != attempt_id)
                    .collect();
                self.attempts.retain(|id, _| *id == attempt_id);
                Ok(HostConfirmation {
                    host_tag,
                    cancelled,
                })
            }
            Err(error) => {
                let mut spent = self.record.clone();
                spent.failed_confirmations = spent.failed_confirmations.saturating_add(1);
                let exhausted = spent.failed_confirmations >= MAX_CONFIRMATION_FAILURES;
                if exhausted {
                    spent.state = InvitationState::Consumed {
                        reason: PairingConsumedReason::AttemptsExhausted,
                    };
                }
                // The count is written before the failure is reported, so a host that dies here
                // comes back having spent the guess rather than offering it again.
                self.persist(spent)?;
                self.attempts.remove(&attempt_id);
                if exhausted {
                    self.attempts.clear();
                    return Err(PairingError::AttemptsExhausted);
                }
                Err(error)
            }
        }
    }

    /// Seals the host's signed bundle for one candidate.
    ///
    /// The bundle is built from the invitation: the host's own endpoint and keys, the invitation
    /// identity and the grant the owner proposed. A caller supplies nothing, so nothing a caller
    /// supplies can end up signed by the host's authorisation key.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::WrongPhase`] before confirmation, and an encoding or library error.
    pub fn seal_host_bundle(
        &mut self,
        attempt_id: AttemptId,
        authorisation: &AuthorisationKeyPair,
    ) -> Result<BundleFrame> {
        self.require_open()?;
        let bundle = HostBundle {
            invitation_id: self.record.invitation_id,
            device_id: self.proposal.host.device_id,
            device_key_revision: self.proposal.host.device_key_revision,
            endpoint_id: self.proposal.host.endpoint_id,
            keys: self.proposal.host.keys,
            network_config: self.proposal.host.network_config.clone(),
            proposed_grant: self.proposal.proposed_grant.clone(),
        };
        let attempt = self.attempt_mut(attempt_id)?;
        require_phase(attempt, AttemptPhase::Confirmed)?;
        let (Some(keys), Some(transcript)) = (attempt.keys.as_ref(), attempt.transcript) else {
            return Err(PairingError::WrongPhase {
                expected: AttemptPhase::Confirmed.as_str(),
                actual: "an attempt with no derived keys",
            });
        };
        let signed = bundles::sign_host_bundle(authorisation, bundle, transcript)?;
        attempt.host_bundle_hash = Some(bundles::bundle_hash(&signed.bundle)?);
        bundles::seal_bundle(
            &keys.host_to_client,
            transcript,
            BundleMessageType::HostBundle,
            &mut attempt.budget,
            &signed,
        )
    }

    /// Opens and verifies the candidate's signed bundle.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::WrongPhase`], [`PairingError::ReplayedSequence`],
    /// [`PairingError::TooLarge`], [`PairingError::ContextMismatch`] when the bundle's endpoint is
    /// not its own transport key, or [`PairingError::AuthenticationFailed`].
    pub fn open_client_bundle(
        &mut self,
        attempt_id: AttemptId,
        frame: &BundleFrame,
    ) -> Result<SignedClientBundle> {
        self.require_open()?;
        let attempt = self.attempt_mut(attempt_id)?;
        require_phase(attempt, AttemptPhase::Confirmed)?;
        let (Some(keys), Some(transcript)) = (attempt.keys.as_ref(), attempt.transcript) else {
            return Err(PairingError::WrongPhase {
                expected: AttemptPhase::Confirmed.as_str(),
                actual: "an attempt with no derived keys",
            });
        };
        let signed: SignedClientBundle = bundles::open_bundle(
            &keys.client_to_host,
            transcript,
            BundleMessageType::ClientBundle,
            &mut attempt.budget,
            frame,
        )?;
        bundles::verify_client_bundle(&signed, transcript)?;
        attempt.client_bundle = Some(signed.clone());
        attempt.phase = AttemptPhase::AwaitingFinish;
        Ok(signed)
    }

    /// Accepts `pair.finish`, binding the transcript to the two live iroh endpoints.
    ///
    /// The invitation is already locked to this candidate; what happens here is the endpoint
    /// binding and the verification value the owner is shown.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::EarlyData`] for a request in 0-RTT,
    /// [`PairingError::ContextMismatch`] when the request names another attempt or another
    /// transcript, [`PairingError::EndpointMismatch`] when the live peer is not the candidate the
    /// bundle authenticated, and [`PairingError::AuthenticationFailed`] when the tag fails.
    pub fn finish(
        &mut self,
        request: &PairFinishRequest,
        live_peer: &dyn LivePeer,
    ) -> Result<LockedCandidate> {
        self.require_open()?;
        require_completed_handshake(live_peer)?;
        let host_endpoint = self.proposal.host.endpoint_id;
        let live_client_endpoint = live_peer.live_endpoint()?;
        let attempt_id = request.attempt_id;
        if self.record.state.locked_attempt() != Some(attempt_id) {
            // Another candidate holds the invitation, or none does yet.
            return Err(PairingError::CandidateLocked);
        }
        let attempt = self.attempt_mut(attempt_id)?;
        require_phase(attempt, AttemptPhase::AwaitingFinish)?;
        let (Some(keys), Some(transcript), Some(host_bundle_hash), Some(client_bundle)) = (
            attempt.keys.as_ref(),
            attempt.transcript,
            attempt.host_bundle_hash,
            attempt.client_bundle.clone(),
        ) else {
            return Err(PairingError::WrongPhase {
                expected: AttemptPhase::AwaitingFinish.as_str(),
                actual: "an attempt with no exchanged bundles",
            });
        };
        if request.invitation_id != attempt.context.invitation_id
            || request.transcript != transcript
            || request.host_bundle_hash != host_bundle_hash
        {
            return Err(PairingError::ContextMismatch {
                what: "the transcript pair.finish names",
            });
        }
        let client_bundle_hash = bundles::bundle_hash(&client_bundle.bundle)?;
        if request.client_bundle_hash != client_bundle_hash {
            return Err(PairingError::ContextMismatch {
                what: "the client bundle hash pair.finish names",
            });
        }
        // The live peer must be the endpoint the authenticated bundle declared. A candidate that
        // proves the transcript from another endpoint is a different device.
        if live_client_endpoint != client_bundle.bundle.endpoint_id {
            return Err(PairingError::EndpointMismatch { side: "client" });
        }
        keys.verify_binding_tag(
            &finish_mac_input(
                request.invitation_id,
                attempt_id,
                transcript,
                &host_endpoint,
                &live_client_endpoint,
                host_bundle_hash,
                client_bundle_hash,
            ),
            &request.binding_tag,
        )?;

        attempt.phase = AttemptPhase::AwaitingApproval;
        Ok(LockedCandidate {
            attempt_id,
            transcript,
            client_bundle,
            verification_value: verification_value(
                transcript,
                host_bundle_hash,
                client_bundle_hash,
            ),
        })
    }

    /// Commits the device record and grant after the issuing owner approves.
    ///
    /// Confirming a new device is a sensitive action, so this needs a fresh single-use owner
    /// confirmation naming [`SensitiveAction::ConfirmDevice`] and the digest of the exact
    /// transcript and client bundle the owner was shown. The grant committed is the one the
    /// invitation proposed: the candidate cannot enlarge it through its bundle.
    ///
    /// The device record, the grant, the consumed invitation and the security event are one store
    /// transaction, and this reports success only after that transaction returns.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::NotIssuingOwner`], [`PairingError::OwnerConfirmationRequired`],
    /// [`PairingError::ContextMismatch`], [`PairingError::WrongPhase`] and
    /// [`PairingError::Store`].
    pub fn confirm(
        &mut self,
        approval: &OwnerApproval<'_>,
        ledger: &mut ConfirmationLedger,
        transcript: Digest256,
        client_bundle_hash: Digest256,
        device_id: DeviceId,
        grant_id: GrantId,
    ) -> Result<PairingCommitment> {
        self.require_issuing_owner(approval.owner)?;
        if let Some(committed) = self.store.commitment(self.record.invitation_id)? {
            // A transport retry retrieves the committed result; it never commits again, so it
            // cannot replace the public keys or the grant. This reads through the store, so the
            // retry works after a restart too.
            return Ok(committed);
        }
        self.require_open()?;
        let Some(attempt_id) = self.record.state.locked_attempt() else {
            return Err(PairingError::WrongPhase {
                expected: AttemptPhase::AwaitingApproval.as_str(),
                actual: "an invitation with no locked candidate",
            });
        };
        let attempt = self.attempt(attempt_id)?;
        let phase = attempt.phase;
        let (Some(recorded), Some(host_bundle_hash), Some(client_bundle)) = (
            attempt.transcript,
            attempt.host_bundle_hash,
            attempt.client_bundle.clone(),
        ) else {
            return Err(PairingError::WrongPhase {
                expected: AttemptPhase::AwaitingApproval.as_str(),
                actual: phase.as_str(),
            });
        };
        if phase != AttemptPhase::AwaitingApproval {
            return Err(PairingError::WrongPhase {
                expected: AttemptPhase::AwaitingApproval.as_str(),
                actual: phase.as_str(),
            });
        }
        if recorded != transcript
            || bundles::bundle_hash(&client_bundle.bundle)? != client_bundle_hash
        {
            return Err(PairingError::ContextMismatch {
                what: "the transcript the owner approved",
            });
        }
        approval.accept_confirm_device(
            ledger,
            &self.clock,
            confirm_action_digest(transcript, client_bundle_hash),
        )?;

        let commitment = PairingCommitment {
            invitation_id: self.record.invitation_id,
            attempt_id,
            device_id,
            grant_id,
            client_keys: client_bundle.bundle.keys,
            client_bundle: Some(client_bundle.bundle.clone()),
            proposed_grant: self.proposal.proposed_grant.clone(),
            verification_value: verification_value(
                transcript,
                host_bundle_hash,
                client_bundle_hash,
            ),
            committed_at_ms: TimestampMs::new(self.clock.wall_clock_ms()),
        };
        let mut record = self.record.clone();
        record.state = InvitationState::Committed;
        // One transaction. A pairing is reported as complete only after it returns, so a crash
        // cannot leave a device with no grant or a completed pairing with no security event.
        match self.store.commit(&record, &commitment) {
            Ok(()) => {
                self.record = record;
                self.attempts.clear();
                Ok(commitment)
            }
            Err(error) => {
                self.fenced = true;
                Err(error)
            }
        }
    }

    /// Consumes the invitation because the owner denied it.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::NotIssuingOwner`] or [`PairingError::Store`].
    pub fn deny(&mut self, owner: &OwnerContext) -> Result<()> {
        self.require_issuing_owner(owner)?;
        self.consume(PairingConsumedReason::Denied)
    }

    /// Consumes the invitation because the owner cancelled it.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::NotIssuingOwner`] or [`PairingError::Store`].
    pub fn cancel(&mut self, owner: &OwnerContext) -> Result<()> {
        self.require_issuing_owner(owner)?;
        self.consume(PairingConsumedReason::Cancelled)
    }

    /// Reports the invitation's state to one viewer.
    ///
    /// A candidate sees only its own attempt, and no secret material. It must ask from the
    /// endpoint its own authenticated bundle declared, so knowing an attempt identity is not
    /// enough to watch someone else's pairing. The issuing owner sees the verification value and
    /// the remaining allowance.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::NotIssuingOwner`] when the viewer is neither, and
    /// [`PairingError::EarlyData`] for a candidate asking in 0-RTT.
    pub fn status(&mut self, viewer: StatusViewer<'_>) -> Result<PairStatus> {
        // Reading the record rather than remembering it: the other entry mode may have consumed or
        // locked this invitation since the last transition here.
        if let Some(record) = self.store.load(self.record.invitation_id)? {
            self.record = record;
        }
        if self.is_expired() {
            self.consume(PairingConsumedReason::Expired)?;
        }
        let committed = self.store.commitment(self.record.invitation_id)?;
        let permitted = match viewer {
            StatusViewer::IssuingOwner(owner) => owner == &self.issuing_owner,
            StatusViewer::Candidate {
                attempt_id,
                live_peer,
            } => self.candidate_may_view(attempt_id, live_peer, committed.as_ref())?,
        };
        if !permitted {
            return Err(PairingError::NotIssuingOwner);
        }
        // A committed invitation answers from the store, so the result survives a restart and the
        // in-memory attempts being cleared.
        if let Some(committed) = committed {
            return Ok(PairStatus::Committed {
                device_id: committed.device_id,
                grant_id: committed.grant_id,
            });
        }
        Ok(match self.record.state {
            InvitationState::Open => PairStatus::Open {
                remaining_confirmations: self.remaining_confirmations(),
                expires_at_ms: self.advertised_expires_at_ms,
            },
            InvitationState::Locked { attempt_id } => {
                // A locked candidate has an entry here only while this state machine is serving
                // it. After a restart, or when the other entry mode holds it, there is none, and
                // "locked" is still the honest answer.
                let ready = self.attempts.get(&attempt_id).and_then(|attempt| {
                    match (
                        attempt.phase,
                        attempt.transcript,
                        attempt.host_bundle_hash,
                        attempt.client_bundle.as_ref(),
                    ) {
                        (
                            AttemptPhase::AwaitingApproval,
                            Some(transcript),
                            Some(host_hash),
                            Some(client_bundle),
                        ) => Some((transcript, host_hash, client_bundle)),
                        _ => None,
                    }
                });
                match ready {
                    Some((transcript, host_hash, client_bundle)) => PairStatus::AwaitingApproval {
                        attempt_id,
                        verification_value: verification_value(
                            transcript,
                            host_hash,
                            bundles::bundle_hash(&client_bundle.bundle)?,
                        ),
                        expires_at_ms: self.advertised_expires_at_ms,
                    },
                    // Locked, but the bundles are not both in yet: there is no verification value
                    // to show, and saying "open" would say another candidate could still take it.
                    None => PairStatus::Locked {
                        attempt_id,
                        expires_at_ms: self.advertised_expires_at_ms,
                    },
                }
            }
            InvitationState::Committed => {
                return Err(PairingError::Store {
                    reason: "a committed invitation has no commitment record".to_owned(),
                });
            }
            InvitationState::Consumed { reason } => PairStatus::Consumed { reason },
        })
    }

    /// Releases the locator reservation, proving possession of the control token.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::RendezvousUnavailable`].
    pub fn release(&self, rendezvous: &dyn RendezvousHost) -> Result<()> {
        rendezvous.release_locator(&self.reservation.locator, &self.reservation.control_token)
    }

    /// Decides whether a candidate may read this invitation's status.
    fn candidate_may_view(
        &self,
        attempt_id: AttemptId,
        live_peer: &dyn LivePeer,
        committed: Option<&PairingCommitment>,
    ) -> Result<bool> {
        require_completed_handshake(live_peer)?;
        let endpoint = live_peer.live_endpoint()?;
        if let Some(committed) = committed {
            return Ok(
                committed.attempt_id == attempt_id && committed.client_keys.transport == endpoint
            );
        }
        // Before the bundle exchange the candidate has proved the code but not its endpoint, so
        // there is nothing to check an asker against and the answer is the ambiguous refusal.
        Ok(self
            .attempts
            .get(&attempt_id)
            .and_then(|attempt| attempt.client_bundle.as_ref())
            .is_some_and(|signed| signed.bundle.endpoint_id == endpoint))
    }

    fn require_issuing_owner(&self, owner: &OwnerContext) -> Result<()> {
        if owner != &self.issuing_owner {
            return Err(PairingError::NotIssuingOwner);
        }
        Ok(())
    }

    fn is_expired(&self) -> bool {
        // A reboot invalidates a monotonic deadline, so a record from another boot is expired
        // whatever its number says. Clock uncertainty cannot extend an invitation either: the
        // wall clock is not consulted.
        self.clock.boot_identity() != self.record.boot_identity
            || self.clock.monotonic_ms() >= self.record.deadline_monotonic_ms
    }

    /// Reloads the authoritative record, drops timed-out candidates and checks the invitation.
    fn require_open(&mut self) -> Result<()> {
        if self.fenced {
            return Err(PairingError::Store {
                reason: "this invitation was fenced by a failed write".to_owned(),
            });
        }
        // The store is the authority. An invitation that offers both entry modes is served by two
        // state machines over one record, so each reloads before it decides.
        if let Some(record) = self.store.load(self.record.invitation_id)? {
            self.record = record;
        }
        if let InvitationState::Consumed { reason } = self.record.state {
            return Err(PairingError::Consumed { reason });
        }
        if self.record.state == InvitationState::Committed {
            return Err(PairingError::AlreadyCommitted);
        }
        if self.is_expired() {
            self.consume(PairingConsumedReason::Expired)?;
            return Err(PairingError::Expired);
        }
        let now = self.clock.monotonic_ms();
        let locked = self.record.state.locked_attempt();
        // A candidate that ran out of handshake time frees its slot and charges no guess.
        self.attempts
            .retain(|id, attempt| Some(*id) == locked || now < attempt.deadline_monotonic_ms);
        if let Some(locked) = locked {
            // A candidate already holds the invitation. The route it arrived by does not matter:
            // whichever state machine reloaded this record refuses to start another candidate.
            if !self.attempts.contains_key(&locked) {
                return Err(PairingError::CandidateLocked);
            }
        }
        Ok(())
    }

    /// Writes a record and adopts it, fencing the invitation when the write fails.
    fn persist(&mut self, record: InvitationRecord) -> Result<()> {
        match self.store.save(&record) {
            Ok(()) => {
                self.record = record;
                Ok(())
            }
            Err(error) => {
                // The decision could not be recorded, so it is not made. The invitation serves
                // nobody until a restart cancels it: that is what stops a spent guess coming back.
                self.fenced = true;
                Err(error)
            }
        }
    }

    fn consume(&mut self, reason: PairingConsumedReason) -> Result<()> {
        if !matches!(
            self.record.state,
            InvitationState::Consumed { .. } | InvitationState::Committed
        ) {
            let mut record = self.record.clone();
            record.state = InvitationState::Consumed { reason };
            self.persist(record)?;
        }
        self.attempts.clear();
        Ok(())
    }

    fn attempt(&self, attempt_id: AttemptId) -> Result<&HostAttempt> {
        self.attempts
            .get(&attempt_id)
            .ok_or(PairingError::WrongPhase {
                expected: "a live attempt",
                actual: "an attempt this invitation does not hold",
            })
    }

    fn attempt_mut(&mut self, attempt_id: AttemptId) -> Result<&mut HostAttempt> {
        self.attempts
            .get_mut(&attempt_id)
            .ok_or(PairingError::WrongPhase {
                expected: "a live attempt",
                actual: "an attempt this invitation does not hold",
            })
    }
}

/// Checks one attempt's phase.
fn require_phase(attempt: &HostAttempt, expected: AttemptPhase) -> Result<()> {
    if attempt.phase == expected {
        return Ok(());
    }
    Err(PairingError::WrongPhase {
        expected: expected.as_str(),
        actual: attempt.phase.as_str(),
    })
}

/// Returns the digest an owner's device-confirmation challenge must name.
///
/// It covers the exact transcript and client bundle the owner was shown, so a confirmation
/// obtained for one candidate cannot approve another.
#[must_use]
pub fn confirm_action_digest(transcript: Digest256, client_bundle_hash: Digest256) -> Digest256 {
    Digest256::from_bytes(kr_cbor::sha256(&kr_cbor::encode(
        &kr_cbor::CanonicalValue::Array(vec![
            kr_cbor::CanonicalValue::text("kr-pair/confirm-device/1"),
            kr_cbor::CanonicalValue::bytes(transcript.as_bytes().as_slice()),
            kr_cbor::CanonicalValue::bytes(client_bundle_hash.as_bytes().as_slice()),
        ]),
    )))
}

/// Who is asking for an invitation's status.
#[derive(Clone, Copy)]
pub enum StatusViewer<'a> {
    /// The owner that issued it.
    IssuingOwner(&'a OwnerContext),
    /// One candidate, which must ask from the endpoint its own bundle declared.
    Candidate {
        /// Its attempt.
        attempt_id: AttemptId,
        /// The live connection it is asking over.
        live_peer: &'a dyn LivePeer,
    },
}

impl core::fmt::Debug for StatusViewer<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::IssuingOwner(owner) => write!(formatter, "IssuingOwner({owner:?})"),
            Self::Candidate { attempt_id, .. } => {
                write!(formatter, "Candidate({attempt_id:?})")
            }
        }
    }
}

/// Cancels every invitation a host left unfinished, which a host does when it starts.
///
/// A candidate's attempt lives only in memory, so nothing can resume one. Consumed records and
/// failure counts survive, which is the other half of the rule.
///
/// # Errors
///
/// Returns [`PairingError::Store`].
pub fn cancel_unfinished_invitations(store: &dyn InvitationStore) -> Result<Vec<InvitationId>> {
    let mut cancelled = Vec::new();
    for mut record in store.unfinished()? {
        record.state = InvitationState::Consumed {
            reason: PairingConsumedReason::HostRestarted,
        };
        store.save(&record)?;
        cancelled.push(record.invitation_id);
    }
    Ok(cancelled)
}

/// Returns 128 random bits.
fn random_uuid() -> Result<Uuid> {
    let mut bytes = [0u8; 16];
    kr_crypto::random_bytes(&mut bytes)?;
    Ok(Uuid::from_bytes(bytes))
}

/// Returns 256 random bits.
fn random_bytes32() -> Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    kr_crypto::random_bytes(&mut bytes)?;
    Ok(bytes)
}

/// Returns a fresh attempt identity: 128 random bits.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable.
pub fn new_attempt_id() -> Result<AttemptId> {
    Ok(AttemptId::new(random_uuid()?))
}

/// Returns a fresh 256-bit nonce.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable.
pub fn new_nonce() -> Result<Nonce256> {
    Ok(Nonce256::from_bytes(random_bytes32()?))
}

/// Returns the secret half of a code, for a caller that already holds the invitation.
///
/// It exists so a test and the candidate-side state machine can run one exchange without the code
/// travelling through a display. Nothing in the host path calls it.
#[must_use]
pub fn code_secret(code: &GeneratedCode) -> &CodeSecret {
    code.secret()
}
