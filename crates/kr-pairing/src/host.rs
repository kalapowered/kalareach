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
//! Four rules shape the rest of this file:
//!
//! * **The lock is at the PAKE, not at `pair.finish`.** A successful key confirmation locks the
//!   invitation to that candidate and cancels the others there and then. Leaving the invitation
//!   open until `finish` would let a second candidate keep guessing against an invitation someone
//!   had already proved.
//! * **The store is the authority, and every write is conditional.** A transition reloads the
//!   record, decides from it, and writes only if the stored record is still exactly that one. An
//!   invitation may be served by this state machine and by the direct-QR one at the same time, so
//!   an unconditional write would let the slower of the two undo the faster one's lock, spent
//!   guess or consumption.
//! * **A write that fails fences the invitation.** If the host cannot record a spent guess, it
//!   refuses to serve the invitation at all rather than hand the guess back.
//! * **Nothing is committed that was not authorised.** Issuing needs a fresh owner confirmation
//!   naming the proposed rights; confirming needs one naming the exact candidate; and the grant
//!   itself is validated and narrowed against its parent inside the committing transaction.

use std::collections::BTreeMap;

use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::secret::SymmetricKey;
use kr_protocol::actor::ActorIngress;
use kr_protocol::grant::Grant;
use kr_protocol::ids::{ActorId, AttemptId, DeviceId, DeviceKeyRevision, InvitationId};
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
use crate::confirm::{self, ConfirmationExpectation, ConfirmationLedger, HostEnrolment};
use crate::error::{PairingError, Result};
use crate::grants::{self, GrantIdentities, GrantKind};
use crate::platform::{
    InvitationRecord, InvitationState, InvitationStore, LivePeer, LocatorReservation, PairingClock,
    PairingCommitment, RendezvousHost, TransitionOutcome, require_completed_handshake,
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

/// The domain a short-code device confirmation's action digest is computed under.
///
/// The direct route has its own, so a confirmation obtained for one entry mode cannot approve a
/// candidate that arrived by the other.
pub const CONFIRM_DEVICE_DOMAIN: &str = "kr-pair/confirm-device/short-code/1";

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
    /// Which kind of grant those rights are, which decides the rules they are checked against.
    ///
    /// Nothing infers this: a session invitation and a personal owner grant have different rules,
    /// and a caller says which it is issuing so the rules for that kind are the ones applied.
    pub grant_kind: GrantKind,
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
        host: &HostIdentity,
        proposed_grant: &ProposedGrant,
    ) -> Result<()> {
        self.accept(
            ledger,
            clock,
            &ConfirmationExpectation {
                action: SensitiveAction::IssueInvitation,
                action_digest: confirm::action_digest(proposed_grant)?,
                host_device_id: host.device_id,
                host_endpoint_id: host.endpoint_id,
                // There is no destination device yet: the invitation is issued before anybody
                // answers it, and a challenge that named one would be naming a guess.
                destination_keys: None,
                destination_rights: &proposed_grant.actions,
            },
        )
    }

    /// Accepts a confirmation to add exactly this device with exactly these rights.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::OwnerConfirmationRequired`] or
    /// [`PairingError::AuthenticationFailed`].
    pub fn accept_confirm_device(
        &self,
        ledger: &mut ConfirmationLedger,
        clock: &dyn PairingClock,
        host: &HostIdentity,
        client_keys: &DevicePublicKeys,
        proposed_grant: &ProposedGrant,
        action_digest: Digest256,
    ) -> Result<()> {
        self.accept(
            ledger,
            clock,
            &ConfirmationExpectation {
                action: SensitiveAction::ConfirmDevice,
                action_digest,
                host_device_id: host.device_id,
                host_endpoint_id: host.endpoint_id,
                destination_keys: Some(client_keys),
                destination_rights: &proposed_grant.actions,
            },
        )
    }

    fn accept(
        &self,
        ledger: &mut ConfirmationLedger,
        clock: &dyn PairingClock,
        expectation: &ConfirmationExpectation<'_>,
    ) -> Result<()> {
        confirm::accept_confirmation(
            ledger,
            clock,
            self.request,
            self.proof,
            self.signer,
            self.enrolment,
            expectation,
        )
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
    /// The three digests the owner approves by name.
    pub approved: ApprovedCandidate,
    /// The candidate's signed bundle.
    pub client_bundle: SignedClientBundle,
    /// The eight hexadecimal characters both devices display.
    pub verification_value: String,
}

/// Exactly what the owner is shown and names back.
///
/// All three digests travel together because the approval is over all three: the transcript the
/// two devices confirmed, and the two bundles that transcript authenticated. An approval that
/// named only the transcript would not say which host bundle the candidate was shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApprovedCandidate {
    /// The transcript both devices confirmed.
    pub transcript: Digest256,
    /// The host bundle's hash.
    pub host_bundle_hash: Digest256,
    /// The candidate bundle's hash.
    pub client_bundle_hash: Digest256,
}

impl ApprovedCandidate {
    /// Returns the digest an owner's device-confirmation challenge must name.
    ///
    /// The domain separates this route from the direct one, so a confirmation obtained for a QR
    /// redemption cannot approve a short-code candidate or the reverse.
    #[must_use]
    pub fn action_digest(&self) -> Digest256 {
        Digest256::from_bytes(kr_cbor::sha256(&kr_cbor::encode(
            &kr_cbor::CanonicalValue::Array(vec![
                kr_cbor::CanonicalValue::text(CONFIRM_DEVICE_DOMAIN),
                kr_cbor::CanonicalValue::bytes(self.transcript.as_bytes().as_slice()),
                kr_cbor::CanonicalValue::bytes(self.host_bundle_hash.as_bytes().as_slice()),
                kr_cbor::CanonicalValue::bytes(self.client_bundle_hash.as_bytes().as_slice()),
            ]),
        )))
    }

    /// Returns the eight hexadecimal characters both devices display for this candidate.
    #[must_use]
    pub fn verification_value(&self) -> String {
        verification_value(
            self.transcript,
            self.host_bundle_hash,
            self.client_bundle_hash,
        )
    }
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
    /// The candidate whose bundle this invitation authenticated, kept after its attempt is gone.
    ///
    /// A denied, cancelled or expired invitation clears its attempts, and the candidate still has
    /// to be able to ask what happened. This is the identity that answer is checked against.
    last_candidate: Option<AuthenticatedCandidate>,
    /// Set when a durable write failed. The invitation serves nobody afterwards.
    fenced: bool,
}

/// A candidate this invitation authenticated, kept for as long as the invitation is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AuthenticatedCandidate {
    attempt_id: AttemptId,
    endpoint_id: EndpointKey,
}

impl<S: InvitationStore, C: PairingClock> HostInvitation<S, C> {
    /// Issues an invitation: a fresh code, a reserved locator and a persisted record.
    ///
    /// Issuing a persistent pairing invitation is one of the six actions that need a fresh owner
    /// confirmation bound to the exact rights being proposed, so the challenge must name
    /// [`SensitiveAction::IssueInvitation`], this host, and the digest and rights of this proposed
    /// grant. The challenge is consumed here and works exactly once. The proposal is checked
    /// against the rules for its kind before anything is reserved or written, so a grant that
    /// could never be issued does not become an invitation somebody can answer.
    ///
    /// The identity is 128 random bits, the deadline is five minutes on the monotonic clock, and
    /// the record-control token is a separate random 256-bit value the service only ever sees
    /// hashed.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::OwnerConfirmationRequired`] without a valid single-use
    /// confirmation, [`PairingError::GrantNotPermitted`] for a proposal its kind does not allow,
    /// [`PairingError::RendezvousUnavailable`] when the service cannot reserve a locator,
    /// [`PairingError::Store`] when the record cannot be persisted, and a crypto error when
    /// libsodium is unavailable.
    pub fn issue(
        store: S,
        clock: C,
        rendezvous: &dyn RendezvousHost,
        proposal: InvitationProposal,
        approval: &OwnerApproval<'_>,
        ledger: &mut ConfirmationLedger,
    ) -> Result<Self> {
        approval.accept_issue(ledger, &clock, &proposal.host, &proposal.proposed_grant)?;
        grants::validate_proposal(
            &proposal.proposed_grant,
            proposal.grant_kind,
            clock.wall_clock_ms(),
        )?;
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
        store.create(&record)?;
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
            last_candidate: None,
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

    /// Returns the three digests the candidate holding the invitation produced.
    ///
    /// The issuing device shows the owner what this candidate proved; the owner then names those
    /// digests back in `pair.confirm`, which is what stops an approval being applied to a
    /// candidate the owner was not shown. It answers only once both bundles are in, because the
    /// two bundle hashes are part of what the owner approves.
    ///
    /// # Errors
    ///
    /// Returns an encoding error when a bundle is outside KR-CBOR-1.
    pub fn locked_candidate(&self) -> Result<Option<ApprovedCandidate>> {
        let Some(attempt_id) = self.record.state.locked_attempt() else {
            return Ok(None);
        };
        let Some(attempt) = self.attempts.get(&attempt_id) else {
            return Ok(None);
        };
        let (Some(transcript), Some(host_bundle_hash), Some(client_bundle)) = (
            attempt.transcript,
            attempt.host_bundle_hash,
            attempt.client_bundle.as_ref(),
        ) else {
            return Ok(None);
        };
        Ok(Some(ApprovedCandidate {
            transcript,
            host_bundle_hash,
            client_bundle_hash: bundles::bundle_hash(&client_bundle.bundle)?,
        }))
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

    /// Returns the owner that issued this invitation.
    #[must_use]
    pub const fn issuing_owner(&self) -> &OwnerContext {
        &self.issuing_owner
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
        // From here the candidate has an authenticated identity, which outlives its attempt: a
        // denied or cancelled invitation still has to answer the candidate that asks what happened.
        self.last_candidate = Some(AuthenticatedCandidate {
            attempt_id,
            endpoint_id: signed.bundle.endpoint_id,
        });
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
        // Before anything reads or writes the record: a request in early data is replayable, and a
        // replay must not be able to expire an invitation or move it on.
        require_completed_handshake(live_peer)?;
        self.require_open()?;
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
        let approved = ApprovedCandidate {
            transcript,
            host_bundle_hash,
            client_bundle_hash,
        };
        Ok(LockedCandidate {
            attempt_id,
            approved,
            client_bundle,
            verification_value: approved.verification_value(),
        })
    }

    /// Commits the device record and grant after the issuing owner approves.
    ///
    /// Confirming a new device is a sensitive action, so this needs a fresh single-use owner
    /// confirmation naming this host, the candidate's own key bundle, the proposed rights and the
    /// digest of the exact transcript and bundles the owner was shown.
    ///
    /// The grant is issued here rather than assumed: `issue_grant` checks it against the rules for
    /// its kind and against the parent it is delegated from, so a grant that widens its parent is
    /// refused inside the committing transition rather than written and relied on. The rights are
    /// the invitation's: the candidate cannot enlarge them through its bundle.
    ///
    /// The device record, the validated grant, the consumed invitation, the owner's proof and the
    /// security event are one store transaction, and this reports success only after that
    /// transaction returns.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::NotIssuingOwner`], [`PairingError::OwnerConfirmationRequired`],
    /// [`PairingError::GrantNotPermitted`], [`PairingError::ContextMismatch`],
    /// [`PairingError::WrongPhase`] and [`PairingError::Store`].
    pub fn confirm(
        &mut self,
        approval: &OwnerApproval<'_>,
        ledger: &mut ConfirmationLedger,
        approved: &ApprovedCandidate,
        identities: &GrantIdentities,
        parent: Option<&Grant>,
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
        if phase != AttemptPhase::AwaitingApproval {
            return Err(PairingError::WrongPhase {
                expected: AttemptPhase::AwaitingApproval.as_str(),
                actual: phase.as_str(),
            });
        }
        let client_bundle = attempt.client_bundle.clone();
        let recorded = self.locked_candidate()?;
        let (Some(recorded), Some(client_bundle)) = (recorded, client_bundle) else {
            return Err(PairingError::WrongPhase {
                expected: AttemptPhase::AwaitingApproval.as_str(),
                actual: phase.as_str(),
            });
        };
        if recorded != *approved {
            return Err(PairingError::ContextMismatch {
                what: "the candidate the owner approved",
            });
        }
        if identities.issuer_device_id != self.proposal.host.device_id {
            return Err(PairingError::ContextMismatch {
                what: "the host device a grant is issued by",
            });
        }
        approval.accept_confirm_device(
            ledger,
            &self.clock,
            &self.proposal.host,
            &client_bundle.bundle.keys,
            &self.proposal.proposed_grant,
            approved.action_digest(),
        )?;
        let grant = grants::issue_grant(
            self.proposal.proposed_grant.clone(),
            self.proposal.grant_kind,
            self.clock.wall_clock_ms(),
            identities,
            parent,
        )?;

        let commitment = PairingCommitment {
            invitation_id: self.record.invitation_id,
            attempt_id,
            device_id: identities.recipient_device_id,
            grant,
            client_keys: client_bundle.bundle.keys,
            client_bundle: Some(client_bundle.bundle.clone()),
            proposed_grant: self.proposal.proposed_grant.clone(),
            verification_value: approved.verification_value(),
            owner_confirmation: approval.proof.clone(),
            committed_at_ms: TimestampMs::new(self.clock.wall_clock_ms()),
        };
        let mut next = self.record.clone();
        next.state = InvitationState::Committed;
        // One transaction, conditional on the record nothing else has moved. A pairing is reported
        // as complete only after it returns, so a crash cannot leave a device with no grant or a
        // completed pairing with no security event.
        match self.store.commit(&self.record, &next, &commitment) {
            Ok(TransitionOutcome::Written) => {
                self.record = next;
                self.attempts.clear();
                Ok(commitment)
            }
            Ok(TransitionOutcome::Stale(current)) => Err(self.adopt_stale(current)),
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
        self.require_not_fenced()?;
        self.reload()?;
        self.consume(PairingConsumedReason::Denied)
    }

    /// Consumes the invitation because the owner cancelled it.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::NotIssuingOwner`] or [`PairingError::Store`].
    pub fn cancel(&mut self, owner: &OwnerContext) -> Result<()> {
        self.require_issuing_owner(owner)?;
        self.require_not_fenced()?;
        self.reload()?;
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
    /// Returns [`PairingError::NotIssuingOwner`] when the viewer is neither,
    /// [`PairingError::EarlyData`] for a candidate asking in 0-RTT, and [`PairingError::Store`]
    /// when a failed write has fenced the invitation.
    pub fn status(&mut self, viewer: StatusViewer<'_>) -> Result<PairStatus> {
        // A candidate's connection is checked before the record is read or written: a status
        // request in early data is replayable, and a replay must not expire an invitation.
        if let StatusViewer::Candidate { live_peer, .. } = viewer {
            require_completed_handshake(live_peer)?;
        }
        // Fenced means the last durable decision is unknown, and an unknown state is not reported
        // as an open invitation.
        self.require_not_fenced()?;
        self.reload()?;
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
                grant_id: committed.grant.grant_id,
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
                let ready = self
                    .attempts
                    .get(&attempt_id)
                    .filter(|attempt| attempt.phase == AttemptPhase::AwaitingApproval)
                    .is_some();
                match (ready, self.locked_candidate()?) {
                    (true, Some(approved)) => PairStatus::AwaitingApproval {
                        attempt_id,
                        verification_value: approved.verification_value(),
                        expires_at_ms: self.advertised_expires_at_ms,
                    },
                    // Locked, but the bundles are not both in yet: there is no verification value
                    // to show, and saying "open" would say another candidate could still take it.
                    _ => PairStatus::Locked {
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
        let endpoint = live_peer.live_endpoint()?;
        if let Some(committed) = committed {
            return Ok(
                committed.attempt_id == attempt_id && committed.client_keys.transport == endpoint
            );
        }
        // The live attempt first, then the identity kept from it. The second is what answers a
        // candidate after a denial, a cancellation or an expiry has cleared the attempts: the
        // candidate still authenticated itself, and it is still the only one that may be told.
        // Before the bundle exchange there is no authenticated endpoint at all, and then the
        // answer is the ambiguous refusal.
        if let Some(signed) = self
            .attempts
            .get(&attempt_id)
            .and_then(|attempt| attempt.client_bundle.as_ref())
        {
            return Ok(signed.bundle.endpoint_id == endpoint);
        }
        Ok(self.last_candidate.is_some_and(|candidate| {
            candidate.attempt_id == attempt_id && candidate.endpoint_id == endpoint
        }))
    }

    fn require_issuing_owner(&self, owner: &OwnerContext) -> Result<()> {
        if owner != &self.issuing_owner {
            return Err(PairingError::NotIssuingOwner);
        }
        Ok(())
    }

    /// Refuses everything once a durable write has failed.
    ///
    /// The last decision is not known to have been recorded, so this invitation serves nobody: it
    /// reports no status, accepts no candidate and consumes nothing until a restart cancels it.
    /// Any other behaviour risks handing a spent guess back.
    fn require_not_fenced(&self) -> Result<()> {
        if self.fenced {
            return Err(PairingError::Store {
                reason: "this invitation was fenced by a failed write".to_owned(),
            });
        }
        Ok(())
    }

    /// Reads the authoritative record. The store is where an invitation's state lives.
    fn reload(&mut self) -> Result<()> {
        if let Some(record) = self.store.load(self.record.invitation_id)? {
            self.record = record;
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
        self.require_not_fenced()?;
        // The store is the authority. An invitation that offers both entry modes is served by two
        // state machines over one record, so each reloads before it decides and writes back only
        // if the record has not moved.
        self.reload()?;
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
            let Some(attempt) = self.attempts.get(&locked) else {
                // A candidate already holds the invitation, by the other entry mode or from
                // before a restart. Whichever state machine reloaded this record refuses to start
                // another candidate.
                return Err(PairingError::CandidateLocked);
            };
            // Holding the invitation does not suspend the handshake deadline. A candidate that
            // proved the code and then stopped would otherwise hold the invitation for its whole
            // five minutes; the invitation is consumed instead, so the owner can issue another.
            if attempt.phase != AttemptPhase::AwaitingApproval
                && now >= attempt.deadline_monotonic_ms
            {
                self.consume(PairingConsumedReason::Expired)?;
                return Err(PairingError::Expired);
            }
        }
        Ok(())
    }

    /// Writes a record if the stored one is still the one this decision was made from.
    ///
    /// Three outcomes, and all three are decided here rather than by the caller: the write landed;
    /// another writer moved the record first, so this decision is void and its record is adopted;
    /// or the store failed, and the invitation is fenced because the decision may or may not have
    /// been recorded.
    fn persist(&mut self, next: InvitationRecord) -> Result<()> {
        match self.store.transition(&self.record, &next) {
            Ok(TransitionOutcome::Written) => {
                self.record = next;
                Ok(())
            }
            Ok(TransitionOutcome::Stale(current)) => Err(self.adopt_stale(current)),
            Err(error) => {
                // The decision could not be recorded, so it is not made. The invitation serves
                // nobody until a restart cancels it: that is what stops a spent guess coming back.
                self.fenced = true;
                Err(error)
            }
        }
    }

    /// Adopts a record another writer wrote first, and returns why this decision is void.
    fn adopt_stale(&mut self, current: InvitationRecord) -> PairingError {
        let refusal = match current.state {
            InvitationState::Consumed { reason } => PairingError::Consumed { reason },
            InvitationState::Committed => PairingError::AlreadyCommitted,
            InvitationState::Locked { .. } => PairingError::CandidateLocked,
            InvitationState::Open => PairingError::ContextMismatch {
                what: "an invitation record another writer changed",
            },
        };
        self.record = current;
        self.attempts.clear();
        refusal
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
    for record in store.unfinished()? {
        let mut next = record.clone();
        next.state = InvitationState::Consumed {
            reason: PairingConsumedReason::HostRestarted,
        };
        // Conditional, like every other write: an invitation somebody moved between the listing
        // and here is left as they left it rather than overwritten by a sweep.
        if store.transition(&record, &next)? == TransitionOutcome::Written {
            cancelled.push(record.invitation_id);
        }
    }
    Ok(cancelled)
}

/// Retrieves a completed pairing by invitation identity, for a host that has restarted.
///
/// A pairing's result lives in the store, not in the invitation object: that object is gone after
/// a restart, and the candidate may still be asking. This is the host-side lookup, for code inside
/// the host's own trust boundary.
///
/// # Errors
///
/// Returns [`PairingError::Store`].
pub fn recover_commitment(
    store: &dyn InvitationStore,
    invitation_id: InvitationId,
) -> Result<Option<PairingCommitment>> {
    store.commitment(invitation_id)
}

/// Answers a candidate that asks what became of a pairing, after the host restarted.
///
/// The candidate proves the same endpoint its bundle declared and names its own attempt, so this
/// tells nobody else anything. It reports a committed pairing from the commitment and everything
/// else from the record.
///
/// # Errors
///
/// Returns [`PairingError::EarlyData`] in 0-RTT, [`PairingError::NotIssuingOwner`] when the asker
/// is not that candidate, and [`PairingError::Store`].
pub fn recover_candidate_status(
    store: &dyn InvitationStore,
    invitation_id: InvitationId,
    attempt_id: AttemptId,
    live_peer: &dyn LivePeer,
) -> Result<PairStatus> {
    require_completed_handshake(live_peer)?;
    let endpoint = live_peer.live_endpoint()?;
    if let Some(committed) = store.commitment(invitation_id)? {
        if committed.attempt_id != attempt_id || committed.client_keys.transport != endpoint {
            return Err(PairingError::NotIssuingOwner);
        }
        return Ok(PairStatus::Committed {
            device_id: committed.device_id,
            grant_id: committed.grant.grant_id,
        });
    }
    let Some(record) = store.load(invitation_id)? else {
        return Err(PairingError::NotIssuingOwner);
    };
    match record.state {
        // Nothing here can prove which candidate is asking, because the endpoint a candidate
        // authenticated with lives in the invitation object that the restart lost.
        InvitationState::Consumed { reason } => Ok(PairStatus::Consumed { reason }),
        _ => Err(PairingError::NotIssuingOwner),
    }
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
