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
//! Everything durable goes through [`InvitationStore`] before the step returns, so a failed write
//! is a failed step: a host that crashed between deciding and persisting comes back with the
//! decision it persisted, not the one it made.

use std::collections::BTreeMap;

use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::secret::SymmetricKey;
use kr_protocol::actor::ActorIngress;
use kr_protocol::ids::{ActorId, AttemptId, DeviceId, GrantId, InvitationId};
use kr_protocol::pairing::{
    BundleMessageType, ClientBundle, HostBundle, INVITATION_LIFETIME_MS, MAX_CONFIRMATION_FAILURES,
    PairFinishRequest, PairStatus, PairingConsumedReason, PairingContext, ProposedGrant,
    RendezvousOrigin, SignedClientBundle, finish_mac_input, verification_value,
};
use kr_protocol::scalars::{Digest256, EndpointKey, Mac256, Nonce256, TimestampMs, Uuid};

use crate::bundles::{self, BundleFrame, ExchangeBudget};
use crate::code::{CodeSecret, GeneratedCode, generate_code};
use crate::error::{PairingError, Result};
use crate::platform::{
    InvitationRecord, InvitationState, InvitationStore, LivePeer, LocatorReservation, PairingClock,
    RendezvousHost,
};
use crate::spake::{Role, SpakeState};
use crate::transcript::AttemptKeys;

/// The most candidates one invitation serves at a time.
///
/// The rendezvous room holds one host connection and at most four candidate slots. The host keeps
/// the same bound, so a room that misbehaves cannot make it hold more.
pub const MAX_CANDIDATES: usize = 4;

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

/// Where one candidate's attempt has reached.
#[derive(Debug, PartialEq, Eq)]
enum AttemptPhase {
    /// The host has sent its PAKE message and is waiting for the candidate's.
    AwaitingClientPake,
    /// Both messages are in and the host is waiting for the client confirmation tag.
    AwaitingClientConfirmation,
    /// The tags matched; the bundle exchange is open.
    Confirmed,
    /// The candidate's bundle is in and `pair.finish` is expected.
    AwaitingFinish,
    /// The candidate holds the invitation and the owner is deciding.
    AwaitingApproval,
}

impl AttemptPhase {
    const fn as_str(&self) -> &'static str {
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
}

/// What a successful `pair.finish` produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockedCandidate {
    /// The candidate that now holds the invitation.
    pub attempt_id: AttemptId,
    /// The transcript both devices confirmed.
    pub transcript: Digest256,
    /// The candidate's signed bundle.
    pub client_bundle: SignedClientBundle,
    /// The eight hexadecimal characters both devices display.
    pub verification_value: String,
    /// The candidates this lock cancelled.
    pub cancelled: Vec<AttemptId>,
}

/// What the owner's approval committed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedPairing {
    /// The candidate that was approved.
    pub attempt_id: AttemptId,
    /// The transcript.
    pub transcript: Digest256,
    /// The device record the host created for the candidate.
    pub device_id: DeviceId,
    /// The grant the host issued.
    pub grant_id: GrantId,
    /// The candidate's bundle, which is what the device record is written from.
    pub client_bundle: ClientBundle,
    /// The grant the invitation proposed, unchanged.
    pub proposed_grant: ProposedGrant,
}

/// The host's side of one short-code invitation.
pub struct HostInvitation<S: InvitationStore, C: PairingClock> {
    store: S,
    clock: C,
    origin: RendezvousOrigin,
    record: InvitationRecord,
    code: GeneratedCode,
    reservation: LocatorReservation,
    proposed_grant: ProposedGrant,
    issuing_owner: OwnerContext,
    host_device_id: DeviceId,
    host_endpoint: EndpointKey,
    advertised_expires_at_ms: TimestampMs,
    attempts: BTreeMap<AttemptId, HostAttempt>,
    committed: Option<CommittedPairing>,
}

impl<S: InvitationStore, C: PairingClock> HostInvitation<S, C> {
    /// Issues an invitation: a fresh code, a reserved locator and a persisted record.
    ///
    /// The identity is 128 random bits, the deadline is five minutes on the monotonic clock, and
    /// the record-control token is a separate random 256-bit value the service only ever sees
    /// hashed.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::RendezvousUnavailable`] when the service cannot reserve a locator,
    /// [`PairingError::Store`] when the record cannot be persisted, and a crypto error when
    /// libsodium is unavailable.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        store: S,
        clock: C,
        rendezvous: &dyn RendezvousHost,
        origin: RendezvousOrigin,
        proposed_grant: ProposedGrant,
        issuing_owner: OwnerContext,
        host_device_id: DeviceId,
        host_endpoint: EndpointKey,
    ) -> Result<Self> {
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
                &origin,
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
            locator: reservation.locator.clone(),
            state: InvitationState::Open,
            failed_confirmations: 0,
            deadline_monotonic_ms,
            boot_identity: clock.boot_identity(),
        };
        store.save(&record)?;
        Ok(Self {
            store,
            clock,
            origin,
            record,
            code,
            reservation,
            proposed_grant,
            issuing_owner,
            host_device_id,
            host_endpoint,
            advertised_expires_at_ms,
            attempts: BTreeMap::new(),
            committed: None,
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
        self.host_device_id
    }

    /// Returns how many failed confirmations the invitation has left.
    ///
    /// The issuing device shows this, so an owner watching a pairing can see the allowance fall.
    #[must_use]
    pub const fn remaining_confirmations(&self) -> u32 {
        MAX_CONFIRMATION_FAILURES.saturating_sub(self.record.failed_confirmations)
    }

    /// Returns the record as it is persisted.
    #[must_use]
    pub const fn record(&self) -> &InvitationRecord {
        &self.record
    }

    /// Returns the transcript of the candidate that holds the invitation.
    ///
    /// The issuing device shows the owner what this candidate proved; the owner then names that
    /// transcript back in `pair.confirm`, which is what stops an approval being applied to a
    /// candidate the owner was not shown.
    #[must_use]
    pub fn locked_transcript(&self) -> Option<Digest256> {
        let InvitationState::AwaitingApproval { attempt_id } = self.record.state else {
            return None;
        };
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
        let InvitationState::AwaitingApproval { attempt_id } = self.record.state else {
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
    /// [`PairingError::CandidateLocked`], [`PairingError::AttemptsExhausted`] or
    /// [`PairingError::TooLarge`] when the room is full.
    pub fn admit(&mut self, attempt_id: AttemptId, client_nonce: Nonce256) -> Result<Vec<u8>> {
        self.require_open()?;
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
            rendezvous_origin: self.origin.clone(),
            locator: self.record.locator.clone(),
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
            },
        );
        Ok(message)
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
        if attempt.phase != AttemptPhase::AwaitingClientPake {
            return Err(PairingError::WrongPhase {
                expected: AttemptPhase::AwaitingClientPake.as_str(),
                actual: attempt.phase.as_str(),
            });
        }
        let spake = attempt.spake.take().ok_or(PairingError::WrongPhase {
            expected: AttemptPhase::AwaitingClientPake.as_str(),
            actual: attempt.phase.as_str(),
        })?;
        let host_message = spake.message().to_vec();
        let shared = spake.finish(message)?;
        let transcript = attempt.context.transcript(&host_message, message);
        attempt.keys = Some(AttemptKeys::derive(shared.expose(), transcript)?);
        attempt.transcript = Some(transcript);
        attempt.phase = AttemptPhase::AwaitingClientConfirmation;
        Ok(())
    }

    /// Verifies the candidate's confirmation tag and returns the host's.
    ///
    /// This is the serial path. A tag that verifies and does not match consumes one of the five
    /// guesses, the count is persisted before the failure is returned, and the fifth failure
    /// consumes the invitation and cancels every competing candidate.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::AuthenticationFailed`] for a wrong tag,
    /// [`PairingError::AttemptsExhausted`] once the allowance is gone, and
    /// [`PairingError::Store`] when the count cannot be persisted.
    pub fn verify_client_confirmation(
        &mut self,
        attempt_id: AttemptId,
        tag: &Mac256,
    ) -> Result<Mac256> {
        self.require_open()?;
        if self.remaining_confirmations() == 0 {
            return Err(PairingError::AttemptsExhausted);
        }
        let attempt = self.attempt_mut(attempt_id)?;
        if attempt.phase != AttemptPhase::AwaitingClientConfirmation {
            return Err(PairingError::WrongPhase {
                expected: AttemptPhase::AwaitingClientConfirmation.as_str(),
                actual: attempt.phase.as_str(),
            });
        }
        let (Some(keys), Some(transcript)) = (attempt.keys.as_ref(), attempt.transcript) else {
            return Err(PairingError::WrongPhase {
                expected: AttemptPhase::AwaitingClientConfirmation.as_str(),
                actual: attempt.phase.as_str(),
            });
        };
        match keys.verify_client_confirmation(transcript, tag) {
            Ok(()) => {
                let host_tag = keys.host_confirmation(transcript);
                attempt.phase = AttemptPhase::Confirmed;
                Ok(host_tag)
            }
            Err(error) => {
                // The count is written before the failure is reported, so a host that dies here
                // comes back having spent the guess rather than offering it again.
                self.record.failed_confirmations =
                    self.record.failed_confirmations.saturating_add(1);
                self.attempts.remove(&attempt_id);
                if self.record.failed_confirmations >= MAX_CONFIRMATION_FAILURES {
                    self.consume(PairingConsumedReason::AttemptsExhausted)?;
                    return Err(PairingError::AttemptsExhausted);
                }
                self.store.save(&self.record)?;
                Err(error)
            }
        }
    }

    /// Seals the host's signed bundle for one candidate.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::WrongPhase`] before confirmation, and an encoding or library error.
    pub fn seal_host_bundle(
        &mut self,
        attempt_id: AttemptId,
        authorisation: &AuthorisationKeyPair,
        bundle: HostBundle,
    ) -> Result<BundleFrame> {
        self.require_open()?;
        let attempt = self.attempt_mut(attempt_id)?;
        if attempt.phase != AttemptPhase::Confirmed {
            return Err(PairingError::WrongPhase {
                expected: AttemptPhase::Confirmed.as_str(),
                actual: attempt.phase.as_str(),
            });
        }
        let (Some(keys), Some(transcript)) = (attempt.keys.as_ref(), attempt.transcript) else {
            return Err(PairingError::WrongPhase {
                expected: AttemptPhase::Confirmed.as_str(),
                actual: attempt.phase.as_str(),
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
    /// [`PairingError::TooLarge`] or [`PairingError::AuthenticationFailed`].
    pub fn open_client_bundle(
        &mut self,
        attempt_id: AttemptId,
        frame: &BundleFrame,
    ) -> Result<SignedClientBundle> {
        self.require_open()?;
        let attempt = self.attempt_mut(attempt_id)?;
        if attempt.phase != AttemptPhase::Confirmed {
            return Err(PairingError::WrongPhase {
                expected: AttemptPhase::Confirmed.as_str(),
                actual: attempt.phase.as_str(),
            });
        }
        let (Some(keys), Some(transcript)) = (attempt.keys.as_ref(), attempt.transcript) else {
            return Err(PairingError::WrongPhase {
                expected: AttemptPhase::Confirmed.as_str(),
                actual: attempt.phase.as_str(),
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
        if !signed.bundle.keys.purposes_are_distinct() {
            return Err(PairingError::ContextMismatch {
                what: "a candidate's key purposes, two of which share a key",
            });
        }
        attempt.client_bundle = Some(signed.clone());
        attempt.phase = AttemptPhase::AwaitingFinish;
        Ok(signed)
    }

    /// Accepts `pair.finish`, binding the transcript to the two live iroh endpoints.
    ///
    /// A successful finish locks the invitation to this candidate and cancels the others, which is
    /// what section 10 means by "a successful PAKE atomically locks the invitation to that
    /// candidate while owner approval is pending".
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::ContextMismatch`] when the request names another attempt or another
    /// transcript, [`PairingError::EndpointMismatch`] when the live peer is not the candidate the
    /// bundle authenticated, and [`PairingError::AuthenticationFailed`] when the tag fails.
    pub fn finish(
        &mut self,
        request: &PairFinishRequest,
        live_peer: &dyn LivePeer,
    ) -> Result<LockedCandidate> {
        self.require_open()?;
        let host_endpoint = self.host_endpoint;
        let live_client_endpoint = live_peer.live_endpoint()?;
        let attempt_id = request.attempt_id;
        let attempt = self.attempt_mut(attempt_id)?;
        if attempt.phase != AttemptPhase::AwaitingFinish {
            return Err(PairingError::WrongPhase {
                expected: AttemptPhase::AwaitingFinish.as_str(),
                actual: attempt.phase.as_str(),
            });
        }
        let (Some(keys), Some(transcript), Some(host_bundle_hash), Some(client_bundle)) = (
            attempt.keys.as_ref(),
            attempt.transcript,
            attempt.host_bundle_hash,
            attempt.client_bundle.clone(),
        ) else {
            return Err(PairingError::WrongPhase {
                expected: AttemptPhase::AwaitingFinish.as_str(),
                actual: attempt.phase.as_str(),
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
        let value = verification_value(transcript, host_bundle_hash, client_bundle_hash);
        let cancelled: Vec<AttemptId> = self
            .attempts
            .keys()
            .copied()
            .filter(|id| *id != attempt_id)
            .collect();
        self.attempts.retain(|id, _| *id == attempt_id);
        self.record.state = InvitationState::AwaitingApproval { attempt_id };
        self.store.save(&self.record)?;
        Ok(LockedCandidate {
            attempt_id,
            transcript,
            client_bundle,
            verification_value: value,
            cancelled,
        })
    }

    /// Commits the device record and grant after the issuing owner approves.
    ///
    /// The owner names the exact transcript and client bundle hash, so an approval cannot be
    /// applied to a candidate the owner was not shown. The grant committed is the one the
    /// invitation proposed: the candidate cannot enlarge it through its bundle.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::NotIssuingOwner`], [`PairingError::ContextMismatch`] and
    /// [`PairingError::WrongPhase`].
    pub fn confirm(
        &mut self,
        owner: &OwnerContext,
        transcript: Digest256,
        client_bundle_hash: Digest256,
        device_id: DeviceId,
        grant_id: GrantId,
    ) -> Result<CommittedPairing> {
        self.require_issuing_owner(owner)?;
        if let Some(committed) = self.committed.clone() {
            // A transport retry retrieves the committed result; it never commits again, so it
            // cannot replace the public keys or the grant.
            return Ok(committed);
        }
        self.require_open()?;
        let InvitationState::AwaitingApproval { attempt_id } = self.record.state else {
            return Err(PairingError::WrongPhase {
                expected: AttemptPhase::AwaitingApproval.as_str(),
                actual: "an invitation with no locked candidate",
            });
        };
        let attempt = self.attempt(attempt_id)?;
        let (Some(recorded), Some(client_bundle)) =
            (attempt.transcript, attempt.client_bundle.clone())
        else {
            return Err(PairingError::WrongPhase {
                expected: AttemptPhase::AwaitingApproval.as_str(),
                actual: attempt.phase.as_str(),
            });
        };
        if recorded != transcript
            || bundles::bundle_hash(&client_bundle.bundle)? != client_bundle_hash
        {
            return Err(PairingError::ContextMismatch {
                what: "the transcript the owner approved",
            });
        }
        let committed = CommittedPairing {
            attempt_id,
            transcript,
            device_id,
            grant_id,
            client_bundle: client_bundle.bundle,
            proposed_grant: self.proposed_grant.clone(),
        };
        // The device record, the grant and the consumed invitation are one transition: the record
        // is written as committed before the result is reported, so a retry retrieves it rather
        // than committing again.
        self.record.state = InvitationState::Committed;
        self.store.save(&self.record)?;
        self.attempts.clear();
        self.committed = Some(committed.clone());
        Ok(committed)
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
    /// A candidate sees only its own attempt, and no secret material. The issuing owner sees the
    /// verification value and the remaining allowance.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::NotIssuingOwner`] when the viewer is neither.
    pub fn status(&mut self, viewer: StatusViewer<'_>) -> Result<PairStatus> {
        let expired = self.is_expired();
        if expired {
            self.consume(PairingConsumedReason::Expired)?;
        }
        let permitted = match viewer {
            StatusViewer::IssuingOwner(owner) => owner == &self.issuing_owner,
            StatusViewer::Candidate(attempt_id) => {
                matches!(self.record.state, InvitationState::AwaitingApproval { attempt_id: locked } if locked == attempt_id)
                    || self.attempts.contains_key(&attempt_id)
            }
        };
        if !permitted {
            return Err(PairingError::NotIssuingOwner);
        }
        Ok(match self.record.state {
            InvitationState::Open => PairStatus::Open {
                remaining_confirmations: self.remaining_confirmations(),
                expires_at_ms: self.advertised_expires_at_ms,
            },
            InvitationState::AwaitingApproval { attempt_id } => {
                let attempt = self.attempt(attempt_id)?;
                let (Some(transcript), Some(host_bundle_hash), Some(client_bundle)) = (
                    attempt.transcript,
                    attempt.host_bundle_hash,
                    attempt.client_bundle.as_ref(),
                ) else {
                    return Err(PairingError::WrongPhase {
                        expected: AttemptPhase::AwaitingApproval.as_str(),
                        actual: attempt.phase.as_str(),
                    });
                };
                PairStatus::AwaitingApproval {
                    attempt_id,
                    verification_value: verification_value(
                        transcript,
                        host_bundle_hash,
                        bundles::bundle_hash(&client_bundle.bundle)?,
                    ),
                    expires_at_ms: self.advertised_expires_at_ms,
                }
            }
            InvitationState::Committed => {
                let committed = self.committed.as_ref().ok_or(PairingError::WrongPhase {
                    expected: "a committed pairing",
                    actual: "an invitation with no committed result",
                })?;
                PairStatus::Committed {
                    device_id: committed.device_id,
                    grant_id: committed.grant_id,
                }
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

    fn require_open(&mut self) -> Result<()> {
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
        Ok(())
    }

    fn consume(&mut self, reason: PairingConsumedReason) -> Result<()> {
        if !matches!(
            self.record.state,
            InvitationState::Consumed { .. } | InvitationState::Committed
        ) {
            self.record.state = InvitationState::Consumed { reason };
            self.store.save(&self.record)?;
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

/// Who is asking for an invitation's status.
#[derive(Clone, Copy, Debug)]
pub enum StatusViewer<'a> {
    /// The owner that issued it.
    IssuingOwner(&'a OwnerContext),
    /// One candidate, on its own authenticated endpoint.
    Candidate(AttemptId),
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
