//! The direct QR flow.
//!
//! An owner issues a five-minute, single-use invitation carrying the host endpoint key, the
//! selected discovery and relay configuration, a random 256-bit secret and the proposed grant. The
//! invitation grants nothing until the candidate proves possession of that secret over an iroh
//! connection authenticated against the pinned host endpoint.
//!
//! The transcript is `D`: the domain `kr-pair/direct/1`, the invitation identity, both endpoint
//! identities, both complete key bundles, the proposed-grant digest, both nonces and the
//! invitation's original expiry. The candidate supplies `HMAC-SHA256(invitation_secret, D)` and an
//! Ed25519 signature over `D`. Both are required: the tag proves possession of the secret and the
//! signature binds the candidate's key-purpose declarations to its authorisation key.
//!
//! The proof domain is not the short code's. An invitation that offers both entry modes uses
//! distinct domains and one atomic candidate record, so a proof from one route can never be
//! replayed into the other and neither route replaces a candidate already awaiting approval.

use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::secret::Secret;
use kr_crypto::sign::{self, SigningTranscript};
use kr_crypto::{constant_time_eq, kdf};
use kr_protocol::grant::Grant;
use kr_protocol::ids::{AttemptId, InvitationId};
use kr_protocol::pairing::{
    ClientBundle, DIRECT_DOMAIN, DevicePublicKeys, DirectChallenge, DirectQrPayload,
    DirectRedeemProof, DirectTranscript, INVITATION_LIFETIME_MS, PairStatus, PairingConsumedReason,
    ProposedGrant, QrPayload, direct_verification_value,
};
use kr_protocol::scalars::{
    Digest256, EndpointKey, Mac256, Nonce256, SecretBytes32, TimestampMs, Uuid,
};

use crate::bundles;
use crate::confirm::ConfirmationLedger;
use crate::error::{PairingError, Result};
use crate::grants::{self, GrantIdentities, GrantKind};
use crate::host::{HostIdentity, OwnerApproval, OwnerContext};
use crate::platform::{
    InvitationRecord, InvitationState, InvitationStore, LivePeer, PairingClock, PairingCommitment,
    TransitionOutcome, require_completed_handshake,
};

/// The candidate a direct redemption locked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectCandidate {
    /// The attempt that holds the invitation.
    pub attempt_id: AttemptId,
    /// The transcript `D`, which `pair.confirm` names exactly.
    pub transcript: DirectTranscript,
    /// The digest of `D`, which is what a caller stores and compares.
    pub transcript_digest: Digest256,
    /// The eight hexadecimal characters both devices display.
    pub verification_value: String,
    /// What the candidate declared about itself, in the shape a device record is written from.
    ///
    /// The two entry modes produce the same thing here, so a caller writes one device record from
    /// either route. The display members are display text; the authority is the key bundle.
    pub client_bundle: ClientBundle,
}

/// The domain a direct device confirmation's action digest is computed under.
///
/// The short-code route has its own, so a confirmation obtained for one entry mode cannot approve
/// a candidate that arrived by the other.
pub const CONFIRM_DEVICE_DOMAIN: &str = "kr-pair/confirm-device/direct/1";

/// Exactly what the owner is shown for a direct redemption, and names back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApprovedRedemption {
    /// The digest of the transcript `D`.
    pub transcript_digest: Digest256,
    /// The digest of the candidate's complete purpose-key bundle.
    pub client_key_digest: Digest256,
}

impl ApprovedRedemption {
    /// Returns the digest an owner's device-confirmation challenge must name.
    #[must_use]
    pub fn action_digest(&self) -> Digest256 {
        Digest256::from_bytes(kr_cbor::sha256(&kr_cbor::encode(
            &kr_cbor::CanonicalValue::Array(vec![
                kr_cbor::CanonicalValue::text(CONFIRM_DEVICE_DOMAIN),
                kr_cbor::CanonicalValue::bytes(self.transcript_digest.as_bytes().as_slice()),
                kr_cbor::CanonicalValue::bytes(self.client_key_digest.as_bytes().as_slice()),
            ]),
        )))
    }
}

/// The host's side of one direct invitation.
pub struct DirectInvitation<S: InvitationStore, C: PairingClock> {
    store: S,
    clock: C,
    record: InvitationRecord,
    secret: Secret<32>,
    host: HostIdentity,
    proposed_grant: ProposedGrant,
    grant_kind: GrantKind,
    issuing_owner: OwnerContext,
    expires_at_ms: TimestampMs,
    /// The outstanding challenge. A challenge is single use and expires with the invitation.
    challenge: Option<OutstandingChallenge>,
    candidate: Option<DirectCandidate>,
    /// Set when a durable write failed. The invitation serves nobody afterwards.
    fenced: bool,
}

/// One challenge the host has issued, and the connection it issued it to.
///
/// The connection is part of it because a challenge is an offer to one candidate: answering it
/// from somewhere else is another device using a challenge it was not given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OutstandingChallenge {
    host_nonce: Nonce256,
    client_endpoint: EndpointKey,
}

impl<S: InvitationStore, C: PairingClock> DirectInvitation<S, C> {
    /// Issues a direct invitation and persists its record.
    ///
    /// Issuing a persistent pairing invitation needs a fresh owner confirmation bound to the
    /// rights being proposed, the same as the short-code route: the QR carries the full secret, so
    /// producing one is handing out the invitation itself. The proposal is checked against the
    /// rules for its kind before anything is written.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::OwnerConfirmationRequired`] without a valid single-use
    /// confirmation, [`PairingError::GrantNotPermitted`] for a proposal its kind does not allow,
    /// [`PairingError::Store`] when the record cannot be persisted, and a crypto error when
    /// libsodium is unavailable.
    pub fn issue(
        store: S,
        clock: C,
        host: HostIdentity,
        proposed_grant: ProposedGrant,
        grant_kind: GrantKind,
        approval: &OwnerApproval<'_>,
        ledger: &mut ConfirmationLedger,
    ) -> Result<Self> {
        approval.accept_issue(ledger, &clock, &host, &proposed_grant)?;
        grants::validate_proposal(&proposed_grant, grant_kind, clock.wall_clock_ms())?;
        bundles::require_consistent_keys(
            &host.keys,
            &host.endpoint_id,
            "the endpoint a host declares, which is not its own transport key",
        )?;
        let mut identity = [0u8; 16];
        kr_crypto::random_bytes(&mut identity)?;
        let record = InvitationRecord {
            invitation_id: InvitationId::new(Uuid::from_bytes(identity)),
            // A direct invitation has no rendezvous record, so there is no locator to reserve.
            locator: None,
            state: InvitationState::Open,
            failed_confirmations: 0,
            deadline_monotonic_ms: clock.monotonic_ms().saturating_add(INVITATION_LIFETIME_MS),
            boot_identity: clock.boot_identity(),
        };
        store.create(&record, approval.proof)?;
        let expires_at_ms =
            TimestampMs::new(clock.wall_clock_ms().saturating_add(INVITATION_LIFETIME_MS));
        let issuing_owner = approval.owner.clone();
        Ok(Self {
            store,
            clock,
            record,
            secret: Secret::random()?,
            host,
            proposed_grant,
            grant_kind,
            issuing_owner,
            expires_at_ms,
            challenge: None,
            candidate: None,
            fenced: false,
        })
    }

    /// Returns the self-contained QR payload.
    ///
    /// It carries the full secret, which is what makes it work on a direct LAN path with no
    /// service. A code-mode QR is not an offline invitation and this is not a code-mode QR.
    #[must_use]
    pub fn qr_payload(&self) -> QrPayload {
        QrPayload::Direct(Box::new(DirectQrPayload {
            invitation_id: self.record.invitation_id,
            endpoint_id: self.host.endpoint_id,
            network_config: self.host.network_config.clone(),
            secret: SecretBytes32::from_bytes(*self.secret.expose()),
            proposed_grant: self.proposed_grant.clone(),
            expires_at_ms: self.expires_at_ms,
        }))
    }

    /// Returns the invitation identity.
    #[must_use]
    pub const fn invitation_id(&self) -> InvitationId {
        self.record.invitation_id
    }

    /// Returns the record as this host last read or wrote it.
    #[must_use]
    pub const fn record(&self) -> &InvitationRecord {
        &self.record
    }

    /// Returns the candidate that holds the invitation, when one does.
    #[must_use]
    pub fn candidate(&self) -> Option<&DirectCandidate> {
        self.candidate.as_ref()
    }

    /// Issues a fresh single-use challenge and returns it with the host's complete key bundle.
    ///
    /// A redemption starts here rather than at the QR: the challenge is the host's, so a proof
    /// cannot be prepared before the host has agreed to serve one. The challenge is bound to the
    /// connection it is issued on, so it is an offer to that candidate and to nobody else.
    ///
    /// An invitation with a candidate already holding it issues no challenge at all, by this route
    /// or the other: a single-use invitation has one candidate.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Expired`], [`PairingError::Consumed`],
    /// [`PairingError::CandidateLocked`], [`PairingError::EarlyData`] or a crypto error.
    pub fn issue_challenge(&mut self, live_peer: &dyn LivePeer) -> Result<DirectChallenge> {
        require_completed_handshake(live_peer)?;
        let client_endpoint = live_peer.live_endpoint()?;
        self.require_no_candidate()?;
        let mut nonce = [0u8; 32];
        kr_crypto::random_bytes(&mut nonce)?;
        let host_nonce = Nonce256::from_bytes(nonce);
        // Issuing a new challenge retires the previous one: a challenge is single use, and a stale
        // one is not held open beside its replacement.
        self.challenge = Some(OutstandingChallenge {
            host_nonce,
            client_endpoint,
        });
        Ok(DirectChallenge {
            invitation_id: self.record.invitation_id,
            host_nonce,
            host_keys: self.host.keys,
            device_key_revision: self.host.device_key_revision,
            endpoint_id: self.host.endpoint_id,
            expires_at_ms: self.expires_at_ms,
        })
    }

    /// Verifies a redemption and locks the candidate.
    ///
    /// Nothing about the challenge is spent until the redemption is one this challenge could
    /// answer: a stale nonce, another connection or a submitted endpoint that is not the live peer
    /// are all refused with the outstanding challenge left intact, so a bystander cannot cancel
    /// the candidate's redemption by sending rubbish.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::EarlyData`] for a redemption in 0-RTT,
    /// [`PairingError::ContextMismatch`] for a stale or unknown challenge,
    /// [`PairingError::EndpointMismatch`] when the submitted endpoint is not the live peer, and
    /// [`PairingError::AuthenticationFailed`] when either proof fails.
    pub fn redeem(
        &mut self,
        proof: &DirectRedeemProof,
        client_endpoint: &EndpointKey,
        live_peer: &dyn LivePeer,
    ) -> Result<DirectCandidate> {
        require_completed_handshake(live_peer)?;
        if proof.invitation_id != self.record.invitation_id {
            return Err(PairingError::ContextMismatch {
                what: "the invitation a redemption names",
            });
        }
        // A retry of the redemption that already succeeded retrieves its result. The attempt
        // identity is the host's, so a candidate whose response was lost has no other way to learn
        // it, and refusing would strand a device that did everything right.
        if let Some(existing) = self.retry(proof, client_endpoint, live_peer)? {
            return Ok(existing);
        }
        self.require_no_candidate()?;
        let Some(outstanding) = self.challenge else {
            return Err(PairingError::ContextMismatch {
                what: "a redemption with no outstanding challenge",
            });
        };
        if proof.host_nonce != outstanding.host_nonce {
            return Err(PairingError::ContextMismatch {
                what: "the challenge a redemption answers",
            });
        }
        // The submitted endpoint must be the live authenticated peer, and that peer must be the
        // one the challenge was issued to. Both are checked before anything is spent or locked.
        let live = live_peer.live_endpoint()?;
        if live != *client_endpoint || live != outstanding.client_endpoint {
            return Err(PairingError::EndpointMismatch { side: "client" });
        }
        // And the key bundle must declare that same endpoint as its transport key, so the device
        // record is written for the device that actually proved possession of the secret.
        bundles::require_consistent_keys(
            &proof.client_keys,
            client_endpoint,
            "the endpoint a redemption declares, which is not its own transport key",
        )?;

        // From here the redemption is one this challenge answers, so the challenge is spent
        // whatever the proofs say: a single-use challenge does not survive a wrong answer.
        self.challenge = None;

        let transcript = DirectTranscript {
            invitation_id: self.record.invitation_id,
            host_endpoint_id: self.host.endpoint_id,
            client_endpoint_id: *client_endpoint,
            host_keys: self.host.keys,
            client_keys: proof.client_keys,
            proposed_grant_digest: proposed_grant_digest(&self.proposed_grant)?,
            host_nonce: outstanding.host_nonce,
            client_nonce: proof.client_nonce,
            expires_at_ms: self.expires_at_ms,
        };
        let bytes = transcript.to_canonical_bytes();

        // Possession of the invitation secret.
        let secret_key = kr_crypto::secret::SymmetricKey::from_bytes(*self.secret.expose());
        kdf::verify_hmac_sha256(&secret_key, &bytes, &proof.secret_proof)
            .map_err(|_| PairingError::AuthenticationFailed)?;
        // The candidate's own signature over the same transcript, which binds its key purposes.
        sign::verify(
            &proof.client_keys.authorisation,
            &SigningTranscript::from_canonical_bytes(DIRECT_DOMAIN, bytes)?,
            &proof.signature,
        )
        .map_err(|_| PairingError::AuthenticationFailed)?;

        let mut attempt = [0u8; 16];
        kr_crypto::random_bytes(&mut attempt)?;
        let attempt_id = AttemptId::new(Uuid::from_bytes(attempt));
        let candidate = DirectCandidate {
            attempt_id,
            transcript_digest: Digest256::from_bytes(kr_cbor::sha256(
                &transcript.to_canonical_bytes(),
            )),
            verification_value: direct_verification_value(&transcript),
            client_bundle: ClientBundle {
                endpoint_id: *client_endpoint,
                keys: proof.client_keys,
                device_key_revision: proof.device_key_revision,
                device_name: proof.device_name.clone(),
                platform: proof.platform,
            },
            transcript,
        };
        // The lock is persisted before the candidate is told it holds the invitation.
        let mut record = self.record.clone();
        record.state = InvitationState::Locked { attempt_id };
        self.persist(record)?;
        self.candidate = Some(candidate.clone());
        Ok(candidate)
    }

    /// Commits the device record, the grant and the consumed invitation after the owner approves.
    ///
    /// Confirming a new device is a sensitive action, so this needs a fresh single-use owner
    /// confirmation naming this host, the candidate's key bundle, the proposed rights and the
    /// digest of the exact redemption the owner was shown. The grant is issued here, validated
    /// against the rules for its kind and narrowed against its parent. The writes are one store
    /// transaction and success is reported only after it returns.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::NotIssuingOwner`], [`PairingError::OwnerConfirmationRequired`],
    /// [`PairingError::GrantNotPermitted`], [`PairingError::WrongPhase`],
    /// [`PairingError::Store`] or [`PairingError::ContextMismatch`] when the owner names another
    /// transcript or another client-key digest.
    pub fn confirm(
        &mut self,
        approval: &OwnerApproval<'_>,
        ledger: &mut ConfirmationLedger,
        approved: &ApprovedRedemption,
        identities: &GrantIdentities,
        parent: Option<&Grant>,
    ) -> Result<PairingCommitment> {
        if approval.owner != &self.issuing_owner {
            return Err(PairingError::NotIssuingOwner);
        }
        if let Some(committed) = self.store.commitment(self.record.invitation_id)? {
            // An idempotent retry retrieves the committed result; it cannot change the submitted
            // keys or the proposed rights, and it works after a restart.
            return Ok(committed);
        }
        self.require_open()?;
        let Some(candidate) = self.candidate.clone() else {
            return Err(PairingError::WrongPhase {
                expected: "owner approval",
                actual: "an invitation with no locked candidate",
            });
        };
        if candidate.transcript_digest != approved.transcript_digest {
            return Err(PairingError::ContextMismatch {
                what: "the transcript the owner approved",
            });
        }
        if client_keys_digest(&candidate.transcript.client_keys)? != approved.client_key_digest {
            return Err(PairingError::ContextMismatch {
                what: "the client key digest the owner approved",
            });
        }
        if identities.issuer_device_id != self.host.device_id {
            return Err(PairingError::ContextMismatch {
                what: "the host device a grant is issued by",
            });
        }
        approval.accept_confirm_device(
            ledger,
            &self.clock,
            &self.host,
            &candidate.transcript.client_keys,
            &self.proposed_grant,
            approved.action_digest(),
        )?;
        let grant = grants::issue_grant(
            self.proposed_grant.clone(),
            self.grant_kind,
            self.clock.wall_clock_ms(),
            identities,
            parent,
        )?;

        let commitment = PairingCommitment {
            invitation_id: self.record.invitation_id,
            attempt_id: candidate.attempt_id,
            device_id: identities.recipient_device_id,
            grant,
            client_keys: candidate.transcript.client_keys,
            client_bundle: Some(candidate.client_bundle.clone()),
            proposed_grant: self.proposed_grant.clone(),
            verification_value: candidate.verification_value.clone(),
            owner_confirmation: approval.proof.clone(),
            committed_at_ms: TimestampMs::new(self.clock.wall_clock_ms()),
        };
        let mut next = self.record.clone();
        next.state = InvitationState::Committed;
        match self.store.commit(&self.record, &next, &commitment) {
            Ok(TransitionOutcome::Written) => {
                self.record = next;
                self.challenge = None;
                Ok(commitment)
            }
            Ok(TransitionOutcome::Stale(current)) => Err(self.adopt_stale(current)),
            Err(error) => {
                self.fenced = true;
                Err(error)
            }
        }
    }

    /// Consumes the invitation without a grant.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::NotIssuingOwner`] or [`PairingError::Store`].
    pub fn cancel(&mut self, owner: &OwnerContext) -> Result<()> {
        self.end(owner, PairingConsumedReason::Cancelled)
    }

    /// Consumes the invitation because the owner refused the candidate it was shown.
    ///
    /// The candidate is told its approval was denied, which is one of the outcomes section 10's
    /// user interface distinguishes, rather than that the invitation was withdrawn.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::NotIssuingOwner`] or [`PairingError::Store`].
    pub fn deny(&mut self, owner: &OwnerContext) -> Result<()> {
        self.end(owner, PairingConsumedReason::Denied)
    }

    fn end(&mut self, owner: &OwnerContext, reason: PairingConsumedReason) -> Result<()> {
        if owner != &self.issuing_owner {
            return Err(PairingError::NotIssuingOwner);
        }
        self.require_not_fenced()?;
        self.reload()?;
        self.consume(reason)
    }

    /// Reports the invitation's state.
    ///
    /// A candidate sees only its own attempt, and must ask from the endpoint its own redemption
    /// declared. The issuing owner sees everything. Neither sees secret material.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::NotIssuingOwner`] when the viewer is neither,
    /// [`PairingError::EarlyData`] for a candidate asking in 0-RTT, and [`PairingError::Store`]
    /// when a failed write has fenced the invitation.
    pub fn status(&mut self, viewer: DirectStatusViewer<'_>) -> Result<PairStatus> {
        if let DirectStatusViewer::Candidate { live_peer, .. } = viewer {
            require_completed_handshake(live_peer)?;
        }
        self.require_not_fenced()?;
        self.reload()?;
        if self.is_expired() {
            self.consume(PairingConsumedReason::Expired)?;
        }
        let committed = self.store.commitment(self.record.invitation_id)?;
        let permitted = match viewer {
            DirectStatusViewer::IssuingOwner(owner) => owner == &self.issuing_owner,
            DirectStatusViewer::Candidate {
                attempt_id,
                live_peer,
            } => {
                let endpoint = live_peer.live_endpoint()?;
                // The authenticated endpoint identifies the candidate; the attempt identity is
                // checked when the asker has one. A candidate whose redemption response was lost
                // never learnt it and is still the device that redeemed.
                let names =
                    |candidate: AttemptId| attempt_id.is_none_or(|asked| asked == candidate);
                committed.as_ref().map_or_else(
                    || {
                        // The candidate's identity outlives its lock, so a denied, cancelled or
                        // expired invitation still answers the device that redeemed it.
                        self.candidate.as_ref().is_some_and(|candidate| {
                            names(candidate.attempt_id)
                                && candidate.transcript.client_endpoint_id == endpoint
                        })
                    },
                    |committed| {
                        names(committed.attempt_id) && committed.client_keys.transport == endpoint
                    },
                )
            }
        };
        if !permitted {
            return Err(PairingError::NotIssuingOwner);
        }
        if let Some(committed) = committed {
            return Ok(PairStatus::Committed {
                device_id: committed.device_id,
                grant_id: committed.grant.grant_id,
            });
        }
        Ok(match self.record.state {
            InvitationState::Open => PairStatus::Open {
                // A direct invitation has no password to guess, so it has no guess allowance.
                remaining_confirmations: 0,
                expires_at_ms: self.expires_at_ms,
            },
            InvitationState::Locked { attempt_id } => match self.candidate.as_ref() {
                Some(candidate) if candidate.attempt_id == attempt_id => {
                    PairStatus::AwaitingApproval {
                        attempt_id,
                        verification_value: candidate.verification_value.clone(),
                        expires_at_ms: self.expires_at_ms,
                    }
                }
                // The other entry mode's candidate, or one from before a restart. There is no
                // verification value to show for it here, and it is not open either.
                _ => PairStatus::Locked {
                    attempt_id,
                    expires_at_ms: self.expires_at_ms,
                },
            },
            InvitationState::Committed => {
                return Err(PairingError::Store {
                    reason: "a committed invitation has no commitment record".to_owned(),
                });
            }
            InvitationState::Consumed { reason } => PairStatus::Consumed { reason },
        })
    }

    fn is_expired(&self) -> bool {
        self.clock.boot_identity() != self.record.boot_identity
            || self.clock.monotonic_ms() >= self.record.deadline_monotonic_ms
    }

    /// Refuses everything once a durable write has failed.
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

    /// Reloads the authoritative record and checks the invitation.
    fn require_open(&mut self) -> Result<()> {
        self.require_not_fenced()?;
        // One invitation may offer a short code and a direct QR. The store is the authority, so
        // both routes read one candidate and one consumption and neither replaces the other's.
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
        // A candidate already holds the invitation and is not replaced, by this route or the
        // other. A record that says one holds it while this flow has none is the other route's.
        if let Some(attempt_id) = self.record.state.locked_attempt()
            && self
                .candidate
                .as_ref()
                .map(|candidate| candidate.attempt_id)
                != Some(attempt_id)
        {
            return Err(PairingError::CandidateLocked);
        }
        Ok(())
    }

    /// Returns the locked candidate when this redemption is the one that produced it.
    ///
    /// Everything the transcript covers has to match, the connection has to be the same
    /// authenticated endpoint, and both proofs are verified again over the recorded transcript.
    /// Nothing is written and no challenge is spent: this returns a result that already exists.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Consumed`], [`PairingError::AlreadyCommitted`],
    /// [`PairingError::Expired`] or [`PairingError::Store`].
    fn retry(
        &mut self,
        proof: &DirectRedeemProof,
        client_endpoint: &EndpointKey,
        live_peer: &dyn LivePeer,
    ) -> Result<Option<DirectCandidate>> {
        let Some(existing) = self.candidate.clone() else {
            return Ok(None);
        };
        let transcript = &existing.transcript;
        if transcript.client_endpoint_id != *client_endpoint
            || transcript.host_nonce != proof.host_nonce
            || transcript.client_nonce != proof.client_nonce
            || transcript.client_keys != proof.client_keys
            || live_peer.live_endpoint()? != *client_endpoint
        {
            return Ok(None);
        }
        // A cancelled or expired invitation hands nothing back. A committed one does: the device
        // is paired, and the attempt identity it is retrying for is how it asks about that.
        self.require_not_fenced()?;
        self.reload()?;
        if let InvitationState::Consumed { reason } = self.record.state {
            return Err(PairingError::Consumed { reason });
        }
        if self.record.state != InvitationState::Committed && self.is_expired() {
            self.consume(PairingConsumedReason::Expired)?;
            return Err(PairingError::Expired);
        }
        let bytes = transcript.to_canonical_bytes();
        let secret_key = kr_crypto::secret::SymmetricKey::from_bytes(*self.secret.expose());
        kdf::verify_hmac_sha256(&secret_key, &bytes, &proof.secret_proof)
            .map_err(|_| PairingError::AuthenticationFailed)?;
        sign::verify(
            &proof.client_keys.authorisation,
            &SigningTranscript::from_canonical_bytes(DIRECT_DOMAIN, bytes)?,
            &proof.signature,
        )
        .map_err(|_| PairingError::AuthenticationFailed)?;
        Ok(Some(existing))
    }

    /// Checks the invitation and refuses once any candidate holds it, this flow's own included.
    ///
    /// A direct invitation is single use. Once a candidate has redeemed it, another challenge or
    /// another redemption would replace a candidate the owner may already be looking at.
    fn require_no_candidate(&mut self) -> Result<()> {
        self.require_open()?;
        if self.record.state.locked_attempt().is_some() {
            return Err(PairingError::CandidateLocked);
        }
        Ok(())
    }

    /// Writes a record if the stored one is still the one this decision was made from.
    fn persist(&mut self, next: InvitationRecord) -> Result<()> {
        match self.store.transition(&self.record, &next) {
            Ok(TransitionOutcome::Written) => {
                self.record = next;
                Ok(())
            }
            Ok(TransitionOutcome::Stale(current)) => Err(self.adopt_stale(current)),
            Err(error) => {
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
        self.challenge = None;
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
        self.challenge = None;
        Ok(())
    }
}

/// Who is asking for a direct invitation's status.
#[derive(Clone, Copy)]
pub enum DirectStatusViewer<'a> {
    /// The owner that issued it.
    IssuingOwner(&'a OwnerContext),
    /// The candidate, which must ask from the endpoint its redemption declared.
    Candidate {
        /// Its attempt. The host generates it at redemption, so a candidate whose response was
        /// lost has none, and the endpoint it authenticated with is what identifies it either way.
        attempt_id: Option<AttemptId>,
        /// The live connection it is asking over.
        live_peer: &'a dyn LivePeer,
    },
}

impl core::fmt::Debug for DirectStatusViewer<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::IssuingOwner(owner) => write!(formatter, "IssuingOwner({owner:?})"),
            Self::Candidate { attempt_id, .. } => write!(formatter, "Candidate({attempt_id:?})"),
        }
    }
}

/// Returns the digest of a proposed grant, which `D` names rather than embedding.
///
/// # Errors
///
/// Returns an encoding error when the proposal is outside KR-CBOR-1.
pub fn proposed_grant_digest(proposal: &ProposedGrant) -> Result<Digest256> {
    Ok(Digest256::from_bytes(kr_cbor::sha256(
        &kr_cbor::to_canonical_vec(proposal)?,
    )))
}

/// Returns the digest of a complete purpose-key bundle, which `pair.confirm` names.
///
/// # Errors
///
/// Returns an encoding error when the bundle is outside KR-CBOR-1.
pub fn client_keys_digest(keys: &DevicePublicKeys) -> Result<Digest256> {
    Ok(Digest256::from_bytes(kr_cbor::sha256(
        &kr_cbor::to_canonical_vec(keys)?,
    )))
}

/// Builds the candidate's side of a redemption from a scanned QR payload and a host challenge.
///
/// # Errors
///
/// Returns [`PairingError::ContextMismatch`] when the challenge does not answer this invitation or
/// comes from another endpoint, and an encoding or library error otherwise.
pub fn redeem_proof(
    payload: &DirectQrPayload,
    challenge: &DirectChallenge,
    authorisation: &AuthorisationKeyPair,
    candidate: &CandidateIdentity,
    live_peer: &dyn LivePeer,
) -> Result<(DirectRedeemProof, DirectTranscript)> {
    let CandidateIdentity {
        keys: client_keys,
        device_key_revision,
        device_name,
        platform,
        endpoint_id: client_endpoint,
    } = candidate;
    let (client_keys, device_key_revision, platform) =
        (*client_keys, *device_key_revision, *platform);
    let device_name = device_name.clone();
    if challenge.invitation_id != payload.invitation_id {
        return Err(PairingError::ContextMismatch {
            what: "the invitation a challenge answers",
        });
    }
    // The QR pinned the endpoint; a challenge from any other endpoint is another host.
    if challenge.endpoint_id != payload.endpoint_id {
        return Err(PairingError::ContextMismatch {
            what: "the host endpoint a challenge comes from",
        });
    }
    // And the connection this arrived on must be to that endpoint. Without this the candidate
    // would send its proof, which carries the invitation secret's tag, to whichever peer it
    // happened to reach: a relay or a discovery answer that pointed elsewhere would be enough.
    require_completed_handshake(live_peer)?;
    if live_peer.live_endpoint()? != payload.endpoint_id {
        return Err(PairingError::EndpointMismatch { side: "host" });
    }
    // The host's key bundle must declare that endpoint as its own transport key.
    bundles::require_consistent_keys(
        &challenge.host_keys,
        &challenge.endpoint_id,
        "the endpoint a host challenge declares, which is not its own transport key",
    )?;
    bundles::require_consistent_keys(
        &candidate.keys,
        &candidate.endpoint_id,
        "the endpoint a candidate declares, which is not its own transport key",
    )?;
    if challenge.expires_at_ms != payload.expires_at_ms {
        return Err(PairingError::ContextMismatch {
            what: "the expiry a challenge names",
        });
    }
    let mut nonce = [0u8; 32];
    kr_crypto::random_bytes(&mut nonce)?;
    let transcript = DirectTranscript {
        invitation_id: payload.invitation_id,
        host_endpoint_id: payload.endpoint_id,
        client_endpoint_id: *client_endpoint,
        host_keys: challenge.host_keys,
        client_keys,
        proposed_grant_digest: proposed_grant_digest(&payload.proposed_grant)?,
        host_nonce: challenge.host_nonce,
        client_nonce: Nonce256::from_bytes(nonce),
        expires_at_ms: payload.expires_at_ms,
    };
    let bytes = transcript.to_canonical_bytes();
    let secret = kr_crypto::secret::SymmetricKey::from_bytes(*payload.secret.expose());
    let proof = DirectRedeemProof {
        invitation_id: payload.invitation_id,
        client_keys,
        device_key_revision,
        device_name,
        platform,
        host_nonce: challenge.host_nonce,
        client_nonce: transcript.client_nonce,
        secret_proof: kdf::hmac_sha256(&secret, &bytes),
        signature: sign::sign(
            authorisation,
            &SigningTranscript::from_canonical_bytes(DIRECT_DOMAIN, bytes)?,
        )?,
    };
    Ok((proof, transcript))
}

/// Everything a candidate declares about itself when it redeems.
///
/// The five members travelled as five arguments until they outgrew one signature. They belong
/// together anyway: they are what the device record is written from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateIdentity {
    /// The candidate's complete purpose-key bundle.
    pub keys: DevicePublicKeys,
    /// The revision of those keys.
    pub device_key_revision: kr_protocol::ids::DeviceKeyRevision,
    /// The candidate's display name. Display text, never authority.
    pub device_name: kr_protocol::pairing::DeviceName,
    /// The candidate's platform.
    pub platform: kr_protocol::pairing::DevicePlatform,
    /// The candidate's iroh endpoint identity.
    pub endpoint_id: EndpointKey,
}

/// Returns true when two verification values are the same, comparing in constant time.
///
/// The value is not a secret, but comparing it in variable time would leak how much of it matched
/// to anything watching, and a constant-time comparison costs nothing here.
#[must_use]
pub fn verification_values_match(ours: &str, theirs: &str) -> bool {
    constant_time_eq(ours.as_bytes(), theirs.as_bytes())
}

/// Returns the tag a candidate computes over `D` with the invitation secret.
///
/// It is exposed for the cross-language vectors; the flow above computes it itself.
#[must_use]
pub fn secret_proof(secret: &SecretBytes32, transcript: &DirectTranscript) -> Mac256 {
    let key = kr_crypto::secret::SymmetricKey::from_bytes(*secret.expose());
    kdf::hmac_sha256(&key, &transcript.to_canonical_bytes())
}
