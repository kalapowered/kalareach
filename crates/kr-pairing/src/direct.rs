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
use kr_protocol::ids::{AttemptId, DeviceId, GrantId, InvitationId};
use kr_protocol::pairing::{
    DIRECT_DOMAIN, DevicePublicKeys, DirectChallenge, DirectQrPayload, DirectRedeemProof,
    DirectTranscript, INVITATION_LIFETIME_MS, NetworkConfig, PairStatus, PairingConsumedReason,
    ProposedGrant, QrPayload, direct_verification_value,
};
use kr_protocol::scalars::{
    Digest256, EndpointKey, Mac256, Nonce256, SecretBytes32, TimestampMs, Uuid,
};

use crate::error::{PairingError, Result};
use crate::host::OwnerContext;
use crate::platform::{InvitationRecord, InvitationState, InvitationStore, LivePeer, PairingClock};

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
}

/// What a direct confirmation committed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectCommit {
    /// The attempt that was approved.
    pub attempt_id: AttemptId,
    /// The device record the host created.
    pub device_id: DeviceId,
    /// The grant the host issued.
    pub grant_id: GrantId,
    /// The candidate's complete purpose-key bundle.
    pub client_keys: DevicePublicKeys,
    /// The grant the invitation proposed, unchanged.
    pub proposed_grant: ProposedGrant,
}

/// The host's side of one direct invitation.
pub struct DirectInvitation<S: InvitationStore, C: PairingClock> {
    store: S,
    clock: C,
    record: InvitationRecord,
    secret: Secret<32>,
    host_endpoint: EndpointKey,
    host_keys: DevicePublicKeys,
    host_key_revision: kr_protocol::ids::DeviceKeyRevision,
    network_config: NetworkConfig,
    proposed_grant: ProposedGrant,
    issuing_owner: OwnerContext,
    expires_at_ms: TimestampMs,
    /// The outstanding challenge. A challenge is single use and expires with the invitation.
    challenge: Option<Nonce256>,
    candidate: Option<DirectCandidate>,
    committed: Option<DirectCommit>,
}

impl<S: InvitationStore, C: PairingClock> DirectInvitation<S, C> {
    /// Issues a direct invitation and persists its record.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Store`] or a crypto error.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        store: S,
        clock: C,
        host_endpoint: EndpointKey,
        host_keys: DevicePublicKeys,
        host_key_revision: kr_protocol::ids::DeviceKeyRevision,
        network_config: NetworkConfig,
        proposed_grant: ProposedGrant,
        issuing_owner: OwnerContext,
    ) -> Result<Self> {
        let mut identity = [0u8; 16];
        kr_crypto::random_bytes(&mut identity)?;
        let record = InvitationRecord {
            invitation_id: InvitationId::new(Uuid::from_bytes(identity)),
            // A direct invitation has no rendezvous record, so it has no locator to reserve. The
            // field is part of the shared record shape; the value is the one a QR carries instead.
            locator: kr_protocol::pairing::Locator::new("1111")
                .expect("a placeholder locator is alphabet characters"),
            state: InvitationState::Open,
            failed_confirmations: 0,
            deadline_monotonic_ms: clock.monotonic_ms().saturating_add(INVITATION_LIFETIME_MS),
            boot_identity: clock.boot_identity(),
        };
        store.save(&record)?;
        let expires_at_ms =
            TimestampMs::new(clock.wall_clock_ms().saturating_add(INVITATION_LIFETIME_MS));
        Ok(Self {
            store,
            clock,
            record,
            secret: Secret::random()?,
            host_endpoint,
            host_keys,
            host_key_revision,
            network_config,
            proposed_grant,
            issuing_owner,
            expires_at_ms,
            challenge: None,
            candidate: None,
            committed: None,
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
            endpoint_id: self.host_endpoint,
            network_config: self.network_config.clone(),
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

    /// Returns the record as it is persisted.
    #[must_use]
    pub const fn record(&self) -> &InvitationRecord {
        &self.record
    }

    /// Replaces the persisted record, for a caller that shares one record across both entry modes.
    ///
    /// An invitation may offer a short code and a direct QR. Both routes then read and write one
    /// candidate and consumption record, so a candidate already awaiting approval is not replaced
    /// by the other route.
    pub fn adopt_record(&mut self, record: InvitationRecord) {
        self.record = record;
    }

    /// Issues a fresh single-use challenge and returns it with the host's complete key bundle.
    ///
    /// A redemption starts here rather than at the QR: the challenge is the host's, so a proof
    /// cannot be prepared before the host has agreed to serve one.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Expired`], [`PairingError::Consumed`],
    /// [`PairingError::CandidateLocked`] or a crypto error.
    pub fn issue_challenge(&mut self) -> Result<DirectChallenge> {
        self.require_open()?;
        let mut nonce = [0u8; 32];
        kr_crypto::random_bytes(&mut nonce)?;
        let host_nonce = Nonce256::from_bytes(nonce);
        // Issuing a new challenge retires the previous one: a challenge is single use, and a stale
        // one is not held open beside its replacement.
        self.challenge = Some(host_nonce);
        Ok(DirectChallenge {
            invitation_id: self.record.invitation_id,
            host_nonce,
            host_keys: self.host_keys,
            device_key_revision: self.host_key_revision,
            endpoint_id: self.host_endpoint,
            expires_at_ms: self.expires_at_ms,
        })
    }

    /// Verifies a redemption and locks the candidate.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::ContextMismatch`] for a stale or unknown challenge,
    /// [`PairingError::EndpointMismatch`] when the submitted endpoint is not the live peer, and
    /// [`PairingError::AuthenticationFailed`] when either proof fails.
    pub fn redeem(
        &mut self,
        proof: &DirectRedeemProof,
        client_endpoint: &EndpointKey,
        live_peer: &dyn LivePeer,
    ) -> Result<DirectCandidate> {
        self.require_open()?;
        if proof.invitation_id != self.record.invitation_id {
            return Err(PairingError::ContextMismatch {
                what: "the invitation a redemption names",
            });
        }
        // The challenge is single use: it is taken here, so a second redemption with the same
        // nonce finds none outstanding.
        let Some(expected) = self.challenge.take() else {
            return Err(PairingError::ContextMismatch {
                what: "a redemption with no outstanding challenge",
            });
        };
        if proof.host_nonce != expected {
            return Err(PairingError::ContextMismatch {
                what: "the challenge a redemption answers",
            });
        }
        // The submitted endpoint must be the live authenticated peer, before anything is locked.
        if live_peer.live_endpoint()? != *client_endpoint {
            return Err(PairingError::EndpointMismatch { side: "client" });
        }
        if !proof.client_keys.purposes_are_distinct() {
            return Err(PairingError::ContextMismatch {
                what: "a candidate's key purposes, two of which share a key",
            });
        }

        let transcript = DirectTranscript {
            invitation_id: self.record.invitation_id,
            host_endpoint_id: self.host_endpoint,
            client_endpoint_id: *client_endpoint,
            host_keys: self.host_keys,
            client_keys: proof.client_keys,
            proposed_grant_digest: proposed_grant_digest(&self.proposed_grant)?,
            host_nonce: expected,
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
            transcript,
        };
        self.record.state = InvitationState::AwaitingApproval { attempt_id };
        self.store.save(&self.record)?;
        self.candidate = Some(candidate.clone());
        Ok(candidate)
    }

    /// Commits the device record, the grant and the consumed invitation after the owner approves.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::NotIssuingOwner`], [`PairingError::WrongPhase`] or
    /// [`PairingError::ContextMismatch`] when the owner names another transcript or another
    /// client-key digest.
    pub fn confirm(
        &mut self,
        owner: &OwnerContext,
        transcript_digest: Digest256,
        client_key_digest: Digest256,
        device_id: DeviceId,
        grant_id: GrantId,
    ) -> Result<DirectCommit> {
        if owner != &self.issuing_owner {
            return Err(PairingError::NotIssuingOwner);
        }
        if let Some(committed) = self.committed.clone() {
            // An idempotent retry retrieves the committed result; it cannot change the submitted
            // keys or the proposed rights.
            return Ok(committed);
        }
        self.require_open()?;
        let Some(candidate) = self.candidate.clone() else {
            return Err(PairingError::WrongPhase {
                expected: "owner approval",
                actual: "an invitation with no locked candidate",
            });
        };
        if candidate.transcript_digest != transcript_digest {
            return Err(PairingError::ContextMismatch {
                what: "the transcript the owner approved",
            });
        }
        if client_keys_digest(&candidate.transcript.client_keys)? != client_key_digest {
            return Err(PairingError::ContextMismatch {
                what: "the client key digest the owner approved",
            });
        }
        let commit = DirectCommit {
            attempt_id: candidate.attempt_id,
            device_id,
            grant_id,
            client_keys: candidate.transcript.client_keys,
            proposed_grant: self.proposed_grant.clone(),
        };
        self.record.state = InvitationState::Committed;
        self.store.save(&self.record)?;
        self.challenge = None;
        self.committed = Some(commit.clone());
        Ok(commit)
    }

    /// Consumes the invitation without a grant.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::NotIssuingOwner`] or [`PairingError::Store`].
    pub fn cancel(&mut self, owner: &OwnerContext) -> Result<()> {
        if owner != &self.issuing_owner {
            return Err(PairingError::NotIssuingOwner);
        }
        self.consume(PairingConsumedReason::Cancelled)
    }

    /// Reports the invitation's state.
    ///
    /// A candidate sees only its own attempt, the issuing owner sees everything, and neither sees
    /// secret material.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::NotIssuingOwner`] when the viewer is neither.
    pub fn status(&mut self, viewer: DirectStatusViewer<'_>) -> Result<PairStatus> {
        if self.is_expired() {
            self.consume(PairingConsumedReason::Expired)?;
        }
        let permitted = match viewer {
            DirectStatusViewer::IssuingOwner(owner) => owner == &self.issuing_owner,
            DirectStatusViewer::Candidate(attempt_id) => self
                .candidate
                .as_ref()
                .is_some_and(|candidate| candidate.attempt_id == attempt_id),
        };
        if !permitted {
            return Err(PairingError::NotIssuingOwner);
        }
        Ok(match self.record.state {
            InvitationState::Open => PairStatus::Open {
                remaining_confirmations: 0,
                expires_at_ms: self.expires_at_ms,
            },
            InvitationState::AwaitingApproval { attempt_id } => {
                let candidate = self.candidate.as_ref().ok_or(PairingError::WrongPhase {
                    expected: "owner approval",
                    actual: "an invitation with no locked candidate",
                })?;
                PairStatus::AwaitingApproval {
                    attempt_id,
                    verification_value: candidate.verification_value.clone(),
                    expires_at_ms: self.expires_at_ms,
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

    fn is_expired(&self) -> bool {
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
        // A candidate already awaiting approval is not replaced, by this route or the other. A
        // record that says a candidate holds it while this flow has none is the other route's
        // candidate.
        if matches!(self.record.state, InvitationState::AwaitingApproval { .. })
            && self.candidate.is_none()
        {
            return Err(PairingError::CandidateLocked);
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
        self.challenge = None;
        Ok(())
    }
}

/// Who is asking for a direct invitation's status.
#[derive(Clone, Copy, Debug)]
pub enum DirectStatusViewer<'a> {
    /// The owner that issued it.
    IssuingOwner(&'a OwnerContext),
    /// The candidate, on its own authenticated endpoint.
    Candidate(AttemptId),
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
