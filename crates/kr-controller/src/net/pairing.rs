//! The host's side of pairing, behind the transport's bounded pre-authorisation surface.
//!
//! An unpaired endpoint reaches three methods and nothing else. The transport is the door: it
//! bounds the frames, the request budget and the rate, and refuses every other method at that
//! ingress. This module is what stands behind the door, and it is a thin adapter rather than a
//! second implementation: `kr-pairing` owns the transcripts, the budgets, the phase rules and the
//! conditional writes, and what happens here is that a wire request becomes a call on its state
//! machine and the answer becomes a wire reply.
//!
//! Two things are deliberately *not* here.
//!
//! The owner ceremony is not. Issuing an invitation and approving a candidate each need a fresh
//! owner confirmation, and producing one is the platform's job: a user-presence context on a
//! device, not something a daemon can decide for itself. So the daemon issues the challenge,
//! holds the ledger that makes it single use, and takes the signed proof from whoever ran the
//! ceremony.
//!
//! Durable invitation state is not either, and section 10 is why: a candidate's attempt state
//! lives only in memory, and a host cancels every unfinished invitation when it starts, because
//! nothing can resume one. What has to survive a restart is the *device record*, and that is in
//! [`super::devices`], written durably before a pairing is reported as complete.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use kr_pairing::confirm::{ConfirmationLedger, HostEnrolment, request_confirmation};
use kr_pairing::direct::{
    ApprovedRedemption, DirectInvitation, DirectStatusViewer, client_keys_digest,
};
use kr_pairing::grants::{GrantIdentities, GrantKind};
use kr_pairing::host::{HostIdentity, OwnerApproval, OwnerContext};
use kr_pairing::platform::{
    InvitationRecord, InvitationStore, LivePeer, PairingClock, PairingCommitment, TransitionOutcome,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{DeviceId, GrantId, InvitationId};
use kr_protocol::pairing::{
    DevicePublicKeys, OwnerConfirmationRequest, PairStatus, ProposedGrant, QrPayload,
    SensitiveAction,
};
use kr_protocol::preauth::{
    PairRedeemParams, PairRedeemResult, PairStatusParams, PairStatusResult,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Digest256;
use kr_transport::preauth::{ConnectionPeer, PairingMethod, PairingSurface};

use super::devices::{DeviceDirectory, DeviceRecord};
use crate::error::{ControllerError, Result};

/// The clock every pairing deadline on this host is measured on.
///
/// Three readings, and each is used for what only it can answer. The monotonic reading is the
/// machine's own boot-scoped counter, so a deadline it decides cannot be moved by a clock
/// adjustment. The boot identity says which boot that counter belongs to, so a deadline recorded
/// before a restart reads as long past rather than as time still to run. The wall-clock reading is
/// what an expiry a *peer* has to read is expressed in.
#[derive(Clone, Debug)]
pub struct HostPairingClock {
    boot: kr_pairing::platform::BootIdentity,
}

impl HostPairingClock {
    /// Builds the clock of a host running in this boot.
    ///
    /// The pairing rules compare boot identities for equality and never interpret them, so the
    /// host's own opaque boot value is reduced to a fixed-width digest rather than truncated: two
    /// different boots must not collide, and the value's length is the platform's choice.
    #[must_use]
    pub fn new(boot_identity: &kr_protocol::identity::BootIdentity) -> Self {
        let digest = kr_cbor::sha256(boot_identity.value.as_slice());
        Self {
            boot: kr_pairing::platform::BootIdentity(digest),
        }
    }
}

impl PairingClock for HostPairingClock {
    fn monotonic_ms(&self) -> u64 {
        kr_ipc::clock::SharedClock::boot_elapsed_ms(&kr_ipc::clock::SystemSharedClock)
    }

    fn boot_identity(&self) -> kr_pairing::platform::BootIdentity {
        self.boot
    }

    fn wall_clock_ms(&self) -> u64 {
        kr_ipc::now_ms().get()
    }
}

/// The invitation state one run of this daemon holds.
///
/// Every write is conditional on the record the caller read, which is the contract `kr-pairing`
/// asks of a store: one invitation may be served by two entry modes at once, and an unconditional
/// write would let the slower of them undo the faster one's lock or consumption.
#[derive(Debug, Default)]
pub struct InvitationState {
    records: Mutex<BTreeMap<InvitationId, InvitationRecord>>,
    commitments: Mutex<BTreeMap<InvitationId, PairingCommitment>>,
}

/// A shared handle on that state, so one invitation can be driven from two places.
#[derive(Clone, Debug)]
pub struct SharedInvitations(Arc<InvitationState>);

impl SharedInvitations {
    /// Creates empty invitation state.
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(InvitationState::default()))
    }
}

impl Default for SharedInvitations {
    fn default() -> Self {
        Self::new()
    }
}

impl InvitationStore for SharedInvitations {
    fn create(&self, record: &InvitationRecord) -> kr_pairing::Result<()> {
        let mut records = self
            .0
            .records
            .lock()
            .unwrap_or_else(|held| held.into_inner());
        if records.contains_key(&record.invitation_id) {
            return Err(kr_pairing::PairingError::Store {
                reason: "that invitation already exists".to_owned(),
            });
        }
        records.insert(record.invitation_id, record.clone());
        Ok(())
    }

    fn load(&self, invitation_id: InvitationId) -> kr_pairing::Result<Option<InvitationRecord>> {
        Ok(self
            .0
            .records
            .lock()
            .unwrap_or_else(|held| held.into_inner())
            .get(&invitation_id)
            .cloned())
    }

    fn transition(
        &self,
        expected: &InvitationRecord,
        next: &InvitationRecord,
    ) -> kr_pairing::Result<TransitionOutcome> {
        let mut records = self
            .0
            .records
            .lock()
            .unwrap_or_else(|held| held.into_inner());
        match records.get(&expected.invitation_id) {
            Some(current) if current == expected => {
                records.insert(next.invitation_id, next.clone());
                Ok(TransitionOutcome::Written)
            }
            Some(current) => Ok(TransitionOutcome::Stale(current.clone())),
            None => Err(kr_pairing::PairingError::Store {
                reason: "that invitation has no record".to_owned(),
            }),
        }
    }

    fn commit(
        &self,
        expected: &InvitationRecord,
        next: &InvitationRecord,
        commitment: &PairingCommitment,
    ) -> kr_pairing::Result<TransitionOutcome> {
        // The record and the commitment move together, under one lock, so nothing can read a
        // committed invitation whose commitment is not there yet.
        let mut records = self
            .0
            .records
            .lock()
            .unwrap_or_else(|held| held.into_inner());
        match records.get(&expected.invitation_id) {
            Some(current) if current == expected => {
                self.0
                    .commitments
                    .lock()
                    .unwrap_or_else(|held| held.into_inner())
                    .insert(commitment.invitation_id, commitment.clone());
                records.insert(next.invitation_id, next.clone());
                Ok(TransitionOutcome::Written)
            }
            Some(current) => Ok(TransitionOutcome::Stale(current.clone())),
            None => Err(kr_pairing::PairingError::Store {
                reason: "that invitation has no record".to_owned(),
            }),
        }
    }

    fn commitment(
        &self,
        invitation_id: InvitationId,
    ) -> kr_pairing::Result<Option<PairingCommitment>> {
        Ok(self
            .0
            .commitments
            .lock()
            .unwrap_or_else(|held| held.into_inner())
            .get(&invitation_id)
            .cloned())
    }

    fn unfinished(&self) -> kr_pairing::Result<Vec<InvitationRecord>> {
        Ok(self
            .0
            .records
            .lock()
            .unwrap_or_else(|held| held.into_inner())
            .values()
            .filter(|record| {
                matches!(
                    record.state,
                    kr_pairing::platform::InvitationState::Open
                        | kr_pairing::platform::InvitationState::Locked { .. }
                )
            })
            .cloned()
            .collect())
    }
}

/// One direct invitation, and the owner that issued it.
type Invitation = DirectInvitation<SharedInvitations, HostPairingClock>;

/// The host's pairing state machine, and the surface an unpaired connection reaches it through.
pub struct PairingHost {
    identity: HostIdentity,
    clock: HostPairingClock,
    /// The enrolled owner signer every confirmation proof must carry.
    owner_signer: kr_protocol::scalars::AuthorisationKey,
    /// Whether this host has an owner yet, which decides whether the bootstrap exception applies.
    enrolment: HostEnrolment,
    devices: Arc<DeviceDirectory>,
    invitations: SharedInvitations,
    /// The challenges this host has issued, each consumable once.
    ledger: Mutex<ConfirmationLedger>,
    /// The invitation this host is currently offering. One at a time: an invitation is single use,
    /// and a host that offered several would have to decide which one a candidate meant.
    open: Mutex<Option<Invitation>>,
}

impl std::fmt::Debug for PairingHost {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairingHost")
            .field("device", &self.identity.device_id)
            .finish_non_exhaustive()
    }
}

impl PairingHost {
    /// Builds the pairing host of one daemon.
    #[must_use]
    pub fn new(
        identity: HostIdentity,
        clock: HostPairingClock,
        owner_signer: kr_protocol::scalars::AuthorisationKey,
        enrolment: HostEnrolment,
        devices: Arc<DeviceDirectory>,
    ) -> Self {
        Self {
            identity,
            clock,
            owner_signer,
            enrolment,
            devices,
            invitations: SharedInvitations::new(),
            ledger: Mutex::new(ConfirmationLedger::new()),
            open: Mutex::new(None),
        }
    }

    /// Returns what this host declares about itself in an invitation.
    #[must_use]
    pub const fn identity(&self) -> &HostIdentity {
        &self.identity
    }

    /// Issues the challenge an owner signs to authorise one sensitive pairing action.
    ///
    /// The challenge is recorded here, so the proof that answers it can be spent exactly once. A
    /// caller that never comes back leaves a challenge that expires on its own.
    ///
    /// # Errors
    ///
    /// Returns an error when the random generator is unavailable.
    pub fn request_confirmation(
        &self,
        action: SensitiveAction,
        action_digest: Digest256,
        destination_keys: Option<DevicePublicKeys>,
        destination_rights: std::collections::BTreeSet<ActionRight>,
    ) -> Result<OwnerConfirmationRequest> {
        let request = request_confirmation(
            &self.clock,
            action,
            action_digest,
            destination_keys,
            destination_rights,
            self.identity.device_id,
            self.identity.endpoint_id,
        )
        .map_err(pairing_failure)?;
        self.ledger().issue(&request, &self.clock);
        Ok(request)
    }

    /// Issues a direct invitation and returns the payload its QR encodes.
    ///
    /// # Errors
    ///
    /// Returns the pairing refusal: no valid owner confirmation, a proposal the grant kind does not
    /// allow, or an invitation already open.
    pub fn issue_direct(
        &self,
        proposed_grant: ProposedGrant,
        grant_kind: GrantKind,
        owner: &OwnerContext,
        approval: &OwnerApproval<'_>,
    ) -> Result<QrPayload> {
        let mut open = self.open();
        if open.is_some() {
            return Err(ControllerError::InvalidArgument(
                "this host is already offering an invitation; cancel it before issuing another"
                    .to_owned(),
            ));
        }
        let _ = owner;
        let invitation = DirectInvitation::issue(
            self.invitations.clone(),
            self.clock.clone(),
            self.identity.clone(),
            proposed_grant,
            grant_kind,
            approval,
            &mut self.ledger(),
        )
        .map_err(pairing_failure)?;
        let payload = invitation.qr_payload();
        *open = Some(invitation);
        Ok(payload)
    }

    /// Returns the candidate the open invitation is holding, for the owner to approve.
    ///
    /// # Errors
    ///
    /// Returns an error when no invitation is open, or when no candidate holds it yet.
    pub fn awaiting_approval(&self) -> Result<(ApprovedRedemption, DevicePublicKeys, String)> {
        let open = self.open();
        let invitation = open.as_ref().ok_or_else(no_invitation)?;
        let candidate = invitation.candidate().ok_or_else(|| {
            ControllerError::InvalidArgument("no candidate holds this invitation".to_owned())
        })?;
        let keys = candidate.transcript.client_keys;
        let approved = ApprovedRedemption {
            transcript_digest: candidate.transcript_digest,
            client_key_digest: client_keys_digest(&keys).map_err(pairing_failure)?,
        };
        Ok((approved, keys, candidate.verification_value.clone()))
    }

    /// Approves the candidate the owner was shown, and records the device it becomes.
    ///
    /// The commitment and the device record are written in that order and both before this
    /// returns, so a pairing is reported as complete only once the record a later connection is
    /// authorised against exists.
    ///
    /// # Errors
    ///
    /// Returns the pairing refusal, or a storage failure when the device record cannot be written.
    pub fn confirm(
        &self,
        approval: &OwnerApproval<'_>,
        approved: &ApprovedRedemption,
        identities: &GrantIdentities,
    ) -> Result<DeviceRecord> {
        let commitment = {
            let mut open = self.open();
            let invitation = open.as_mut().ok_or_else(no_invitation)?;
            invitation
                .confirm(approval, &mut self.ledger(), approved, identities, None)
                .map_err(pairing_failure)?
        };
        let bundle = commitment.client_bundle.as_ref().ok_or_else(|| {
            ControllerError::registry("a committed pairing carries the candidate's declaration")
        })?;
        let record = DeviceRecord {
            device_id: commitment.device_id,
            endpoint_id: commitment.client_keys.transport,
            device_key_revision: bundle.device_key_revision,
            authorisation: commitment.client_keys.authorisation,
            device_name: bundle.device_name.clone(),
            platform: bundle.platform,
            grant: commitment.grant.clone(),
            paired_at_ms: commitment.committed_at_ms,
            revoked_at_ms: None,
        };
        self.devices.commit(&record)?;
        Ok(record)
    }

    /// Consumes the open invitation without issuing a grant.
    ///
    /// # Errors
    ///
    /// Returns the pairing refusal, including one for an owner that did not issue it.
    pub fn cancel(&self, owner: &OwnerContext) -> Result<()> {
        let mut open = self.open();
        let invitation = open.as_mut().ok_or_else(no_invitation)?;
        invitation.cancel(owner).map_err(pairing_failure)?;
        *open = None;
        Ok(())
    }

    /// Returns what the open invitation is doing, for the owner that issued it.
    ///
    /// # Errors
    ///
    /// Returns the pairing refusal, including one for an owner that did not issue it.
    pub fn owner_status(&self, owner: &OwnerContext) -> Result<PairStatus> {
        let mut open = self.open();
        let invitation = open.as_mut().ok_or_else(no_invitation)?;
        invitation
            .status(DirectStatusViewer::IssuingOwner(owner))
            .map_err(pairing_failure)
    }

    fn open(&self) -> std::sync::MutexGuard<'_, Option<Invitation>> {
        self.open.lock().unwrap_or_else(|held| held.into_inner())
    }

    fn ledger(&self) -> std::sync::MutexGuard<'_, ConfirmationLedger> {
        self.ledger.lock().unwrap_or_else(|held| held.into_inner())
    }

    /// Returns the approval shape a caller presents, bound to this host's enrolled signer.
    #[must_use]
    pub fn approval<'a>(
        &'a self,
        owner: &'a OwnerContext,
        request: &'a OwnerConfirmationRequest,
        proof: &'a kr_protocol::pairing::OwnerConfirmationProof,
    ) -> OwnerApproval<'a> {
        OwnerApproval {
            owner,
            signer: &self.owner_signer,
            enrolment: self.enrolment,
            request,
            proof,
        }
    }

    fn redeem(
        &self,
        peer: &ConnectionPeer,
        params: &PairRedeemParams,
    ) -> std::result::Result<PairRedeemResult, ProtocolError> {
        let mut open = self.open.lock().unwrap_or_else(|held| held.into_inner());
        let invitation = open.as_mut().ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::PermissionDenied,
                "this host is not offering an invitation",
            )
        })?;
        match params {
            PairRedeemParams::Challenge { invitation_id } => {
                if *invitation_id != invitation.invitation_id() {
                    return Err(ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        "that invitation is not the one this host is offering",
                    ));
                }
                let challenge = invitation
                    .issue_challenge(peer as &dyn LivePeer)
                    .map_err(pairing_refusal)?;
                Ok(PairRedeemResult::Challenge(Box::new(challenge)))
            }
            PairRedeemParams::Direct(proof) => {
                let candidate = invitation
                    .redeem(proof, peer.endpoint_id(), peer as &dyn LivePeer)
                    .map_err(pairing_refusal)?;
                Ok(PairRedeemResult::Locked {
                    attempt_id: candidate.attempt_id,
                    verification_value: candidate.verification_value.clone(),
                })
            }
        }
    }

    fn candidate_status(
        &self,
        peer: &ConnectionPeer,
        params: &PairStatusParams,
    ) -> std::result::Result<PairStatusResult, ProtocolError> {
        let mut open = self.open.lock().unwrap_or_else(|held| held.into_inner());
        let invitation = open.as_mut().ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::PermissionDenied,
                "this host is not offering an invitation",
            )
        })?;
        if params.invitation_id != invitation.invitation_id() {
            return Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "that invitation is not the one this host is offering",
            ));
        }
        let status = invitation
            .status(DirectStatusViewer::Candidate {
                // The host generated the attempt identity, so a candidate whose redemption answer
                // was lost has none; the endpoint it authenticated with is what identifies it
                // either way.
                attempt_id: None,
                live_peer: peer as &dyn LivePeer,
            })
            .map_err(pairing_refusal)?;
        Ok(PairStatusResult { status })
    }
}

impl PairingSurface for PairingHost {
    fn call(
        &self,
        method: PairingMethod,
        peer: &ConnectionPeer,
        params: &kr_protocol::envelope::ParamsValue,
    ) -> std::result::Result<kr_protocol::envelope::ParamsValue, ProtocolError> {
        match method {
            PairingMethod::Redeem => {
                let params: PairRedeemParams = params.to_typed().map_err(malformed)?;
                let result = self.redeem(peer, &params)?;
                kr_protocol::envelope::ParamsValue::from_typed(&result).map_err(malformed)
            }
            PairingMethod::Status => {
                let params: PairStatusParams = params.to_typed().map_err(malformed)?;
                let result = self.candidate_status(peer, &params)?;
                kr_protocol::envelope::ParamsValue::from_typed(&result).map_err(malformed)
            }
            // The short-code route's finisher. This host offers direct invitations, whose
            // redemption is complete when the owner approves it, so there is nothing to finish.
            PairingMethod::Finish => Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "this host's invitations are completed by their redemption",
            )),
        }
    }
}

fn no_invitation() -> ControllerError {
    ControllerError::InvalidArgument("this host is not offering an invitation".to_owned())
}

fn pairing_failure(error: kr_pairing::PairingError) -> ControllerError {
    ControllerError::InvalidArgument(error.to_string())
}

/// Returns what a candidate is told, under the pairing error's own stable code.
///
/// The mapping is `kr-pairing`'s, in one place, so this surface cannot report a pairing outcome
/// under a code the rest of the build reports it differently under.
fn pairing_refusal(error: kr_pairing::PairingError) -> ProtocolError {
    ProtocolError::new(error.code(), error.to_string())
}

fn malformed(error: impl std::fmt::Display) -> ProtocolError {
    ProtocolError::new(ErrorCode::InvalidArgument, error.to_string())
}

/// Returns the device and grant identities a new pairing is committed under.
///
/// Both are minted by the host: a candidate cannot choose the identity its record will have, and
/// the grant is issued at the authority revision in force when it is written.
///
/// # Errors
///
/// Returns an error when the random generator is unavailable.
pub fn fresh_identities(
    issuer_device_id: DeviceId,
    authority_revision: kr_protocol::ids::AuthorityRevision,
) -> Result<GrantIdentities> {
    Ok(GrantIdentities {
        grant_id: GrantId::new(kr_ipc::new_uuid()),
        issuer_device_id,
        recipient_device_id: DeviceId::new(kr_ipc::new_uuid()),
        authority_revision,
    })
}
