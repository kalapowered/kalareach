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

use std::sync::{Arc, Mutex};

use kr_pairing::confirm::{ConfirmationLedger, HostEnrolment, request_confirmation};
use kr_pairing::direct::{
    ApprovedRedemption, DirectInvitation, DirectStatusViewer, client_keys_digest,
};
use kr_pairing::grants::{GrantIdentities, GrantKind};
use kr_pairing::host::{HostIdentity, OwnerApproval, OwnerContext};
use kr_pairing::platform::{LivePeer, PairingClock};
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
use super::invitations::{InvitationRows, IssueTerms};
use crate::error::{ControllerError, Result};
use kr_protocol::invitation::{InviteGrantKind, InviteModeKind};

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

/// One direct invitation, and the owner that issued it.
type Invitation = DirectInvitation<InvitationRows, HostPairingClock>;

/// What an owner confirms when it establishes this host's clock again.
///
/// The digest of this, and of nothing else, is what the confirmation is bound to.
pub const CLOCK_PURPOSE: &str = "kr-host-clock/1";

/// The host's pairing state machine, and the surface an unpaired connection reaches it through.
pub struct PairingHost {
    identity: HostIdentity,
    clock: HostPairingClock,
    /// The enrolled owner signer every confirmation proof must carry.
    owner_signer: kr_protocol::scalars::AuthorisationKey,
    /// Whether this host has an owner yet, which decides whether the bootstrap exception applies.
    enrolment: HostEnrolment,
    devices: Arc<DeviceDirectory>,
    invitations: InvitationRows,
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
            invitations: InvitationRows::new(Arc::clone(&devices)),
            devices,
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
        network_config: kr_protocol::pairing::NetworkConfig,
        approval: &OwnerApproval<'_>,
    ) -> Result<QrPayload> {
        let mut open = self.open();
        if open.is_some() {
            return Err(ControllerError::InvalidArgument(
                "this host is already offering an invitation; cancel it before issuing another"
                    .to_owned(),
            ));
        }
        // The configuration the invitation carries is the one this endpoint is actually using,
        // taken now: a QR that named no relay and no address would be a QR a candidate on another
        // network could not dial. The host's declared identity is otherwise unchanged, because a
        // caller must not be able to make the host sign a bundle naming anything else.
        let mut identity = self.identity.clone();
        identity.network_config = network_config;
        let terms = IssueTerms {
            mode: InviteModeKind::Direct,
            rendezvous_origin: None,
            grant_kind: match grant_kind {
                GrantKind::PersonalOwner => InviteGrantKind::PersonalOwner,
                GrantKind::SessionInvitation => InviteGrantKind::SessionInvitation,
            },
            proposed_grant: proposed_grant.clone(),
            issuing_actor: approval.owner.actor_id.clone(),
            issuing_ingress: approval.owner.ingress,
            action: None,
            issued_at_ms: kr_ipc::now_ms(),
        };
        let invitation = DirectInvitation::issue(
            self.invitations.issuing(terms),
            self.clock.clone(),
            identity,
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
        // The record was written inside the store's own commit, so this reads back what is
        // durable rather than writing a second copy. An idempotent retry of the confirmation finds
        // the committed result and the same record behind it.
        self.devices
            .record_for_device(commitment.device_id)?
            .ok_or_else(|| {
                ControllerError::registry("this pairing committed without leaving a device record")
            })
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

    /// Accepts an owner's confirmation that this host may read its own clock again.
    ///
    /// Section 9 wants qualified time evidence or an authenticated action about the clock itself
    /// before a host that found its clock going backwards decides another expiry from it. This is
    /// the second of those, and it is bound to the clock: the digest covers this purpose and
    /// nothing else, so an approval the owner gave for a pairing cannot be spent on it, and a
    /// confirmation is consumed once like every other.
    ///
    /// # Errors
    ///
    /// Returns an error when the approval is not this host's owner's, when it confirms something
    /// else, or when the challenge has already been spent.
    pub fn accept_clock(&self, approval: &OwnerApproval<'_>) -> Result<()> {
        let digest = kr_pairing::confirm::action_digest(&CLOCK_PURPOSE)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        kr_pairing::confirm::accept_confirmation(
            &mut self.ledger(),
            &self.clock,
            approval.request,
            approval.proof,
            // This host's own enrolled signer, not the one the approval carries: an approval is a
            // request to be checked, and checking it against a key it supplied itself would
            // accept any key at all.
            &self.owner_signer,
            self.enrolment,
            &kr_pairing::confirm::ConfirmationExpectation {
                action: SensitiveAction::ChangeHostAuthority,
                action_digest: digest,
                host_device_id: self.identity.device_id,
                host_endpoint_id: self.identity.endpoint_id,
                // It sends authority nowhere and grants nothing. What it changes is what this host
                // will decide about the authority it has already issued.
                destination_keys: None,
                destination_rights: &kr_protocol::scalars::CanonicalSet::new(),
            },
        )
        .map_err(|error| ControllerError::PermissionDenied {
            detail: error.to_string(),
        })
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

    /// Answers a candidate about a pairing this host has already committed.
    ///
    /// It reads the durable device record rather than an invitation, which is what makes the
    /// answer survive a restart: a candidate whose redemption succeeded and whose answer was lost
    /// can still learn which device it became.
    fn committed_status(
        &self,
        peer: &ConnectionPeer,
        invitation_id: InvitationId,
    ) -> std::result::Result<PairStatusResult, ProtocolError> {
        let unknown = || {
            ProtocolError::new(
                ErrorCode::PermissionDenied,
                "this host is not offering that invitation",
            )
        };
        let record = self
            .devices
            .record_for_endpoint(peer.endpoint_id())
            .map_err(|error| ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string()))?
            // A record that does not say which invitation it came from is not an answer about
            // this one. It stays paired; it simply has no committed result to be told about.
            .filter(|record| record.committed_invitation_id == Some(invitation_id))
            .ok_or_else(unknown)?;
        Ok(PairStatusResult {
            status: PairStatus::Committed {
                device_id: record.device_id,
                grant_id: record.grant.grant_id,
            },
            owner: kr_protocol::scalars::Nullable::null(),
        })
    }

    fn candidate_status(
        &self,
        peer: &ConnectionPeer,
        params: &PairStatusParams,
    ) -> std::result::Result<PairStatusResult, ProtocolError> {
        let mut open = self.open.lock().unwrap_or_else(|held| held.into_inner());
        let matching = open
            .as_ref()
            .is_some_and(|invitation| invitation.invitation_id() == params.invitation_id);
        if !matching {
            // No invitation object for this candidate to ask about, which is the ordinary state
            // after a restart: section 10 cancels every unfinished invitation when a host starts,
            // and a committed one leaves a device record behind. The record is keyed by the
            // endpoint identity this connection was authenticated as, so this answers the caller
            // about itself and about nothing else.
            return self.committed_status(peer, params.invitation_id);
        }
        let invitation = open
            .as_mut()
            .expect("the invitation is the one asked about");
        let status = invitation
            .status(DirectStatusViewer::Candidate {
                // The host generated the attempt identity, so a candidate whose redemption answer
                // was lost has none; the endpoint it authenticated with is what identifies it
                // either way.
                attempt_id: None,
                live_peer: peer as &dyn LivePeer,
            })
            .map_err(pairing_refusal)?;
        Ok(PairStatusResult {
            status,
            owner: kr_protocol::scalars::Nullable::null(),
        })
    }
}

/// The host accepts the owner's confirmation of a sensitive action against its own ledger.
///
/// The challenge has to be one this host issued and still holds, so a caller cannot present a
/// challenge of its own making with a matching signature. Consuming it here is what makes one
/// ceremony authorise exactly one action.
impl crate::sharing::OwnerConfirmations for PairingHost {
    fn accept(
        &self,
        action: SensitiveAction,
        action_digest: Digest256,
        proof: &kr_protocol::pairing::OwnerConfirmationProof,
    ) -> Result<crate::sharing::ConfirmedAction> {
        crate::sharing::ConfirmedAction::verify(
            &kr_pairing::confirm::ConfirmationExpectation {
                action,
                action_digest,
                host_device_id: self.identity.device_id,
                host_endpoint_id: self.identity.endpoint_id,
                // A catalogue action sends authority to no device and grants no session right.
                // What it changes is what this host will trust or run.
                destination_keys: None,
                destination_rights: &kr_protocol::scalars::CanonicalSet::new(),
            },
            &mut self.ledger(),
            &self.clock,
            // The host's own retained challenge is what the ledger compares this against, so a
            // challenge the caller made up is refused before the signature is ever believed.
            &proof.request,
            proof,
            &self.owner_signer,
            self.enrolment,
        )
    }

    fn host_device_id(&self) -> DeviceId {
        self.identity.device_id
    }

    fn clock(&self) -> &dyn kr_pairing::platform::PairingClock {
        &self.clock
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
