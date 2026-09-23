//! The host's side of pairing: section 23's six pairing methods, served.
//!
//! The issuing owner reaches `pair.invite`, `pair.confirm`, `pair.cancel` and its own form of
//! `pair.status` over local IPC. An unpaired candidate reaches `pair.redeem`, `pair.finish` and its
//! own form of `pair.status` through the transport's bounded pre-authorisation surface, and nothing
//! else. This module is a thin adapter: `kr-pairing` owns the transcripts, the budgets, the phase
//! rules and the conditional writes, [`super::invitations`] owns the durable records, and
//! [`super::owner`] owns the owner confirmations every sensitive step spends.
//!
//! **One invitation at a time, one serial path.** The host offers one invitation, held behind one
//! lock, and every transition of it (a candidate's step, the owner's confirmation or cancellation,
//! a status read that expires it) runs synchronously under that lock and never across an await.
//! That lock is the serial path section 10 counts failed confirmations in: two candidates cannot
//! both read the last remaining guess.
//!
//! **The issuing owner is exact.** An invitation remembers the owner context that issued it, and
//! only that context confirms, cancels or reads it. `pair.invite` is local-only, so a paired device
//! never is that context; an owner device approves by completing the owner confirmation the issuer
//! then spends.

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard};

use kr_pairing::direct::{
    ApprovedRedemption, DirectInvitation, DirectStatusViewer, client_keys_digest,
};
use kr_pairing::grants::{GrantIdentities, GrantKind, validate_proposal};
use kr_pairing::host::{HostIdentity, recover_candidate_status};
use kr_pairing::platform::{InvitationState, LivePeer, PairingClock};
use kr_protocol::confirmation::{
    ConfirmationDisplay, ConfirmationSubject, OwnerConfirmationCompleteParams,
    OwnerConfirmationCompleteResult, OwnerConfirmationPendingResult,
    OwnerConfirmationRequestParams, OwnerConfirmationRequestResult,
};
use kr_protocol::envelope::{MutationRequest, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, ActorId, AuthorityRevision, DeviceId, GrantId, InvitationId};
use kr_protocol::invitation::{
    InviteEntry, InviteGrantKind, InviteMode, InviteModeKind, PairCancelParams, PairCandidateView,
    PairConfirmParams, PairConfirmResult, PairInviteParams, PairInviteResult, PairOwnerView,
    PairingApproval, QrText, default_rendezvous_origin, issuance_digest,
};
use kr_protocol::method::Method;
use kr_protocol::pairing::{
    DevicePublicKeys, MAX_CONFIRMATION_FAILURES, NetworkConfig, PairStatus, PairingConsumedReason,
    ProposedGrant, QrPayload, RendezvousOrigin, SensitiveAction,
};
use kr_protocol::preauth::{
    PairRedeemParams, PairRedeemResult, PairStatusParams, PairStatusResult,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Digest256, Nullable};
use kr_transport::preauth::{ConnectionPeer, PairingMethod, PairingSurface};

use super::invitations::{Admission, InvitationRow, InvitationRows, IssueTerms, WriteAdmission};
use super::owner::{Caller, OwnerAuthority, Resolved, refusal};
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

/// What an owner confirms when it establishes this host's clock again.
///
/// The digest of this, and of nothing else, is what the confirmation is bound to.
pub const CLOCK_PURPOSE: &str = "kr-host-clock/1";

/// The invitation this host is offering, and what it was issued as.
struct Open {
    mode: OpenMode,
    /// The admission slot of this invitation's writes, set while an owner mutation drives it.
    admission: WriteAdmission,
    /// The answer `pair.invite` gave, returned again to a retry of the same action.
    answer: PairInviteResult,
    issued_by: ActorId,
    action: (ActionId, Digest256),
    grant_kind: InviteGrantKind,
    proposed_grant: ProposedGrant,
}

enum OpenMode {
    Direct(Box<DirectInvitation<InvitationRows, HostPairingClock>>),
}

/// A candidate bound to its endpoint and waiting for the owner.
struct Bound {
    approval: PairingApproval,
    digest: Digest256,
    keys: DevicePublicKeys,
    view: PairCandidateView,
}

impl Open {
    const fn invitation_id(&self) -> InvitationId {
        self.answer.invitation_id
    }

    fn state(&self) -> InvitationState {
        match &self.mode {
            OpenMode::Direct(invitation) => invitation.record().state,
        }
    }

    /// Returns the candidate the owner is asked about, once it has bound its transcript.
    fn bound(&self) -> Result<Option<Bound>> {
        match &self.mode {
            OpenMode::Direct(invitation) => {
                let Some(candidate) = invitation.candidate() else {
                    return Ok(None);
                };
                let keys = candidate.client_bundle.keys;
                let approved = ApprovedRedemption {
                    transcript_digest: candidate.transcript_digest,
                    client_key_digest: client_keys_digest(&keys).map_err(refusal)?,
                };
                Ok(Some(Bound {
                    approval: PairingApproval::Direct {
                        transcript_digest: approved.transcript_digest,
                        client_key_digest: approved.client_key_digest,
                    },
                    digest: approved.action_digest(),
                    keys,
                    view: PairCandidateView {
                        device_name: candidate.client_bundle.device_name.clone(),
                        platform: candidate.client_bundle.platform,
                        keys,
                        verification_value: candidate.verification_value.clone(),
                    },
                }))
            }
        }
    }
}

/// The host's pairing service.
pub struct PairingHost {
    identity: HostIdentity,
    clock: HostPairingClock,
    rows: InvitationRows,
    owner: OwnerAuthority,
    /// The invitation this host is offering. One at a time: an invitation is single use, and a
    /// host that offered several would have to decide which one a candidate meant.
    open: Mutex<Option<Open>>,
    /// Invitations that ended without a commitment and were replaced, newest last, so each one's
    /// candidate can still be told how it ended. At most [`ENDED_KEPT`] of them.
    ended: Mutex<VecDeque<Open>>,
}

/// How many ended invitations a host keeps for their candidates once newer ones replace them.
///
/// A candidate asks about its own invitation while it is still connected, so a short history is
/// enough; it is bounded so a host issuing invitations all day holds a fixed amount.
pub const ENDED_KEPT: usize = 16;

impl std::fmt::Debug for PairingHost {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairingHost")
            .field("device", &self.identity.device_id)
            .finish_non_exhaustive()
    }
}

impl PairingHost {
    /// Builds the pairing service of one daemon over its durable records.
    #[must_use]
    pub fn new(identity: HostIdentity, clock: HostPairingClock, rows: InvitationRows) -> Self {
        let owner = OwnerAuthority::new(
            identity.device_id,
            identity.endpoint_id,
            clock.clone(),
            rows.clone(),
        );
        Self {
            identity,
            clock,
            rows,
            owner,
            open: Mutex::new(None),
            ended: Mutex::new(VecDeque::new()),
        }
    }

    /// Returns what this host declares about itself in an invitation.
    #[must_use]
    pub const fn identity(&self) -> &HostIdentity {
        &self.identity
    }

    /// Returns the owner-confirmation service.
    #[must_use]
    pub const fn owner(&self) -> &OwnerAuthority {
        &self.owner
    }

    /// Returns the durable pairing records.
    #[must_use]
    pub const fn rows(&self) -> &InvitationRows {
        &self.rows
    }

    /// `owner.confirmation.request`: issues the challenge for one subject, described by the host.
    ///
    /// # Errors
    ///
    /// Returns the refusal: a subject the host cannot describe, a proposal its kind does not
    /// allow, or a caller without owner authority.
    pub fn request_confirmation(
        &self,
        caller: &Caller,
        params: &OwnerConfirmationRequestParams,
        action: (ActionId, Digest256),
        admission: &dyn Fn() -> Result<()>,
    ) -> Result<OwnerConfirmationRequestResult> {
        // A retry is answered before anything about the subject is resolved again: the invitation
        // it named may be gone, and the answer it was owed is the challenge it was given.
        if let Some(retained) = self.owner.retained_request(caller, action) {
            return retained;
        }
        let resolved = match &params.subject {
            ConfirmationSubject::IssueInvitation {
                mode,
                rendezvous_origin,
                grant_kind,
                proposed_grant,
            } => {
                let origin = resolved_origin(*mode, rendezvous_origin.0.as_ref())?;
                validate_proposal(
                    proposed_grant,
                    kind_of(*grant_kind),
                    self.clock.wall_clock_ms(),
                )
                .map_err(refusal)?;
                Resolved {
                    action: SensitiveAction::IssueInvitation,
                    digest: issuance_digest(*mode, origin.as_ref(), *grant_kind, proposed_grant)
                        .map_err(ControllerError::registry)?,
                    destination: None,
                    rights: proposed_grant.actions.clone(),
                    display: ConfirmationDisplay::IssueInvitation {
                        mode: *mode,
                        rendezvous_origin: origin.map_or_else(Nullable::null, Nullable::some),
                        grant_kind: *grant_kind,
                        proposed_grant: proposed_grant.clone(),
                    },
                    first_owner: is_owner_grant(*grant_kind, proposed_grant),
                }
            }
            ConfirmationSubject::ConfirmDevice { invitation_id } => {
                let open = self.open();
                let invitation = open
                    .as_ref()
                    .filter(|open| open.invitation_id() == *invitation_id)
                    .ok_or_else(|| not_offering(*invitation_id))?;
                let bound = invitation
                    .bound()?
                    .ok_or_else(|| ControllerError::Refused {
                        code: ErrorCode::InvalidArgument,
                        detail: "no candidate is waiting for this invitation's approval yet"
                            .to_owned(),
                    })?;
                Resolved {
                    action: SensitiveAction::ConfirmDevice,
                    digest: bound.digest,
                    destination: Some(bound.keys),
                    rights: invitation.proposed_grant.actions.clone(),
                    display: ConfirmationDisplay::ConfirmDevice {
                        invitation_id: *invitation_id,
                        candidate: bound.view,
                        proposed_grant: invitation.proposed_grant.clone(),
                    },
                    first_owner: is_owner_grant(invitation.grant_kind, &invitation.proposed_grant),
                }
            }
            ConfirmationSubject::EstablishClock => Resolved {
                action: SensitiveAction::ChangeHostAuthority,
                digest: clock_digest()?,
                destination: None,
                rights: CanonicalSet::new(),
                display: ConfirmationDisplay::EstablishClock,
                first_owner: false,
            },
            ConfirmationSubject::Described(described) => {
                if !described.is_describable() {
                    return Err(ControllerError::Refused {
                        code: ErrorCode::InvalidArgument,
                        detail: "issuing an invitation, confirming a device and establishing the \
                                 clock are described by this host; name them as such"
                            .to_owned(),
                    });
                }
                Resolved {
                    action: described.action,
                    digest: described.action_digest,
                    destination: described.destination_keys.0,
                    rights: described.destination_rights.clone(),
                    display: ConfirmationDisplay::Described(described.clone()),
                    first_owner: false,
                }
            }
        };
        self.owner.request(caller, resolved, action, admission)
    }

    /// `owner.confirmation.pending`: the challenges an owner can still answer.
    ///
    /// # Errors
    ///
    /// Returns `PERMISSION_DENIED` for a caller without owner authority.
    pub fn pending_confirmations(&self, caller: &Caller) -> Result<OwnerConfirmationPendingResult> {
        self.owner.pending(caller)
    }

    /// `owner.confirmation.complete`: verifies and records an answer.
    ///
    /// # Errors
    ///
    /// Returns the refusal [`OwnerAuthority::complete`] decides.
    pub fn complete_confirmation(
        &self,
        caller: &Caller,
        params: &OwnerConfirmationCompleteParams,
        admission: &dyn Fn() -> Result<()>,
    ) -> Result<OwnerConfirmationCompleteResult> {
        if let Some(retained) = self.owner.retained_answer(caller, params) {
            return retained;
        }
        self.owner.complete(caller, params, admission)
    }

    /// `pair.invite`: issues one invitation under a fresh owner confirmation naming its grant.
    ///
    /// A retry of the same action with the same parameters gets the same answer while the
    /// invitation is open, and after a restart is told what became of it; nothing new is issued
    /// for it. The same action with other parameters is `ID_CONFLICT`.
    ///
    /// # Errors
    ///
    /// Returns the refusal: no answered confirmation for exactly this grant, a proposal its kind
    /// does not allow, an invitation already on offer, or a store failure.
    pub fn invite(
        &self,
        caller: &Caller,
        params: &PairInviteParams,
        action: (ActionId, Digest256),
        network_config: NetworkConfig,
        admission: &Admission,
    ) -> Result<PairInviteResult> {
        if caller.device.is_some() {
            return Err(ControllerError::PermissionDenied {
                detail: "an invitation is issued over local IPC only".to_owned(),
            });
        }
        let (action, digest) = action;
        let mut open = self.open();
        if let Some(retained) = self.retained_invite(&open, caller, action, digest) {
            return retained;
        }
        // An invitation nobody used before its deadline is not on offer any more, and does not
        // hold up the next one.
        if let Some(offered) = open.as_mut() {
            match &mut offered.mode {
                OpenMode::Direct(invitation) => invitation.expire_if_due().map_err(refusal)?,
            }
        }
        if let Some(offered) = open.as_ref()
            && matches!(
                offered.state(),
                InvitationState::Open | InvitationState::Locked { .. }
            )
        {
            return Err(ControllerError::Refused {
                code: ErrorCode::InvalidArgument,
                detail: "this host is already offering an invitation; cancel it before issuing \
                         another"
                    .to_owned(),
            });
        }
        let kind = kind_of(params.grant_kind);
        let origin = match &params.mode {
            InviteMode::Code { rendezvous_origin } => {
                resolved_origin(InviteModeKind::Code, rendezvous_origin.0.as_ref())?
            }
            InviteMode::Direct => None,
        };
        let expectation_digest = issuance_digest(
            params.mode.kind(),
            origin.as_ref(),
            params.grant_kind,
            &params.proposed_grant,
        )
        .map_err(ControllerError::registry)?;
        let rights = params.proposed_grant.actions.clone();
        let expectation = self.owner.expectation(
            SensitiveAction::IssueInvitation,
            expectation_digest,
            None,
            &rights,
        );
        let terms = IssueTerms {
            mode: params.mode.kind(),
            rendezvous_origin: origin.clone(),
            grant_kind: params.grant_kind,
            proposed_grant: params.proposed_grant.clone(),
            issuing_actor: caller.actor_id.clone(),
            issuing_ingress: caller.ingress,
            action: Some((action, digest)),
            issued_at_ms: kr_ipc::now_ms(),
        };
        let owner = caller.owner_context();
        // Asked before anything is spent: the caller's registration and the deadline its mutation
        // was admitted under, which the wait for this thread and for the invitation's lock may have
        // used up. A mutation refused here leaves the owner's answer unspent. It is asked once
        // more inside the transaction that writes the invitation, after every later wait.
        admission()?;
        let (mode, answer, slot) = match &params.mode {
            InviteMode::Direct => {
                let mut identity = self.identity.clone();
                identity.network_config = network_config;
                let rows = self.rows.issuing(terms);
                let slot = rows.write_admission().clone();
                let (spendable, mut challenges) = self.owner.spend(&expectation)?;
                let issued = admitted(&slot, admission, || {
                    DirectInvitation::issue(
                        rows,
                        self.clock.clone(),
                        identity,
                        params.proposed_grant.clone(),
                        kind,
                        &spendable.approval(&owner),
                        challenges.ledger(),
                    )
                });
                challenges.forget(spendable.request());
                drop(challenges);
                let invitation = issued?;
                let payload = invitation.qr_payload();
                let QrPayload::Direct(direct) = &payload else {
                    return Err(ControllerError::registry(
                        "a direct invitation produced another kind of payload",
                    ));
                };
                let answer = PairInviteResult {
                    invitation_id: invitation.invitation_id(),
                    expires_at_ms: direct.expires_at_ms,
                    entry: InviteEntry::Direct {
                        qr_text: qr_text(&payload)?,
                    },
                };
                (OpenMode::Direct(Box::new(invitation)), answer, slot)
            }
            InviteMode::Code { .. } => {
                return Err(ControllerError::Refused {
                    code: ErrorCode::RendezvousConfigError,
                    detail: "this host has no rendezvous service to offer a code through"
                        .to_owned(),
                });
            }
        };
        // The invitation this one replaces has ended; its candidate may still ask how.
        if let Some(previous) = open.take() {
            self.keep_ended(previous);
        }
        *open = Some(Open {
            mode,
            admission: slot,
            answer: answer.clone(),
            issued_by: caller.actor_id.clone(),
            action: (action, digest),
            grant_kind: params.grant_kind,
            proposed_grant: params.proposed_grant.clone(),
        });
        Ok(answer)
    }

    /// `pair.confirm`: commits the candidate the owner was shown, under a fresh confirmation.
    ///
    /// # Errors
    ///
    /// Returns the refusal: another caller than the issuing owner, an approval naming another
    /// candidate, no answered confirmation for exactly this candidate, or a store failure.
    pub fn confirm(
        &self,
        caller: &Caller,
        params: &PairConfirmParams,
        authority_revision: AuthorityRevision,
        admission: &Admission,
    ) -> Result<PairConfirmResult> {
        let mut open = self.open();
        let Some(offered) = open
            .as_mut()
            .filter(|offered| offered.invitation_id() == params.invitation_id)
        else {
            drop(open);
            return self.committed_answer(caller, params.invitation_id);
        };
        if offered.issued_by != caller.actor_id {
            return Err(refusal(kr_pairing::PairingError::NotIssuingOwner));
        }
        let bound = offered.bound()?.ok_or_else(|| {
            refusal(kr_pairing::PairingError::WrongPhase {
                expected: "owner approval",
                actual: "an invitation no candidate has bound yet",
            })
        })?;
        if bound.approval != params.approval {
            return Err(refusal(kr_pairing::PairingError::ContextMismatch {
                what: "the candidate the owner approved",
            }));
        }
        let rights = offered.proposed_grant.actions.clone();
        let expectation = self.owner.expectation(
            SensitiveAction::ConfirmDevice,
            bound.digest,
            Some(&bound.keys),
            &rights,
        );
        let identities = fresh_identities(self.identity.device_id, authority_revision)?;
        let owner = caller.owner_context();
        // Asked before the answer is spent, and again inside the commit's own transaction.
        admission()?;
        let slot = offered.admission.clone();
        let (spendable, mut challenges) = self.owner.spend(&expectation)?;
        let committed = match (&mut offered.mode, params.approval) {
            (
                OpenMode::Direct(invitation),
                PairingApproval::Direct {
                    transcript_digest,
                    client_key_digest,
                },
            ) => admitted(&slot, admission, || {
                invitation.confirm(
                    &spendable.approval(&owner),
                    challenges.ledger(),
                    &ApprovedRedemption {
                        transcript_digest,
                        client_key_digest,
                    },
                    &identities,
                    None,
                )
            }),
            (OpenMode::Direct(_), PairingApproval::Code { .. }) => {
                Err(refusal(kr_pairing::PairingError::ContextMismatch {
                    what: "the mode of the approval",
                }))
            }
        };
        challenges.forget(spendable.request());
        drop(challenges);
        let commitment = committed?;
        let event = self
            .rows
            .event_for(commitment.invitation_id)?
            .ok_or_else(|| {
                ControllerError::registry("a committed pairing has no security event")
            })?;
        *open = None;
        Ok(PairConfirmResult {
            device_id: commitment.device_id,
            grant_id: commitment.grant.grant_id,
            event,
        })
    }

    /// `pair.cancel`: consumes the invitation without a grant, as a withdrawal or as a denial.
    ///
    /// # Errors
    ///
    /// Returns the refusal: another caller than the issuing owner, or a store failure.
    pub fn cancel(
        &self,
        caller: &Caller,
        params: &PairCancelParams,
        admission: &Admission,
    ) -> Result<PairStatusResult> {
        let mut open = self.open();
        if let Some(offered) = open
            .as_mut()
            .filter(|offered| offered.invitation_id() == params.invitation_id)
            .filter(|offered| {
                matches!(
                    offered.state(),
                    InvitationState::Open | InvitationState::Locked { .. }
                )
            })
        {
            let owner = caller.owner_context();
            admission()?;
            let slot = offered.admission.clone();
            match &mut offered.mode {
                OpenMode::Direct(invitation) => admitted(&slot, admission, || {
                    if params.deny {
                        invitation.deny(&owner)
                    } else {
                        invitation.cancel(&owner)
                    }
                }),
            }?;
            // The ended invitation stays: its candidate authenticated itself, and asking what
            // happened is how it learns it was denied or withdrawn. The next invitation replaces
            // it here and keeps it among the ended ones, where the candidate can still ask.
        }
        drop(open);
        self.recorded_status(caller, params.invitation_id)
    }

    /// `pair.status` for the issuing owner: the invitation's state and everything the owner is
    /// shown, including exactly what `pair.confirm` must name.
    ///
    /// # Errors
    ///
    /// Returns the refusal: another caller than the issuing owner, or a store failure.
    pub fn owner_status(
        &self,
        caller: &Caller,
        params: &PairStatusParams,
    ) -> Result<PairStatusResult> {
        let mut open = self.open();
        if let Some(offered) = open
            .as_mut()
            .filter(|offered| offered.invitation_id() == params.invitation_id)
        {
            if offered.issued_by != caller.actor_id {
                return Err(refusal(kr_pairing::PairingError::NotIssuingOwner));
            }
            let owner = caller.owner_context();
            let status = match &mut offered.mode {
                OpenMode::Direct(invitation) => {
                    invitation.status(DirectStatusViewer::IssuingOwner(&owner))
                }
            }
            .map_err(refusal)?;
            let remaining = match &offered.mode {
                OpenMode::Direct(invitation) => MAX_CONFIRMATION_FAILURES
                    .saturating_sub(invitation.record().failed_confirmations),
            };
            let bound = match status {
                PairStatus::AwaitingApproval { .. } => offered.bound()?,
                _ => None,
            };
            let view = PairOwnerView {
                mode: InviteModeKind::Direct,
                rendezvous_origin: Nullable::null(),
                remaining_confirmations: remaining,
                grant_kind: offered.grant_kind,
                proposed_grant: offered.proposed_grant.clone(),
                candidate: bound
                    .as_ref()
                    .map_or_else(Nullable::null, |bound| Nullable::some(bound.view.clone())),
                approval: bound
                    .as_ref()
                    .map_or_else(Nullable::null, |bound| Nullable::some(bound.approval)),
                event: Nullable::null(),
            };
            return Ok(PairStatusResult {
                status,
                owner: Nullable::some(view),
            });
        }
        drop(open);
        self.recorded_status(caller, params.invitation_id)
    }

    /// Consumes an answered clock confirmation, immediately before the clock is trusted again.
    ///
    /// # Errors
    ///
    /// Returns `OWNER_CONFIRMATION_REQUIRED` without an answered confirmation naming the clock.
    pub fn accept_clock(&self) -> Result<()> {
        let rights = CanonicalSet::new();
        let expectation = self.owner.expectation(
            SensitiveAction::ChangeHostAuthority,
            clock_digest()?,
            None,
            &rights,
        );
        self.owner
            .consume_for(&expectation, "establish this host's clock")
    }

    /// Answers the issuing owner from the durable record, once the invitation object is gone.
    fn recorded_status(
        &self,
        caller: &Caller,
        invitation_id: InvitationId,
    ) -> Result<PairStatusResult> {
        let row = self.issued_row(caller, invitation_id)?;
        let commitment =
            kr_pairing::platform::InvitationStore::commitment(&self.rows, invitation_id)
                .map_err(refusal)?;
        let status = match (row.record.state, commitment.as_ref()) {
            (_, Some(commitment)) => PairStatus::Committed {
                device_id: commitment.device_id,
                grant_id: commitment.grant.grant_id,
            },
            (InvitationState::Consumed { reason }, None) => PairStatus::Consumed { reason },
            (InvitationState::Committed, None) => {
                return Err(ControllerError::registry(
                    "a committed invitation has no commitment record",
                ));
            }
            // An unfinished record whose object is gone was left by a daemon that stopped; the
            // restart sweep consumes it, and until then it is reported as the restart left it.
            (InvitationState::Open | InvitationState::Locked { .. }, None) => {
                PairStatus::Consumed {
                    reason: PairingConsumedReason::HostRestarted,
                }
            }
        };
        let candidate = commitment.as_ref().and_then(|commitment| {
            commitment
                .client_bundle
                .as_ref()
                .map(|bundle| PairCandidateView {
                    device_name: bundle.device_name.clone(),
                    platform: bundle.platform,
                    keys: commitment.client_keys,
                    verification_value: commitment.verification_value.clone(),
                })
        });
        let view = PairOwnerView {
            mode: row.terms.mode,
            rendezvous_origin: row
                .terms
                .rendezvous_origin
                .clone()
                .map_or_else(Nullable::null, Nullable::some),
            remaining_confirmations: MAX_CONFIRMATION_FAILURES
                .saturating_sub(row.record.failed_confirmations),
            grant_kind: row.terms.grant_kind,
            proposed_grant: row.terms.proposed_grant.clone(),
            candidate: candidate.map_or_else(Nullable::null, Nullable::some),
            approval: Nullable::null(),
            event: self
                .rows
                .event_for(invitation_id)?
                .map_or_else(Nullable::null, Nullable::some),
        };
        Ok(PairStatusResult {
            status,
            owner: Nullable::some(view),
        })
    }

    /// A retry of `pair.confirm` after the pairing committed gets the committed result.
    fn committed_answer(
        &self,
        caller: &Caller,
        invitation_id: InvitationId,
    ) -> Result<PairConfirmResult> {
        let row = self.issued_row(caller, invitation_id)?;
        let commitment =
            kr_pairing::platform::InvitationStore::commitment(&self.rows, invitation_id)
                .map_err(refusal)?
                .ok_or_else(|| no_longer_open(&row))?;
        let event = self.rows.event_for(invitation_id)?.ok_or_else(|| {
            ControllerError::registry("a committed pairing has no security event")
        })?;
        Ok(PairConfirmResult {
            device_id: commitment.device_id,
            grant_id: commitment.grant.grant_id,
            event,
        })
    }

    /// Reads an invitation's durable row, for the owner that issued it and nobody else.
    fn issued_row(&self, caller: &Caller, invitation_id: InvitationId) -> Result<InvitationRow> {
        let row = self
            .rows
            .row(invitation_id)?
            .ok_or_else(|| not_offering(invitation_id))?;
        if row.terms.issuing_actor != caller.actor_id || row.terms.issuing_ingress != caller.ingress
        {
            return Err(refusal(kr_pairing::PairingError::NotIssuingOwner));
        }
        Ok(row)
    }

    /// Returns what a repeated mutation is owed, when its action already has an outcome.
    ///
    /// This is asked before a first admission's freshness is: a caller that reconnects and repeats
    /// an action it already submitted gets that action's own result, not a refusal about a window
    /// that has since been replaced. Nothing here writes.
    #[must_use]
    pub fn retained(
        &self,
        caller: &Caller,
        method: Method,
        mutation: &MutationRequest,
        digest: Digest256,
    ) -> Option<Result<ParamsValue>> {
        match method {
            Method::PairInvite => {
                let open = self.open();
                self.retained_invite(&open, caller, mutation.action_id, digest)
                    .map(|retained| retained.and_then(|answer| encode(&answer)))
            }
            Method::OwnerConfirmationRequest => self
                .owner
                .retained_request(caller, (mutation.action_id, digest))
                .map(|retained| retained.and_then(|answer| encode(&answer))),
            Method::OwnerConfirmationComplete => {
                let params: OwnerConfirmationCompleteParams = mutation.params.to_typed().ok()?;
                self.owner
                    .retained_answer(caller, &params)
                    .map(|retained| retained.and_then(|answer| encode(&answer)))
            }
            Method::PairConfirm => {
                let params: PairConfirmParams = mutation.params.to_typed().ok()?;
                kr_pairing::platform::InvitationStore::commitment(&self.rows, params.invitation_id)
                    .ok()??;
                Some(
                    self.committed_answer(caller, params.invitation_id)
                        .and_then(|answer| encode(&answer)),
                )
            }
            Method::PairCancel => {
                let params: PairCancelParams = mutation.params.to_typed().ok()?;
                let row = self.rows.row(params.invitation_id).ok()??;
                let wanted = if params.deny {
                    PairingConsumedReason::Denied
                } else {
                    PairingConsumedReason::Cancelled
                };
                (row.record.state == InvitationState::Consumed { reason: wanted }).then(|| {
                    self.recorded_status(caller, params.invitation_id)
                        .and_then(|answer| encode(&answer))
                })
            }
            _ => None,
        }
    }

    /// The answer a repeated `pair.invite` is owed: the open invitation's, or what became of it.
    fn retained_invite(
        &self,
        open: &Option<Open>,
        caller: &Caller,
        action: ActionId,
        digest: Digest256,
    ) -> Option<Result<PairInviteResult>> {
        if let Some(offered) = open.as_ref()
            && offered.issued_by == caller.actor_id
            && offered.action.0 == action
        {
            if offered.action.1 != digest {
                return Some(Err(id_conflict()));
            }
            // An invitation that ended stays in memory for its candidate's sake; its issuer is
            // told what became of it from the durable row, like after a restart.
            if matches!(
                offered.state(),
                InvitationState::Open | InvitationState::Locked { .. }
            ) {
                return Some(Ok(offered.answer.clone()));
            }
        }
        match self.rows.row_for_action(&caller.actor_id, action) {
            Ok(Some(row)) => Some(Err(
                if row.terms.action.map(|(_, recorded)| recorded) == Some(digest) {
                    no_longer_open(&row)
                } else {
                    id_conflict()
                },
            )),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        }
    }

    /// `pair.status` from a paired device: the device's own committed pairing, and nothing else.
    ///
    /// A device paired through an invitation may reconnect as the device it became and ask about
    /// that invitation; the answer is about itself. It is the issuing owner of nothing.
    ///
    /// # Errors
    ///
    /// Returns `PERMISSION_DENIED` for any other invitation.
    pub fn device_status(
        &self,
        caller: &Caller,
        params: &PairStatusParams,
    ) -> Result<PairStatusResult> {
        let Some(device) = caller.device.as_ref() else {
            return Err(refusal(kr_pairing::PairingError::NotIssuingOwner));
        };
        if device.committed_invitation_id != Some(params.invitation_id) {
            return Err(refusal(kr_pairing::PairingError::NotIssuingOwner));
        }
        Ok(PairStatusResult {
            status: PairStatus::Committed {
                device_id: device.device_id,
                grant_id: device.grant.grant_id,
            },
            owner: Nullable::null(),
        })
    }

    fn open(&self) -> MutexGuard<'_, Option<Open>> {
        self.open.lock().unwrap_or_else(|held| held.into_inner())
    }

    /// Keeps an invitation that ended without a commitment, for its candidate, dropping the
    /// oldest kept one beyond [`ENDED_KEPT`].
    ///
    /// Taken only while the open invitation's lock is held, and always after it, so the two locks
    /// are taken in one order.
    fn keep_ended(&self, ended: Open) {
        let mut kept = self.ended.lock().unwrap_or_else(|held| held.into_inner());
        kept.push_back(ended);
        while kept.len() > ENDED_KEPT {
            kept.pop_front();
        }
    }

    /// Answers a candidate about an invitation that ended and was replaced, when this host still
    /// keeps it. kr-pairing authenticates the candidate by the endpoint it bound, as it does for
    /// the open invitation.
    fn ended_status(
        &self,
        peer: &ConnectionPeer,
        invitation_id: InvitationId,
    ) -> Option<std::result::Result<PairStatus, ProtocolError>> {
        let mut kept = self.ended.lock().unwrap_or_else(|held| held.into_inner());
        let ended = kept
            .iter_mut()
            .find(|ended| ended.invitation_id() == invitation_id)?;
        Some(
            match &mut ended.mode {
                OpenMode::Direct(invitation) => invitation.status(DirectStatusViewer::Candidate {
                    attempt_id: None,
                    live_peer: peer as &dyn LivePeer,
                }),
            }
            .map_err(protocol_refusal),
        )
    }

    fn redeem(
        &self,
        peer: &ConnectionPeer,
        params: &PairRedeemParams,
    ) -> std::result::Result<PairRedeemResult, ProtocolError> {
        let mut open = self.open();
        let Some(OpenMode::Direct(invitation)) = open.as_mut().map(|offered| &mut offered.mode)
        else {
            return Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "this host is not offering a direct invitation",
            ));
        };
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
                    .map_err(protocol_refusal)?;
                Ok(PairRedeemResult::Challenge(Box::new(challenge)))
            }
            PairRedeemParams::Direct(proof) => {
                let candidate = invitation
                    .redeem(proof, peer.endpoint_id(), peer as &dyn LivePeer)
                    .map_err(protocol_refusal)?;
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
        let mut open = self.open();
        if let Some(offered) = open
            .as_mut()
            .filter(|offered| offered.invitation_id() == params.invitation_id)
        {
            let status = match &mut offered.mode {
                OpenMode::Direct(invitation) => {
                    invitation.status(DirectStatusViewer::Candidate {
                        // The host generated the attempt identity, so a candidate whose
                        // redemption answer was lost has none; the endpoint it authenticated with
                        // is what identifies it either way.
                        attempt_id: None,
                        live_peer: peer as &dyn LivePeer,
                    })
                }
            }
            .map_err(protocol_refusal)?;
            return Ok(PairStatusResult {
                status,
                owner: Nullable::null(),
            });
        }
        drop(open);
        // An invitation that ended and was replaced still answers its own candidate.
        if let Some(status) = self.ended_status(peer, params.invitation_id) {
            return Ok(PairStatusResult {
                status: status?,
                owner: Nullable::null(),
            });
        }
        // No invitation object for this candidate to ask about, which is the ordinary state after
        // a commit or a restart. A committed pairing is on record with the endpoint the candidate
        // proved, so this answers the caller about itself and about nothing else.
        let status = recover_candidate_status(&self.rows, params.invitation_id, None, peer)
            .map_err(|_| {
                ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "this host is not offering that invitation",
                )
            })?;
        Ok(PairStatusResult {
            status,
            owner: Nullable::null(),
        })
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
            PairingMethod::Finish => Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "this host is not offering a code invitation",
            )),
        }
    }
}

/// Runs one owner-driven write of an invitation with the mutation's admission asked inside the
/// write's own transaction, and reports a lapse as the lapse it is.
///
/// Only a refusal is reinterpreted. The store refused before writing anything, which is what an
/// admission that lapsed inside the write looks like, and a lapse is final: a withdrawn
/// registration is not restored and a passed deadline does not come back, so asking once more
/// says whether the refusal was the lapse. Every other failure is reported as it happened; a failed
/// write in particular is a write of unknown outcome, whatever the admission says by now.
fn admitted<T>(
    slot: &WriteAdmission,
    admission: &Admission,
    call: impl FnOnce() -> kr_pairing::Result<T>,
) -> Result<T> {
    slot.during(admission, call).map_err(|error| match error {
        kr_pairing::PairingError::Refused { .. } => {
            admission().err().unwrap_or_else(|| refusal(error))
        }
        other => refusal(other),
    })
}

/// Returns the kr-pairing grant kind a protocol kind names.
const fn kind_of(kind: InviteGrantKind) -> GrantKind {
    match kind {
        InviteGrantKind::PersonalOwner => GrantKind::PersonalOwner,
        InviteGrantKind::SessionInvitation => GrantKind::SessionInvitation,
    }
}

/// Returns true when a proposal is a personal owner grant, which is what establishes an owner.
fn is_owner_grant(kind: InviteGrantKind, proposed: &ProposedGrant) -> bool {
    kind == InviteGrantKind::PersonalOwner && proposed.actions.contains(&ActionRight::HostManage)
}

fn clock_digest() -> Result<Digest256> {
    kr_pairing::confirm::action_digest(&CLOCK_PURPOSE).map_err(refusal)
}

/// Returns the origin a code invitation reserves at: the one named, or this host's default.
///
/// A direct invitation names none, and one that did would be naming a service it never contacts.
fn resolved_origin(
    mode: InviteModeKind,
    named: Option<&RendezvousOrigin>,
) -> Result<Option<RendezvousOrigin>> {
    match (mode, named) {
        (InviteModeKind::Code, Some(origin)) => Ok(Some(origin.clone())),
        (InviteModeKind::Code, None) => Ok(Some(default_rendezvous_origin())),
        (InviteModeKind::Direct, None) => Ok(None),
        (InviteModeKind::Direct, Some(_)) => Err(ControllerError::Refused {
            code: ErrorCode::InvalidArgument,
            detail: "a direct invitation contacts no rendezvous service, so it names no origin"
                .to_owned(),
        }),
    }
}

fn encode<T: serde::Serialize>(value: &T) -> Result<ParamsValue> {
    ParamsValue::from_typed(value)
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
}

fn qr_text(payload: &QrPayload) -> Result<QrText> {
    let text = payload.to_text().map_err(ControllerError::registry)?;
    QrText::new(text.as_str()).map_err(ControllerError::registry)
}

fn id_conflict() -> ControllerError {
    ControllerError::Refused {
        code: ErrorCode::IdConflict,
        detail: "this action already issued an invitation with other parameters".to_owned(),
    }
}

fn not_offering(invitation_id: InvitationId) -> ControllerError {
    ControllerError::Refused {
        code: ErrorCode::InvalidArgument,
        detail: format!("this host is not offering invitation {invitation_id}"),
    }
}

/// Says what became of the invitation an action issued, which a retry of that action is told.
fn no_longer_open(row: &InvitationRow) -> ControllerError {
    let error = match row.record.state {
        InvitationState::Consumed { reason } => kr_pairing::PairingError::Consumed { reason },
        InvitationState::Committed => kr_pairing::PairingError::AlreadyCommitted,
        InvitationState::Open | InvitationState::Locked { .. } => {
            kr_pairing::PairingError::Consumed {
                reason: PairingConsumedReason::HostRestarted,
            }
        }
    };
    let refused = refusal(error);
    ControllerError::Refused {
        code: refused.code(),
        detail: format!("the invitation this action issued is no longer open: {refused}"),
    }
}

/// Returns what a candidate is told, under the pairing error's own stable code.
///
/// An authentication failure says that and nothing more. Section 10 keeps it ambiguous, and a
/// message naming which value did not match would tell a candidate what the code cannot: whether
/// it had the secret, the transcript or the endpoint wrong.
fn protocol_refusal(error: kr_pairing::PairingError) -> ProtocolError {
    let code = error.code();
    if code == ErrorCode::PairingAuthFailed {
        return ProtocolError::new(code, AUTHENTICATION_FAILED);
    }
    ProtocolError::new(code, error.to_string())
}

/// The one thing a candidate is told when its pairing could not be authenticated.
pub const AUTHENTICATION_FAILED: &str = "the pairing could not be authenticated";

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
    authority_revision: AuthorityRevision,
) -> Result<GrantIdentities> {
    Ok(GrantIdentities {
        grant_id: GrantId::new(kr_ipc::new_uuid()),
        issuer_device_id,
        recipient_device_id: DeviceId::new(kr_ipc::new_uuid()),
        authority_revision,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// An admission that holds for its first `holds` askings and has lapsed from then on.
    fn lapsing_after(holds: usize) -> Admission {
        let asked = Arc::new(AtomicUsize::new(0));
        Arc::new(move || {
            if asked.fetch_add(1, Ordering::SeqCst) < holds {
                Ok(())
            } else {
                Err(ControllerError::WindowExpired {
                    detail: "the deadline passed".to_owned(),
                })
            }
        })
    }

    /// KR-REQ-10.05: a write that failed is reported as a failure even when the admission lapses
    /// before the failure is reported. Its outcome is unknown, and a refusal would say nothing was
    /// written.
    #[test]
    fn a_failed_write_is_not_reported_as_the_admission_lapsing() {
        let slot = WriteAdmission::default();
        let admission = lapsing_after(1);
        let failed = admitted::<()>(&slot, &admission, || {
            admission().expect("admitted inside the write");
            Err(kr_pairing::PairingError::Store {
                reason: "the disk is full".to_owned(),
            })
        });
        let error = failed.expect_err("the write failed");
        assert_eq!(error.code(), ErrorCode::StorageUnavailable, "{error}");
    }

    /// KR-REQ-10.05: a refusal the store made inside the write is reported as the admission's own
    /// lapse, once the admission has lapsed.
    #[test]
    fn a_refused_write_is_reported_as_the_lapse_it_was() {
        let slot = WriteAdmission::default();
        let admission = lapsing_after(0);
        let refused = admitted::<()>(&slot, &admission, || {
            Err(kr_pairing::PairingError::Refused {
                code: ErrorCode::PermissionDenied,
                reason: "the deadline passed".to_owned(),
            })
        });
        assert!(
            matches!(refused, Err(ControllerError::WindowExpired { .. })),
            "{refused:?}"
        );
    }
}
