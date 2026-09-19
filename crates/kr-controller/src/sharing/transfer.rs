//! Transfer of control: handing a session's owner authority to another device.
//!
//! Section 18 lists "scoped invitations, delegation and transfer of control" together, and the
//! third is the one that is not a delegation. A delegation leaves the issuer holding what it had;
//! a transfer does not. So a transfer is two effects that have to happen together:
//!
//! 1. the recipient receives an owner-role grant over the session, and
//! 2. the grant the transferring device held over that session is revoked.
//!
//! [`TransferPlan`] is those two written down before either happens, and [`ControlTransfer`] is
//! what came back afterwards. They are separate types because the plan is what an owner confirms:
//! section 23 requires a fresh confirmation bound to one exact action digest, and the digest has
//! to cover what will happen rather than what was asked for.
//!
//! Two rules a transfer cannot be talked out of:
//!
//! * **It needs the owner's confirmation, always.** It changes who holds host-control authority
//!   over the session, which is [`SensitiveAction::ChangeHostAuthority`].
//! * **It cannot hand over what the transferring device does not hold.** Section 19's delegation
//!   rule does not stop applying because the issuer is giving something up: an actor with a
//!   viewer's grant cannot make somebody else an owner.

use kr_protocol::grant::Grant;
use kr_protocol::ids::{DeviceId, GrantId, SessionId};
use kr_protocol::pairing::SensitiveAction;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Digest256};
use kr_protocol::sharing::SessionRole;

use crate::error::{ControllerError, Result};
use crate::grants::GrantRevocation;

/// What a transfer will do, written down before any of it happens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferPlan {
    /// The session whose control is moving.
    pub session_id: SessionId,
    /// The device giving it up.
    pub from_device_id: DeviceId,
    /// The device receiving it.
    pub to_device_id: DeviceId,
    /// The grant that will be revoked.
    pub revoking_grant_id: GrantId,
    /// The grant that will be issued.
    pub issuing_grant_id: GrantId,
    /// The actions the new owner will hold.
    pub actions: CanonicalSet<ActionRight>,
}

impl TransferPlan {
    /// The sensitive action an owner confirmation for this transfer is bound to.
    #[must_use]
    pub const fn sensitive_action() -> SensitiveAction {
        SensitiveAction::ChangeHostAuthority
    }

    /// The digest an owner's confirmation for this exact transfer covers.
    ///
    /// Every field of the plan, so a confirmation obtained for one transfer cannot authorise
    /// another: not a different session, not a different recipient, not a wider set of actions.
    ///
    /// # Errors
    ///
    /// Returns an encoding error when the plan cannot be represented in KR-CBOR-1.
    pub fn action_digest(&self) -> Result<Digest256> {
        let value = kr_cbor::to_canonical_value(&(
            "kr-transfer/1",
            self.session_id,
            self.from_device_id,
            self.to_device_id,
            self.revoking_grant_id,
            self.issuing_grant_id,
            &self.actions,
        ))
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        Ok(Digest256::from_bytes(kr_cbor::sha256(&kr_cbor::encode(
            &value,
        ))))
    }
}

/// Evidence that an owner confirmed one exact transfer.
///
/// The only way to construct one is [`Self::verify`], which runs the ceremony's own acceptance:
/// the challenge has to describe this plan's digest, this host, these rights and this destination,
/// the proof has to answer it, and the challenge is consumed. A Boolean is something any caller can
/// write; this is not. [`Self::covers`] then checks that the evidence is about *this* plan, which
/// is what stops a confirmation for one transfer being carried to another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfirmedTransfer {
    action_digest: Digest256,
}

impl ConfirmedTransfer {
    /// Verifies and consumes the owner's confirmation for this exact transfer.
    ///
    /// This is the only way to get one. The expectation is built from the plan rather than from
    /// the caller, so a confirmation answered for another action, another host, another
    /// destination or another set of rights does not produce one, and the ceremony's challenge is
    /// consumed here rather than left outstanding.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::PermissionDenied`] when the proof does not answer this
    /// transfer's challenge.
    #[expect(
        clippy::too_many_arguments,
        reason = "a confirmation's acceptance is the plan, the ledger, the clock, the challenge, \
                  the proof, the signer, this host's enrolment and the destination it names; each \
                  one is part of what the owner confirmed, and grouping them into a struct would \
                  hide which of them a caller left out"
    )]
    pub fn verify(
        plan: &TransferPlan,
        ledger: &mut kr_pairing::confirm::ConfirmationLedger,
        clock: &dyn kr_pairing::platform::PairingClock,
        request: &kr_protocol::pairing::OwnerConfirmationRequest,
        proof: &kr_protocol::pairing::OwnerConfirmationProof,
        signer: &kr_protocol::scalars::AuthorisationKey,
        enrolment: kr_pairing::confirm::HostEnrolment,
        destination_keys: Option<&kr_protocol::pairing::DevicePublicKeys>,
    ) -> Result<Self> {
        let action_digest = plan.action_digest()?;
        let expectation = kr_pairing::confirm::ConfirmationExpectation {
            action: TransferPlan::sensitive_action(),
            action_digest,
            host_device_id: request.host_device_id,
            host_endpoint_id: request.host_endpoint_id,
            destination_keys,
            destination_rights: &plan.actions,
        };
        kr_pairing::confirm::accept_confirmation(
            ledger,
            clock,
            request,
            proof,
            signer,
            enrolment,
            &expectation,
        )
        .map_err(|error| ControllerError::PermissionDenied {
            detail: format!("the owner's confirmation does not authorise this transfer: {error}"),
        })?;
        Ok(Self { action_digest })
    }

    /// The digest this confirmation is about.
    #[must_use]
    pub const fn action_digest(&self) -> Digest256 {
        self.action_digest
    }

    /// Checks that this confirmation is about this plan.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::PermissionDenied`] when it is about something else.
    pub fn covers(&self, plan: &TransferPlan) -> Result<()> {
        if plan.action_digest()? == self.action_digest {
            return Ok(());
        }
        Err(ControllerError::PermissionDenied {
            detail: "the owner's confirmation is for a different transfer".to_owned(),
        })
    }
}

/// What a completed transfer did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlTransfer {
    /// The plan it carried out.
    pub plan: TransferPlan,
    /// The grant the recipient now holds.
    pub issued: Grant,
    /// What revoking the transferring device's grant did, including its descendants.
    pub revoked: GrantRevocation,
}

/// Checks that a transferring device may hand over the control it is offering.
///
/// # Errors
///
/// Returns [`ControllerError::PermissionDenied`] when the transferring grant does not carry
/// `session.share`, does not cover the session, or does not carry a right the plan hands over.
pub fn check_transfer(plan: &TransferPlan, holding: &Grant) -> Result<()> {
    if holding.grant_id != plan.revoking_grant_id {
        return Err(ControllerError::PermissionDenied {
            detail: "a transfer gives up the grant the transferring device actually holds"
                .to_owned(),
        });
    }
    if holding.recipient_device_id != plan.from_device_id {
        return Err(ControllerError::PermissionDenied {
            detail: "that grant is not the transferring device's".to_owned(),
        });
    }
    if !holding.permits(ActionRight::SessionShare) {
        return Err(ControllerError::PermissionDenied {
            detail: "transferring control needs session.share".to_owned(),
        });
    }
    if !holding.session_selector.admits(plan.session_id) {
        return Err(ControllerError::PermissionDenied {
            detail: "that grant does not cover the session being transferred".to_owned(),
        });
    }
    if let Some(right) = plan.actions.iter().find(|right| !holding.permits(**right)) {
        return Err(ControllerError::PermissionDenied {
            detail: format!(
                "this transfer hands over {}, which the transferring grant does not carry",
                right.as_str()
            ),
        });
    }
    Ok(())
}

/// The actions an owner-role transfer hands over, narrowed to what the transferring grant holds.
///
/// A transferring device that is itself a controller rather than an owner hands over a
/// controller's actions. Narrowing here rather than refusing keeps the operation usable while
/// [`check_transfer`] keeps it honest: the result is never wider than what was held.
#[must_use]
pub fn transferable_actions(holding: &Grant) -> CanonicalSet<ActionRight> {
    SessionRole::Owner
        .default_actions()
        .iter()
        .copied()
        .filter(|right| holding.permits(*right))
        .collect()
}
