//! Evidence that an owner confirmed one exact sensitive action.
//!
//! Section 10 names six actions that need a fresh owner confirmation bound to the exact action
//! digest, host, nonce and short expiry, and says outright that operating-system peer credentials
//! are not that confirmation. Two of them are the catalogue's: trusting a repository root and
//! granting an executable or native-bridge capability.
//!
//! What lives here is the part every one of them shares. [`ConfirmedAction`] is the evidence, and
//! the only way to get one is [`ConfirmedAction::verify`], which runs the pairing ceremony's own
//! acceptance against the challenge this host issued and consumes it. A Boolean is something any
//! caller can write; this is not.
//!
//! The plans the digests are built from are in `kr_protocol::confirmation`, where the owner's own
//! device builds them again from what it is shown. A confirmation authorises one digest, so a plan
//! that left out a field would be a confirmation that could be carried to a different root, a
//! different release or a wider capability set.

use kr_pairing::confirm::{ConfirmationExpectation, ConfirmationLedger, HostEnrolment};
use kr_pairing::platform::{BootIdentity, PairingClock};
use kr_protocol::ids::DeviceId;
use kr_protocol::pairing::{OwnerConfirmationProof, OwnerConfirmationRequest, SensitiveAction};
use kr_protocol::scalars::{AuthorisationKey, Digest256};

use crate::error::{ControllerError, Result};

/// Evidence that an owner confirmed one exact action, still inside the lifetime it was issued for.
///
/// [`Self::verify`] is the only constructor: the challenge has to be one this host issued and is
/// still holding, the proof has to answer it under the enrolled signer, and the challenge is
/// consumed. [`Self::covers`] then checks that the evidence is about *this* action, which is what
/// stops a confirmation for one action being carried to another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfirmedAction {
    action_digest: Digest256,
    /// The host the challenge was verified against. Evidence accepted for one host says nothing
    /// about another, so this travels with it and is checked where the effect happens.
    host_device_id: DeviceId,
    /// The boot the confirmation was accepted in, and the monotonic moment its lifetime ends.
    ///
    /// The wall clock is what the signer reads; the deadline this host enforces is monotonic and
    /// tied to a boot, because a clock wound back would otherwise lengthen a confirmation.
    boot: BootIdentity,
    expires_at_monotonic_ms: u64,
}

impl ConfirmedAction {
    /// Verifies and consumes the owner's confirmation for one exact action.
    ///
    /// The expectation is built by the caller from what it is about to do, never from the
    /// challenge the caller presented: a challenge that supplied its own host identity and its own
    /// digest would prove that somebody issued a challenge, not that this host's owner approved
    /// this action.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::PermissionDenied`] when this host holds no such outstanding
    /// challenge, or when the proof does not answer it.
    pub fn verify(
        expectation: &ConfirmationExpectation<'_>,
        ledger: &mut ConfirmationLedger,
        clock: &dyn PairingClock,
        request: &OwnerConfirmationRequest,
        proof: &OwnerConfirmationProof,
        signer: &AuthorisationKey,
        enrolment: HostEnrolment,
    ) -> Result<Self> {
        // The deadline this host is enforcing for this challenge, read from the ledger before the
        // acceptance consumes it. It is monotonic and belongs to a boot, which is what makes it a
        // deadline the wall clock cannot lengthen; recomputing one from `expires_at_ms` would take
        // whatever the wall clock said at acceptance, and a clock that had gone back in the
        // meantime would hand the confirmation more life than it was issued with.
        let (boot, expires_at_monotonic_ms) =
            ledger.deadline(request.confirmation_id).ok_or_else(|| {
                ControllerError::PermissionDenied {
                    detail: "this host has no such outstanding confirmation".to_owned(),
                }
            })?;
        kr_pairing::confirm::accept_confirmation(
            ledger,
            clock,
            request,
            proof,
            signer,
            enrolment,
            expectation,
        )
        .map_err(|error| ControllerError::PermissionDenied {
            detail: format!("the owner's confirmation does not authorise this action: {error}"),
        })?;
        Ok(Self {
            action_digest: expectation.action_digest,
            host_device_id: expectation.host_device_id,
            boot,
            expires_at_monotonic_ms,
        })
    }

    /// The digest this confirmation is about.
    #[must_use]
    pub const fn action_digest(&self) -> Digest256 {
        self.action_digest
    }

    /// Checks that this confirmation is about this action, and is still inside its own deadline.
    ///
    /// `subject` is the noun a refusal names, so a caller reads about the thing it asked for
    /// rather than about a digest.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::PermissionDenied`] when it is about something else, when it was
    /// accepted for another host or in an earlier boot, or when the challenge's short expiry has
    /// passed: a confirmation is for a decision the owner is making now, and one carried past its
    /// deadline is not that.
    pub fn covers(
        &self,
        action_digest: Digest256,
        host_device_id: DeviceId,
        clock: &dyn PairingClock,
        subject: &str,
    ) -> Result<()> {
        if action_digest != self.action_digest {
            return Err(ControllerError::PermissionDenied {
                detail: format!("the owner's confirmation is for a different {subject}"),
            });
        }
        if self.host_device_id != host_device_id {
            return Err(ControllerError::PermissionDenied {
                detail: "the owner's confirmation was accepted for another host".to_owned(),
            });
        }
        if clock.boot_identity() != self.boot {
            return Err(ControllerError::PermissionDenied {
                detail: "the owner's confirmation was accepted in an earlier boot".to_owned(),
            });
        }
        if clock.monotonic_ms() >= self.expires_at_monotonic_ms {
            return Err(ControllerError::PermissionDenied {
                detail: format!("the owner's confirmation for this {subject} has expired"),
            });
        }
        Ok(())
    }
}

/// Where a sensitive action's owner confirmation is checked.
///
/// The catalogue's two confirmed methods reach the ceremony through this rather than through the
/// network host directly, so the check is the same one whether a host is on a network or not and a
/// test can drive a real ceremony without one.
pub trait OwnerConfirmations: Send + Sync {
    /// Accepts the owner's confirmation of one exact action and consumes its challenge.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::PermissionDenied`] when this host issued no such challenge, or
    /// when the proof does not answer it.
    fn accept(
        &self,
        action: SensitiveAction,
        action_digest: Digest256,
        proof: &OwnerConfirmationProof,
    ) -> Result<ConfirmedAction>;

    /// Spends, once, the oldest answer an owner device recorded to a challenge this host issued
    /// for exactly this action, and returns the evidence of it.
    ///
    /// This is how a caller that has no owner key of its own, a terminal, has an owner's
    /// confirmation spent: it asked the host for the challenge, an owner device answered it, and
    /// the effect it repeats spends that answer. An answer whose signer has lost its authority is
    /// passed over.
    ///
    /// # Errors
    ///
    /// Returns `OWNER_CONFIRMATION_REQUIRED` while no answered challenge equals this action, so a
    /// caller can ask again until the challenge's deadline.
    fn accept_recorded(
        &self,
        action: SensitiveAction,
        action_digest: Digest256,
    ) -> Result<ConfirmedAction>;

    /// The host a confirmation accepted here is about.
    fn host_device_id(&self) -> DeviceId;

    /// The clock this host measures a confirmation's remaining lifetime on.
    fn clock(&self) -> &dyn PairingClock;
}
