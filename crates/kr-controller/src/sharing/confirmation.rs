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
//! The plans beside it are what the digests are built from. A confirmation authorises one digest,
//! so a plan that left out a field would be a confirmation that could be carried to a different
//! root, a different release or a wider capability set.

use kr_pairing::confirm::{ConfirmationExpectation, ConfirmationLedger, HostEnrolment};
use kr_pairing::platform::{BootIdentity, PairingClock};
use kr_protocol::ids::{DeviceId, EnvironmentId, PluginId};
use kr_protocol::pairing::{OwnerConfirmationProof, OwnerConfirmationRequest, SensitiveAction};
use kr_protocol::scalars::{AuthorisationKey, CanonicalSet, Digest256};

use crate::error::{ControllerError, Result};

/// Adopting a trust root for a repository, as the owner is asked to confirm it.
///
/// The digest covers the root's identity and the trust the enrolment would carry, so a
/// confirmation obtained for one repository cannot enrol another, cannot swap the root underneath
/// it and cannot widen the ceiling it was shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogueTrustPlan {
    /// The environment the repository is enrolled in.
    pub environment_id: EnvironmentId,
    /// This host's identifier for the repository.
    pub catalogue_id: String,
    /// The digest of the exact root bytes being adopted.
    pub root_digest: String,
    /// The key identifiers the root declares for its own role, which is what the owner is trusting.
    pub root_key_ids: CanonicalSet<String>,
    /// The capabilities the enrolment would permit beyond the default ceiling.
    pub ceiling: CanonicalSet<String>,
}

impl CatalogueTrustPlan {
    /// The sensitive action a confirmation for this plan is bound to.
    #[must_use]
    pub const fn sensitive_action() -> SensitiveAction {
        SensitiveAction::TrustRepositoryRoot
    }

    /// The digest an owner's confirmation for this exact enrolment covers.
    ///
    /// # Errors
    ///
    /// Returns an encoding error when the plan cannot be represented in KR-CBOR-1.
    pub fn action_digest(&self) -> Result<Digest256> {
        digest_of(&(
            "kr-catalogue-trust/1",
            self.environment_id,
            &self.catalogue_id,
            &self.root_digest,
            &self.root_key_ids,
            &self.ceiling,
        ))
    }
}

/// Granting an installed package a capability, as the owner is asked to confirm it.
///
/// The release is part of the digest. A grant confirmed for the release in front of the owner
/// cannot be spent on whatever is installed by the time it arrives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginGrantPlan {
    /// The environment the installation belongs to.
    pub environment_id: EnvironmentId,
    /// The package.
    pub plugin_id: PluginId,
    /// The release the grant is for.
    pub version: String,
    /// The exact package hash the grant is for.
    pub package_digest: String,
    /// The capabilities the installation would hold after the change, as a whole set.
    pub grant: CanonicalSet<String>,
}

impl PluginGrantPlan {
    /// The sensitive action a confirmation for this plan is bound to.
    #[must_use]
    pub const fn sensitive_action() -> SensitiveAction {
        SensitiveAction::GrantExecutableCapability
    }

    /// The digest an owner's confirmation for this exact grant covers.
    ///
    /// # Errors
    ///
    /// Returns an encoding error when the plan cannot be represented in KR-CBOR-1.
    pub fn action_digest(&self) -> Result<Digest256> {
        digest_of(&(
            "kr-plugin-grant/1",
            self.environment_id,
            &self.plugin_id,
            &self.version,
            &self.package_digest,
            &self.grant,
        ))
    }
}

/// Installing a package where the installation needs the owner's confirmation, as the owner is
/// asked to confirm it.
///
/// What an installation may do depends on the repository it comes from as well as on its grant, so
/// the repository and its ceiling are in the digest with the release and the grant: a confirmation
/// shown for an installation from one repository cannot install the same package from another
/// that permits it more.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginInstallPlan {
    /// The environment the package is installed in.
    pub environment_id: EnvironmentId,
    /// This host's identifier for the repository the package is installed from.
    pub catalogue_id: String,
    /// The capabilities that repository's ceiling permits, as `catalogue.list` reports them.
    pub ceiling: CanonicalSet<String>,
    /// The package.
    pub plugin_id: PluginId,
    /// The release being installed.
    pub version: String,
    /// The exact package hash being installed.
    pub package_digest: String,
    /// The capabilities the installation is granted, as a whole set.
    pub grant: CanonicalSet<String>,
}

impl PluginInstallPlan {
    /// The sensitive action a confirmation for this plan is bound to.
    #[must_use]
    pub const fn sensitive_action() -> SensitiveAction {
        SensitiveAction::GrantExecutableCapability
    }

    /// The digest an owner's confirmation for this exact installation covers.
    ///
    /// # Errors
    ///
    /// Returns an encoding error when the plan cannot be represented in KR-CBOR-1.
    pub fn action_digest(&self) -> Result<Digest256> {
        digest_of(&(
            "kr-plugin-install/1",
            self.environment_id,
            &self.catalogue_id,
            &self.ceiling,
            &self.plugin_id,
            &self.version,
            &self.package_digest,
            &self.grant,
        ))
    }
}

fn digest_of<T: serde::Serialize>(value: &T) -> Result<Digest256> {
    let value = kr_cbor::to_canonical_value(value)
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
    Ok(Digest256::from_bytes(kr_cbor::sha256(&kr_cbor::encode(
        &value,
    ))))
}

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

    /// The host a confirmation accepted here is about.
    fn host_device_id(&self) -> DeviceId;

    /// The clock this host measures a confirmation's remaining lifetime on.
    fn clock(&self) -> &dyn PairingClock;
}

#[cfg(test)]
mod tests {
    use super::{CatalogueTrustPlan, PluginGrantPlan, PluginInstallPlan};
    use kr_protocol::ids::{EnvironmentId, PluginId};
    use kr_protocol::scalars::{CanonicalSet, Uuid};

    fn trust_plan() -> CatalogueTrustPlan {
        CatalogueTrustPlan {
            environment_id: EnvironmentId::new(Uuid::NIL),
            catalogue_id: "official".to_owned(),
            root_digest: "sha256:aa".to_owned(),
            root_key_ids: ["k1".to_owned()].into_iter().collect::<CanonicalSet<_>>(),
            ceiling: CanonicalSet::new(),
        }
    }

    fn grant_plan() -> PluginGrantPlan {
        PluginGrantPlan {
            environment_id: EnvironmentId::new(Uuid::NIL),
            plugin_id: PluginId::new("kalareach/example").expect("a plugin id"),
            version: "0.1.0".to_owned(),
            package_digest: "sha256:bb".to_owned(),
            grant: CanonicalSet::new(),
        }
    }

    #[test]
    fn a_wider_ceiling_is_a_different_action() {
        let narrow = trust_plan().action_digest().expect("a digest");
        let wide = CatalogueTrustPlan {
            ceiling: ["terminal.stream".to_owned()]
                .into_iter()
                .collect::<CanonicalSet<_>>(),
            ..trust_plan()
        }
        .action_digest()
        .expect("a digest");
        assert_ne!(narrow, wide);
    }

    #[test]
    fn another_root_is_a_different_action() {
        let first = trust_plan().action_digest().expect("a digest");
        let second = CatalogueTrustPlan {
            root_digest: "sha256:cc".to_owned(),
            ..trust_plan()
        }
        .action_digest()
        .expect("a digest");
        assert_ne!(first, second);
    }

    #[test]
    fn another_release_is_a_different_grant() {
        let first = grant_plan().action_digest().expect("a digest");
        let second = PluginGrantPlan {
            package_digest: "sha256:cc".to_owned(),
            ..grant_plan()
        }
        .action_digest()
        .expect("a digest");
        assert_ne!(first, second);
    }

    fn install_plan() -> PluginInstallPlan {
        PluginInstallPlan {
            environment_id: EnvironmentId::new(Uuid::NIL),
            catalogue_id: "official".to_owned(),
            ceiling: ["metadata.match".to_owned()]
                .into_iter()
                .collect::<CanonicalSet<_>>(),
            plugin_id: PluginId::new("kalareach/example").expect("a plugin id"),
            version: "0.1.0".to_owned(),
            package_digest: "sha256:bb".to_owned(),
            grant: CanonicalSet::new(),
        }
    }

    #[test]
    fn the_two_plans_never_share_a_digest() {
        assert_ne!(
            trust_plan().action_digest().expect("a digest"),
            grant_plan().action_digest().expect("a digest")
        );
    }

    /// Each part of an installation is part of what the owner confirmed: the repository it comes
    /// from and that repository's ceiling as much as the release and the grant. And confirming an
    /// installation is never confirming a grant, whatever the two name.
    #[test]
    fn every_part_of_an_installation_is_a_different_action() {
        let confirmed = install_plan().action_digest().expect("a digest");
        let changed = [
            PluginInstallPlan {
                catalogue_id: "wide".to_owned(),
                ..install_plan()
            },
            PluginInstallPlan {
                ceiling: ["metadata.match".to_owned(), "terminal.stream".to_owned()]
                    .into_iter()
                    .collect::<CanonicalSet<_>>(),
                ..install_plan()
            },
            PluginInstallPlan {
                version: "0.2.0".to_owned(),
                ..install_plan()
            },
            PluginInstallPlan {
                package_digest: "sha256:cc".to_owned(),
                ..install_plan()
            },
            PluginInstallPlan {
                grant: ["terminal.input".to_owned()]
                    .into_iter()
                    .collect::<CanonicalSet<_>>(),
                ..install_plan()
            },
        ];
        for plan in changed {
            assert_ne!(
                confirmed,
                plan.action_digest().expect("a digest"),
                "{plan:?}"
            );
        }
        assert_ne!(confirmed, grant_plan().action_digest().expect("a digest"));
    }
}
