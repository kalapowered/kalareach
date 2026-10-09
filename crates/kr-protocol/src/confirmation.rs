//! The owner-confirmation methods: `owner.confirmation.request`, `owner.confirmation.pending` and
//! `owner.confirmation.complete`.
//!
//! Section 10 gives six actions a fresh owner confirmation bound to the exact action digest,
//! destination keys and rights, host, nonce and a short expiry. The challenge and the proof are
//! `pairing::OwnerConfirmationRequest` and `pairing::OwnerConfirmationProof`; what lives here is
//! how a caller asks for one, how an owner device finds one to answer, and how the answer reaches
//! the host.
//!
//! Three rules shape these types:
//!
//! * **The host describes the action, never the caller.** A request names a subject; the host
//!   computes the digest, the destination and the rights from what it will actually do. A
//!   [`ConfirmationSubject::Described`] subject is the exception for the actions no served method
//!   performs yet, and it only ever authorises the effect whose own expectation matches it member
//!   for member.
//! * **An answer is not a spend.** `owner.confirmation.complete` verifies a proof and records it
//!   beside its challenge. The sensitive method consumes it later, once, and only when its own
//!   exact expectation matches, so no method takes a confirmation reference a caller could point
//!   at another action's approval.
//! * **The channel is inside the signature.** A session, plugin or contact-tool channel is never a
//!   confirmation, and the interactive controlling terminal is the initial bootstrap: while a host
//!   has no owner it confirms the first owner and the host's clock, and nothing else.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::account::PolicyAuthority;
use crate::ids::{
    ConfirmationId, EnvironmentId, InvitationId, OrganisationId, PluginId, PolicyKeyRevision,
};
use crate::invitation::{InviteGrantKind, InviteModeKind, PairCandidateView};
use crate::pairing::{
    ConfirmationChannel, DevicePublicKeys, OwnerConfirmationProof, OwnerConfirmationRequest,
    ProposedGrant, RendezvousOrigin, SensitiveAction,
};
use crate::rights::ActionRight;
use crate::scalars::{AuthorisationKey, CanonicalSet, Digest256, Nullable, TimestampMs};

/// What an owner confirms when it establishes a host's clock again.
///
/// The confirmation is bound to the digest of this value and of nothing else. The host asks for
/// it and an owner device checks it, so both compute it from this one definition.
pub const CLOCK_PURPOSE: &str = "kr-host-clock/1";

/// What an owner confirmation is asked for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ConfirmationSubject {
    /// Issuing a persistent pairing invitation proposing exactly this grant.
    ///
    /// The host binds [`crate::invitation::issuance_digest`] over all four members, so the
    /// approval issues exactly this mode at exactly this origin, and the grant's rights.
    IssueInvitation {
        /// How the invitation will be offered.
        mode: InviteModeKind,
        /// The rendezvous origin a code invitation reserves at. Null takes this host's default for
        /// a code invitation, and is the only value a direct invitation takes.
        rendezvous_origin: Nullable<RendezvousOrigin>,
        /// Which rules the proposal is checked against.
        grant_kind: InviteGrantKind,
        /// The exact rights the invitation will propose.
        proposed_grant: ProposedGrant,
    },
    /// Confirming the candidate that holds this invitation.
    ///
    /// The host reads the candidate it bound: its keys, the proposed rights and the digest over the
    /// exact transcript and bundles the owner is shown.
    ConfirmDevice {
        /// The invitation.
        invitation_id: InvitationId,
    },
    /// Adopting a repository's trust root, as this exact `catalogue.add` would.
    ///
    /// The host resolves the root's key identifiers, the ceiling and the repository from the
    /// request itself, so what an owner device shows and signs is what the effect then checks. The
    /// request carries no proof of its own here: a request that already carries one is not a thing
    /// to ask a confirmation for.
    CatalogueAdd(Box<crate::catalogue::CatalogueAddParams>),
    /// Installing a release, as this exact `plugin.install` would.
    ///
    /// The host resolves the repository's ceiling and, from the verified manifest of the exact
    /// package hash, the statement of what a native bridge does, so the owner device shows the
    /// publisher's own words and the confirmation covers them. The request carries no proof.
    PluginInstall(Box<crate::catalogue::PluginInstallParams>),
    /// Establishing this host's clock again after it was found to have gone backwards.
    EstablishClock,
    /// Opting this host into an organisation's policy and pinning the chain of keys that signs
    /// it, as this exact `organisation.enrol` would.
    ///
    /// The host verifies the whole chain first and shows the owner the root and the key signing
    /// now. The request carries the chain and no proof.
    EnrolOrganisation(Box<crate::organisation::OrganisationEnrolParams>),
    /// Making this host exclusively organisation-managed, or ending that, as this exact
    /// `organisation.exclusive.set` would.
    SetExclusiveManagement {
        /// True to make the host exclusively organisation-managed, false to end that.
        exclusive: bool,
    },
    /// An action its caller describes: enlarging a persistent grant, or trusting a repository
    /// root or granting an executable capability where the caller presents the answer's proof
    /// itself.
    ///
    /// The host issues a challenge for exactly this description and shows the owner device the
    /// description and nothing it resolved. Only an effect whose own expectation is equal to it,
    /// member for member, can consume the answer, and only by the proof being presented with the
    /// request: a method that spends a recorded answer takes only a challenge of the subject the
    /// host describes for it, [`ConfirmationSubject::CatalogueAdd`] or
    /// [`ConfirmationSubject::PluginInstall`].
    Described(DescribedAction),
}

/// An action described by its caller, which an owner device is shown as the caller's own words.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DescribedAction {
    /// The action. Only `enlarge_grant`, `trust_repository_root` and
    /// `grant_executable_capability` may be described.
    pub action: SensitiveAction,
    /// The digest of the exact effect.
    pub action_digest: Digest256,
    /// The keys the effect sends authority to, when it names a device.
    pub destination_keys: Nullable<DevicePublicKeys>,
    /// The rights the effect grants.
    pub destination_rights: CanonicalSet<ActionRight>,
}

impl DescribedAction {
    /// Returns true when this action may be described by a caller.
    ///
    /// The three pairing and clock actions have typed subjects the host fills in itself, so a
    /// description of one of them is refused rather than accepted as a second way to ask.
    #[must_use]
    pub const fn is_describable(&self) -> bool {
        matches!(
            self.action,
            SensitiveAction::EnlargeGrant
                | SensitiveAction::TrustRepositoryRoot
                | SensitiveAction::GrantExecutableCapability
        )
    }
}

/// The parameters of `owner.confirmation.request`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerConfirmationRequestParams {
    /// What the confirmation is for.
    pub subject: ConfirmationSubject,
}

/// The result of `owner.confirmation.request`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerConfirmationRequestResult {
    /// The challenge to answer. It is single use and expires after a short interval.
    pub request: OwnerConfirmationRequest,
    /// True while this host has no owner yet, so the interactive-terminal bootstrap applies.
    pub initial_bootstrap: bool,
}

/// The parameters of `owner.confirmation.pending`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerConfirmationPendingParams {}

/// What an owner is asked to approve, as its device shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ConfirmationDisplay {
    /// Issuing an invitation that proposes this grant.
    IssueInvitation {
        /// How it will be offered.
        mode: InviteModeKind,
        /// The origin a code invitation reserves at, the default included.
        rendezvous_origin: Nullable<RendezvousOrigin>,
        /// Which rules the proposal was checked against.
        grant_kind: InviteGrantKind,
        /// The complete proposed grant.
        proposed_grant: ProposedGrant,
    },
    /// Adding this candidate as a device.
    ConfirmDevice {
        /// The invitation it answered.
        invitation_id: InvitationId,
        /// The candidate, its keys and the value both devices display.
        candidate: PairCandidateView,
        /// The complete grant it would receive.
        proposed_grant: ProposedGrant,
    },
    /// Establishing this host's clock again.
    EstablishClock,
    /// Opting this host into this organisation's policy, pinned to these keys.
    EnrolOrganisation {
        /// The organisation.
        organisation_id: OrganisationId,
        /// The first key of its chain, which is its identity.
        root: PolicyKeyShown,
        /// The key signing now, which the host follows rotation from.
        anchor: PolicyKeyShown,
    },
    /// Making this host exclusively organisation-managed, or ending that.
    ExclusiveManagement {
        /// True to make the host exclusively organisation-managed, false to end that.
        exclusive: bool,
        /// The organisations the host is enrolled in, in ascending order.
        organisation_ids: Vec<OrganisationId>,
    },
    /// Adopting this repository's trust root.
    CatalogueAdd {
        /// The environment it is enrolled in.
        environment_id: crate::ids::EnvironmentId,
        /// This host's identifier for the repository.
        catalogue_id: String,
        /// What kind of repository it is.
        kind: crate::catalogue::CatalogueKind,
        /// Where its metadata lives.
        metadata_url: String,
        /// Where its targets live.
        targets_url: String,
        /// The digest of the exact root bytes being adopted.
        root_digest: String,
        /// The key identifiers the root declares for its own role: what the owner is trusting.
        root_key_ids: Vec<String>,
        /// The budgets its syncs and its cache run inside.
        budgets: crate::catalogue::CatalogueBudgets,
        /// The capabilities its packages may hold without a further grant, beyond the default
        /// ceiling.
        ceiling: Vec<String>,
    },
    /// Installing this release with this grant.
    PluginInstall {
        /// The environment the package is installed in.
        environment_id: crate::ids::EnvironmentId,
        /// The repository it is installed from.
        catalogue_id: String,
        /// The package.
        plugin_id: crate::ids::PluginId,
        /// The release.
        version: String,
        /// The exact package hash.
        package_digest: String,
        /// What the repository's ceiling permits by itself.
        ceiling: Vec<String>,
        /// The capabilities the installation is granted.
        grant: Vec<String>,
        /// What the release's own manifest says a native bridge it installs does, where it
        /// installs one. These are the publisher's words, taken by the host from the verified
        /// manifest of the exact package hash and covered by the confirmation; a device shows
        /// them apart from [`NATIVE_BRIDGE_NOTICE`], which is the host's.
        grant_statement: Nullable<String>,
    },
    /// An action its caller described.
    Described(DescribedAction),
}

/// What the host says, in its own words, of a native bridge an installation would place: it runs
/// in the application's own directory with the application's permissions, outside the sandbox
/// every other package runs in.
pub const NATIVE_BRIDGE_NOTICE: &str = "This package installs a native bridge: code in the \
     application's own directory that runs with the application's permissions, outside the plugin \
     sandbox. The publisher's own statement of what it does follows.";

/// Adopting a repository's trust root, as the owner is asked to confirm it.
///
/// The digest covers everything an owner device is shown: the repository's name, kind and
/// locations, the root's identity, the budgets it runs inside and the ceiling the enrolment
/// would carry. A confirmation obtained for one repository cannot enrol another, cannot swap the
/// root, the locations or the budgets underneath it, and cannot widen the ceiling it was shown.
/// The host builds the digest from the request, and an owner device builds it again from what it
/// is shown, so both come from this one definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogueTrustPlan {
    /// The environment the repository is enrolled in.
    pub environment_id: EnvironmentId,
    /// This host's identifier for the repository.
    pub catalogue_id: String,
    /// What kind of repository it is.
    pub kind: crate::catalogue::CatalogueKind,
    /// Where its metadata lives.
    pub metadata_url: String,
    /// Where its targets live.
    pub targets_url: String,
    /// The digest of the exact root bytes being adopted.
    pub root_digest: String,
    /// The key identifiers the root declares for its own role, which is what the owner is trusting.
    pub root_key_ids: CanonicalSet<String>,
    /// The budgets its syncs and its cache run inside.
    pub budgets: crate::catalogue::CatalogueBudgets,
    /// The capabilities the enrolment would permit beyond the default ceiling.
    pub ceiling: CanonicalSet<String>,
}

impl CatalogueTrustPlan {
    /// The sensitive action a confirmation for this plan is bound to.
    #[must_use]
    pub const fn sensitive_action() -> SensitiveAction {
        SensitiveAction::TrustRepositoryRoot
    }

    /// The plan the request `params` names, for the root whose digest and key identifiers are
    /// given. Everything but the root's identity, which only a reader of the root can state, is
    /// the request's own, so the host that builds a plan to describe a request and the client that
    /// builds one to confirm it start from the same words.
    #[must_use]
    pub fn of_request(
        params: &crate::catalogue::CatalogueAddParams,
        root_digest: String,
        root_key_ids: CanonicalSet<String>,
    ) -> Self {
        Self {
            environment_id: params.environment_id,
            catalogue_id: params.catalogue_id.clone(),
            kind: params.kind,
            metadata_url: params.metadata_url.clone(),
            targets_url: params.targets_url.clone(),
            root_digest,
            root_key_ids,
            budgets: params.budgets,
            ceiling: params.ceiling.iter().cloned().collect(),
        }
    }

    /// The digest an owner's confirmation for this exact enrolment covers.
    ///
    /// # Errors
    ///
    /// Returns an encoding error when the plan cannot be represented in KR-CBOR-1.
    pub fn action_digest(&self) -> Result<Digest256, kr_cbor::CborError> {
        digest_of(&(
            "kr-catalogue-trust/2",
            self.environment_id,
            &self.catalogue_id,
            self.kind,
            &self.metadata_url,
            &self.targets_url,
            &self.root_digest,
            &self.root_key_ids,
            self.budgets,
            &self.ceiling,
        ))
    }

    /// What an owner device is shown of this plan.
    #[must_use]
    pub fn display(&self) -> ConfirmationDisplay {
        ConfirmationDisplay::CatalogueAdd {
            environment_id: self.environment_id,
            catalogue_id: self.catalogue_id.clone(),
            kind: self.kind,
            metadata_url: self.metadata_url.clone(),
            targets_url: self.targets_url.clone(),
            root_digest: self.root_digest.clone(),
            root_key_ids: self.root_key_ids.iter().cloned().collect(),
            budgets: self.budgets,
            ceiling: self.ceiling.iter().cloned().collect(),
        }
    }

    /// The plan an owner device is shown, or `None` when the display is another subject's or
    /// lists a set in an order that is not canonical, which no host that follows this definition
    /// sends.
    #[must_use]
    pub fn of_display(display: &ConfirmationDisplay) -> Option<Self> {
        let ConfirmationDisplay::CatalogueAdd {
            environment_id,
            catalogue_id,
            kind,
            metadata_url,
            targets_url,
            root_digest,
            root_key_ids,
            budgets,
            ceiling,
        } = display
        else {
            return None;
        };
        Some(Self {
            environment_id: *environment_id,
            catalogue_id: catalogue_id.clone(),
            kind: *kind,
            metadata_url: metadata_url.clone(),
            targets_url: targets_url.clone(),
            root_digest: root_digest.clone(),
            root_key_ids: canonical(root_key_ids)?,
            budgets: *budgets,
            ceiling: canonical(ceiling)?,
        })
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
    pub fn action_digest(&self) -> Result<Digest256, kr_cbor::CborError> {
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
/// that permits it more. An owner device builds the same digest from what it is shown.
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
    /// What the release's manifest says a native bridge it installs does, which the owner reads
    /// before confirming. It is in the digest, so a confirmation shown one statement cannot
    /// install a release whose manifest says another.
    pub grant_statement: Option<String>,
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
    pub fn action_digest(&self) -> Result<Digest256, kr_cbor::CborError> {
        digest_of(&(
            "kr-plugin-install/2",
            self.environment_id,
            &self.catalogue_id,
            &self.ceiling,
            &self.plugin_id,
            &self.version,
            &self.package_digest,
            &self.grant,
            &self.grant_statement,
        ))
    }

    /// What an owner device is shown of this plan.
    #[must_use]
    pub fn display(&self) -> ConfirmationDisplay {
        ConfirmationDisplay::PluginInstall {
            environment_id: self.environment_id,
            catalogue_id: self.catalogue_id.clone(),
            plugin_id: self.plugin_id.clone(),
            version: self.version.clone(),
            package_digest: self.package_digest.clone(),
            ceiling: self.ceiling.iter().cloned().collect(),
            grant: self.grant.iter().cloned().collect(),
            grant_statement: Nullable(self.grant_statement.clone()),
        }
    }

    /// The plan an owner device is shown, or `None` when the display is another subject's or
    /// lists a set in an order that is not canonical, which no host that follows this definition
    /// sends.
    #[must_use]
    pub fn of_display(display: &ConfirmationDisplay) -> Option<Self> {
        let ConfirmationDisplay::PluginInstall {
            environment_id,
            catalogue_id,
            plugin_id,
            version,
            package_digest,
            ceiling,
            grant,
            grant_statement,
        } = display
        else {
            return None;
        };
        Some(Self {
            environment_id: *environment_id,
            catalogue_id: catalogue_id.clone(),
            ceiling: canonical(ceiling)?,
            plugin_id: plugin_id.clone(),
            version: version.clone(),
            package_digest: package_digest.clone(),
            grant: canonical(grant)?,
            grant_statement: grant_statement.0.clone(),
        })
    }
}

/// One key of an organisation's chain, as an owner is shown it and as the confirmation covers it.
///
/// The whole key is shown, not a fingerprint of it, because the owner device builds the digest
/// again from what it is shown. The moment the revision took over signing is covered too: the host
/// keeps the link it pins byte for byte and decides every later lease against it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyKeyShown {
    /// The revision of the key.
    pub revision: PolicyKeyRevision,
    /// The Ed25519 public key.
    pub public_key: AuthorisationKey,
    /// When this revision took over signing, in UTC milliseconds.
    pub not_before_ms: TimestampMs,
}

/// Opting a host into an organisation's policy, as the owner is asked to confirm it.
///
/// The digest covers the organisation, its first key and the key signing now. A confirmation
/// obtained for one chain cannot enrol another organisation, cannot swap the key the host will
/// follow rotation from, and goes stale when the organisation rotates in between: the chain is
/// then another chain and needs a new confirmation. The host builds the digest from the chain it
/// verified, and an owner device builds it again from what it is shown, so both come from this one
/// definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrganisationEnrolPlan {
    /// The organisation.
    pub organisation_id: OrganisationId,
    /// The first key of its chain.
    pub root: PolicyKeyShown,
    /// The key signing now.
    pub anchor: PolicyKeyShown,
}

impl OrganisationEnrolPlan {
    /// The sensitive action a confirmation for this plan is bound to.
    #[must_use]
    pub const fn sensitive_action() -> SensitiveAction {
        SensitiveAction::ChangeHostAuthority
    }

    /// The plan a published chain states, or `None` when the chain has no link. The chain's own
    /// signatures are the host's to verify before it asks anything of an owner.
    #[must_use]
    pub fn of_authority(authority: &PolicyAuthority) -> Option<Self> {
        let shown = |link: &crate::account::PolicyAuthorityLink| PolicyKeyShown {
            revision: link.payload.key_revision,
            public_key: link.payload.public_key,
            not_before_ms: link.payload.not_before_ms,
        };
        Some(Self {
            organisation_id: authority.organisation_id,
            root: shown(authority.chain.first()?),
            anchor: shown(authority.chain.last()?),
        })
    }

    /// The digest an owner's confirmation for this exact enrolment covers.
    ///
    /// # Errors
    ///
    /// Returns an encoding error when the plan cannot be represented in KR-CBOR-1.
    pub fn action_digest(&self) -> Result<Digest256, kr_cbor::CborError> {
        digest_of(&(
            "kr-organisation/enrol/1",
            self.organisation_id,
            self.root.revision,
            self.root.public_key,
            self.root.not_before_ms,
            self.anchor.revision,
            self.anchor.public_key,
            self.anchor.not_before_ms,
        ))
    }

    /// What an owner device is shown of this plan.
    #[must_use]
    pub const fn display(&self) -> ConfirmationDisplay {
        ConfirmationDisplay::EnrolOrganisation {
            organisation_id: self.organisation_id,
            root: self.root,
            anchor: self.anchor,
        }
    }

    /// The plan an owner device is shown, or `None` when the display is another subject's.
    #[must_use]
    pub const fn of_display(display: &ConfirmationDisplay) -> Option<Self> {
        let ConfirmationDisplay::EnrolOrganisation {
            organisation_id,
            root,
            anchor,
        } = display
        else {
            return None;
        };
        Some(Self {
            organisation_id: *organisation_id,
            root: *root,
            anchor: *anchor,
        })
    }
}

/// Making a host exclusively organisation-managed, or ending that, as the owner is asked to
/// confirm it.
///
/// The digest covers the new value and the organisations the host is enrolled in, so a
/// confirmation for one state of the host is not carried to another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExclusiveManagementPlan {
    /// True to make the host exclusively organisation-managed, false to end that.
    pub exclusive: bool,
    /// The organisations the host is enrolled in.
    pub organisation_ids: CanonicalSet<OrganisationId>,
}

impl ExclusiveManagementPlan {
    /// The sensitive action a confirmation for this plan is bound to.
    #[must_use]
    pub const fn sensitive_action() -> SensitiveAction {
        SensitiveAction::ChangeHostAuthority
    }

    /// The digest an owner's confirmation for this exact change covers.
    ///
    /// # Errors
    ///
    /// Returns an encoding error when the plan cannot be represented in KR-CBOR-1.
    pub fn action_digest(&self) -> Result<Digest256, kr_cbor::CborError> {
        digest_of(&(
            "kr-organisation/exclusive/1",
            self.exclusive,
            &self.organisation_ids,
        ))
    }

    /// What an owner device is shown of this plan.
    #[must_use]
    pub fn display(&self) -> ConfirmationDisplay {
        ConfirmationDisplay::ExclusiveManagement {
            exclusive: self.exclusive,
            organisation_ids: self.organisation_ids.iter().copied().collect(),
        }
    }

    /// The plan an owner device is shown, or `None` when the display is another subject's or
    /// lists the organisations in an order that is not ascending, which no host that follows this
    /// definition sends.
    #[must_use]
    pub fn of_display(display: &ConfirmationDisplay) -> Option<Self> {
        let ConfirmationDisplay::ExclusiveManagement {
            exclusive,
            organisation_ids,
        } = display
        else {
            return None;
        };
        let set: CanonicalSet<OrganisationId> = organisation_ids.iter().copied().collect();
        set.iter().eq(organisation_ids.iter()).then_some(Self {
            exclusive: *exclusive,
            organisation_ids: set,
        })
    }
}

/// The set a list names, or `None` when the list is not strictly ascending: a set a host shows is
/// shown in its canonical order, and one that is not has not been through this definition.
fn canonical(list: &[String]) -> Option<CanonicalSet<String>> {
    let set: CanonicalSet<String> = list.iter().cloned().collect();
    set.iter().eq(list.iter()).then_some(set)
}

fn digest_of<T: Serialize>(value: &T) -> Result<Digest256, kr_cbor::CborError> {
    let value = kr_cbor::to_canonical_value(value)?;
    Ok(Digest256::from_bytes(kr_cbor::sha256(&kr_cbor::encode(
        &value,
    ))))
}

/// One challenge an owner can still answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PendingConfirmation {
    /// The challenge, exactly as a proof must answer it.
    pub request: OwnerConfirmationRequest,
    /// What it approves.
    pub display: ConfirmationDisplay,
    /// True once a proof has answered it and it waits for its action.
    pub answered: bool,
}

/// The result of `owner.confirmation.pending`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerConfirmationPendingResult {
    /// The challenges still outstanding, oldest first.
    pub pending: Vec<PendingConfirmation>,
}

/// The parameters of `owner.confirmation.complete`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerConfirmationCompleteParams {
    /// The proof, carrying the challenge it answers.
    pub proof: OwnerConfirmationProof,
    /// The key a bootstrap proof is signed with.
    ///
    /// Present only for the `local_bootstrap_terminal` channel, which a host accepts only while it
    /// has no owner, only from local IPC and only for establishing its first owner or its clock.
    /// The key proves possession and nothing else: the evidence is the local caller at an
    /// interactive terminal outside a KalaReach session.
    pub bootstrap_signer: Nullable<AuthorisationKey>,
}

/// The result of `owner.confirmation.complete`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OwnerConfirmationCompleteResult {
    /// The challenge the proof answered.
    pub confirmation_id: ConfirmationId,
    /// How the confirmation reached the host.
    pub channel: ConfirmationChannel,
    /// When the host recorded the answer, in UTC milliseconds.
    pub answered_at_ms: TimestampMs,
}

/// The parameters of `host.clock.establish`.
///
/// There are none: what the owner confirmed is the digest of [`CLOCK_PURPOSE`], and the effect is
/// the one the host takes when it trusts its own clock again.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostClockEstablishParams {}

/// The result of `host.clock.establish`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostClockEstablishResult {
    /// The owner confirmation this establishment spent, which the host's acceptance record names.
    pub confirmation_id: ConfirmationId,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalars::Uuid;

    fn described(action: SensitiveAction) -> DescribedAction {
        DescribedAction {
            action,
            action_digest: Digest256::from_bytes([7; 32]),
            destination_keys: Nullable::null(),
            destination_rights: CanonicalSet::new(),
        }
    }

    #[test]
    fn only_the_three_unserved_actions_may_be_described() {
        for action in [
            SensitiveAction::EnlargeGrant,
            SensitiveAction::TrustRepositoryRoot,
            SensitiveAction::GrantExecutableCapability,
        ] {
            assert!(described(action).is_describable(), "{action:?}");
        }
        for action in [
            SensitiveAction::IssueInvitation,
            SensitiveAction::ConfirmDevice,
            SensitiveAction::ChangeHostAuthority,
        ] {
            assert!(!described(action).is_describable(), "{action:?}");
        }
    }

    fn add_params() -> crate::catalogue::CatalogueAddParams {
        crate::catalogue::CatalogueAddParams {
            environment_id: crate::ids::EnvironmentId::new(Uuid::from_bytes([2; 16])),
            catalogue_id: "community".to_owned(),
            kind: crate::catalogue::CatalogueKind::Community,
            metadata_url: "https://repo.example/metadata/".to_owned(),
            targets_url: "https://repo.example/targets/".to_owned(),
            root: "cm9vdA==".to_owned(),
            budgets: crate::catalogue::CatalogueBudgets {
                metadata_bytes: crate::scalars::U64::new(1),
                metadata_entries: crate::scalars::U64::new(1),
                retained_generations: crate::scalars::U64::new(1),
                retained_metadata_bytes: crate::scalars::U64::new(1),
                payload_cache_bytes: crate::scalars::U64::new(1),
                full_offline_mirror: false,
            },
            ceiling: Vec::new(),
            owner_confirmation: Nullable::null(),
        }
    }

    fn install_params() -> crate::catalogue::PluginInstallParams {
        crate::catalogue::PluginInstallParams {
            environment_id: crate::ids::EnvironmentId::new(Uuid::from_bytes([2; 16])),
            catalogue_id: "community".to_owned(),
            plugin_id: crate::ids::PluginId::new("kalareach/example").expect("a plugin id"),
            version: "0.1.0".to_owned(),
            package_digest: "sha256:aa".to_owned(),
            grant: vec!["native_bridge.install".to_owned()],
            owner_confirmation: Nullable::null(),
        }
    }

    /// The two catalogue subjects name the exact request without its proof, and an owner device
    /// is shown what the host resolved from it, the publisher's statement apart from the host's
    /// own notice.
    #[test]
    fn a_catalogue_subject_and_what_is_shown_for_it_round_trip() {
        for subject in [
            ConfirmationSubject::CatalogueAdd(Box::new(add_params())),
            ConfirmationSubject::PluginInstall(Box::new(install_params())),
        ] {
            let params = OwnerConfirmationRequestParams { subject };
            let bytes = kr_cbor::to_canonical_vec(&params).expect("encodes");
            let decoded: OwnerConfirmationRequestParams =
                kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT).expect("decodes");
            assert_eq!(decoded, params);
        }
        for display in [
            ConfirmationDisplay::CatalogueAdd {
                environment_id: crate::ids::EnvironmentId::new(Uuid::from_bytes([2; 16])),
                catalogue_id: "community".to_owned(),
                kind: crate::catalogue::CatalogueKind::Community,
                metadata_url: "https://repo.example/metadata/".to_owned(),
                targets_url: "https://repo.example/targets/".to_owned(),
                root_digest: "sha256:aa".to_owned(),
                root_key_ids: vec!["k1".to_owned()],
                budgets: add_params().budgets,
                ceiling: Vec::new(),
            },
            ConfirmationDisplay::PluginInstall {
                environment_id: crate::ids::EnvironmentId::new(Uuid::from_bytes([2; 16])),
                catalogue_id: "community".to_owned(),
                plugin_id: crate::ids::PluginId::new("kalareach/example").expect("a plugin id"),
                version: "0.1.0".to_owned(),
                package_digest: "sha256:aa".to_owned(),
                ceiling: vec!["metadata.match".to_owned()],
                grant: vec!["native_bridge.install".to_owned()],
                grant_statement: Nullable::some("Installs three registration files".to_owned()),
            },
        ] {
            let bytes = kr_cbor::to_canonical_vec(&display).expect("encodes");
            let decoded: ConfirmationDisplay =
                kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT).expect("decodes");
            assert_eq!(decoded, display);
        }
        assert!(
            NATIVE_BRIDGE_NOTICE.contains("outside"),
            "the host's own sentence says the bridge runs outside the plugin sandbox"
        );
    }

    fn trust_plan() -> CatalogueTrustPlan {
        CatalogueTrustPlan::of_request(
            &add_params(),
            "sha256:aa".to_owned(),
            ["k1".to_owned()].into_iter().collect(),
        )
    }

    fn grant_plan() -> PluginGrantPlan {
        PluginGrantPlan {
            environment_id: crate::ids::EnvironmentId::new(Uuid::from_bytes([2; 16])),
            plugin_id: crate::ids::PluginId::new("kalareach/example").expect("a plugin id"),
            version: "0.1.0".to_owned(),
            package_digest: "sha256:bb".to_owned(),
            grant: CanonicalSet::new(),
        }
    }

    fn install_plan() -> PluginInstallPlan {
        PluginInstallPlan {
            environment_id: crate::ids::EnvironmentId::new(Uuid::from_bytes([2; 16])),
            catalogue_id: "community".to_owned(),
            ceiling: ["metadata.match".to_owned()].into_iter().collect(),
            plugin_id: crate::ids::PluginId::new("kalareach/example").expect("a plugin id"),
            version: "0.1.0".to_owned(),
            package_digest: "sha256:bb".to_owned(),
            grant: ["native_bridge.install".to_owned()].into_iter().collect(),
            grant_statement: Some("Installs three registration files".to_owned()),
        }
    }

    /// Every part of an enrolment an owner device shows is part of what the owner confirmed: the
    /// repository's name, kind and locations, the root, the budgets it runs inside and the
    /// ceiling. A confirmation for one enrolment is never a confirmation for another.
    #[test]
    fn every_part_of_an_enrolment_is_a_different_action() {
        let confirmed = trust_plan().action_digest().expect("a digest");
        let mut other_budgets = add_params().budgets;
        other_budgets.metadata_entries = crate::scalars::U64::new(2);
        let changed = [
            CatalogueTrustPlan {
                environment_id: crate::ids::EnvironmentId::new(Uuid::from_bytes([3; 16])),
                ..trust_plan()
            },
            CatalogueTrustPlan {
                catalogue_id: "elsewhere".to_owned(),
                ..trust_plan()
            },
            CatalogueTrustPlan {
                kind: crate::catalogue::CatalogueKind::Official,
                ..trust_plan()
            },
            CatalogueTrustPlan {
                metadata_url: "https://other.example/metadata/".to_owned(),
                ..trust_plan()
            },
            CatalogueTrustPlan {
                targets_url: "https://other.example/targets/".to_owned(),
                ..trust_plan()
            },
            CatalogueTrustPlan {
                root_digest: "sha256:cc".to_owned(),
                ..trust_plan()
            },
            CatalogueTrustPlan {
                root_key_ids: ["k1".to_owned(), "k2".to_owned()].into_iter().collect(),
                ..trust_plan()
            },
            CatalogueTrustPlan {
                budgets: other_budgets,
                ..trust_plan()
            },
            CatalogueTrustPlan {
                budgets: crate::catalogue::CatalogueBudgets {
                    full_offline_mirror: true,
                    ..add_params().budgets
                },
                ..trust_plan()
            },
            CatalogueTrustPlan {
                ceiling: ["terminal.stream".to_owned()].into_iter().collect(),
                ..trust_plan()
            },
        ];
        for plan in changed {
            assert_ne!(
                confirmed,
                plan.action_digest().expect("a digest"),
                "{plan:?}"
            );
        }
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

    /// Each part of an installation is part of what the owner confirmed: the repository it comes
    /// from and that repository's ceiling as much as the release and the grant. And confirming an
    /// installation is never confirming a grant or an enrolment, whatever they name.
    #[test]
    fn every_part_of_an_installation_is_a_different_action() {
        let confirmed = install_plan().action_digest().expect("a digest");
        let changed = [
            PluginInstallPlan {
                environment_id: crate::ids::EnvironmentId::new(Uuid::from_bytes([3; 16])),
                ..install_plan()
            },
            PluginInstallPlan {
                catalogue_id: "wide".to_owned(),
                ..install_plan()
            },
            PluginInstallPlan {
                ceiling: ["metadata.match".to_owned(), "terminal.stream".to_owned()]
                    .into_iter()
                    .collect(),
                ..install_plan()
            },
            PluginInstallPlan {
                plugin_id: crate::ids::PluginId::new("kalareach/other").expect("a plugin id"),
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
                grant: ["terminal.input".to_owned()].into_iter().collect(),
                ..install_plan()
            },
            PluginInstallPlan {
                grant_statement: Some("Installs three other files".to_owned()),
                ..install_plan()
            },
            PluginInstallPlan {
                grant_statement: None,
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
        assert_ne!(confirmed, trust_plan().action_digest().expect("a digest"));
    }

    /// What an owner device is shown is the plan, member for member: a device that builds the
    /// plan again from the display gets the digest the host built, and changing any member it
    /// shows changes the digest.
    #[test]
    fn a_display_states_the_plan_its_digest_covers() {
        let trust = trust_plan();
        assert_eq!(
            CatalogueTrustPlan::of_display(&trust.display()),
            Some(trust.clone())
        );
        let install = install_plan();
        assert_eq!(
            PluginInstallPlan::of_display(&install.display()),
            Some(install.clone())
        );
        // Each display is only its own plan's.
        assert_eq!(PluginInstallPlan::of_display(&trust.display()), None);
        assert_eq!(CatalogueTrustPlan::of_display(&install.display()), None);
        assert_eq!(
            CatalogueTrustPlan::of_display(&ConfirmationDisplay::EstablishClock),
            None
        );

        let ConfirmationDisplay::CatalogueAdd {
            environment_id,
            catalogue_id,
            kind,
            metadata_url,
            targets_url,
            root_digest,
            root_key_ids,
            budgets,
            ceiling,
        } = trust.display()
        else {
            panic!("an enrolment is shown as an enrolment");
        };
        let shown = |edit: &dyn Fn(&mut ConfirmationDisplay)| {
            let mut display = ConfirmationDisplay::CatalogueAdd {
                environment_id,
                catalogue_id: catalogue_id.clone(),
                kind,
                metadata_url: metadata_url.clone(),
                targets_url: targets_url.clone(),
                root_digest: root_digest.clone(),
                root_key_ids: root_key_ids.clone(),
                budgets,
                ceiling: ceiling.clone(),
            };
            edit(&mut display);
            CatalogueTrustPlan::of_display(&display)
                .map(|plan| plan.action_digest().expect("a digest"))
        };
        let confirmed = Some(trust.action_digest().expect("a digest"));
        assert_eq!(shown(&|_| {}), confirmed, "the control: nothing changed");
        for (name, edit) in [
            (
                "the location of the metadata",
                &(|display: &mut ConfirmationDisplay| {
                    if let ConfirmationDisplay::CatalogueAdd { metadata_url, .. } = display {
                        "https://other.example/metadata/".clone_into(metadata_url);
                    }
                }) as &dyn Fn(&mut ConfirmationDisplay),
            ),
            (
                "the location of the targets",
                &|display: &mut ConfirmationDisplay| {
                    if let ConfirmationDisplay::CatalogueAdd { targets_url, .. } = display {
                        "https://other.example/targets/".clone_into(targets_url);
                    }
                },
            ),
            ("the kind", &|display: &mut ConfirmationDisplay| {
                if let ConfirmationDisplay::CatalogueAdd { kind, .. } = display {
                    *kind = crate::catalogue::CatalogueKind::Official;
                }
            }),
            ("a budget", &|display: &mut ConfirmationDisplay| {
                if let ConfirmationDisplay::CatalogueAdd { budgets, .. } = display {
                    budgets.payload_cache_bytes = crate::scalars::U64::new(2);
                }
            }),
            ("the ceiling", &|display: &mut ConfirmationDisplay| {
                if let ConfirmationDisplay::CatalogueAdd { ceiling, .. } = display {
                    ceiling.push("terminal.stream".to_owned());
                }
            }),
        ] {
            assert_ne!(shown(edit), confirmed, "{name}");
        }

        // A list that is not in canonical order, or repeats a member, is not a display a host
        // that follows this definition sends.
        let mut unordered = install.display();
        if let ConfirmationDisplay::PluginInstall { grant, .. } = &mut unordered {
            *grant = vec!["b".to_owned(), "a".to_owned()];
        }
        assert_eq!(PluginInstallPlan::of_display(&unordered), None);
        let mut repeated = trust.display();
        if let ConfirmationDisplay::CatalogueAdd { root_key_ids, .. } = &mut repeated {
            *root_key_ids = vec!["k1".to_owned(), "k1".to_owned()];
        }
        assert_eq!(CatalogueTrustPlan::of_display(&repeated), None);
    }

    /// The digest an owner confirms to establish a host's clock is the one every owner device
    /// recomputes, so its bytes are fixed here: a change to the purpose, to its encoding or to the
    /// hash would leave an owner device approving a digest the host never asks for.
    #[test]
    fn the_clock_confirmation_digest_is_fixed() {
        let encoded = kr_cbor::to_canonical_vec(&CLOCK_PURPOSE).expect("encodes");
        assert_eq!(
            encoded,
            [
                0x6f, 0x6b, 0x72, 0x2d, 0x68, 0x6f, 0x73, 0x74, 0x2d, 0x63, 0x6c, 0x6f, 0x63, 0x6b,
                0x2f, 0x31,
            ]
        );
        let digest = kr_cbor::sha256(&encoded);
        let expected: [u8; 32] = [
            0xc8, 0xe5, 0x87, 0xc2, 0xc5, 0x01, 0x4f, 0xf1, 0x45, 0x48, 0x57, 0xdd, 0xab, 0x5a,
            0xb8, 0x11, 0xed, 0xb9, 0xf2, 0x43, 0xb3, 0xd5, 0x9c, 0xa6, 0xd0, 0x6a, 0x6f, 0xf2,
            0x05, 0x97, 0x75, 0x56,
        ];
        assert_eq!(digest, expected);
    }

    fn organisation_plan() -> OrganisationEnrolPlan {
        let key = |revision: u64, byte: u8, at: u64| PolicyKeyShown {
            revision: PolicyKeyRevision::new(revision),
            public_key: AuthorisationKey::from_bytes([byte; 32]),
            not_before_ms: TimestampMs::new(at),
        };
        OrganisationEnrolPlan {
            organisation_id: OrganisationId::new(Uuid::from_bytes([4; 16])),
            root: key(1, 0x11, 1_000),
            anchor: key(3, 0x33, 3_000),
        }
    }

    /// An owner confirms an enrolment by its digest, and every owner device builds that digest
    /// again from what it is shown. The digest of a fixed plan is pinned, so a change to the
    /// domain, the members or their order would show here; and each member is covered, so a
    /// confirmation for one chain is not carried to another organisation, another key, or the same
    /// key with another activation, which the host decides every later lease against.
    #[test]
    fn an_enrolment_confirmation_covers_the_chain_and_an_owner_device_rebuilds_it() {
        let plan = organisation_plan();
        let confirmed = plan.action_digest().expect("encodes");
        assert_eq!(
            confirmed,
            Digest256::from_bytes([
                0xc7, 0xd9, 0xdd, 0x9d, 0xf9, 0x2b, 0xbd, 0x40, 0x53, 0xc1, 0xd1, 0x9a, 0x30, 0xa3,
                0x64, 0x6b, 0x09, 0xdd, 0x28, 0xf3, 0xa5, 0x79, 0x20, 0xee, 0x26, 0x35, 0x0d, 0x93,
                0x05, 0xab, 0x22, 0x32,
            ]),
            "the digest of the fixed plan, computed apart from this code as the SHA-256 of the \
             KR-CBOR-1 array of the domain, the organisation, and each key's revision, public key \
             and activation"
        );
        assert_eq!(
            OrganisationEnrolPlan::sensitive_action(),
            SensitiveAction::ChangeHostAuthority
        );
        let shown = OrganisationEnrolPlan::of_display(&plan.display()).expect("the same plan");
        assert_eq!(shown, plan);
        assert_eq!(shown.action_digest().expect("encodes"), confirmed);
        assert_eq!(
            OrganisationEnrolPlan::of_display(&ConfirmationDisplay::EstablishClock),
            None
        );
        for (name, edit) in [
            ("organisation", {
                let mut other = plan;
                other.organisation_id = OrganisationId::new(Uuid::from_bytes([5; 16]));
                other
            }),
            ("root key", {
                let mut other = plan;
                other.root.public_key = AuthorisationKey::from_bytes([0x12; 32]);
                other
            }),
            ("root activation", {
                let mut other = plan;
                other.root.not_before_ms = TimestampMs::new(1_001);
                other
            }),
            ("anchor revision", {
                let mut other = plan;
                other.anchor.revision = PolicyKeyRevision::new(4);
                other
            }),
            ("anchor key", {
                let mut other = plan;
                other.anchor.public_key = AuthorisationKey::from_bytes([0x34; 32]);
                other
            }),
            ("anchor activation", {
                let mut other = plan;
                other.anchor.not_before_ms = TimestampMs::new(3_001);
                other
            }),
        ] {
            assert_ne!(edit.action_digest().expect("encodes"), confirmed, "{name}");
        }
    }

    /// The same for making a host exclusively organisation-managed: the new value and the
    /// organisations are covered, and a display that lists them out of order is not one a host
    /// that follows this definition sends.
    #[test]
    fn an_exclusive_management_confirmation_covers_the_value_and_the_organisations() {
        let first = OrganisationId::new(Uuid::from_bytes([1; 16]));
        let second = OrganisationId::new(Uuid::from_bytes([2; 16]));
        let plan = ExclusiveManagementPlan {
            exclusive: true,
            organisation_ids: [second, first].into_iter().collect(),
        };
        let confirmed = plan.action_digest().expect("encodes");
        assert_eq!(
            confirmed,
            Digest256::from_bytes([
                0x9d, 0x1d, 0xcb, 0xd8, 0x7f, 0xdd, 0xab, 0x76, 0x85, 0x34, 0xb6, 0x2f, 0x59, 0xb7,
                0x88, 0xef, 0x29, 0xcc, 0xab, 0xb3, 0xa1, 0x63, 0x2f, 0x23, 0x3a, 0xbe, 0x4f, 0xd8,
                0x2c, 0xbd, 0x7f, 0x7f,
            ]),
            "the digest of the fixed plan, computed apart from this code as the SHA-256 of the \
             KR-CBOR-1 array of the domain, the new value and the organisations in ascending order"
        );
        let shown = ExclusiveManagementPlan::of_display(&plan.display()).expect("the same plan");
        assert_eq!(shown, plan);
        assert_eq!(shown.action_digest().expect("encodes"), confirmed);
        assert_eq!(
            ExclusiveManagementPlan {
                exclusive: false,
                ..plan.clone()
            }
            .action_digest()
            .expect("encodes"),
            Digest256::from_bytes([
                0x4d, 0x84, 0x29, 0x81, 0xdb, 0x53, 0xe6, 0x64, 0xb8, 0xb3, 0x0c, 0x87, 0xc0, 0x80,
                0xa6, 0xb6, 0xd3, 0xfa, 0xbf, 0xd0, 0xf1, 0xad, 0x2f, 0xcc, 0xac, 0xb0, 0x2e, 0x45,
                0x9e, 0xbd, 0xd3, 0xa0,
            ]),
            "turning it off is another confirmation"
        );
        assert_ne!(
            ExclusiveManagementPlan {
                exclusive: false,
                ..plan.clone()
            }
            .action_digest()
            .expect("encodes"),
            confirmed,
            "turning it off is another confirmation"
        );
        assert_ne!(
            ExclusiveManagementPlan {
                organisation_ids: [first].into_iter().collect(),
                ..plan.clone()
            }
            .action_digest()
            .expect("encodes"),
            confirmed,
            "another set of organisations is another confirmation"
        );
        let unordered = ConfirmationDisplay::ExclusiveManagement {
            exclusive: true,
            organisation_ids: vec![second, first],
        };
        assert_eq!(ExclusiveManagementPlan::of_display(&unordered), None);
        assert_eq!(
            ExclusiveManagementPlan::of_display(&ConfirmationDisplay::EstablishClock),
            None
        );
    }

    #[test]
    fn a_request_names_a_subject_and_round_trips() {
        for subject in [
            ConfirmationSubject::ConfirmDevice {
                invitation_id: InvitationId::new(Uuid::from_bytes([1; 16])),
            },
            ConfirmationSubject::EstablishClock,
            ConfirmationSubject::SetExclusiveManagement { exclusive: true },
            ConfirmationSubject::Described(described(SensitiveAction::TrustRepositoryRoot)),
        ] {
            let params = OwnerConfirmationRequestParams { subject };
            let bytes = kr_cbor::to_canonical_vec(&params).expect("encodes");
            let decoded: OwnerConfirmationRequestParams =
                kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT).expect("decodes");
            assert_eq!(decoded, params);
        }
    }
}
