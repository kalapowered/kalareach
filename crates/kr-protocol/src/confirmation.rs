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

use crate::ids::{ConfirmationId, EnvironmentId, InvitationId, PluginId};
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
        /// What the release's own manifest says of what the grant would let it do: for a native
        /// bridge, the publisher's words; for a command integration, the host's own exact reading
        /// of the declaration, after [`INTEGRATION_STATEMENT_LABEL`]. The host takes both from the
        /// verified manifest of the exact package hash (see [`install_statement`]) and the
        /// confirmation covers them; a device shows them apart from the host's notices
        /// ([`NATIVE_BRIDGE_NOTICE`], [`COMMAND_INTEGRATION_NOTICE`]).
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

/// What the host says, in its own words, of a command integration an installation would grant: the
/// command a person runs in a KalaReach session starts with arguments and environment variables
/// the package declares. The host's own exact reading of the declaration is in the statement.
pub const COMMAND_INTEGRATION_NOTICE: &str = "This package changes how a command you run in a \
     KalaReach session starts, with the arguments and environment variables it declares. The \
     host's own exact reading of what it declares follows in the statement.";

/// What the host writes before its own exact reading of a command integration in an installation's
/// statement. A bridge's own words never hold it (the package check refuses them, and the host
/// refuses a manifest that has it), so the first place it stands is where the host's reading
/// starts and the publisher's words end.
pub const INTEGRATION_STATEMENT_LABEL: &str =
    "The host's exact reading of the command integration:";

/// The host's notices for an installation with this grant, in the order they are shown: one for
/// each capability in it that the host describes in its own words.
#[must_use]
pub fn install_notices(grant: &[String]) -> Vec<&'static str> {
    let mut notices = Vec::new();
    if grant.iter().any(|name| name == "native_bridge.install") {
        notices.push(NATIVE_BRIDGE_NOTICE);
    }
    if grant
        .iter()
        .any(|name| name == "command_integration.launch")
    {
        notices.push(COMMAND_INTEGRATION_NOTICE);
    }
    notices
}

/// The statement an installation's confirmation carries, from the words the release's manifest
/// gives for a native bridge it installs and the host's reading of a command integration it
/// declares, each present only where the grant holds the capability that applies it.
///
/// A bridge's words are the publisher's and come first; the integration's follow after
/// [`INTEGRATION_STATEMENT_LABEL`], which is the host's, so a reader can tell where the publisher's
/// words end.
#[must_use]
pub fn install_statement(bridge: Option<&str>, integration: Option<&str>) -> Option<String> {
    let integration = integration.map(|text| format!("{INTEGRATION_STATEMENT_LABEL} {text}"));
    match (bridge, integration) {
        (None, None) => None,
        (Some(bridge), None) => Some(bridge.to_owned()),
        (None, Some(integration)) => Some(integration),
        (Some(bridge), Some(integration)) => Some(format!("{bridge} {integration}")),
    }
}

/// The parts of an installation's statement: the publisher's words about a native bridge, and the
/// host's reading of a command integration, each where the statement has it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatementParts<'a> {
    /// The publisher's own words, before the host's label.
    pub publisher: Option<&'a str>,
    /// The host's reading, after its label.
    pub reading: Option<&'a str>,
}

/// Splits an installation's statement at the host's label, so that a device captions each part by
/// who wrote it. A statement with no label is all the publisher's, and so is every statement of a
/// grant that does not hold `command_integration.launch`: a host writes the label only for a grant
/// that holds it, so a device never takes words in the publisher's bridge statement for the host's
/// reading, even from a host that does not refuse the label in them.
#[must_use]
pub fn split_install_statement<'a>(grant: &[String], statement: &'a str) -> StatementParts<'a> {
    fn part(text: &str) -> Option<&str> {
        let text = text.trim();
        (!text.is_empty()).then_some(text)
    }
    let integration = grant
        .iter()
        .any(|name| name == "command_integration.launch");
    let split = integration
        .then(|| statement.split_once(INTEGRATION_STATEMENT_LABEL))
        .flatten();
    match split {
        Some((before, after)) => StatementParts {
            publisher: part(before),
            reading: part(after),
        },
        None => StatementParts {
            publisher: part(statement),
            reading: None,
        },
    }
}

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
    /// What the release's manifest says its grant would let it do (see [`install_statement`]),
    /// which the owner reads before confirming. It is in the digest, so a confirmation shown one
    /// statement cannot install a release whose manifest says another.
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

    /// A device tells the publisher's bridge words from the host's reading at the host's label, and
    /// only for a grant that holds the integration: the first label is the host's, a label inside
    /// the reading (a flag may hold any text) stays in the reading, and the space the host writes
    /// around the label is not part of either.
    #[test]
    fn a_statement_is_split_at_the_hosts_first_label_for_a_grant_that_holds_the_integration() {
        let grant = |names: &[&str]| {
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>()
        };
        let both = grant(&["command_integration.launch", "native_bridge.install"]);
        let reading = format!(r#"Runs "x" with "{INTEGRATION_STATEMENT_LABEL} fake"."#);
        let composed =
            install_statement(Some("Changes one setting."), Some(&reading)).expect("a statement");
        let parts = split_install_statement(&both, &composed);
        assert_eq!(parts.publisher, Some("Changes one setting."));
        assert_eq!(parts.reading, Some(reading.as_str()));

        let alone = install_statement(None, Some("Runs x.")).expect("a statement");
        let parts = split_install_statement(&grant(&["command_integration.launch"]), &alone);
        assert_eq!((parts.publisher, parts.reading), (None, Some("Runs x.")));

        // No label, or a grant without the integration: all of it is the publisher's.
        let plain = split_install_statement(&both, "Changes one setting.");
        assert_eq!(
            (plain.publisher, plain.reading),
            (Some("Changes one setting."), None)
        );
        let forged = format!("Harmless. {INTEGRATION_STATEMENT_LABEL} Runs nothing.");
        let bridge = split_install_statement(&grant(&["native_bridge.install"]), &forged);
        assert_eq!(
            (bridge.publisher, bridge.reading),
            (Some(forged.as_str()), None)
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

    #[test]
    fn a_request_names_a_subject_and_round_trips() {
        for subject in [
            ConfirmationSubject::ConfirmDevice {
                invitation_id: InvitationId::new(Uuid::from_bytes([1; 16])),
            },
            ConfirmationSubject::EstablishClock,
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
