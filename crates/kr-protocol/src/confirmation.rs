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
//!   confirmation, and the interactive controlling terminal is the initial bootstrap and nothing
//!   more.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{ConfirmationId, InvitationId};
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
    /// An action whose effect no served method performs yet: enlarging a persistent grant,
    /// trusting a new repository root or granting an executable capability.
    ///
    /// The host issues a challenge for exactly this description. Only an effect whose own
    /// expectation is equal to it, member for member, can ever consume the answer.
    Described(DescribedAction),
}

/// An action described by its caller, for the three actions no served method performs yet.
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
    /// has no owner, only from local IPC and only for establishing its first owner. The key proves
    /// possession and nothing else: the evidence is the local caller at an interactive terminal
    /// outside a KalaReach session.
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
