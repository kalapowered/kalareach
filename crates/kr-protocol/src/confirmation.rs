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
    ProposedGrant, SensitiveAction,
};
use crate::rights::ActionRight;
use crate::scalars::{AuthorisationKey, CanonicalSet, Digest256, Nullable, TimestampMs};

/// What an owner confirmation is asked for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationSubject {
    /// Issuing a persistent pairing invitation proposing exactly this grant.
    ///
    /// The host binds the digest of the proposed grant and its rights; the mode says how the
    /// invitation will be offered, and neither mode carries authority.
    IssueInvitation {
        /// How the invitation will be offered.
        mode: InviteModeKind,
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
#[serde(rename_all = "snake_case")]
pub enum ConfirmationDisplay {
    /// Issuing an invitation that proposes this grant.
    IssueInvitation {
        /// How it will be offered.
        mode: InviteModeKind,
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
    /// An action its caller described.
    Described(DescribedAction),
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
