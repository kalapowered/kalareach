//! Organisation policy on a host: opting in, and what the host reports of it.
//!
//! A host opts into an organisation's policy by pinning the chain of keys that signs it, on an
//! owner's confirmation of exactly that chain (`organisation.enrol`). A member's device then
//! presents the lease the organisation signed for it (`membership.present`), and the host answers
//! for that device while the lease lasts. The owner applies the organisation's signed policy
//! (`organisation.policy.apply`), and the adapters the policy allows are the only ones the host
//! admits. `organisation.list` reports what the host holds for each organisation, whether it is
//! exclusively organisation-managed and every time that was turned off.
//!
//! What the host holds for an organisation is a key chain it verified when it enrolled and the
//! rotations it has followed since, each through a link the anchor's own key signed. A lease is
//! checked against those keys and against the device that presented it before it is kept, and a
//! policy against the key the chain ends with.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::account::MembershipLease;
use crate::account::OrganisationPolicy;
use crate::account::PolicyAuthority;
use crate::action::RevocationBarrier;
use crate::ids::{
    AccountId, AuthorityRevision, DeviceId, OrganisationId, OrganisationPolicyRevision, PluginId,
    PolicyKeyRevision,
};
use crate::pairing::ConfirmationChannel;
use crate::scalars::{CanonicalSet, KeyId, Nullable, TimestampMs, U64};

/// The parameters of `organisation.enrol`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganisationEnrolParams {
    /// The organisation's whole published policy-signing chain, as a member exported it. The host
    /// verifies every link and the head before it shows the owner anything, and the owner's
    /// confirmation is for exactly the root and the key signing now.
    pub authority: PolicyAuthority,
}

/// The result of `organisation.enrol`, and what a repeat of the action is answered with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganisationEnrolResult {
    /// The organisation the host is now enrolled in.
    pub organisation_id: OrganisationId,
    /// The authority revision in force when the host enrolled. A grant that requires this
    /// organisation names it, and a grant that names another is not honoured.
    pub enrolment_revision: AuthorityRevision,
    /// The highest key revision the host has accepted.
    pub accepted_head: PolicyKeyRevision,
    /// The identifier of the organisation's first key, which is its identity: what an
    /// administrator can read out to the person enrolling.
    pub root_key_id: KeyId,
}

/// The parameters of `organisation.policy.apply`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganisationPolicyApplyParams {
    /// The policy the organisation signed, as a member exported it. The host applies it only when
    /// it is signed by the key the host's chain ends with, names a revision above the one it
    /// holds, and states a structure this contract admits.
    pub policy: OrganisationPolicy,
    /// The organisation's chain, when it has moved since the host last accepted one. The key that
    /// signs a policy is the one the chain ends with, so a policy under a newer key needs the chain
    /// beside it. A chain that is not newer changes nothing. A newer chain that does not verify,
    /// or that shows an installed lease was signed after its key was succeeded, refuses the whole
    /// request and keeps nothing: a lease that has to be dropped is fenced when the chain is
    /// presented with `membership.present`.
    pub authority: Nullable<PolicyAuthority>,
}

/// The result of `organisation.policy.apply`, and what a repeat of the action is answered with.
///
/// The host verifies the whole policy and keeps its revision and its adapter allowlist. It neither
/// keeps nor applies the other settings the policy states: the least client version, the longest
/// grant, what members' clients may reach outside KalaReach, the backup requirements and the audit
/// retention.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganisationPolicyApplyResult {
    /// The organisation whose policy the host holds now.
    pub organisation_id: OrganisationId,
    /// The revision of that policy. The host refuses a policy at or below it, except the same
    /// revision with the same allowlist, which changes nothing and puts the host's list in force
    /// again.
    pub organisation_policy_revision: OrganisationPolicyRevision,
    /// The adapters this organisation allows, or null for every adapter the host qualifies.
    pub adapter_allowlist: Nullable<CanonicalSet<PluginId>>,
    /// The adapters the host admits as the answer was made: the adapters every enrolled
    /// organisation that states a list allows, or null while none does. A repeat of the action is
    /// given this list, not the one in force now; `organisation.list` reports the list in force.
    pub effective_adapter_allowlist: Nullable<CanonicalSet<PluginId>>,
}

/// The parameters of `organisation.exclusive.set`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganisationExclusiveSetParams {
    /// True to make the host exclusively organisation-managed, false to end that.
    pub exclusive: bool,
}

/// The parameters of `organisation.withdraw`. Its result is the revocation result every fence
/// reports: the revision now in force and the per-worker completion of the fence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganisationWithdrawParams {
    /// The organisation the host leaves.
    pub organisation_id: OrganisationId,
}

/// The result of `organisation.exclusive.set`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganisationExclusiveSetResult {
    /// The value the action set, which is what the answer to a repeat of the action reports. A
    /// later change leaves it as it was; `organisation.list` reports whether the host is
    /// exclusively organisation-managed now.
    pub exclusive: bool,
    /// The authority revision in force when the change was answered.
    pub authority_revision: AuthorityRevision,
    /// The per-worker completion of the fence that making a host exclusive owes, because it
    /// restricts work already admitted. Null when the change was to end exclusive management,
    /// which restricts nothing.
    pub barrier: Nullable<RevocationBarrier>,
}

/// The parameters of `organisation.list`. There are none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganisationListParams {}

/// The lease a host holds for one bound device, as `organisation.list` reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganisationLeaseView {
    /// When the organisation signed it, in UTC milliseconds.
    pub issued_at_ms: TimestampMs,
    /// When it stops being usable, in UTC milliseconds.
    pub expires_at_ms: TimestampMs,
}

/// A device bound to a member account in an organisation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganisationMemberView {
    /// The device.
    pub device_id: DeviceId,
    /// The member account its first verified lease named.
    pub account_id: AccountId,
    /// The identifier of the authorisation key that lease named and the device proved.
    pub device_key_id: KeyId,
    /// When the host bound the device, in UTC milliseconds.
    pub bound_at_ms: TimestampMs,
    /// The newest lease the host recorded for the device, or null when it has recorded none. A
    /// restarted host holds no lease until the device presents a newer one, and this is the
    /// record of the last one, not a promise that it is still in force.
    pub lease: Nullable<OrganisationLeaseView>,
}

/// One organisation this host is enrolled in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganisationEnrolmentView {
    /// The organisation.
    pub organisation_id: OrganisationId,
    /// The identifier of its first key, which is its identity.
    pub root_key_id: KeyId,
    /// The revision of the key the host follows rotation from.
    pub anchor_revision: PolicyKeyRevision,
    /// The identifier of that key.
    pub anchor_key_id: KeyId,
    /// The highest key revision the host has accepted.
    pub accepted_head: PolicyKeyRevision,
    /// The authority revision in force when the host enrolled.
    pub enrolment_revision: AuthorityRevision,
    /// The revision of the policy the host applied for this organisation, or null while it has
    /// applied none. It is not the enrolment revision a grant that requires the organisation names.
    pub organisation_policy_revision: Nullable<OrganisationPolicyRevision>,
    /// The adapters that policy allows, or null when it allows every adapter the host qualifies or
    /// the host has applied none.
    pub adapter_allowlist: Nullable<CanonicalSet<PluginId>>,
    /// The devices bound to member accounts, by device identity.
    pub members: Vec<OrganisationMemberView>,
}

/// A time exclusive management was turned off, kept by the host so its owners and the
/// organisation can see it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExclusiveManagementEvent {
    /// The event's position in the host's outbox of such events.
    pub sequence: U64,
    /// When the host turned it off, in UTC milliseconds.
    pub at_ms: TimestampMs,
    /// How the owner's confirmation reached the host. The interactive controlling terminal is the
    /// channel of a host that had no owner device left to confirm on.
    pub channel: ConfirmationChannel,
    /// The organisations the host was enrolled in when it turned exclusive management off.
    pub organisation_ids: CanonicalSet<OrganisationId>,
}

/// The result of `organisation.list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganisationListResult {
    /// The organisations this host is enrolled in, by organisation identity.
    pub enrolments: Vec<OrganisationEnrolmentView>,
    /// The adapters the host admits: the adapters every enrolled organisation that states a list
    /// allows, or null while none does. Two organisations whose lists share nothing leave an empty
    /// set, which admits no adapter.
    pub effective_adapter_allowlist: Nullable<CanonicalSet<PluginId>>,
    /// Whether this host is exclusively organisation-managed.
    pub exclusive: bool,
    /// Whether this host trusts its own clock. While it does not, it installs no lease and
    /// follows no chain, and the owner trusts the clock again with `host.clock.establish`.
    pub clock_trusted: bool,
    /// Every time exclusive management was turned off, oldest first.
    pub exclusive_events: Vec<ExclusiveManagementEvent>,
    /// The device identity and authorisation key the host presents leases as for its own local
    /// owner, which an organisation signs a lease for while the host is exclusively
    /// organisation-managed.
    pub host_device: HostDeviceView,
    /// The sessions whose workers cannot be told what the host's local owner may do: a worker an
    /// earlier build started, or one this host has not reached. While one runs, the host does not
    /// become exclusively organisation-managed, and one that runs on an exclusive host serves its
    /// local caller without the hold. Ending the session (`kr close`) ends the exception.
    pub workers_without_local_enforcement: Vec<crate::ids::SessionId>,
}

/// The identity the host presents a lease as for its own local owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostDeviceView {
    /// The host's own device identifier.
    pub device_id: DeviceId,
    /// The authorisation key a lease for the host's local owner names.
    pub authorisation_key: crate::scalars::AuthorisationKey,
}

/// The parameters of `membership.present`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MembershipPresentParams {
    /// The lease the organisation signed for this device. The device the lease names is the one
    /// that presents it: a host refuses a lease that names another device's key.
    pub lease: MembershipLease,
    /// The organisation's chain, when it has moved since the host last accepted one. A chain
    /// that is not newer changes nothing, and the lease beside it is still judged against the
    /// keys the host already holds. A newer chain that does not verify refuses the presentation.
    /// The host keeps a newer chain only with the lease beside it: a presentation that is refused
    /// keeps nothing, and the device presents the chain again with its next lease.
    pub authority: Nullable<PolicyAuthority>,
}

/// The result of `membership.present`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MembershipPresentResult {
    /// The organisation the lease speaks for.
    pub organisation_id: OrganisationId,
    /// The member account it names.
    pub account_id: AccountId,
    /// The key revision that signed it.
    pub key_revision: PolicyKeyRevision,
    /// When it stops being usable, in UTC milliseconds.
    pub expires_at_ms: TimestampMs,
    /// Whether this host is exclusively organisation-managed.
    pub exclusive: bool,
    /// The last time exclusive management was turned off at this host's terminal, or null when it
    /// never was. A member's client carries it to the organisation with its next lease request.
    pub exclusive_ended_at_terminal_ms: Nullable<TimestampMs>,
}

/// What the claim of an organisation change keeps while its answer is still to be built from the
/// fence the change owes.
///
/// A withdrawal and making a host exclusively organisation-managed restrict work already
/// admitted, so each writes its policy row and this marker in one transaction and answers from the
/// barrier that follows. The marker is what lets a repeat of the action tell a change that
/// committed from one that never began.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum OrganisationChangeMarker {
    /// `organisation.withdraw` committed for this organisation.
    Withdrawn {
        /// The organisation the host left.
        organisation_id: OrganisationId,
    },
    /// `organisation.exclusive.set` committed with `exclusive` true.
    ExclusiveOn,
}
