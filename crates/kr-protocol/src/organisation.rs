//! Organisation policy on a host: opting in, presenting a membership lease, exclusive management
//! and withdrawal.
//!
//! A host opts into an organisation's policy by pinning the chain of keys that signs it, on an
//! owner's confirmation of exactly that chain (`organisation.enrol`). A member's device then
//! presents the lease the organisation signed for it (`membership.present`), and the host answers
//! for that device while the lease lasts. The owner can make the host exclusively
//! organisation-managed (`organisation.exclusive.set`), so personal access answers to a lease
//! too, and can leave an organisation (`organisation.withdraw`). `organisation.list` reports all
//! of it.
//!
//! What the host holds for an organisation is a key chain it verified when it enrolled and the
//! rotations it has followed since, each through a link the anchor's own key signed. A lease is
//! checked against those keys and against the device that presented it before it is kept.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::account::{MembershipLease, PolicyAuthority};
use crate::action::RevocationBarrier;
use crate::ids::{AccountId, AuthorityRevision, DeviceId, OrganisationId, PolicyKeyRevision};
use crate::pairing::ConfirmationChannel;
use crate::scalars::{CanonicalSet, KeyId, Nullable, TimestampMs, U64};
use crate::sharing::RevocationResult;

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

/// The parameters of `organisation.exclusive.set`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganisationExclusiveSetParams {
    /// True to make this host exclusively organisation-managed, false to end that.
    pub exclusive: bool,
}

/// The result of `organisation.exclusive.set`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganisationExclusiveSetResult {
    /// Whether the host is exclusively organisation-managed now.
    pub exclusive: bool,
    /// The authority revision in force when the change was answered.
    pub authority_revision: AuthorityRevision,
    /// The per-worker completion of the fence that making a host exclusive owes, because it
    /// restricts work already admitted. Null when the change was to end exclusive management,
    /// which restricts nothing.
    pub barrier: Nullable<RevocationBarrier>,
}

/// The parameters of `organisation.withdraw`. The answer is a [`RevocationResult`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganisationWithdrawParams {
    /// The organisation to leave.
    pub organisation_id: OrganisationId,
}

/// The result of `organisation.withdraw`: the revision it advanced to and the per-worker
/// completion of its fence, as a revocation reports them.
pub type OrganisationWithdrawResult = RevocationResult;

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
    /// Whether this host is exclusively organisation-managed.
    pub exclusive: bool,
    /// Whether this host trusts its own clock. While it does not, it installs no lease and
    /// follows no chain, and the owner trusts the clock again with `host.clock.establish`.
    pub clock_trusted: bool,
    /// Every time exclusive management was turned off, oldest first.
    pub exclusive_events: Vec<ExclusiveManagementEvent>,
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
    /// keys the host already holds.
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
