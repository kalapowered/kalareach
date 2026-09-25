//! What this host's authority state has to survive a restart.
//!
//! Section 24 puts "team policy, membership deadlines, authority-feed checkpoints" in the
//! environment's authority store and then states the rule they exist for: **no restored old policy
//! can revive authority**. A host that held its restrictions only in memory would drop them on
//! every restart, which is the same failure by a different route: whatever the last policy said,
//! the host would come back unrestricted.
//!
//! So four things are written down.
//!
//! * **The authority floor.** The highest revision this host has ever accepted. It only rises, and
//!   a policy document naming anything at or below it is refused.
//! * **The time floor.** The highest UTC reading this host has decided expiry from. A clock wound
//!   back past a deadline therefore does not revive a grant this host has already refused.
//! * **The host's restrictions.** The bounded offline-validity policy, whether this host is
//!   exclusively organisation-managed, and which organisations it is enrolled in with the
//!   policy-signing links it verified.
//! * **The lease records.** For each member device, the newest lease this host installed and the
//!   run that installed it, so a lease is installed at most once whatever either clock says.
//! * **The feed's checkpoints.** The revision this host has accepted, its retained revocation
//!   records, and which enrolled hosts have acknowledged each one.
//!
//! What is **not** written down is a membership lease. A lease lasts at most fifteen minutes and is
//! refreshed every five; restoring one across a restart would be restoring a deadline the
//! organisation may have withdrawn, and the safe direction is for a restarted host to hold none
//! until the member's device presents a newer one. Its record is written down instead, and the
//! record is what refuses the old lease after a restart.
//!
//! ## The limit this does not remove
//!
//! The floors live in the same database as everything else they protect. Restoring that whole file
//! to an earlier point takes the floors back with it, so this stops a *policy document* from
//! reviving authority and not a restore of the host's entire state. That is recorded rather than
//! claimed away: an authority store recovered wholesale is a recovery event, and the remedy is the
//! remote feed, which this host does not issue and cannot rewind.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use kr_protocol::account::PolicyAuthorityLink;
use kr_protocol::ids::{
    AccountId, AuthorityRevision, ControllerGeneration, DeviceId, OrganisationId, PolicyKeyRevision,
};
use kr_protocol::pairing::RevocationRequest;
use kr_protocol::scalars::{AuthorisationKey, CanonicalSet, Digest256, Nullable, TimestampMs};
use kr_protocol::sharing::OfflineValidityPolicy;

/// One organisation enrolment, as it is written down.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredEnrolment {
    /// The organisation.
    pub organisation_id: OrganisationId,
    /// The first revision's link: the organisation's identity.
    pub root: PolicyAuthorityLink,
    /// The policy-signing links this host verified and keeps, oldest first. The last is the anchor
    /// rotation is followed from.
    pub links: Vec<PolicyAuthorityLink>,
    /// The highest head revision this host has accepted.
    pub accepted_head: PolicyKeyRevision,
    /// The host authority revision in force when this host enrolled. An organisation grant's
    /// requirement names it.
    pub enrolment_revision: AuthorityRevision,
}

/// The newest lease this host installed for one member's device, as it is written down.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredLeaseRecord {
    /// The organisation.
    pub organisation_id: OrganisationId,
    /// The member account.
    pub account_id: AccountId,
    /// The authorisation key of the device the lease is for.
    pub device_key: AuthorisationKey,
    /// When the lease was issued.
    pub issued_at_ms: TimestampMs,
    /// When it expires.
    pub expires_at_ms: TimestampMs,
    /// The SHA-256 digest of its signing input.
    pub digest: Digest256,
    /// The controller generation that installed it.
    pub installed_in: ControllerGeneration,
}

/// This host's policy, as it is written down.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredPolicy {
    /// The highest authority revision this host has ever accepted.
    pub accepted_floor: AuthorityRevision,
    /// The highest UTC reading this host has decided expiry from.
    pub utc_floor_ms: TimestampMs,
    /// Whether this host is exclusively organisation-managed.
    pub exclusively_managed: bool,
    /// The bounded offline-validity policy, when the owner chose one.
    pub offline: Nullable<OfflineValidityPolicy>,
    /// The organisations this host is enrolled in.
    pub enrolments: Vec<StoredEnrolment>,
    /// The newest lease this host installed for each member device. A withdrawal keeps them.
    pub lease_records: Vec<StoredLeaseRecord>,
}

/// One retained revocation record, as it is written down.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRevocation {
    /// The request a remote owner published.
    pub request: RevocationRequest,
    /// The revision this host issued for it.
    pub authority_revision: AuthorityRevision,
    /// When this host applied it.
    pub applied_at_ms: TimestampMs,
    /// The enrolled hosts that have acknowledged it.
    pub acknowledged_by: CanonicalSet<DeviceId>,
    /// True once every enrolled host had acknowledged it.
    ///
    /// A settled record is kept rather than deleted. Its revision is what a device list reports as
    /// that host's last acknowledgement, and its identity is what stops the same request being
    /// applied a second time under a new revision.
    pub settled: bool,
}

/// This host's half of the authority feed, as it is written down.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredFeed {
    /// The host this feed speaks for.
    pub host_device_id: DeviceId,
    /// The latest revision this host has accepted.
    pub accepted: AuthorityRevision,
    /// The enrolled hosts that must acknowledge this host's records.
    pub enrolled: CanonicalSet<DeviceId>,
    /// The records, settled and unsettled, by request identity.
    pub records: Vec<StoredRevocation>,
    /// The last successful synchronisation.
    pub last_synchronised_at_ms: Nullable<TimestampMs>,
}

impl StoredFeed {
    /// The records, keyed by request identity.
    #[must_use]
    pub fn by_request(&self) -> BTreeMap<kr_protocol::ids::RevocationRequestId, StoredRevocation> {
        self.records
            .iter()
            .map(|record| (record.request.request_id, record.clone()))
            .collect()
    }
}
