//! The host's own policy: what is true of this host rather than of one grant.
//!
//! Three things live here, and each is a rule section 10, 17 or 24 states directly.
//!
//! * **Organisation leases (section 17).** "A signed membership lease lasts at most 15 minutes...
//!   Expired membership blocks further organisation-mediated reads and mutations even if the
//!   transport remains connected." So a lease is checked on every request against the clock, not
//!   against whether a socket is open, and a grant that requires membership is refused the moment
//!   its lease lapses. "Personal local owner access continues unless the host was explicitly
//!   enrolled as exclusively organisation-managed", so a grant with no organisation requirement is
//!   untouched by a lapse unless the host was enrolled that way.
//! * **The bounded offline-validity policy (section 10).** Optional, and off by default: "the
//!   default non-expiring owner grant remains account-free and usable without an authority-feed
//!   dependency." An owner who chooses a bound gets exactly that bound, measured from the last
//!   successful feed synchronisation, and the stale status and last sync are visible.
//! * **Revalidation after wake and reboot (section 24).** "Revalidate expiry after wake/reboot; no
//!   restored old policy can revive authority." Two halves. Expiry is re-read against the clock
//!   the moment this host wakes or starts, which [`HostPolicy::revalidate`] does; and a policy
//!   document restored from a backup cannot put back an authority the host has already moved past,
//!   which [`HostPolicy::accept_policy`] refuses by keeping the highest revision this host has
//!   ever accepted.
//!
//! The third rule is the one an implementation loses by accident: a host that simply loads
//! whatever its policy file holds will happily load last month's file. The floor is separate from
//! the loaded document for that reason, and it only ever goes up.

use std::collections::BTreeMap;

use kr_protocol::account::MembershipLease;
use kr_protocol::grant::Grant;
use kr_protocol::ids::{AuthorityRevision, OrganisationId, PolicyKeyRevision};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::CanonicalSet;
use kr_protocol::sharing::{MembershipRefusal, OfflineValidityPolicy};

use super::Refusal;

/// What the intersection of one grant with this host's policy produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyIntersection {
    /// The rights both the grant and the policy allow.
    pub rights: CanonicalSet<ActionRight>,
    /// The organisation whose lease narrowed them, when one did.
    pub organisation_id: Option<OrganisationId>,
}

/// One organisation this host has opted into.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Enrolment {
    /// The policy-signing key revision this host has pinned. A lease signed under another one is
    /// refused, which is what pinning the policy-signing authority means.
    pinned_revision: PolicyKeyRevision,
    /// The lease this host currently holds, when it holds one.
    lease: Option<MembershipLease>,
}

/// This host's policy.
#[derive(Clone, Debug)]
pub struct HostPolicy {
    authority_revision: AuthorityRevision,
    /// The highest authority revision this host has ever accepted.
    ///
    /// Separate from [`Self::authority_revision`] because a restored old policy would otherwise
    /// put the revision back. This only ever rises.
    accepted_floor: AuthorityRevision,
    enrolments: BTreeMap<OrganisationId, Enrolment>,
    /// True when this host was enrolled as exclusively organisation-managed, so personal local
    /// owner access stops with the organisation's.
    exclusively_managed: bool,
    offline: Option<OfflineValidityPolicy>,
    /// When the host last woke or started, in UTC milliseconds.
    revalidated_at_ms: u64,
}

impl HostPolicy {
    /// A host with no organisation enrolment and no offline bound: the personal default.
    #[must_use]
    pub fn personal(authority_revision: AuthorityRevision) -> Self {
        Self {
            authority_revision,
            accepted_floor: authority_revision,
            enrolments: BTreeMap::new(),
            exclusively_managed: false,
            offline: None,
            revalidated_at_ms: 0,
        }
    }

    /// The authority revision in force.
    #[must_use]
    pub const fn authority_revision(&self) -> AuthorityRevision {
        self.authority_revision
    }

    /// The highest authority revision this host has ever accepted.
    #[must_use]
    pub const fn accepted_floor(&self) -> AuthorityRevision {
        self.accepted_floor
    }

    /// Advances the authority revision.
    ///
    /// The floor rises with it, so nothing can put the revision back afterwards.
    pub const fn advance_authority_revision(&mut self, revision: AuthorityRevision) {
        if revision.get() > self.authority_revision.get() {
            self.authority_revision = revision;
        }
        if revision.get() > self.accepted_floor.get() {
            self.accepted_floor = revision;
        }
    }

    /// Accepts an authority revision this host has been told about.
    ///
    /// Section 24: a restored old policy cannot revive authority. A revision at or below the floor
    /// is refused, whatever document carried it and however well signed that document is, because
    /// a signature proves who wrote a policy and not that the policy is the current one.
    ///
    /// Returns whether it was accepted.
    pub const fn accept_policy(&mut self, revision: AuthorityRevision) -> bool {
        if revision.get() <= self.accepted_floor.get() {
            return false;
        }
        self.authority_revision = revision;
        self.accepted_floor = revision;
        true
    }

    /// Enrols this host in an organisation and pins its policy-signing revision.
    pub fn enrol(
        &mut self,
        organisation_id: OrganisationId,
        pinned_revision: PolicyKeyRevision,
        exclusively_managed: bool,
    ) {
        self.enrolments.insert(
            organisation_id,
            Enrolment {
                pinned_revision,
                lease: None,
            },
        );
        self.exclusively_managed = exclusively_managed;
    }

    /// Records the signed membership lease this host currently holds.
    ///
    /// The signature itself is checked where the lease arrives; what is kept here is the lease and
    /// the revision it was signed under, both of which are read again on every request.
    pub fn install_lease(&mut self, lease: MembershipLease) {
        let organisation_id = lease.payload.organisation_id;
        if let Some(enrolment) = self.enrolments.get_mut(&organisation_id) {
            enrolment.lease = Some(lease);
        }
    }

    /// Drops the lease this host holds for an organisation.
    ///
    /// A disabled member loses new leases immediately, and this is how the host stops using the
    /// one it already had.
    pub fn drop_lease(&mut self, organisation_id: OrganisationId) {
        if let Some(enrolment) = self.enrolments.get_mut(&organisation_id) {
            enrolment.lease = None;
        }
    }

    /// Returns true when this host was enrolled as exclusively organisation-managed.
    #[must_use]
    pub const fn is_exclusively_managed(&self) -> bool {
        self.exclusively_managed
    }

    /// Chooses a bounded offline-validity policy for personal remote access.
    pub const fn set_offline_validity(&mut self, offline: Option<OfflineValidityPolicy>) {
        self.offline = offline;
    }

    /// The bounded offline-validity policy, when the owner chose one.
    #[must_use]
    pub const fn offline_validity(&self) -> Option<&OfflineValidityPolicy> {
        self.offline.as_ref()
    }

    /// Records a successful authority-feed synchronisation.
    pub const fn note_feed_synchronised(&mut self, at_ms: u64) {
        if let Some(offline) = self.offline.as_mut() {
            offline.last_synchronised_at_ms =
                kr_protocol::scalars::Nullable::some(kr_protocol::scalars::TimestampMs::new(at_ms));
        }
    }

    /// Revalidates this host's policy after a wake or a reboot.
    ///
    /// Nothing is cached across the gap. Expiry is decided from `now_ms` on the next request, and
    /// this records the moment so a caller can see that the revalidation happened rather than
    /// assuming it. The authority floor is untouched, which is the point: waking up is not a
    /// reason to accept an older policy.
    pub const fn revalidate(&mut self, now_ms: u64) {
        self.revalidated_at_ms = now_ms;
    }

    /// When this host last revalidated after a wake or a reboot.
    #[must_use]
    pub const fn revalidated_at_ms(&self) -> u64 {
        self.revalidated_at_ms
    }

    /// Intersects one grant with this policy.
    ///
    /// # Errors
    ///
    /// Returns the rule that refused: an unusable organisation lease, or a lapsed offline bound.
    pub fn intersect(
        &self,
        grant: &Grant,
        now_ms: u64,
    ) -> std::result::Result<PolicyIntersection, Refusal> {
        match grant.organisation.as_ref() {
            Some(requirement) => {
                let Some(enrolment) = self.enrolments.get(&requirement.organisation_id) else {
                    return Err(Refusal::MembershipUnusable {
                        refusal: MembershipRefusal::NoLease,
                    });
                };
                let Some(lease) = enrolment.lease.as_ref() else {
                    return Err(Refusal::MembershipUnusable {
                        refusal: MembershipRefusal::NoLease,
                    });
                };
                if lease.payload.organisation_id != requirement.organisation_id
                    || lease.payload.key_revision != enrolment.pinned_revision
                {
                    return Err(Refusal::MembershipUnusable {
                        refusal: MembershipRefusal::WrongAuthority,
                    });
                }
                // The clock decides, and nothing else does. An open transport is not a lease.
                if !lease.payload.is_valid_at(now_ms) {
                    return Err(Refusal::MembershipUnusable {
                        refusal: MembershipRefusal::LeaseExpired,
                    });
                }
                let rights = grant
                    .actions
                    .iter()
                    .copied()
                    .filter(|right| lease.payload.maximum_grants.contains(right))
                    .collect();
                Ok(PolicyIntersection {
                    rights,
                    organisation_id: Some(requirement.organisation_id),
                })
            }
            None => {
                // Personal authority. It continues through an organisation outage, unless this
                // host was explicitly enrolled as exclusively organisation-managed, in which case
                // there is no personal path left to continue on.
                if self.exclusively_managed
                    && let Some(refusal) = self.first_unusable_lease(now_ms)
                {
                    return Err(Refusal::MembershipUnusable { refusal });
                }
                if let Some(offline) = self.offline.as_ref()
                    && !offline.is_inside_bound(now_ms)
                {
                    return Err(Refusal::OfflineValidityLapsed {
                        last_synchronised_at_ms: offline
                            .last_synchronised_at_ms
                            .as_ref()
                            .map(|at| at.get()),
                    });
                }
                Ok(PolicyIntersection {
                    rights: grant.actions.clone(),
                    organisation_id: None,
                })
            }
        }
    }

    fn first_unusable_lease(&self, now_ms: u64) -> Option<MembershipRefusal> {
        for enrolment in self.enrolments.values() {
            match enrolment.lease.as_ref() {
                None => return Some(MembershipRefusal::NoLease),
                Some(lease) if !lease.payload.is_valid_at(now_ms) => {
                    return Some(MembershipRefusal::LeaseExpired);
                }
                Some(_) => {}
            }
        }
        None
    }
}
