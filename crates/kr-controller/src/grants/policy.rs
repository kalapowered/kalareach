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

use kr_protocol::account::{MEMBERSHIP_LEASE_MAX_LIFETIME_MS, MembershipLease};
use kr_protocol::actor::ActorIngress;
use kr_protocol::grant::Grant;
use kr_protocol::ids::{AccountId, AuthorityRevision, OrganisationId, PolicyKeyRevision};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::CanonicalSet;
use kr_protocol::sharing::{MembershipRefusal, OfflineValidityPolicy};

use super::durable::{StoredEnrolment, StoredPolicy};
use super::{AccessRequest, Refusal};

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
pub struct Enrolment {
    /// The policy-signing key revision this host has pinned. A lease signed under another one is
    /// refused, which is what pinning the policy-signing authority means.
    pub pinned_key_revision: PolicyKeyRevision,
    /// The organisation policy revision this host has pinned. A grant that names a different one
    /// is answering to a policy this host has not accepted.
    pub pinned_policy_revision: AuthorityRevision,
    /// The leases this host currently holds, one per member account.
    ///
    /// Per account rather than per organisation, because section 17 disables a member
    /// individually: one valid member's lease must not sustain a disabled member's access.
    pub leases: BTreeMap<AccountId, MembershipLease>,
}

/// Why a lease this host was offered was not installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseRefused {
    /// This host is not enrolled in that organisation.
    NotEnrolled,
    /// The lease was signed under a policy-signing key revision this host has not pinned.
    WrongKeyRevision,
    /// The lease lasts longer than the 15 minutes section 17 permits.
    TooLong,
    /// The lease grants more than its own role's ceiling.
    AboveRoleCeiling,
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
    ///
    /// Its own restriction rather than a side effect of enrolling, because it is a host-level
    /// decision: enrolling in a second organisation must not undo it.
    exclusively_managed: bool,
    offline: Option<OfflineValidityPolicy>,
    /// When the host last woke or started, in UTC milliseconds.
    revalidated_at_ms: u64,
    /// The highest UTC reading this host has decided anything from.
    ///
    /// Expiry is decided from the later of this and the clock. Without it, a clock wound back past
    /// a deadline would revive a grant this host has already refused: section 24 asks for expiry to
    /// be revalidated after a wake, and a revalidation that trusts a smaller number than the last
    /// one is not a revalidation.
    utc_floor_ms: u64,
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
            utc_floor_ms: 0,
        }
    }

    /// The reading this host decides expiry from: the later of `now_ms` and its own floor.
    #[must_use]
    pub const fn settled_now(&self, now_ms: u64) -> u64 {
        if now_ms > self.utc_floor_ms {
            now_ms
        } else {
            self.utc_floor_ms
        }
    }

    /// Raises the floor to a reading this host has decided from.
    ///
    /// Only ever forward. A reading below the floor is a clock that went backwards, and section 9
    /// already says what a host does about that; what this guarantees is that it does not become a
    /// second chance for something already expired.
    pub const fn observe_utc(&mut self, now_ms: u64) {
        if now_ms > self.utc_floor_ms {
            self.utc_floor_ms = now_ms;
        }
    }

    /// The highest UTC reading this host has decided from.
    #[must_use]
    pub const fn utc_floor_ms(&self) -> u64 {
        self.utc_floor_ms
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

    /// Enrols this host in an organisation and pins the authority it will answer to.
    ///
    /// Enrolling says nothing about whether this host is exclusively organisation-managed. That is
    /// [`Self::set_exclusively_managed`], because it is a decision about the *host* and a second
    /// enrolment must not be able to undo it.
    pub fn enrol(
        &mut self,
        organisation_id: OrganisationId,
        pinned_key_revision: PolicyKeyRevision,
        pinned_policy_revision: AuthorityRevision,
    ) {
        self.enrolments
            .entry(organisation_id)
            .and_modify(|enrolment| {
                enrolment.pinned_key_revision = pinned_key_revision;
                enrolment.pinned_policy_revision = pinned_policy_revision;
            })
            .or_insert_with(|| Enrolment {
                pinned_key_revision,
                pinned_policy_revision,
                leases: BTreeMap::new(),
            });
    }

    /// The enrolment this host holds for an organisation.
    #[must_use]
    pub fn enrolment(&self, organisation_id: OrganisationId) -> Option<&Enrolment> {
        self.enrolments.get(&organisation_id)
    }

    /// Installs a signed membership lease for one member account.
    ///
    /// The signature is verified where the lease arrives from the policy service. What is checked
    /// here is everything section 17 states about a lease's *contents*, because a host that stored
    /// whatever it was handed would be enforcing the sender's arithmetic: the organisation it is
    /// enrolled in, the key revision it pinned, the 15-minute maximum lifetime, and the role's own
    /// ceiling.
    ///
    /// # Errors
    ///
    /// Returns which of those it failed.
    pub fn install_lease(
        &mut self,
        lease: MembershipLease,
    ) -> std::result::Result<(), LeaseRefused> {
        let organisation_id = lease.payload.organisation_id;
        let Some(enrolment) = self.enrolments.get_mut(&organisation_id) else {
            return Err(LeaseRefused::NotEnrolled);
        };
        if lease.payload.key_revision != enrolment.pinned_key_revision {
            return Err(LeaseRefused::WrongKeyRevision);
        }
        if !lease.payload.lifetime_within_maximum() {
            return Err(LeaseRefused::TooLong);
        }
        if !lease.payload.grants_within_role() {
            return Err(LeaseRefused::AboveRoleCeiling);
        }
        enrolment
            .leases
            .insert(lease.payload.account_id.clone(), lease);
        Ok(())
    }

    /// Drops the lease this host holds for one member account.
    ///
    /// A disabled SCIM member loses new leases immediately, and this is how the host stops using
    /// the one it already had for that member without touching anybody else's.
    pub fn drop_lease(&mut self, organisation_id: OrganisationId, account_id: &AccountId) {
        if let Some(enrolment) = self.enrolments.get_mut(&organisation_id) {
            enrolment.leases.remove(account_id);
        }
    }

    /// Records that this host is, or is no longer, exclusively organisation-managed.
    pub const fn set_exclusively_managed(&mut self, exclusively_managed: bool) {
        self.exclusively_managed = exclusively_managed;
    }

    /// Returns true when this host is exclusively organisation-managed.
    #[must_use]
    pub const fn is_exclusively_managed(&self) -> bool {
        self.exclusively_managed
    }

    /// The longest a lease this host will install may last.
    #[must_use]
    pub const fn maximum_lease_lifetime_ms() -> u64 {
        MEMBERSHIP_LEASE_MAX_LIFETIME_MS
    }

    /// This policy, as it is written down.
    ///
    /// The leases are deliberately not in it. A lease lasts at most fifteen minutes and is
    /// refreshed every five; restoring one across a restart would be restoring a deadline the
    /// organisation may have withdrawn in the meantime.
    #[must_use]
    pub fn snapshot(&self) -> StoredPolicy {
        StoredPolicy {
            accepted_floor: self.accepted_floor,
            utc_floor_ms: kr_protocol::scalars::TimestampMs::new(self.utc_floor_ms),
            exclusively_managed: self.exclusively_managed,
            offline: kr_protocol::scalars::Nullable(self.offline),
            enrolments: self
                .enrolments
                .iter()
                .map(|(organisation_id, enrolment)| StoredEnrolment {
                    organisation_id: *organisation_id,
                    pinned_key_revision: enrolment.pinned_key_revision,
                    pinned_policy_revision: enrolment.pinned_policy_revision,
                })
                .collect(),
        }
    }

    /// Rebuilds a policy from what was written down, at the revision now in force.
    ///
    /// The floor is the higher of what was stored and what the registry holds, so neither half can
    /// take the other back: a restored policy file cannot lower the revision the daemon has
    /// reached, and a registry read cannot lower the floor the policy recorded.
    #[must_use]
    pub fn restore(stored: &StoredPolicy, authority_revision: AuthorityRevision) -> Self {
        let floor =
            AuthorityRevision::new(stored.accepted_floor.get().max(authority_revision.get()));
        Self {
            authority_revision: floor,
            accepted_floor: floor,
            enrolments: stored
                .enrolments
                .iter()
                .map(|enrolment| {
                    (
                        enrolment.organisation_id,
                        Enrolment {
                            pinned_key_revision: enrolment.pinned_key_revision,
                            pinned_policy_revision: enrolment.pinned_policy_revision,
                            leases: BTreeMap::new(),
                        },
                    )
                })
                .collect(),
            exclusively_managed: stored.exclusively_managed,
            offline: stored.offline.0,
            revalidated_at_ms: 0,
            utc_floor_ms: stored.utc_floor_ms.get(),
        }
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

    /// Intersects one grant with this policy for one request.
    ///
    /// # Errors
    ///
    /// Returns the rule that refused: an organisation lease this host cannot use, a grant whose
    /// recipient this host cannot attribute to a member, or a lapsed offline bound.
    pub fn intersect(
        &self,
        grant: &Grant,
        request: &AccessRequest,
        now_ms: u64,
    ) -> std::result::Result<PolicyIntersection, Refusal> {
        match grant.organisation.as_ref() {
            Some(requirement) => {
                let Some(enrolment) = self.enrolments.get(&requirement.organisation_id) else {
                    return Err(Refusal::MembershipUnusable {
                        refusal: MembershipRefusal::NoLease,
                    });
                };
                // The grant names the policy revision it answers to. A grant issued under a policy
                // this host has since replaced is not this host's to honour.
                if requirement.policy_revision != enrolment.pinned_policy_revision {
                    return Err(Refusal::MembershipUnusable {
                        refusal: MembershipRefusal::WrongAuthority,
                    });
                }
                // Whose lease answers for this grant. Without the account, one valid member's
                // lease would sustain a disabled member's access, which is the whole of what
                // section 17's per-member disablement is for.
                let Some(account_id) = request.recipient_account.as_ref() else {
                    return Err(Refusal::MembershipUnattributed);
                };
                let Some(lease) = enrolment.leases.get(account_id) else {
                    return Err(Refusal::MembershipUnusable {
                        refusal: MembershipRefusal::NoLease,
                    });
                };
                if lease.payload.key_revision != enrolment.pinned_key_revision {
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
                // host is exclusively organisation-managed, in which case there is no personal
                // path left to continue on.
                if self.exclusively_managed
                    && let Some(refusal) = self.first_unusable_lease(now_ms)
                {
                    return Err(Refusal::MembershipUnusable { refusal });
                }
                // The bounded offline policy is for *remote* personal access. Section 10 puts it
                // there in so many words, and a person at the keyboard of their own machine is not
                // the case it is about: refusing them because a cloud feed is unreachable would be
                // the cloud dependency the default is written to avoid.
                if request.ingress != ActorIngress::LocalIpc
                    && let Some(offline) = self.offline.as_ref()
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

    /// The first reason a lease this host holds is unusable, for the exclusively-managed path.
    ///
    /// An enrolment with no lease at all is as unusable as an expired one: a host that is
    /// exclusively organisation-managed and holds nothing has nothing to work under.
    fn first_unusable_lease(&self, now_ms: u64) -> Option<MembershipRefusal> {
        for enrolment in self.enrolments.values() {
            if enrolment.leases.is_empty() {
                return Some(MembershipRefusal::NoLease);
            }
            for lease in enrolment.leases.values() {
                if lease.payload.key_revision != enrolment.pinned_key_revision {
                    return Some(MembershipRefusal::WrongAuthority);
                }
                if !lease.payload.is_valid_at(now_ms) {
                    return Some(MembershipRefusal::LeaseExpired);
                }
            }
        }
        None
    }
}
