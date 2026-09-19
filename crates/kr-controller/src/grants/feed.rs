//! The host's half of the remote authority feed.
//!
//! Section 10 divides this deliberately, and the division is the security property:
//!
//! > "Remote owners publish uniquely identified, signed revocation requests; the target host
//! > validates current owner authority and **is the sole issuer** of its ordered authority
//! > revisions and acknowledgements. A device cannot assign a higher host revision to its own
//! > request."
//!
//! So a remote owner publishes a [`RevocationRequest`], which carries no revision at all, and this
//! host answers with an [`AuthorityRevisionRecord`] it signs itself. A device that could number
//! its own request could put itself ahead of a revocation already in flight.
//!
//! Four more rules, each a method here:
//!
//! * **A record that does not follow the accepted one is refused.** [`AuthorityFeed::accept`]
//!   keeps the latest accepted revision and rejects anything at or below it, so replaying an old
//!   feed entry cannot put authority back.
//! * **Revocation records are retained until every enrolled host has acknowledged them.** They do
//!   not share mailbox expiry or notification coalescing, so [`AuthorityFeed::retained`] holds them
//!   until [`AuthorityFeed::acknowledge`] has heard from each enrolled host or that host is
//!   explicitly removed.
//! * **A synchronisation is owed from the moment a connection is established.**
//!   [`AuthorityFeed::synchronisation_owed`] is the question a connection asks, and it stays true
//!   until a synchronisation has actually happened.
//! * **When the feed is unavailable, the status is stale and says so.** It is never reported as
//!   up to date because nothing contradicted it.
//!
//! # What this type is, and is not
//!
//! It is the host's **record**: which revisions it has issued and accepted, which revocation
//! records it still owes delivery of, which enrolled hosts have answered, and whether what it is
//! showing is current. It is not the transport. Validating a remote owner's authority over a
//! published request, applying that request's revocation, signing an acknowledgement, holding
//! remote work back until the synchronisation it says is owed has happened, and polling every
//! thirty seconds are each somebody's to do with this record; none of them happens inside it. The
//! web side of the feed - the durable service that stores and distributes these records - is the
//! web repository's.

use std::collections::{BTreeMap, BTreeSet};

use kr_protocol::ids::{AuthorityRevision, DeviceId, RevocationRequestId};
use kr_protocol::pairing::{AuthorityRevisionRecord, RevocationRequest};
use kr_protocol::scalars::{Nullable, TimestampMs};
use kr_protocol::sharing::AuthorityFeedStatus;

use super::durable::{StoredFeed, StoredRevocation};

/// How often a host polls the feed while it is online, in milliseconds.
pub const FEED_POLL_INTERVAL_MS: u64 = 30_000;

/// One retained revocation record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedRevocation {
    /// The request a remote owner published.
    pub request: RevocationRequest,
    /// The revision this host issued for it.
    pub authority_revision: AuthorityRevision,
    /// When this host applied it, in UTC milliseconds.
    pub applied_at_ms: u64,
    /// The enrolled hosts that have acknowledged it.
    pub acknowledged_by: BTreeSet<DeviceId>,
    /// True once every enrolled host had acknowledged it.
    ///
    /// A settled record is kept rather than deleted. Its revision is what the device list reports
    /// as a host's last acknowledgement, and its identity is what stops the same request being
    /// applied a second time under a new revision. Deleting it would make a republished request
    /// look new and a settled acknowledgement look like one that never happened.
    pub settled: bool,
}

impl RetainedRevocation {
    /// Whether every enrolled host has acknowledged this record.
    #[must_use]
    pub fn is_settled(&self, enrolled: &BTreeSet<DeviceId>) -> bool {
        enrolled.is_subset(&self.acknowledged_by)
    }
}

/// Why this host would not act on a feed entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeedRefusal {
    /// The record's revision is at or below the one this host has accepted.
    OutOfOrder {
        /// What this host holds.
        accepted: AuthorityRevision,
        /// What the record offered.
        offered: AuthorityRevision,
    },
    /// The record was issued by another host.
    AnotherHost,
    /// This request has already been applied.
    AlreadyApplied,
}

/// This host's view of the remote authority feed.
#[derive(Clone, Debug)]
pub struct AuthorityFeed {
    host_device_id: DeviceId,
    accepted: AuthorityRevision,
    records: BTreeMap<RevocationRequestId, RetainedRevocation>,
    enrolled: BTreeSet<DeviceId>,
    last_synchronised_at_ms: Option<u64>,
    stale: bool,
    /// True until this host has synchronised on the connection it now holds.
    owes_synchronisation: bool,
}

impl AuthorityFeed {
    /// A feed for one host at one revision.
    ///
    /// A fresh feed owes a synchronisation: a host that has just started has not heard from the
    /// feed, and section 10 requires the synchronisation before affected remote access rather than
    /// after the first request that needed it.
    #[must_use]
    pub fn new(host_device_id: DeviceId, accepted: AuthorityRevision) -> Self {
        Self {
            host_device_id,
            accepted,
            records: BTreeMap::new(),
            enrolled: BTreeSet::new(),
            last_synchronised_at_ms: None,
            stale: true,
            owes_synchronisation: true,
        }
    }

    /// The latest revision this host has accepted.
    #[must_use]
    pub const fn accepted_revision(&self) -> AuthorityRevision {
        self.accepted
    }

    /// Enrols a host that must acknowledge this host's revocation records.
    pub fn enrol(&mut self, device_id: DeviceId) {
        self.enrolled.insert(device_id);
    }

    /// Removes an enrolled host explicitly.
    ///
    /// Section 10 keeps a revocation record until every affected enrolled host acknowledges it
    /// **or that host is explicitly removed**. This is the second half; the records it was holding
    /// open settle once it is gone.
    pub fn remove_enrolled(&mut self, device_id: DeviceId) {
        self.enrolled.remove(&device_id);
        let enrolled = self.enrolled.clone();
        for record in self.records.values_mut() {
            // The acknowledgement it did make is kept: it is a fact about a host that was enrolled
            // at the time, and the record's job now is only to stop owing delivery to a host that
            // no longer exists.
            record.settled = enrolled.is_subset(&record.acknowledged_by);
        }
    }

    /// The next revision this host would issue, when nothing else allocates one.
    ///
    /// Only this host issues one, and it always follows the one it holds. A request carries no
    /// revision, so there is nothing a device can say that reaches this number.
    #[must_use]
    pub fn next_revision(&self) -> AuthorityRevision {
        AuthorityRevision::new(self.accepted.get().saturating_add(1))
    }

    /// Applies a validated revocation request under the revision the host allocated for it.
    ///
    /// The revision is the **daemon's**, taken from the registry that also numbers local
    /// revocations. One allocator or two is not a detail: two would let a feed entry and a local
    /// revocation claim the same number, and every host downstream orders by that number.
    ///
    /// The signature and the owner authority behind `request` are checked before this is called;
    /// what is checked here is the ordering, the host it is addressed to, and whether this exact
    /// request has already been applied.
    ///
    /// # Errors
    ///
    /// Returns [`FeedRefusal::AnotherHost`] when the request is addressed elsewhere,
    /// [`FeedRefusal::OutOfOrder`] when the allocated revision does not follow the accepted one,
    /// and [`FeedRefusal::AlreadyApplied`] when a **different** request carries an identity this
    /// host has already applied.
    pub fn apply(
        &mut self,
        request: RevocationRequest,
        revision: AuthorityRevision,
        now_ms: u64,
    ) -> std::result::Result<AuthorityRevision, FeedRefusal> {
        if request.host_device_id != self.host_device_id {
            return Err(FeedRefusal::AnotherHost);
        }
        if let Some(held) = self.records.get(&request.request_id) {
            // Idempotent, but only for the same request. A republished request is the same
            // revocation and keeps its revision; a different request wearing that identity is
            // refused rather than quietly answered with somebody else's result.
            if held.request == request {
                return Ok(held.authority_revision);
            }
            return Err(FeedRefusal::AlreadyApplied);
        }
        if revision.get() <= self.accepted.get() {
            return Err(FeedRefusal::OutOfOrder {
                accepted: self.accepted,
                offered: revision,
            });
        }
        self.accepted = revision;
        self.records.insert(
            request.request_id,
            RetainedRevocation {
                request,
                authority_revision: revision,
                applied_at_ms: now_ms,
                acknowledged_by: BTreeSet::new(),
                settled: false,
            },
        );
        Ok(revision)
    }

    /// Records that this host allocated a revision for a revocation of its own.
    ///
    /// A local revocation is not a feed entry, but it does consume a revision, and the feed has to
    /// know: otherwise `apply` would allocate a number the registry has already used and the
    /// device list would report a revision older than the one in force.
    pub const fn note_revision(&mut self, revision: AuthorityRevision) {
        if revision.get() > self.accepted.get() {
            self.accepted = revision;
        }
    }

    /// Accepts an authority revision record this host issued earlier and is now reading back.
    ///
    /// # Errors
    ///
    /// Returns [`FeedRefusal::AnotherHost`] for a record from another host and
    /// [`FeedRefusal::OutOfOrder`] for one at or below the revision this host has accepted.
    pub fn accept(
        &mut self,
        record: &AuthorityRevisionRecord,
    ) -> std::result::Result<(), FeedRefusal> {
        if record.host_device_id != self.host_device_id {
            return Err(FeedRefusal::AnotherHost);
        }
        if record.authority_revision.get() <= self.accepted.get() {
            return Err(FeedRefusal::OutOfOrder {
                accepted: self.accepted,
                offered: record.authority_revision,
            });
        }
        self.accepted = record.authority_revision;
        Ok(())
    }

    /// Records one enrolled host's acknowledgement of one revocation record.
    ///
    /// Returns whether every enrolled host has now acknowledged it. The record is kept either way:
    /// what changes when it settles is that this host stops owing its delivery, not that it
    /// forgets the revocation happened.
    pub fn acknowledge(&mut self, request_id: RevocationRequestId, device_id: DeviceId) -> bool {
        let enrolled = self.enrolled.clone();
        let Some(record) = self.records.get_mut(&request_id) else {
            return false;
        };
        record.acknowledged_by.insert(device_id);
        record.settled = enrolled.is_subset(&record.acknowledged_by);
        record.settled
    }

    /// The revocation records this host is still owed acknowledgements for.
    #[must_use]
    pub fn retained(&self) -> Vec<&RetainedRevocation> {
        self.records
            .values()
            .filter(|record| !record.settled)
            .collect()
    }

    /// Every revocation record this host has applied, settled or not.
    #[must_use]
    pub fn applied(&self) -> Vec<&RetainedRevocation> {
        self.records.values().collect()
    }

    /// The last acknowledgement one enrolled host made, as the device list shows it.
    ///
    /// Read across every applied record, settled included, because a settled record is exactly the
    /// one a host acknowledged and forgetting it would report that host as never having answered.
    #[must_use]
    pub fn last_acknowledgement(&self, device_id: DeviceId) -> Option<AuthorityRevision> {
        self.records
            .values()
            .filter(|record| record.acknowledged_by.contains(&device_id))
            .map(|record| record.authority_revision)
            .max()
    }

    /// Records a successful synchronisation with the feed.
    pub const fn synchronised(&mut self, at_ms: u64) {
        self.last_synchronised_at_ms = Some(at_ms);
        self.stale = false;
        self.owes_synchronisation = false;
    }

    /// Records that the feed could not be reached.
    ///
    /// The status becomes stale and stays stale. What this does *not* do is owe a fresh
    /// synchronisation: an unreachable feed is not a reason to stop serving work this host is
    /// already authorised for, and section 10 answers an unreachable feed with the personal
    /// offline-grant or organisation lease policy rather than with a refusal.
    pub const fn unreachable(&mut self) {
        self.stale = true;
    }

    /// Records that this host's connection was replaced, so a synchronisation is owed again.
    pub const fn reconnected(&mut self) {
        self.owes_synchronisation = true;
        self.stale = true;
    }

    /// Whether remote work must wait for a synchronisation.
    ///
    /// True from the moment a connection is established until a synchronisation has happened on
    /// it. Section 10: "Synchronise at reconnect before affected remote access when the feed is
    /// reachable."
    #[must_use]
    pub const fn synchronisation_owed(&self) -> bool {
        self.owes_synchronisation
    }

    /// When the next poll is due, while this host is online.
    #[must_use]
    pub fn next_poll_due_ms(&self) -> Option<u64> {
        self.last_synchronised_at_ms
            .map(|last| last.saturating_add(FEED_POLL_INTERVAL_MS))
    }

    /// What this host shows about the feed.
    #[must_use]
    pub fn status(&self) -> AuthorityFeedStatus {
        AuthorityFeedStatus {
            accepted_revision: self.accepted,
            last_synchronised_at_ms: Nullable(self.last_synchronised_at_ms.map(TimestampMs::new)),
            stale: self.stale,
            unacknowledged_records: u32::try_from(self.retained().len()).unwrap_or(u32::MAX),
        }
    }

    /// This feed, as it is written down.
    #[must_use]
    pub fn snapshot(&self) -> StoredFeed {
        StoredFeed {
            host_device_id: self.host_device_id,
            accepted: self.accepted,
            enrolled: self.enrolled.iter().copied().collect(),
            records: self
                .records
                .values()
                .map(|record| StoredRevocation {
                    request: record.request.clone(),
                    authority_revision: record.authority_revision,
                    applied_at_ms: TimestampMs::new(record.applied_at_ms),
                    acknowledged_by: record.acknowledged_by.iter().copied().collect(),
                    settled: record.settled,
                })
                .collect(),
            last_synchronised_at_ms: Nullable(self.last_synchronised_at_ms.map(TimestampMs::new)),
        }
    }

    /// Rebuilds a feed from what was written down.
    ///
    /// A restarted host owes a synchronisation and its status is stale, whatever it last recorded:
    /// what it knew before it stopped is not evidence about the feed now.
    #[must_use]
    pub fn restore(stored: &StoredFeed) -> Self {
        Self {
            host_device_id: stored.host_device_id,
            accepted: stored.accepted,
            records: stored
                .records
                .iter()
                .map(|record| {
                    (
                        record.request.request_id,
                        RetainedRevocation {
                            request: record.request.clone(),
                            authority_revision: record.authority_revision,
                            applied_at_ms: record.applied_at_ms.get(),
                            acknowledged_by: record.acknowledged_by.iter().copied().collect(),
                            settled: record.settled,
                        },
                    )
                })
                .collect(),
            enrolled: stored.enrolled.iter().copied().collect(),
            last_synchronised_at_ms: stored.last_synchronised_at_ms.as_ref().map(|at| at.get()),
            stale: true,
            owes_synchronisation: true,
        }
    }
}
