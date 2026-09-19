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
//! * **Synchronise at reconnect, before affected remote access.**
//!   [`AuthorityFeed::synchronisation_owed`] is what a connection asks before it serves remote
//!   work, and it stays true until a synchronisation has actually happened.
//! * **When the feed is unavailable, the status is stale and says so.** It is never reported as
//!   up to date because nothing contradicted it.
//!
//! The web side of the feed - the durable service that stores and distributes these records - is
//! the web repository's. What is here is the host's half: what it issues, what it accepts, what it
//! retains and what it refuses to do before it has synchronised.

use std::collections::{BTreeMap, BTreeSet};

use kr_protocol::ids::{AuthorityRevision, DeviceId, RevocationRequestId};
use kr_protocol::pairing::{AuthorityRevisionRecord, RevocationRequest};
use kr_protocol::scalars::{Nullable, TimestampMs};
use kr_protocol::sharing::AuthorityFeedStatus;

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
    retained: BTreeMap<RevocationRequestId, RetainedRevocation>,
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
            retained: BTreeMap::new(),
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
        for record in self.retained.values_mut() {
            record.acknowledged_by.remove(&device_id);
        }
        self.collect();
    }

    /// The next revision this host would issue.
    ///
    /// Only this host issues one, and it always follows the one it holds. A request carries no
    /// revision, so there is nothing a device can say that reaches this number.
    #[must_use]
    pub fn next_revision(&self) -> AuthorityRevision {
        AuthorityRevision::new(self.accepted.get().saturating_add(1))
    }

    /// Applies a validated revocation request and returns the revision this host issued for it.
    ///
    /// The signature and the owner authority behind `request` are checked before this is called;
    /// what is checked here is the ordering and the identity of the host it is addressed to.
    ///
    /// # Errors
    ///
    /// Returns [`FeedRefusal::AnotherHost`] when the request is addressed elsewhere, and
    /// [`FeedRefusal::AlreadyApplied`] when this request has already been applied.
    pub fn apply(
        &mut self,
        request: RevocationRequest,
        now_ms: u64,
    ) -> std::result::Result<AuthorityRevision, FeedRefusal> {
        if request.host_device_id != self.host_device_id {
            return Err(FeedRefusal::AnotherHost);
        }
        if let Some(held) = self.retained.get(&request.request_id) {
            // Idempotent: a republished request is the same revocation, and issuing a second
            // revision for it would make one owner's action look like two.
            return Ok(held.authority_revision);
        }
        let revision = self.next_revision();
        self.accepted = revision;
        self.retained.insert(
            request.request_id,
            RetainedRevocation {
                request,
                authority_revision: revision,
                applied_at_ms: now_ms,
                acknowledged_by: BTreeSet::new(),
            },
        );
        Ok(revision)
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
    /// Returns whether the record is now settled and has been collected.
    pub fn acknowledge(&mut self, request_id: RevocationRequestId, device_id: DeviceId) -> bool {
        let enrolled = self.enrolled.clone();
        let Some(record) = self.retained.get_mut(&request_id) else {
            return false;
        };
        record.acknowledged_by.insert(device_id);
        let settled = record.is_settled(&enrolled);
        if settled {
            self.retained.remove(&request_id);
        }
        settled
    }

    /// The revocation records this host is still retaining.
    #[must_use]
    pub fn retained(&self) -> Vec<&RetainedRevocation> {
        self.retained.values().collect()
    }

    /// The last acknowledgement one enrolled host made, as the device list shows it.
    #[must_use]
    pub fn last_acknowledgement(&self, device_id: DeviceId) -> Option<AuthorityRevision> {
        self.retained
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
            unacknowledged_records: u32::try_from(self.retained.len()).unwrap_or(u32::MAX),
        }
    }

    fn collect(&mut self) {
        let enrolled = self.enrolled.clone();
        self.retained
            .retain(|_, record| !record.is_settled(&enrolled));
    }
}
