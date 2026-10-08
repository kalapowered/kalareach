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
//! * **A feed that answered that this host was removed from it says so.** The status shows
//!   the removal and the last synchronisation before it, and [`AuthorityFeed::is_removed`] is what
//!   the grants that rest on the feed ask.
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

use super::durable::{StoredFeed, StoredRemoval, StoredRevocation};

/// How often a host polls the feed while it is online, in milliseconds.
pub const FEED_POLL_INTERVAL_MS: u64 = 30_000;

/// One retained revocation record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedRevocation {
    /// The request a remote owner published.
    pub request: RevocationRequest,
    /// The revision this host issued for it, once the revocation has taken effect.
    pub authority_revision: Option<AuthorityRevision>,
    /// The revision the feed held when this host began to apply the request. The revision record
    /// it issues for it follows this one, so a crash between applying and acknowledging reissues
    /// the same record.
    pub previous_revision: AuthorityRevision,
    /// When this host began to apply it, in UTC milliseconds.
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

/// What beginning to apply a request found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Beginning {
    /// The host had not taken this request before.
    New,
    /// The host had taken this very request, and goes on from where that left it.
    Resumed,
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
    /// The feed's answer that this host was removed from it.
    removal: Option<Removal>,
}

/// The feed's answer that this host was removed from it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Removal {
    /// The origin of the feed that answered.
    origin: String,
    /// When this host first read the answer, in UTC milliseconds.
    at_ms: u64,
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
            removal: None,
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

    /// Notes that this host begins to apply a validated revocation request, before it does.
    ///
    /// The signature and the owner authority behind `request` are checked before this is called;
    /// what is checked here is the host it is addressed to and whether this request, or another
    /// under its identity, has been taken before. The record is written down before the
    /// revocation takes effect, so a host that stops in between finds the request half applied and
    /// finishes it (the revocation is idempotent) instead of taking it for new.
    /// `previous` is the revision the feed holds, which the revision record this host issues for
    /// the request follows.
    ///
    /// # Errors
    ///
    /// Returns [`FeedRefusal::AnotherHost`] when the request is addressed elsewhere and
    /// [`FeedRefusal::AlreadyApplied`] when a **different** request carries an identity this host
    /// has already taken.
    pub fn begin(
        &mut self,
        request: RevocationRequest,
        previous: AuthorityRevision,
        now_ms: u64,
    ) -> std::result::Result<Beginning, FeedRefusal> {
        if request.host_device_id != self.host_device_id {
            return Err(FeedRefusal::AnotherHost);
        }
        if let Some(held) = self.records.get(&request.request_id) {
            // Idempotent, but only for the same request. A republished request is the same
            // revocation and keeps its revision; a different request wearing that identity is
            // refused rather than quietly answered with somebody else's result.
            if held.request == request {
                return Ok(Beginning::Resumed);
            }
            return Err(FeedRefusal::AlreadyApplied);
        }
        self.records.insert(
            request.request_id,
            RetainedRevocation {
                request,
                authority_revision: None,
                previous_revision: previous,
                applied_at_ms: now_ms,
                acknowledged_by: BTreeSet::new(),
                settled: false,
            },
        );
        Ok(Beginning::New)
    }

    /// Notes that a request took effect under `revision`, which the daemon's registry allocated.
    ///
    /// The registry is the one allocator: a feed entry and a local revocation draw on the same
    /// numbers, and every host downstream orders by them. The feed has been told of the number
    /// already ([`Self::note_revision`]), so this records it against the request and moves nothing
    /// back. A request taken again keeps the revision it first took.
    pub fn took_effect(&mut self, request_id: RevocationRequestId, revision: AuthorityRevision) {
        if let Some(record) = self.records.get_mut(&request_id)
            && record.authority_revision.is_none()
        {
            record.authority_revision = Some(revision);
        }
        self.note_revision(revision);
    }

    /// What this host holds of one request, when it has taken it.
    #[must_use]
    pub fn record(&self, request_id: RevocationRequestId) -> Option<&RetainedRevocation> {
        self.records.get(&request_id)
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

    /// Records that the feed at `origin` answered that this host was removed from it.
    ///
    /// A removal ends the feed's retention of everything addressed to this host, so the records it
    /// was still owed settle: this host is the enrolled host that has been removed, which is the
    /// second way section 10 lets retention end. The last successful synchronisation stays what it
    /// was, because a removal is not one. An answer that repeats one already recorded for the same
    /// origin changes nothing.
    pub fn removed_from(&mut self, origin: &str, at_ms: u64) {
        if self.is_removed_from(origin) {
            return;
        }
        self.removal = Some(Removal {
            origin: origin.to_owned(),
            at_ms,
        });
        self.stale = true;
        self.remove_enrolled(self.host_device_id);
    }

    /// Whether the feed at `origin` has answered that this host was removed from it.
    #[must_use]
    pub fn is_removed_from(&self, origin: &str) -> bool {
        self.removal
            .as_ref()
            .is_some_and(|removal| removal.origin == origin)
    }

    /// Whether this host was removed from the feed it reads, so that nothing it would learn from
    /// the feed again can be waited for.
    #[must_use]
    pub const fn is_removed(&self) -> bool {
        self.removal.is_some()
    }

    /// Forgets a removal, because the feed this host reads is no longer the one that answered it,
    /// and enrols this host with whatever it reads next.
    pub fn clear_removal(&mut self) {
        if self.removal.take().is_some() {
            self.enrol(self.host_device_id);
        }
    }

    /// What this host shows about the feed.
    #[must_use]
    pub fn status(&self) -> AuthorityFeedStatus {
        AuthorityFeedStatus {
            accepted_revision: self.accepted,
            last_synchronised_at_ms: Nullable(self.last_synchronised_at_ms.map(TimestampMs::new)),
            stale: self.stale,
            removed_at_ms: Nullable(
                self.removal
                    .as_ref()
                    .map(|removal| TimestampMs::new(removal.at_ms)),
            ),
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
                    authority_revision: Nullable(record.authority_revision),
                    previous_revision: record.previous_revision,
                    applied_at_ms: TimestampMs::new(record.applied_at_ms),
                    acknowledged_by: record.acknowledged_by.iter().copied().collect(),
                    settled: record.settled,
                })
                .collect(),
            last_synchronised_at_ms: Nullable(self.last_synchronised_at_ms.map(TimestampMs::new)),
        }
    }

    /// The removal this feed holds, as it is written down.
    ///
    /// It is kept beside the feed's own record and not in it, so a host's earlier record stays
    /// readable.
    #[must_use]
    pub fn removal(&self) -> Option<StoredRemoval> {
        self.removal.as_ref().map(|removal| StoredRemoval {
            origin: removal.origin.clone(),
            at_ms: TimestampMs::new(removal.at_ms),
        })
    }

    /// Takes back a removal that was written down, when this host starts.
    pub fn restore_removal(&mut self, stored: &StoredRemoval) {
        self.removal = Some(Removal {
            origin: stored.origin.clone(),
            at_ms: stored.at_ms.get(),
        });
        self.remove_enrolled(self.host_device_id);
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
                            authority_revision: record.authority_revision.0,
                            previous_revision: record.previous_revision,
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
            removal: None,
        }
    }
}
