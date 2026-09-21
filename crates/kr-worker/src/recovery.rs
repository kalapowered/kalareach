//! The frozen copies a paged recovery is read out of.
//!
//! A view that lost its place installs the resources this host is arbitrating and then applies the
//! events that follow them. How many resources that is depends on what this host's upstreams asked
//! of it, so the state does not fit one control frame and has to be read in pages.
//!
//! Pages of a live map are not one state. Between two of them the host can settle a request, admit
//! another and move every identifier a later page would have started at, and a client that joined
//! those pages together would install a state the host was never in. Refusing a continuation
//! whenever the map moved does not fix it either: a host busy enough to move between two pages is
//! busy enough to move between every two pages, and the client would never finish.
//!
//! So the state is copied once, at the moment its cursor is fixed, and every page of that recovery
//! is read out of the copy. The pages are one state whatever the host does meanwhile, and the
//! client applies the events above the copy's cursor exactly as it does for a snapshot that fitted
//! one page.
//!
//! What a copy costs is bounded three ways: it ends when its last page is read, it ends when the
//! connection reading it goes, and it ends at [`RECOVERY_COPY_DEADLINE`] whatever the reader does.
//! Beyond that the copies of one host are held under a ceiling, and a new copy ends the oldest
//! unfinished one rather than pushing the host past it.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use kr_protocol::gateway::PendingResource;
use kr_protocol::ids::{ConnectionId, PendingResourceId};
use kr_transport::clock::ContinuousInstant;

use crate::broker::ReplayCursor;

/// How long a frozen copy outlives the page that made it.
///
/// A client pages a recovery as fast as its connection answers, so this is not a budget it plans
/// against; it is how long the host keeps a copy nobody came back for. It sits between the five
/// seconds this host gives a peer to finish a write and the two minutes it gives a person to
/// answer a request, which is the scale of a client that is still there but slow.
pub const RECOVERY_COPY_DEADLINE: Duration = Duration::from_secs(30);

/// How many bytes of frozen copies one host holds at once.
///
/// It is sixteen times what one page carries, so several connections recover at the same time
/// without waiting for each other, and a host whose clients all leave mid-recovery still gives
/// that memory back at the deadline rather than at the end of the session.
pub const MAX_RECOVERY_COPY_BYTES: usize = 16 * (crate::service::MAX_REPLAY_PAGE_BYTES as usize);

/// What one resource counts against a page's byte bound and its copy's share of the ceiling.
///
/// It is what the resource encodes to, measured with the codec that puts it on the wire, plus what
/// carrying it in an array costs. An estimate would not do: a page is bounded so that the answer
/// fits the frame the peer said it can receive, and an estimate that reads low is a page that
/// cannot be sent, which is the failure paging exists to prevent.
fn resource_bytes(resource: &PendingResource) -> usize {
    /// What the enclosing array spends on one element, and what a codec may round up by.
    const CARRIED: usize = 16;
    crate::snapshot::wire::measure(resource)
        .map_or(MAX_RECOVERY_COPY_BYTES, |cost| cost.bytes)
        .saturating_add(CARRIED)
}

/// What a page leaves for the rest of the answer it travels in.
///
/// A page is cut to fit a frame, but the frame also carries the session, its attachments and the
/// cursors around it. This is what the page gives up for those, so a full page and the answer it
/// belongs to still fit what the peer said it can receive.
pub const RECOVERY_ANSWER_RESERVE: usize = 16 * 1024;

/// How much of a copy one page may carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageBounds {
    /// How many resources the page carries at most.
    pub resources: usize,
    /// How many bytes of resource the page carries at most.
    pub bytes: usize,
}

/// One bounded page of a frozen copy, and the state it belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryPage {
    /// Which copy this page was cut from, which is what a continuation names.
    pub snapshot: u64,
    /// The position the whole copy is current at.
    pub cursor: ReplayCursor,
    /// The resources this page carries, in identifier order.
    pub resources: Vec<PendingResource>,
    /// The resource the next page continues after, when the copy continues past this page.
    pub continue_after: Option<PendingResourceId>,
}

/// One connection's frozen copy of the resources.
#[derive(Debug)]
struct Frozen {
    /// Which copy this is.
    ///
    /// It is the identity a continuation names, and no two copies of one host share it. A position
    /// would not do: a host changes what a page carries without moving its stream - a gap makes
    /// every unresolved resource volatile and announces nothing - so two copies taken at one
    /// position can hold different states, and a continuation of the first must not be answered
    /// out of the second.
    snapshot: u64,
    /// The position the copy was taken at.
    cursor: ReplayCursor,
    /// The whole state, in identifier order.
    resources: Vec<PendingResource>,
    /// What this copy counts against the host's ceiling.
    bytes: usize,
    /// When it was taken.
    taken: ContinuousInstant,
}

/// The frozen copies one host is serving recoveries out of.
///
/// One connection reads one copy at a time: a first page replaces whatever that connection was
/// reading, because a client that starts a recovery again has abandoned the one before it.
#[derive(Debug)]
pub struct RecoveryCopies {
    /// The most bytes of copies this host holds at once.
    ceiling: usize,
    held: Mutex<Held>,
}

/// The copies themselves, and the counter that names them.
///
/// The counter both identifies a copy and orders it against the others, because a copy taken later
/// always takes a higher number.
#[derive(Debug, Default)]
struct Held {
    copies: BTreeMap<ConnectionId, Frozen>,
    next_snapshot: u64,
}

impl Held {
    /// Ends every copy that reached the deadline.
    fn expire(&mut self, now: ContinuousInstant) {
        self.copies.retain(|_, frozen| {
            now.saturating_duration_since(frozen.taken) < RECOVERY_COPY_DEADLINE
        });
    }

    /// What the copies held here add up to.
    fn bytes(&self) -> usize {
        self.copies
            .values()
            .fold(0_usize, |total, frozen| total.saturating_add(frozen.bytes))
    }

    /// Ends the copy taken longest ago, and says whether there was one.
    fn end_oldest(&mut self) -> bool {
        let Some(oldest) = self
            .copies
            .iter()
            .min_by_key(|(_, frozen)| frozen.snapshot)
            .map(|(connection, _)| *connection)
        else {
            return false;
        };
        self.copies.remove(&oldest);
        true
    }
}

impl RecoveryCopies {
    /// The copies of a host that holds [`MAX_RECOVERY_COPY_BYTES`] of them.
    #[must_use]
    pub fn new() -> Self {
        Self::with_ceiling(MAX_RECOVERY_COPY_BYTES)
    }

    /// The copies of a host that holds `ceiling` bytes of them.
    #[must_use]
    pub fn with_ceiling(ceiling: usize) -> Self {
        Self {
            ceiling,
            held: Mutex::new(Held::default()),
        }
    }

    /// Freezes `resources` for this connection and returns the first page of them.
    ///
    /// `resources` is the whole state at `cursor`, in identifier order, taken under the lock that
    /// fixed that cursor. A copy is kept only when the state does not fit one page: a recovery
    /// that ended in its first page has nothing left to be continued.
    ///
    /// The host makes room for what it keeps. Copies that reached the deadline go first, then the
    /// oldest unfinished copy goes, one at a time, until this one fits under the ceiling. A reader
    /// whose copy went is told to start again, which it can always do, because a first page never
    /// depends on a copy. One copy larger than the whole ceiling is still kept while it is the
    /// only one: a host that refused it could not be recovered from at all.
    pub fn begin(
        &self,
        connection: ConnectionId,
        cursor: ReplayCursor,
        resources: Vec<PendingResource>,
        now: ContinuousInstant,
        bounds: PageBounds,
    ) -> RecoveryPage {
        debug_assert!(
            resources.is_sorted_by_key(|resource| resource.resource_id),
            "a copy is paged by identifier, so it is taken in identifier order"
        );
        let (carried, continue_after) = take_page(&resources, bounds);
        let mut held = self
            .held
            .lock()
            .expect("the recovery copies are not poisoned");
        held.expire(now);
        // This connection's previous recovery is abandoned, and its bytes are given back before
        // the new copy asks for room.
        held.copies.remove(&connection);
        let snapshot = held.next_snapshot;
        held.next_snapshot = held.next_snapshot.saturating_add(1);
        if continue_after.is_some() {
            let bytes = resources.iter().fold(0_usize, |total, resource| {
                total.saturating_add(resource_bytes(resource))
            });
            while held.bytes().saturating_add(bytes) > self.ceiling && held.end_oldest() {}
            held.copies.insert(
                connection,
                Frozen {
                    snapshot,
                    cursor,
                    resources,
                    bytes,
                    taken: now,
                },
            );
        }
        RecoveryPage {
            snapshot,
            cursor,
            resources: carried,
            continue_after,
        }
    }

    /// Reads the page after `after` out of the copy this connection is reading.
    ///
    /// `snapshot` names which copy the client means, and a copy that has ended answers `None`: the
    /// client takes a fresh first page. The copy ends here when this page is its last, because a
    /// client that has the whole state has nothing more to come back for.
    pub fn resume(
        &self,
        connection: ConnectionId,
        snapshot: u64,
        after: PendingResourceId,
        now: ContinuousInstant,
        bounds: PageBounds,
    ) -> Option<RecoveryPage> {
        let mut held = self
            .held
            .lock()
            .expect("the recovery copies are not poisoned");
        held.expire(now);
        let frozen = held.copies.get(&connection)?;
        if frozen.snapshot != snapshot {
            return None;
        }
        let position = frozen
            .resources
            .binary_search_by(|resource| resource.resource_id.cmp(&after))
            .ok()?;
        let rest = frozen.resources.get(position.saturating_add(1)..)?;
        let cursor = frozen.cursor;
        let (carried, continue_after) = take_page(rest, bounds);
        if continue_after.is_none() {
            held.copies.remove(&connection);
        }
        Some(RecoveryPage {
            snapshot,
            cursor,
            resources: carried,
            continue_after,
        })
    }

    /// Ends every copy that has reached its deadline.
    ///
    /// The host calls this on its own cadence as well as on its way through a recovery, so a copy
    /// nobody came back for is given back at its deadline rather than at the next recovery.
    pub fn expire(&self, now: ContinuousInstant) {
        self.held
            .lock()
            .expect("the recovery copies are not poisoned")
            .expire(now);
    }

    /// Ends the copy a connection was reading, because the connection has gone.
    pub fn forget(&self, connection: ConnectionId) {
        self.held
            .lock()
            .expect("the recovery copies are not poisoned")
            .copies
            .remove(&connection);
    }

    /// How many bytes of copy this host is holding, which is what the ceiling bounds.
    #[cfg(test)]
    fn held_bytes(&self) -> usize {
        self.held
            .lock()
            .expect("the recovery copies are not poisoned")
            .bytes()
    }
}

impl Default for RecoveryCopies {
    fn default() -> Self {
        Self::new()
    }
}

/// Takes as much of `resources` as one page carries, and says where the next page continues.
///
/// The first resource of a page is carried whatever it measures. A page that refused it would
/// never advance, and the client would be asking for a state it can never be given.
fn take_page(
    resources: &[PendingResource],
    bounds: PageBounds,
) -> (Vec<PendingResource>, Option<PendingResourceId>) {
    let mut carried: Vec<PendingResource> = Vec::new();
    let mut measured = 0_usize;
    for resource in resources {
        let cost = resource_bytes(resource);
        let full = carried.len() >= bounds.resources
            || (!carried.is_empty() && measured.saturating_add(cost) > bounds.bytes);
        if full {
            let continue_after = carried.last().map(|last| last.resource_id);
            return (carried, continue_after);
        }
        measured = measured.saturating_add(cost);
        carried.push(resource.clone());
    }
    (carried, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::gateway::{
        DownstreamRequestId, NativeClassification, NativeMethodClass, PendingKind, PendingState,
    };
    use kr_protocol::ids::{
        ApplicationInstanceId, GatewayConnectionId, SourceGeneration, UpstreamMethod,
        UpstreamRequestId,
    };
    use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};
    use kr_protocol::session::Durability;
    use kr_transport::clock::{ContinuousClock, ManualClock};

    fn connection(byte: u8) -> ConnectionId {
        ConnectionId::new(Uuid::from_bytes([byte; 16]))
    }

    fn cursor() -> ReplayCursor {
        ReplayCursor {
            generation: 7,
            sequence: 41,
        }
    }

    /// One reading of a clock that has not moved, for the tests that are not about time.
    fn instant() -> ContinuousInstant {
        ManualClock::new().now()
    }

    /// A state of `count` resources, in the identifier order a copy is taken in.
    fn state(count: u8) -> Vec<PendingResource> {
        let mut resources: Vec<PendingResource> = (1..=count)
            .map(|byte| PendingResource {
                resource_id: PendingResourceId::new(Uuid::from_bytes([byte; 16])),
                application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([2; 16])),
                request: DownstreamRequestId::new(
                    GatewayConnectionId::new(1),
                    UpstreamRequestId::new(format!("upstream-{byte}")).expect("valid"),
                ),
                kind: PendingKind::Approval,
                method: UpstreamMethod::new("session/request_permission").expect("valid"),
                classification: NativeClassification::declared(NativeMethodClass::Mutation),
                source_generation: SourceGeneration::new(1),
                state: PendingState::Pending,
                durability: Durability::Durable,
                deadline_ms: Nullable::null(),
                recorded_at: TimestampMs::new(1),
                interpretation_verified: true,
            })
            .collect();
        resources.sort_unstable_by_key(|resource| resource.resource_id);
        resources
    }

    /// One connection and the recovery it is reading, for a test that keeps several.
    struct Reading {
        connection: ConnectionId,
        page: RecoveryPage,
    }

    fn bounds(resources: usize) -> PageBounds {
        PageBounds {
            resources,
            bytes: usize::MAX,
        }
    }

    #[test]
    fn a_copy_is_read_to_its_end_whatever_the_state_does_meanwhile() {
        let copies = RecoveryCopies::new();
        let whole = state(9);
        let first = copies.begin(connection(1), cursor(), whole.clone(), instant(), bounds(4));
        assert_eq!(first.resources.len(), 4, "a page carries what it may");
        let mut collected: Vec<_> = first
            .resources
            .iter()
            .map(|resource| resource.resource_id)
            .collect();
        let mut after = first.continue_after;
        while let Some(resource_id) = after {
            let page = copies
                .resume(
                    connection(1),
                    first.snapshot,
                    resource_id,
                    instant(),
                    bounds(4),
                )
                .expect("a copy that has not ended is read to its end");
            collected.extend(page.resources.iter().map(|resource| resource.resource_id));
            after = page.continue_after;
        }
        let expected: Vec<_> = whole.iter().map(|resource| resource.resource_id).collect();
        assert_eq!(collected, expected, "the pages are the state, once each");
    }

    #[test]
    fn a_copy_ends_when_its_last_page_is_read() {
        let copies = RecoveryCopies::new();
        let whole = state(6);
        let first = copies.begin(connection(1), cursor(), whole.clone(), instant(), bounds(5));
        let last = first.continue_after.expect("five of six leaves one");
        let page = copies
            .resume(connection(1), first.snapshot, last, instant(), bounds(5))
            .expect("the last page is answered");
        assert_eq!(page.continue_after, None, "and it completes the state");
        assert_eq!(copies.held_bytes(), 0, "so nothing is still held for it");
        assert!(
            copies
                .resume(connection(1), first.snapshot, last, instant(), bounds(5))
                .is_none(),
            "and a continuation of it is refused rather than answered"
        );
    }

    #[test]
    fn a_copy_that_reached_its_deadline_is_not_continued() {
        let clock = ManualClock::new();
        let copies = RecoveryCopies::new();
        let first = copies.begin(connection(1), cursor(), state(6), clock.now(), bounds(2));
        let after = first.continue_after.expect("the state continues");
        clock.advance(RECOVERY_COPY_DEADLINE - Duration::from_millis(1));
        assert!(
            copies
                .resume(connection(1), first.snapshot, after, clock.now(), bounds(2))
                .is_some(),
            "a copy is read while it is inside its deadline"
        );
        clock.advance(Duration::from_millis(1));
        assert!(
            copies
                .resume(connection(1), first.snapshot, after, clock.now(), bounds(2))
                .is_none(),
            "and refused once it is not"
        );
        assert_eq!(copies.held_bytes(), 0, "the memory goes with it");
    }

    #[test]
    fn a_connection_that_goes_takes_its_copy_with_it() {
        let copies = RecoveryCopies::new();
        let first = copies.begin(connection(1), cursor(), state(6), instant(), bounds(2));
        let after = first.continue_after.expect("the state continues");
        copies.forget(connection(1));
        assert_eq!(copies.held_bytes(), 0);
        assert!(
            copies
                .resume(connection(1), first.snapshot, after, instant(), bounds(2))
                .is_none(),
            "what the connection was reading is no longer there to read"
        );
    }

    #[test]
    fn two_connections_read_their_own_copies() {
        let copies = RecoveryCopies::new();
        let first = copies.begin(connection(1), cursor(), state(6), instant(), bounds(2));
        let other_cursor = ReplayCursor {
            generation: cursor().generation,
            sequence: cursor().sequence + 5,
        };
        let other = copies.begin(connection(2), other_cursor, state(4), instant(), bounds(2));
        let mine = copies
            .resume(
                connection(1),
                first.snapshot,
                first.continue_after.expect("the state continues"),
                instant(),
                bounds(2),
            )
            .expect("my copy is still mine");
        assert_eq!(mine.cursor, cursor(), "and it is the state I asked for");
        assert!(
            copies
                .resume(
                    connection(2),
                    first.snapshot,
                    other.continue_after.expect("the state continues"),
                    instant(),
                    bounds(2),
                )
                .is_none(),
            "a connection cannot read another connection's copy by naming it"
        );
        assert!(
            copies
                .resume(
                    connection(2),
                    other.snapshot,
                    other.continue_after.expect("the state continues"),
                    instant(),
                    bounds(2),
                )
                .is_some(),
            "while its own copy is still there to read"
        );
    }

    #[test]
    fn a_new_recovery_replaces_the_one_that_connection_was_reading() {
        let copies = RecoveryCopies::new();
        let first = copies.begin(connection(1), cursor(), state(6), instant(), bounds(2));
        let after = first.continue_after.expect("the state continues");
        // The same position, which is what a host that changed a state without announcing
        // anything gives the next copy: a gap rewrites every unresolved resource's durability and
        // moves no cursor. So the copy is named by itself and not by where it was taken.
        let fresh = copies.begin(connection(1), cursor(), state(6), instant(), bounds(2));
        assert_ne!(
            fresh.snapshot, first.snapshot,
            "a copy taken at a position another copy was taken at is still another copy"
        );
        assert!(
            copies
                .resume(connection(1), first.snapshot, after, instant(), bounds(2))
                .is_none(),
            "the abandoned copy is gone"
        );
        assert!(
            copies
                .resume(connection(1), fresh.snapshot, after, instant(), bounds(2))
                .is_some(),
            "and the one that replaced it is what this connection reads"
        );
    }

    #[test]
    fn a_copy_nobody_comes_back_for_is_given_back_at_its_deadline() {
        let clock = ManualClock::new();
        let copies = RecoveryCopies::new();
        let first = copies.begin(connection(1), cursor(), state(6), clock.now(), bounds(2));
        clock.advance(RECOVERY_COPY_DEADLINE);
        copies.expire(clock.now());
        assert_eq!(
            copies.held_bytes(),
            0,
            "the host gives the memory back on its own cadence, not at the next recovery"
        );
        assert!(
            copies
                .resume(
                    connection(1),
                    first.snapshot,
                    first.continue_after.expect("the state continues"),
                    clock.now(),
                    bounds(2)
                )
                .is_none()
        );
    }

    #[test]
    fn the_oldest_unfinished_copy_goes_before_the_ceiling_does() {
        let one = state(6);
        let held = one
            .iter()
            .fold(0_usize, |total, resource| total + resource_bytes(resource));
        // Room for two copies of this state and not for three.
        let copies = RecoveryCopies::with_ceiling(held * 2 + held / 2);
        let first = copies.begin(connection(1), cursor(), one.clone(), instant(), bounds(2));
        let second = Reading {
            connection: connection(2),
            page: copies.begin(connection(2), cursor(), one.clone(), instant(), bounds(2)),
        };
        assert_eq!(copies.held_bytes(), held * 2, "two copies fit");
        let third = Reading {
            connection: connection(3),
            page: copies.begin(connection(3), cursor(), one.clone(), instant(), bounds(2)),
        };
        assert_eq!(
            copies.held_bytes(),
            held * 2,
            "and a third does not push the host past its ceiling"
        );
        assert!(
            copies
                .resume(
                    connection(1),
                    first.snapshot,
                    first.continue_after.expect("the state continues"),
                    instant(),
                    bounds(2)
                )
                .is_none(),
            "the copy taken longest ago is the one that ended"
        );
        for still_held in [&second, &third] {
            assert!(
                copies
                    .resume(
                        still_held.connection,
                        still_held.page.snapshot,
                        still_held.page.continue_after.expect("the state continues"),
                        instant(),
                        bounds(2)
                    )
                    .is_some(),
                "and the copies that were still being read are still readable"
            );
        }
    }

    #[test]
    fn one_copy_larger_than_the_ceiling_is_still_readable() {
        let one = state(6);
        let held = one
            .iter()
            .fold(0_usize, |total, resource| total + resource_bytes(resource));
        let copies = RecoveryCopies::with_ceiling(held / 2);
        let first = copies.begin(connection(1), cursor(), one, instant(), bounds(2));
        assert!(
            copies
                .resume(
                    connection(1),
                    first.snapshot,
                    first.continue_after.expect("the state continues"),
                    instant(),
                    bounds(2)
                )
                .is_some(),
            "a host that refused it could not be recovered from at all"
        );
    }

    #[test]
    fn a_page_encodes_within_the_bytes_it_was_cut_to() {
        let copies = RecoveryCopies::new();
        let one = state(6);
        let bound = resource_bytes(&one[0]).saturating_mul(3);
        let page = copies.begin(
            connection(1),
            cursor(),
            one,
            instant(),
            PageBounds {
                resources: usize::MAX,
                bytes: bound,
            },
        );
        let measured = crate::snapshot::wire::measure(&page.resources)
            .expect("the page encodes")
            .bytes;
        assert!(
            measured <= bound,
            "a page is cut to what it encodes to, not to an estimate of it: {measured} against {bound}"
        );
        assert!(
            page.continue_after.is_some(),
            "and this bound is smaller than the state"
        );
    }

    #[test]
    fn a_page_holds_at_most_its_byte_bound() {
        let copies = RecoveryCopies::new();
        let one = state(6);
        let two = one
            .iter()
            .take(2)
            .fold(0_usize, |total, resource| total + resource_bytes(resource));
        let page = copies.begin(
            connection(1),
            cursor(),
            one,
            instant(),
            PageBounds {
                resources: usize::MAX,
                bytes: two,
            },
        );
        assert_eq!(page.resources.len(), 2, "what the bound pays for, no more");
        assert!(page.continue_after.is_some(), "and the rest continues");
    }
}
