//! The session's side of the privacy fence around its attention text.
//!
//! The control daemon serves the text of this session's questions and notifications to the
//! people reading the environment's inbox, and it reads that text from this worker when it serves
//! it. Privacy mode asks that once a generation enabling it is committed, no text decided under an
//! earlier generation is published, however long a read or a delivery has been holding it. Two
//! things keep that, and this module is the worker's half of both.
//!
//! # The barrier
//!
//! Before the worker commits a generation that enables privacy mode it raises a transition and
//! tells the daemon so, in a statement on its attention connection. The daemon applies a
//! statement under the lock every release of text takes, so once it acknowledges one saying a
//! transition is in progress, no release of this session's text is under way and none can begin
//! until a later statement settles the transition. Statements carry one order the worker keeps for
//! its whole life, and the daemon applies one only when it comes after the last it applied from
//! the same connection, so a delayed statement cannot undo a later one.
//!
//! # Leases
//!
//! A daemon that does not answer in time cannot be relied on to have stopped anything. So every
//! answer that carries text also carries the end of a lease on the machine's continuous clock,
//! after which the daemon hands no byte of it to anybody, and the worker keeps the latest lease end
//! it has issued under each daemon generation. Without an acknowledgement the worker commits only
//! once every lease has ended; with one, once every lease issued under another daemon generation
//! has ended, since the acknowledging daemon's barrier covers only the answers it holds itself.
//! From the moment a transition is raised no answer carries text, so no new lease prolongs the
//! wait.
//!
//! # Completion
//!
//! Privacy mode reports complete only once the daemon has recorded the new generation, which a
//! request on the current attention connection says when it names that generation. The
//! [`AttentionPrivacy`] subsystem reports that one piece of cleanup until then.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use kr_ipc::clock::SharedClock;
use kr_protocol::attention::{ATTENTION_TEXT_LEASE_MS, AttentionBarrier};
use kr_protocol::ids::{ConnectionId, RequestId};
use kr_protocol::scalars::{Nullable, U64};

use crate::privacy::{Cancelled, Fenced, PrivacyGeneration, PrivacySubsystem, Removed};

/// The longest a raised transition waits for the control daemon's acknowledgement, from the raise
/// to the acknowledgement: the turn at the connection's writer, the write and the answer.
pub const ATTENTION_BARRIER_WAIT: Duration = Duration::from_secs(2);

/// The longest the wait for leases to end sleeps before it reads the continuous clock again.
const LEASE_POLL: Duration = Duration::from_millis(250);

/// The worker's fence state, shared by its connections and the transition that raises it.
pub struct AttentionFence {
    state: Mutex<FenceState>,
    /// Woken when an acknowledgement arrives or the current connection changes.
    changed: tokio::sync::Notify,
    /// Held by the transition in progress, so one is raised at a time.
    transition: Arc<tokio::sync::Mutex<()>>,
    clock: Arc<dyn SharedClock>,
}

impl std::fmt::Debug for AttentionFence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AttentionFence")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
struct FenceState {
    /// The last statement's place in the worker's order.
    sequence: u64,
    /// Whether a transition is in progress.
    raised: bool,
    /// Counts raises and settlements, so an answer whose read straddled one is known for it.
    transitions: u64,
    /// The attention connection that speaks for the daemon now.
    current: Option<Current>,
    /// The latest lease end issued under each daemon generation.
    leases: BTreeMap<u64, u64>,
}

#[derive(Debug)]
struct Current {
    connection_id: ConnectionId,
    /// The daemon generation the connection proved.
    daemon_generation: u64,
    /// The latest statement the daemon acknowledged on it.
    acknowledged: Option<u64>,
    /// The greatest privacy generation its requests named as recorded.
    named: Option<u64>,
}

/// What a statement could learn of the journal's privacy generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalGeneration {
    /// The journal was read: the generation it holds, or none when it holds no privacy record,
    /// and then the session serves no text at all.
    Read(Option<u64>),
    /// The journal could not be read.
    Unreadable,
}

/// A statement to send, and the connection that was current when it was made.
#[derive(Debug)]
pub struct Statement {
    /// The statement.
    pub frame: AttentionBarrier,
    /// Where it goes: the attention connection current when it was made, if there was one.
    pub connection_id: Option<ConnectionId>,
    /// Whether the journal could not be read for it. Such a statement names no generation, and
    /// the connection it goes on is ended after it, so the next connection reads the journal
    /// again.
    pub unreadable: bool,
}

/// Whether a request's recorded generation is behind the generation an answer was decided under.
///
/// A request that names none is behind any generation; an answer decided under none is behind
/// nothing.
#[must_use]
pub const fn behind(recorded: Option<u64>, decided: Option<u64>) -> bool {
    match (recorded, decided) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(recorded), Some(decided)) => recorded < decided,
    }
}

impl AttentionFence {
    /// Builds the fence of a worker that has raised nothing and answered nothing.
    #[must_use]
    pub fn new(clock: Arc<dyn SharedClock>) -> Self {
        Self {
            state: Mutex::new(FenceState::default()),
            changed: tokio::sync::Notify::new(),
            transition: Arc::new(tokio::sync::Mutex::new(())),
            clock,
        }
    }

    fn state(&self) -> MutexGuard<'_, FenceState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes the next statement's place and builds it from the state as it is now.
    ///
    /// `generation` reads the journal's privacy generation; it is called with the state held, so
    /// the generation and whether a transition is raised are read as one. A statement that names
    /// no generation says a transition is in progress whatever the state says: lowering the
    /// daemon's barrier without naming the generation committed would leave it releasing text
    /// decided under the one before, so a statement that cannot say where the session stands keeps
    /// the barrier where it is. A session whose journal holds no privacy record serves no text,
    /// so that costs it nothing.
    fn statement(
        state: &mut FenceState,
        connection_id: Option<ConnectionId>,
        generation: impl FnOnce() -> JournalGeneration,
    ) -> Statement {
        state.sequence = state.sequence.saturating_add(1);
        let (generation, unreadable) = match generation() {
            JournalGeneration::Read(generation) => (generation, false),
            JournalGeneration::Unreadable => (None, true),
        };
        Statement {
            frame: AttentionBarrier {
                request_id: RequestId::new(state.sequence),
                sequence: U64::new(state.sequence),
                raised: state.raised || generation.is_none(),
                generation: Nullable(generation.map(U64::new)),
            },
            connection_id,
            unreadable,
        }
    }

    /// Makes a newly accepted attention connection the current one and returns its first
    /// statement, which is to go out before anything else the connection carries.
    pub fn began(
        &self,
        connection_id: ConnectionId,
        daemon_generation: u64,
        generation: impl FnOnce() -> JournalGeneration,
    ) -> Statement {
        let statement = {
            let mut state = self.state();
            state.current = Some(Current {
                connection_id,
                daemon_generation,
                acknowledged: None,
                named: None,
            });
            Self::statement(&mut state, Some(connection_id), generation)
        };
        self.changed.notify_waiters();
        statement
    }

    /// Forgets a connection that has ended or been withdrawn, when it was the current one.
    pub fn ended(&self, connection_id: ConnectionId) {
        let changed = {
            let mut state = self.state();
            let current = state
                .current
                .as_ref()
                .is_some_and(|current| current.connection_id == connection_id);
            if current {
                state.current = None;
            }
            current
        };
        if changed {
            self.changed.notify_waiters();
        }
    }

    /// Records the daemon's acknowledgement of a statement, when it arrived on the current
    /// connection. One from any other connection says nothing about the daemon this worker speaks
    /// to now.
    pub fn acknowledged(&self, connection_id: ConnectionId, sequence: u64) {
        {
            let mut state = self.state();
            let Some(current) = state
                .current
                .as_mut()
                .filter(|current| current.connection_id == connection_id)
            else {
                return;
            };
            current.acknowledged = Some(
                current
                    .acknowledged
                    .map_or(sequence, |acknowledged| acknowledged.max(sequence)),
            );
        }
        self.changed.notify_waiters();
    }

    /// Records the generation a request on a connection named as the daemon's recorded one, when
    /// it arrived on the current connection.
    pub fn named(&self, connection_id: ConnectionId, recorded: Option<u64>) {
        let Some(recorded) = recorded else {
            return;
        };
        let mut state = self.state();
        if let Some(current) = state
            .current
            .as_mut()
            .filter(|current| current.connection_id == connection_id)
        {
            current.named = Some(current.named.map_or(recorded, |named| named.max(recorded)));
        }
    }

    /// Returns the greatest generation a request on the current connection named as recorded.
    #[must_use]
    pub fn named_on_current(&self) -> Option<u64> {
        self.state()
            .current
            .as_ref()
            .and_then(|current| current.named)
    }

    /// Notes where the transitions stand, before the records of a text answer are read.
    #[must_use]
    pub fn note(&self) -> u64 {
        self.state().transitions
    }

    /// Decides whether a text answer read after [`Self::note`] may carry its text, and registers
    /// its lease when it may.
    ///
    /// It may not while a transition is raised, when a transition was raised or settled while its
    /// records were read, or when the request's recorded generation is behind the generation the
    /// answer was decided under. Otherwise its lease starts now and is counted under the daemon
    /// generation of the connection the answer goes out on, before the answer leaves: a raise
    /// either comes after this and waits for the lease, or came before and the answer carries no
    /// text.
    #[must_use]
    pub fn lease(
        &self,
        noted: u64,
        daemon_generation: u64,
        decided: Option<u64>,
        recorded: Option<u64>,
    ) -> Option<u64> {
        let mut state = self.state();
        if state.raised || state.transitions != noted || behind(recorded, decided) {
            return None;
        }
        let now = self.clock.boot_elapsed_ms();
        let end = now.saturating_add(ATTENTION_TEXT_LEASE_MS);
        // Leases that have ended hold nothing back, so they are let go of here.
        state.leases.retain(|_, until| *until > now);
        let latest = state.leases.entry(daemon_generation).or_insert(end);
        *latest = (*latest).max(end);
        Some(end)
    }

    /// Waits until no other transition is in progress, and holds the turn until it is let go of.
    pub async fn turn(&self) -> tokio::sync::OwnedMutexGuard<()> {
        Arc::clone(&self.transition).lock_owned().await
    }

    /// Raises a transition and returns the statement that says so.
    pub fn raise(&self, generation: impl FnOnce() -> JournalGeneration) -> Statement {
        let mut state = self.state();
        state.raised = true;
        state.transitions = state.transitions.saturating_add(1);
        let connection_id = state.current.as_ref().map(|current| current.connection_id);
        Self::statement(&mut state, connection_id, generation)
    }

    /// Settles the transition in progress and returns the statement that says so, with the
    /// generation the journal holds now.
    pub fn settle(&self, generation: impl FnOnce() -> JournalGeneration) -> Statement {
        let mut state = self.state();
        state.raised = false;
        state.transitions = state.transitions.saturating_add(1);
        let connection_id = state.current.as_ref().map(|current| current.connection_id);
        Self::statement(&mut state, connection_id, generation)
    }

    /// Returns whether a transition is in progress.
    #[must_use]
    pub fn is_raised(&self) -> bool {
        self.state().raised
    }

    /// Waits until the daemon acknowledges the statement at `sequence`, or a later one, on the
    /// connection current when the acknowledgement arrives, until `deadline`.
    ///
    /// Returns the daemon generation of the connection that acknowledged it, or nothing when none
    /// did in time.
    pub async fn until_acknowledged(
        &self,
        sequence: u64,
        deadline: tokio::time::Instant,
    ) -> Option<u64> {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            // Registered before the look, so an acknowledgement between the two is not missed.
            notified.as_mut().enable();
            if let Some(generation) = self.acknowledged_by(sequence) {
                return Some(generation);
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return self.acknowledged_by(sequence);
            }
        }
    }

    fn acknowledged_by(&self, sequence: u64) -> Option<u64> {
        self.state()
            .current
            .as_ref()
            .filter(|current| {
                current
                    .acknowledged
                    .is_some_and(|acknowledged| acknowledged >= sequence)
            })
            .map(|current| current.daemon_generation)
    }

    /// Waits until every lease issued under a daemon generation other than `covered` has ended,
    /// reading the machine's continuous clock again after every wake rather than trusting the
    /// timer that woke it.
    ///
    /// The timer may not count time the machine spent asleep and the continuous clock does, so it
    /// wakes at least every [`LEASE_POLL`] to look again, and a wait that spans a suspension ends
    /// soon after the machine resumes rather than a whole lease later.
    pub async fn until_leases_end(&self, covered: Option<u64>) {
        loop {
            let latest = self
                .state()
                .leases
                .iter()
                .filter(|(generation, _)| Some(**generation) != covered)
                .map(|(_, until)| *until)
                .max();
            let Some(latest) = latest else {
                return;
            };
            let now = self.clock.boot_elapsed_ms();
            if now >= latest {
                return;
            }
            tokio::time::sleep(Duration::from_millis(latest - now).min(LEASE_POLL)).await;
        }
    }
}

/// The attention store's part of privacy mode, as one of the subsystems enabling it drives.
///
/// The worker holds no attention text outside its journal, so its fence, cancellation and removal
/// change nothing; what it reports is the one piece of cleanup that is not the worker's to finish:
/// the control daemon recording the generation this enabling committed. Until a request on the
/// current attention connection names that generation or a later one, it is outstanding.
#[derive(Debug)]
pub struct AttentionPrivacy {
    fence: Arc<AttentionFence>,
    target: Option<u64>,
}

impl AttentionPrivacy {
    /// Builds the subsystem over the worker's fence.
    #[must_use]
    pub const fn new(fence: Arc<AttentionFence>) -> Self {
        Self {
            fence,
            target: None,
        }
    }
}

impl PrivacySubsystem for AttentionPrivacy {
    fn name(&self) -> &'static str {
        "attention"
    }

    fn fence(&mut self, generation: PrivacyGeneration) -> Fenced {
        self.target = Some(generation.get());
        // The release of this session's text at the daemon was stopped before the generation was
        // committed; it is the one content-bearing outbox this subsystem answers for.
        Fenced {
            queues: 1,
            items: 0,
        }
    }

    fn cancel_undispatched(&mut self, _generation: PrivacyGeneration) -> Cancelled {
        Cancelled {
            undispatched: 0,
            in_flight: self.outstanding(),
        }
    }

    fn remove_retained(&mut self, _generation: PrivacyGeneration) -> Removed {
        Removed::default()
    }

    fn outstanding(&self) -> u64 {
        match self.target {
            Some(target)
                if self
                    .fence
                    .named_on_current()
                    .is_none_or(|named| named < target) =>
            {
                1
            }
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fence() -> (Arc<AttentionFence>, kr_ipc::clock::ManualSharedClock) {
        let clock = kr_ipc::clock::ManualSharedClock::new();
        (
            Arc::new(AttentionFence::new(Arc::new(clock.clone()))),
            clock,
        )
    }

    fn connection() -> ConnectionId {
        ConnectionId::new(kr_ipc::new_uuid())
    }

    /// A request that names no recorded generation is behind any, and an answer decided under no
    /// generation is behind nothing.
    #[test]
    fn behind_compares_what_the_daemon_recorded_with_what_decided_the_answer() {
        assert!(behind(None, Some(0)));
        assert!(behind(Some(1), Some(2)));
        assert!(!behind(Some(2), Some(2)));
        assert!(!behind(Some(3), Some(2)));
        assert!(!behind(None, None));
    }

    /// Every statement takes the next place in one order, whichever connection it goes to, and
    /// states the whole fence: a new connection's first statement says a raised transition is
    /// still in progress.
    #[test]
    fn statements_share_one_order_and_state_the_whole_fence() {
        let (fence, _clock) = fence();
        let first = fence.began(connection(), 1, || JournalGeneration::Read(Some(0)));
        let raised = fence.raise(|| JournalGeneration::Read(Some(0)));
        let second = fence.began(connection(), 1, || JournalGeneration::Read(Some(0)));
        let settled = fence.settle(|| JournalGeneration::Read(Some(1)));
        assert!(first.frame.sequence < raised.frame.sequence);
        assert!(raised.frame.sequence < second.frame.sequence);
        assert!(second.frame.sequence < settled.frame.sequence);
        assert!(!first.frame.raised);
        assert!(raised.frame.raised && second.frame.raised);
        assert!(!settled.frame.raised);
        assert_eq!(settled.frame.generation, Nullable::some(U64::new(1)));
    }

    /// A statement that cannot name the journal's generation says a transition is in progress,
    /// even once the transition has been settled.
    #[test]
    fn a_statement_that_cannot_name_the_generation_keeps_the_barrier() {
        let (fence, _clock) = fence();
        let first = fence.began(connection(), 1, || JournalGeneration::Unreadable);
        assert!(first.frame.raised);
        assert_eq!(first.frame.generation, Nullable::null());
        assert!(
            first.unreadable,
            "the connection it goes on is ended after it"
        );
        let _ = fence.raise(|| JournalGeneration::Read(Some(0)));
        let settled = fence.settle(|| JournalGeneration::Unreadable);
        assert!(settled.frame.raised, "an unknown generation lowers nothing");
        assert!(!fence.is_raised(), "though the transition itself is over");

        // A journal with no privacy record names none either, but it was read.
        let recordless = fence.began(connection(), 1, || JournalGeneration::Read(None));
        assert!(recordless.frame.raised);
        assert!(!recordless.unreadable, "its connection stays");
    }

    /// No answer carries text while a transition is raised or when one began or ended while its
    /// records were read, and a lease counts under the daemon generation it went out to.
    #[test]
    fn no_lease_while_raised_or_across_a_transition() {
        let (fence, clock) = fence();
        clock.advance(Duration::from_secs(100));
        let noted = fence.note();
        assert_eq!(
            fence.lease(noted, 1, Some(0), Some(0)),
            Some(100_000 + ATTENTION_TEXT_LEASE_MS)
        );
        let _ = fence.raise(|| JournalGeneration::Read(Some(0)));
        assert_eq!(fence.lease(fence.note(), 1, Some(0), Some(0)), None);
        let _ = fence.settle(|| JournalGeneration::Read(Some(0)));
        // Noted before the settlement: the read straddled it.
        assert_eq!(fence.lease(noted, 1, Some(0), Some(0)), None);
        // A request behind the answer's generation gets no text.
        assert_eq!(fence.lease(fence.note(), 1, Some(1), Some(0)), None);
        assert_eq!(fence.lease(fence.note(), 1, Some(1), None), None);
    }

    /// Without an acknowledgement the wait covers every lease; with one, only the leases issued
    /// under other daemon generations.
    #[tokio::test]
    async fn the_wait_covers_the_leases_the_acknowledging_daemon_does_not_hold() {
        let (fence, clock) = fence();
        clock.advance(Duration::from_secs(10));
        let _ = fence.lease(fence.note(), 1, Some(0), Some(0));
        // Everything issued under generation one is covered by its own acknowledgement.
        tokio::time::timeout(Duration::from_secs(1), fence.until_leases_end(Some(1)))
            .await
            .expect("nothing else to wait for");
        let waiting = {
            let fence = Arc::clone(&fence);
            tokio::spawn(async move { fence.until_leases_end(Some(2)).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !waiting.is_finished(),
            "generation one's lease holds the wait"
        );
        clock.advance(Duration::from_millis(ATTENTION_TEXT_LEASE_MS));
        tokio::time::timeout(Duration::from_secs(10), waiting)
            .await
            .expect("the lease ended")
            .expect("the wait ends");
    }

    /// An acknowledgement counts only from the current connection, and a new connection starts
    /// from none; the same holds for the generation requests name.
    #[tokio::test]
    async fn only_the_current_connection_acknowledges() {
        let (fence, _clock) = fence();
        let old = connection();
        let _ = fence.began(old, 1, || JournalGeneration::Read(Some(0)));
        let raised = fence.raise(|| JournalGeneration::Read(Some(0)));
        let sequence = raised.frame.sequence.get();
        let new = connection();
        let first = fence.began(new, 2, || JournalGeneration::Read(Some(0)));
        fence.acknowledged(old, sequence);
        fence.named(old, Some(1));
        let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        assert_eq!(fence.until_acknowledged(sequence, deadline).await, None);
        assert_eq!(fence.named_on_current(), None);
        // The new connection's first statement, which still says raised, is a later one.
        fence.acknowledged(new, first.frame.sequence.get());
        let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        assert_eq!(fence.until_acknowledged(sequence, deadline).await, Some(2));
        fence.named(new, Some(1));
        assert_eq!(fence.named_on_current(), Some(1));
    }

    /// The subsystem reports the daemon's record of the enabled generation as outstanding until a
    /// request on the current connection names it, and a new connection starts from none.
    #[test]
    fn completion_waits_for_the_current_connection_to_name_the_generation() {
        let (fence, _clock) = fence();
        let link = connection();
        let _ = fence.began(link, 1, || JournalGeneration::Read(Some(0)));
        let mut subsystem = AttentionPrivacy::new(Arc::clone(&fence));
        assert_eq!(subsystem.outstanding(), 0);
        let _ = subsystem.fence(PrivacyGeneration::new(1));
        assert_eq!(subsystem.outstanding(), 1);
        fence.named(link, Some(0));
        assert_eq!(subsystem.outstanding(), 1);
        fence.named(link, Some(1));
        assert_eq!(subsystem.outstanding(), 0);
        let _ = fence.began(connection(), 1, || JournalGeneration::Read(Some(1)));
        assert_eq!(
            subsystem.outstanding(),
            1,
            "a new connection starts from none"
        );
    }
}
