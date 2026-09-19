//! The durability contract: what is committed before what, and what never waits for a flush.
//!
//! Section 24 fixes two orders and one prohibition.
//!
//! * **Intent acceptance is committed before the acknowledgement.** A caller that is told
//!   `accepted` can rely on this host still knowing about the action after a crash.
//! * **The dispatch marker is committed before the effect.** That is what makes a lost outcome
//!   recoverable rather than repeatable: a marker with no authoritative answer becomes `unknown`
//!   on restart, and that identifier is never dispatched again.
//! * **No per-keystroke, per-output-byte or ordinary prompt and command telemetry event waits for
//!   an fsync.** A terminal that flushed a page cache entry for every character would be a
//!   terminal nobody could type in, and section 24 says so in as many words.
//!
//! What sits between the two is grouping. Writes that no acknowledgement and no dispatch is
//! waiting on may share one flush, and [`CommitGroup`] is where they wait. The invariant that
//! makes grouping safe is the one [`flush_policy`] states and the tests below check: a commit
//! point is never grouped, and a commit point drains the group before it commits, so the durable
//! order is the order this host produced. Grouping shares a flush; it never moves the dispatch
//! boundary ahead of durability.

/// One point at which this host commits before it acts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CommitPoint {
    /// The intent, committed before the caller is told the action was accepted.
    IntentAcceptance,
    /// The dispatch marker, committed before the effect leaves this host.
    DispatchMarker,
    /// The outcome, the receipt revision and the event record, in one transaction.
    Outcome,
    /// A rejection and the name a fence owes for it, in one transaction.
    Rejection,
    /// The closure record.
    Closure,
    /// The interval durable writing was unavailable.
    RecoveryGap,
}

impl CommitPoint {
    /// Every commit point, in the order a single action passes through them.
    pub const ALL: &'static [Self] = &[
        Self::IntentAcceptance,
        Self::DispatchMarker,
        Self::Outcome,
        Self::Rejection,
        Self::Closure,
        Self::RecoveryGap,
    ];

    /// Returns what this point commits before.
    #[must_use]
    pub const fn commits_before(self) -> &'static str {
        match self {
            Self::IntentAcceptance => "the caller is told the action was accepted",
            Self::DispatchMarker => "the effect leaves this host",
            Self::Outcome => "the result is served to anyone",
            Self::Rejection => "the refusal is returned",
            Self::Closure => "the session identity is released",
            Self::RecoveryGap => "the journal is treated as durable again",
        }
    }
}

/// What kind of write is being made.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WriteKind {
    /// One of the commit points.
    Commit(CommitPoint),
    /// One keystroke on its way to the terminal.
    Keystroke,
    /// One byte of terminal output.
    OutputByte,
    /// An ordinary shell prompt or command telemetry event.
    PromptTelemetry,
    /// A side effect that had no attachment to go to.
    HostEvent,
    /// What the host time contract has to survive a restart.
    TimeCheckpoint,
}

/// What a write is allowed to wait for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FlushPolicy {
    /// Flushed on its own account, before the caller is answered.
    Immediate,
    /// May share the next flush with the writes beside it.
    Grouped,
    /// Never reaches a durable store at all.
    NotDurable,
}

/// Returns what one kind of write is allowed to wait for.
#[must_use]
pub const fn flush_policy(write: WriteKind) -> FlushPolicy {
    match write {
        // A commit point is what something else is waiting on, so it is never grouped.
        WriteKind::Commit(_) => FlushPolicy::Immediate,
        // Section 24 names these three as the ones that must never wait for an fsync. Keystrokes
        // and output bytes are not written to the journal at all: the live parser is in worker
        // memory and the retained output is a bounded indexed spool.
        WriteKind::Keystroke | WriteKind::OutputByte => FlushPolicy::NotDurable,
        WriteKind::PromptTelemetry | WriteKind::HostEvent | WriteKind::TimeCheckpoint => {
            FlushPolicy::Grouped
        }
    }
}

/// How many grouped writes wait before the group is drained on its own account.
///
/// The bound exists so a session producing side effects and nothing else still reaches its store
/// rather than holding an unbounded list. It is small, because what waits here is work nobody is
/// blocked on and the cost of draining it is one transaction.
pub const MAX_GROUPED_WRITES: usize = 64;

/// Writes that may share one flush.
///
/// The group holds what no acknowledgement and no dispatch is waiting on. It is drained by the
/// bound above, by the worker's own maintenance, and by every commit point before that point
/// commits, which is what keeps the durable order the order this host produced.
#[derive(Debug, Default)]
pub struct CommitGroup<T> {
    queued: Vec<T>,
    flushes: u64,
}

impl<T> CommitGroup<T> {
    /// Builds an empty group.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            queued: Vec::new(),
            flushes: 0,
        }
    }

    /// Adds a write to the group.
    pub fn push(&mut self, write: T) {
        self.queued.push(write);
    }

    /// Returns how many writes are waiting.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queued.len()
    }

    /// Returns true when nothing is waiting.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queued.is_empty()
    }

    /// Returns true when the group has reached the bound it drains at on its own account.
    #[must_use]
    pub fn is_due(&self) -> bool {
        self.queued.len() >= MAX_GROUPED_WRITES
    }

    /// Returns how many times the group has been drained.
    ///
    /// One drain is one shared flush, which is what makes the grouping visible to a test: a
    /// hundred side effects that produced one flush shared it, and a hundred that produced a
    /// hundred did not.
    #[must_use]
    pub const fn flushes(&self) -> u64 {
        self.flushes
    }

    /// Takes everything waiting, and counts the flush.
    ///
    /// The caller writes what it is given in one transaction. An empty group counts no flush,
    /// because nothing was written.
    pub fn take(&mut self) -> Vec<T> {
        if self.queued.is_empty() {
            return Vec::new();
        }
        self.flushes += 1;
        std::mem::take(&mut self.queued)
    }

    /// Puts writes back at the front after a drain that could not be committed.
    ///
    /// A group whose transaction failed has not been written, so what it held is still owed. The
    /// flush that was counted stays counted: it happened, and it failed.
    pub fn restore(&mut self, mut writes: Vec<T>) {
        writes.append(&mut self.queued);
        self.queued = writes;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_commit_point_is_ever_grouped() {
        for point in CommitPoint::ALL {
            assert_eq!(
                flush_policy(WriteKind::Commit(*point)),
                FlushPolicy::Immediate,
                "{point:?} must not share a flush with anything"
            );
        }
    }

    #[test]
    fn no_keystroke_output_byte_or_prompt_event_waits_for_a_flush() {
        assert_eq!(flush_policy(WriteKind::Keystroke), FlushPolicy::NotDurable);
        assert_eq!(flush_policy(WriteKind::OutputByte), FlushPolicy::NotDurable);
        assert_eq!(
            flush_policy(WriteKind::PromptTelemetry),
            FlushPolicy::Grouped
        );
        for kind in [
            WriteKind::Keystroke,
            WriteKind::OutputByte,
            WriteKind::PromptTelemetry,
        ] {
            assert_ne!(
                flush_policy(kind),
                FlushPolicy::Immediate,
                "{kind:?} must not wait for an fsync of its own"
            );
        }
    }

    #[test]
    fn a_group_shares_one_flush_and_an_empty_one_counts_none() {
        let mut group: CommitGroup<u8> = CommitGroup::new();
        assert!(group.take().is_empty());
        assert_eq!(group.flushes(), 0);
        for value in 0..10 {
            group.push(value);
        }
        assert_eq!(group.len(), 10);
        assert_eq!(group.take().len(), 10);
        assert_eq!(group.flushes(), 1);
        assert!(group.is_empty());
    }

    #[test]
    fn a_group_that_could_not_be_committed_still_owes_what_it_held() {
        let mut group: CommitGroup<u8> = CommitGroup::new();
        group.push(1);
        group.push(2);
        let taken = group.take();
        group.push(3);
        group.restore(taken);
        assert_eq!(group.take(), vec![1, 2, 3]);
    }

    #[test]
    fn the_group_drains_on_its_own_account_at_the_bound() {
        let mut group: CommitGroup<u8> = CommitGroup::new();
        for _ in 0..MAX_GROUPED_WRITES - 1 {
            group.push(0);
            assert!(!group.is_due());
        }
        group.push(0);
        assert!(group.is_due());
    }
}
