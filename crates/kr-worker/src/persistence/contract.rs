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
//! What sits between the two is grouping. Section 24 permits writes to share a flush so long as
//! that does not move the dispatch boundary ahead of durability, and the journal's own
//! transactions are where that happens: a receipt transition writes the receipt row, its event
//! and its outbox record in one transaction, so three rows share one flush and either all three
//! are durable or none of them is. [`flush_policy`] is the rule that keeps it safe: a commit
//! point is never grouped with anything a caller is not already waiting on.

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
///
/// This is **this build's policy**, held where it can be read and tested, not a restatement of
/// section 24. The section names the three commit points that must be durable before something
/// else happens and forbids a per-keystroke or per-byte fsync; it permits safe grouped commits to
/// share a flush and does not forbid grouping the commit points with each other. Committing each
/// on its own is a choice made here.
///
/// It is not instrumentation of the store either: nothing consults it on the write path, because
/// the store's own durability settings are what carry a transaction. `Grouped` is a permission
/// rather than a description - a write this allows to share a flush may still be committed alone.
#[must_use]
pub const fn flush_policy(write: WriteKind) -> FlushPolicy {
    match write {
        // A commit point is what something else is waiting on, so this build does not group it.
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
    fn every_commit_point_says_what_it_commits_before() {
        for point in CommitPoint::ALL {
            assert!(
                !point.commits_before().is_empty(),
                "{point:?} does not say what it is ahead of"
            );
        }
    }
}
