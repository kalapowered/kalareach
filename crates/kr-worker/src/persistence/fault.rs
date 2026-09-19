//! The journal-fault and recovery seam.
//!
//! A worker whose journal stops answering is not a worker that stops. Section 7 keeps an
//! authorised stop available on the worker's in-memory authority, section 11 keeps the native
//! terminal's raw input and interruption available under the live input lease, and section 24
//! makes everything else refuse before dispatch. What follows from that is a durability posture
//! the rest of the worker reads rather than guesses at: while the journal is faulted, rich work is
//! fenced and volatile native traffic continues.
//!
//! This module is that posture, and the three signals it is made of.
//!
//! * **A fault is detected.** [`JournalHealth::note_fault`] records what failed, classified from
//!   the store's own answer rather than from a message, and the condition becomes
//!   [`JournalCondition::Faulted`]. Nothing durable is claimed from that moment.
//! * **Rich work is fenced.** [`DurabilityPosture`] is what a subsystem asks before it starts
//!   work that a receipt has to survive. `VolatileNative` is the posture that keeps the terminal
//!   usable and refuses everything that would need a durable record.
//! * **A gap is committed on recovery.** When durable writes work again, the interval the fault
//!   covered is written down as a [`RecoveryGap`], so a reader sees that the record is incomplete
//!   rather than reading continuity into it. A gap whose own write fails leaves the condition
//!   faulted; a recovery this host cannot record is not a recovery it may claim.
//!
//! The seam is a watch channel, so a consumer sees the condition now and is woken when it
//! changes. It never blocks the thread that is reporting the fault, which is the thread holding
//! the session.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use kr_protocol::scalars::TimestampMs;
use tokio::sync::watch;

/// What kind of fault a durable store is in.
///
/// The kind decides nothing about whether work is fenced, because every kind fences it. What it
/// decides is what a person is told and what a host may try next: a full store is a condition the
/// host can act on, and a corrupt one is a condition the archive has to be told about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FaultKind {
    /// No journal was opened for this session at all.
    Absent,
    /// The durable store is full.
    ///
    /// Section 24: a required durable store that is full rejects new durable mutations before
    /// dispatch, subject only to the explicit stop and native-terminal exceptions.
    Full,
    /// A write failed for a reason that is not capacity.
    WriteFailed,
    /// The store answered, and what it holds cannot be read back.
    ///
    /// This is the condition that produces an explicit incomplete archive rather than an invented
    /// success, so it is kept apart from an ordinary write failure.
    Corrupt,
}

impl FaultKind {
    /// Returns the stable name this kind is recorded and reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Full => "full",
            Self::WriteFailed => "write_failed",
            Self::Corrupt => "corrupt",
        }
    }

    /// Returns the kind a stored name refers to.
    #[must_use]
    pub fn from_stored(value: &str) -> Option<Self> {
        match value {
            "absent" => Some(Self::Absent),
            "full" => Some(Self::Full),
            "write_failed" => Some(Self::WriteFailed),
            "corrupt" => Some(Self::Corrupt),
            _ => None,
        }
    }

    /// Classifies one storage failure from the store's own answer.
    ///
    /// The classification reads the result code the store returned rather than the text of its
    /// message, because a message is a presentation and a code is a fact. `SQLITE_FULL` is
    /// capacity; `SQLITE_CORRUPT` and `SQLITE_NOTADB` are a store whose content cannot be
    /// trusted; everything else is a write that failed.
    #[must_use]
    pub fn classify(error: &rusqlite::Error) -> Self {
        use rusqlite::ErrorCode;

        let rusqlite::Error::SqliteFailure(failure, _) = error else {
            return Self::WriteFailed;
        };
        match failure.code {
            ErrorCode::DiskFull => Self::Full,
            ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase => Self::Corrupt,
            _ => Self::WriteFailed,
        }
    }
}

/// One fault, as the seam reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalFault {
    /// What kind of fault it is.
    pub kind: FaultKind,
    /// What the store said, for a person rather than for a decision.
    pub detail: String,
    /// When this host first observed it.
    pub observed_at_ms: TimestampMs,
    /// The receipt-event sequence the last durable write is known to have reached.
    ///
    /// A recovery gap starts here: everything after it is what this host cannot prove it wrote.
    pub durable_through: u64,
}

/// What a journal is able to do right now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JournalCondition {
    /// Every durable write this session needs is available.
    Healthy,
    /// The journal is faulted, and rich work is fenced.
    Faulted(JournalFault),
}

impl JournalCondition {
    /// Returns the fault, when this condition is one.
    #[must_use]
    pub const fn fault(&self) -> Option<&JournalFault> {
        match self {
            Self::Healthy => None,
            Self::Faulted(fault) => Some(fault),
        }
    }

    /// Returns true while durable writes are available.
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy)
    }
}

/// What a subsystem may do while the journal is in its current condition.
///
/// A posture is read, never inferred. A caller that decided for itself whether the journal looked
/// well would decide differently from the caller beside it, and two answers to one question is
/// how a host ends up dispatching an action it cannot record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DurabilityPosture {
    /// Every kind of work proceeds.
    Full,
    /// Rich work is fenced; native terminal traffic and an authorised stop continue.
    ///
    /// The named exceptions are section 7's `session.close`, which proceeds on the worker's
    /// in-memory authority and reports `durability=volatile`, and section 11's raw terminal input
    /// and interruption under the live input lease. Neither authorises a hidden rich retry.
    VolatileNative(JournalFault),
}

impl DurabilityPosture {
    /// Returns the fault this posture is under, when it is under one.
    #[must_use]
    pub const fn fault(&self) -> Option<&JournalFault> {
        match self {
            Self::Full => None,
            Self::VolatileNative(fault) => Some(fault),
        }
    }

    /// Returns the posture this condition puts a worker in.
    #[must_use]
    pub fn of(condition: &JournalCondition) -> Self {
        match condition {
            JournalCondition::Healthy => Self::Full,
            JournalCondition::Faulted(fault) => Self::VolatileNative(fault.clone()),
        }
    }

    /// Returns true when work that needs a durable receipt may start.
    #[must_use]
    pub const fn admits_durable_work(&self) -> bool {
        matches!(self, Self::Full)
    }

    /// Returns whether this kind of work may proceed under this posture.
    #[must_use]
    pub const fn admits(&self, work: WorkClass) -> bool {
        match self {
            Self::Full => true,
            Self::VolatileNative(_) => work.survives_a_journal_fault(),
        }
    }
}

/// What a piece of work needs from the journal.
///
/// Section 24 divides work by what a crash would leave behind rather than by which subsystem asks
/// for it, so this is the division: work whose answer a caller relies on the host still knowing
/// about, and work whose answer is the terminal itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WorkClass {
    /// A typed mutation that needs a durable receipt before it is dispatched.
    RichMutation,
    /// An authorised stop, which section 7 keeps available with `durability=volatile`.
    AuthorisedStop,
    /// Raw terminal input and interruption under the live input lease.
    NativeTerminal,
    /// A read of what this host already holds.
    Read,
}

impl WorkClass {
    /// Returns whether this class still proceeds while the journal is faulted.
    #[must_use]
    pub const fn survives_a_journal_fault(self) -> bool {
        match self {
            Self::RichMutation => false,
            Self::AuthorisedStop | Self::NativeTerminal | Self::Read => true,
        }
    }
}

/// The interval a fault covered, written down when durable writes work again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryGap {
    /// What kind of fault produced it.
    pub kind: FaultKind,
    /// What the store said when it failed.
    pub detail: String,
    /// When the fault was first observed.
    pub faulted_at_ms: TimestampMs,
    /// When durable writes worked again.
    pub recovered_at_ms: TimestampMs,
    /// The receipt-event sequence the last durable write before the fault reached.
    pub durable_through: u64,
    /// The receipt-event sequence the journal resumed at.
    pub resumed_at: u64,
}

/// The shared condition of one session's journal.
///
/// Held by the journal, read by anything that needs the posture. Reporting a fault does not wait
/// for a consumer to be ready for it: the thread that reports it is the thread holding the
/// session, and a seam that waited for a reader would stop the session to tell somebody it had
/// stopped. What it can wait for is a reader that is holding the value while it looks at it,
/// which is bounded by that reader's own borrow.
#[derive(Debug)]
pub struct JournalHealth {
    sender: watch::Sender<JournalCondition>,
    /// The receipt-event sequence the last durable write is known to have reached.
    ///
    /// A recovery gap starts here, so it is kept beside the condition rather than read from the
    /// store: the store is what has just stopped answering.
    durable_mark: AtomicU64,
}

impl Default for JournalHealth {
    fn default() -> Self {
        Self::new()
    }
}

impl JournalHealth {
    /// Builds a health seam in the healthy condition.
    #[must_use]
    pub fn new() -> Self {
        let (sender, _) = watch::channel(JournalCondition::Healthy);
        Self {
            sender,
            durable_mark: AtomicU64::new(0),
        }
    }

    /// Builds a shared health seam.
    #[must_use]
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Returns the condition now.
    #[must_use]
    pub fn condition(&self) -> JournalCondition {
        self.sender.borrow().clone()
    }

    /// Returns the posture now.
    #[must_use]
    pub fn posture(&self) -> DurabilityPosture {
        DurabilityPosture::of(&self.condition())
    }

    /// Subscribes to every change of condition.
    ///
    /// The receiver starts holding the condition now, so a consumer that subscribes after a fault
    /// sees the fault rather than waiting for the next one.
    #[must_use]
    pub fn watch(&self) -> watch::Receiver<JournalCondition> {
        self.sender.subscribe()
    }

    /// Records how far durable writing has reached.
    ///
    /// Called after a write commits, so the mark a later fault is measured from is the last
    /// sequence this host really wrote rather than the last one it attempted.
    pub(crate) fn note_durable_through(&self, sequence: u64) {
        self.durable_mark.fetch_max(sequence, Ordering::Relaxed);
    }

    /// Returns the sequence the last durable write is known to have reached.
    #[must_use]
    pub fn durable_through(&self) -> u64 {
        self.durable_mark.load(Ordering::Relaxed)
    }

    /// Classifies one storage failure and records it.
    ///
    /// This is the producer side of the seam, and it is one call so that every path through the
    /// journal reports a fault the same way. It returns true when the condition changed.
    pub(crate) fn observe(&self, error: &rusqlite::Error, now_ms: u64) -> bool {
        self.note_fault(JournalFault {
            kind: FaultKind::classify(error),
            detail: error.to_string(),
            observed_at_ms: TimestampMs::new(now_ms),
            durable_through: self.durable_through(),
        })
    }

    /// Records a fault, and returns true when it is a change of condition.
    ///
    /// The first fault is what a recovery gap is measured from, so a second fault while one is
    /// already open does not replace it: what is being recorded is the interval durability was
    /// unavailable, and that interval began at the first failure.
    ///
    /// It is crate-private on purpose. The condition is a fact about this host's durable store,
    /// and a subsystem that reported its own failure into it would fence rich work for a reason
    /// the store has nothing to do with.
    pub(crate) fn note_fault(&self, fault: JournalFault) -> bool {
        let mut changed = false;
        self.sender.send_if_modified(|condition| {
            if condition.is_healthy() {
                *condition = JournalCondition::Faulted(fault);
                changed = true;
                true
            } else {
                false
            }
        });
        changed
    }

    /// Returns the journal to the healthy condition, and returns the fault it was in.
    ///
    /// The caller writes the gap down before it calls this. A recovery whose gap could not be
    /// committed is not a recovery, because the record would then read as continuous over an
    /// interval this host knows it did not write. It is crate-private, and
    /// [`crate::journal::Journal::recover`] is the only caller, so no consumer of the seam can
    /// clear a condition without the gap that explains it.
    pub(crate) fn note_recovered(&self) -> Option<JournalFault> {
        let mut previous = None;
        self.sender.send_if_modified(|condition| {
            match std::mem::replace(condition, JournalCondition::Healthy) {
                JournalCondition::Healthy => {
                    *condition = JournalCondition::Healthy;
                    false
                }
                JournalCondition::Faulted(fault) => {
                    previous = Some(fault);
                    true
                }
            }
        });
        previous
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fault(kind: FaultKind) -> JournalFault {
        JournalFault {
            kind,
            detail: "the store said so".to_owned(),
            observed_at_ms: TimestampMs::new(1_000),
            durable_through: 7,
        }
    }

    #[test]
    fn a_faulted_journal_fences_rich_work_and_keeps_the_native_terminal() {
        let health = JournalHealth::new();
        assert!(health.posture().admits(WorkClass::RichMutation));

        assert!(health.note_fault(fault(FaultKind::Full)));
        let posture = health.posture();
        assert!(!posture.admits(WorkClass::RichMutation));
        assert!(posture.admits(WorkClass::AuthorisedStop));
        assert!(posture.admits(WorkClass::NativeTerminal));
        assert!(posture.admits(WorkClass::Read));
        assert!(!posture.admits_durable_work());
    }

    #[test]
    fn a_second_fault_does_not_replace_the_interval_the_first_one_opened() {
        let health = JournalHealth::new();
        assert!(health.note_fault(JournalFault {
            observed_at_ms: TimestampMs::new(10),
            ..fault(FaultKind::WriteFailed)
        }));
        assert!(!health.note_fault(JournalFault {
            observed_at_ms: TimestampMs::new(99),
            ..fault(FaultKind::Full)
        }));
        let recorded = health.condition();
        let open = recorded.fault().expect("the journal is faulted");
        assert_eq!(open.observed_at_ms.get(), 10);
        assert_eq!(open.kind, FaultKind::WriteFailed);
    }

    #[test]
    fn a_consumer_that_subscribes_after_a_fault_sees_it_rather_than_waiting() {
        let health = JournalHealth::new();
        health.note_fault(fault(FaultKind::Corrupt));
        let receiver = health.watch();
        assert_eq!(
            receiver.borrow().fault().map(|fault| fault.kind),
            Some(FaultKind::Corrupt)
        );
    }

    #[test]
    fn recovery_returns_the_fault_the_gap_is_measured_from_and_only_once() {
        let health = JournalHealth::new();
        health.note_fault(fault(FaultKind::Full));
        let recovered = health.note_recovered().expect("a fault was open");
        assert_eq!(recovered.durable_through, 7);
        assert!(health.condition().is_healthy());
        assert!(health.note_recovered().is_none());
    }

    #[test]
    fn a_fault_is_classified_from_the_stores_result_code_rather_than_its_message() {
        let full = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(13),
            Some("database or disk is full".to_owned()),
        );
        assert_eq!(FaultKind::classify(&full), FaultKind::Full);
        let corrupt = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(11),
            Some("database disk image is malformed".to_owned()),
        );
        assert_eq!(FaultKind::classify(&corrupt), FaultKind::Corrupt);
        let not_a_database = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(26),
            Some("file is not a database".to_owned()),
        );
        assert_eq!(FaultKind::classify(&not_a_database), FaultKind::Corrupt);
        let readonly = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(8),
            Some("attempt to write a readonly database".to_owned()),
        );
        assert_eq!(FaultKind::classify(&readonly), FaultKind::WriteFailed);
        assert_eq!(
            FaultKind::classify(&rusqlite::Error::QueryReturnedNoRows),
            FaultKind::WriteFailed
        );
    }

    #[test]
    fn every_fault_kind_reads_back_under_the_name_it_was_recorded_as() {
        for kind in [
            FaultKind::Absent,
            FaultKind::Full,
            FaultKind::WriteFailed,
            FaultKind::Corrupt,
        ] {
            assert_eq!(FaultKind::from_stored(kind.as_str()), Some(kind));
        }
        assert_eq!(FaultKind::from_stored("something else"), None);
    }
}
