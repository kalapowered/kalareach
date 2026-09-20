//! Background CPU and IO priority, and what each platform actually qualifies.
//!
//! Section 22: *enforce cancellable jobs with background CPU/IO priority and a platform-qualified
//! scheduling/resource mechanism; low priority is not proof of terminal latency by itself*.
//!
//! That last clause is the reason this module reports what it did rather than returning a unit.
//! Lowering a thread's priority is a real thing to do and it is not a latency guarantee: the
//! terminal stays responsive because no inference is on its path at all (see [`crate::context`]),
//! and the priority is there so a busy host spends its cores on the person's work first. A module
//! that quietly succeeded on every platform would let a report claim a mechanism that does not
//! exist on the host the report came from.
//!
//! # What this build applies
//!
//! | Platform | CPU | IO |
//! | --- | --- | --- |
//! | Linux | `SCHED_BATCH`, which is the scheduler class for non-interactive work | not applied |
//! | macOS, Windows and the rest | the lowest ordinary thread priority | not applied |
//!
//! IO priority is not applied anywhere in this build, and [`Applied::io`] says so on every
//! platform. Inference reads its weights once at load and then does no IO at all, so what an IO
//! class would change here is one sequential read of a file the host is about to keep mapped.
//! Recording the gap is the honest half of the requirement, and the qualification matrix carries
//! it as an open item rather than as a claim.

/// The mechanism a platform offers for running work in the background.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mechanism {
    /// The Linux scheduler's batch class.
    LinuxSchedBatch,
    /// The lowest ordinary thread priority this platform has.
    LowestThreadPriority,
    /// This build applies nothing on this platform.
    None,
}

impl Mechanism {
    /// Returns the stable name this mechanism is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LinuxSchedBatch => "linux_sched_batch",
            Self::LowestThreadPriority => "lowest_thread_priority",
            Self::None => "none",
        }
    }
}

/// What applying background priority to the calling thread did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Applied {
    /// The mechanism that was used.
    pub mechanism: Mechanism,
    /// Whether the processor class was actually changed.
    pub cpu: bool,
    /// Whether an IO class was actually changed. It is false in this build on every platform.
    pub io: bool,
    /// Why, when nothing was applied.
    pub why: Option<&'static str>,
}

impl Applied {
    /// Returns whether this host qualified a background mechanism.
    #[must_use]
    pub const fn is_qualified(&self) -> bool {
        self.cpu
    }

    fn unqualified(why: &'static str) -> Self {
        Self {
            mechanism: Mechanism::None,
            cpu: false,
            io: false,
            why: Some(why),
        }
    }
}

/// Puts the calling thread into the background class this platform offers.
///
/// It is called by the inference thread and by nothing else. A failure is reported rather than
/// propagated: a host whose scheduler refuses the change still runs descriptions, at ordinary
/// priority, and says so.
#[must_use]
pub fn background_current_thread() -> Applied {
    apply()
}

#[cfg(target_os = "linux")]
fn apply() -> Applied {
    use thread_priority::unix::{NormalThreadSchedulePolicy, ThreadSchedulePolicy};
    use thread_priority::{ThreadPriority, set_thread_priority_and_policy, thread_native_id};

    // SCHED_BATCH is the class Linux documents for non-interactive work: the scheduler stops
    // treating the thread as latency sensitive and gives it a longer effective time slice, which
    // is what keeps a description from interleaving with the terminal.
    match set_thread_priority_and_policy(
        thread_native_id(),
        ThreadPriority::Min,
        ThreadSchedulePolicy::Normal(NormalThreadSchedulePolicy::Batch),
    ) {
        Ok(()) => Applied {
            mechanism: Mechanism::LinuxSchedBatch,
            cpu: true,
            io: false,
            why: None,
        },
        Err(_) => Applied::unqualified("this host refused the batch scheduling class"),
    }
}

#[cfg(not(target_os = "linux"))]
fn apply() -> Applied {
    use thread_priority::{ThreadPriority, set_current_thread_priority};

    match set_current_thread_priority(ThreadPriority::Min) {
        Ok(()) => Applied {
            mechanism: Mechanism::LowestThreadPriority,
            cpu: true,
            io: false,
            why: None,
        },
        Err(_) => Applied::unqualified("this host refused the lowest thread priority"),
    }
}

/// A token that cancels a job.
///
/// Cancellation is checked between decode steps rather than signalled, so there is no moment when
/// a cancelled job is still holding the runtime: the step in progress finishes, which is one token,
/// and the next one does not start. A cancelled job is dropped, never published, and its session
/// keeps the title it had.
#[derive(Clone, Debug, Default)]
pub struct Cancellation(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl Cancellation {
    /// Builds a token that has not been cancelled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancels the job. Cancelling twice is the same as cancelling once.
    pub fn cancel(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }

    /// Returns whether the job has been cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire)
    }
}
