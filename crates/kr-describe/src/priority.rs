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

/// A token that cancels a job, and the gate its description is written through.
///
/// Cancellation is checked between decode steps rather than signalled, so there is no moment when
/// a cancelled job is still holding the runtime: the step in progress finishes, which is one token,
/// and the next one does not start. A cancelled job is dropped, never published, and its session
/// keeps the title it had.
///
/// # The one race a check cannot settle
///
/// Reading the token and then writing the description leaves a moment between the two. A
/// cancellation that arrives in that moment returns to its caller having cancelled nothing: the
/// write is already on its way, and section 22 promises that a cancelled job publishes nothing.
/// Undoing the write afterwards is worse, because the row it would delete is the session's only
/// generated description and the job that wrote the previous one was never cancelled.
///
/// So the check and the write happen together. [`Cancellation::publish_unless_cancelled`] takes
/// this token's lock, reads the stage and holds the lock across the write;
/// [`Cancellation::cancel`] takes the same lock. Two orders remain and both are honest: the
/// cancellation is recorded first and no write happens, or the write completes and the cancellation
/// is told it was too late. A cancelled job is never published, and a published description is
/// never taken away again.
#[derive(Clone, Debug, Default)]
pub struct Cancellation(std::sync::Arc<std::sync::Mutex<Stage>>);

/// Where a job stands, between running, cancelled and published.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Stage {
    /// Running, and still cancellable.
    #[default]
    Running,
    /// Cancelled before it wrote anything.
    Cancelled,
    /// Its description is in the store, which a cancellation can no longer undo.
    Published,
}

impl Cancellation {
    /// Builds a token that has not been cancelled.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancels the job, and says whether the cancellation reached it in time.
    ///
    /// It is false only for a job whose description is already in the store. Cancelling twice is
    /// the same as cancelling once.
    pub fn cancel(&self) -> bool {
        let mut stage = self.stage();
        match *stage {
            Stage::Published => false,
            Stage::Cancelled => true,
            Stage::Running => {
                *stage = Stage::Cancelled;
                true
            }
        }
    }

    /// Returns whether the job has been cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        *self.stage() == Stage::Cancelled
    }

    /// Writes this job's description through the token, unless the job has been cancelled.
    ///
    /// `None` is a cancelled job, and nothing was written. A write that fails leaves the job
    /// cancellable, because a failed write published nothing. A write that panics leaves the job
    /// published, because whether its row reached the store is exactly what nobody knows.
    pub fn publish_unless_cancelled<T, E>(
        &self,
        write: impl FnOnce() -> Result<T, E>,
    ) -> Option<Result<T, E>> {
        let mut stage = self.stage();
        if *stage == Stage::Cancelled {
            return None;
        }
        // The stage moves before the write rather than after it. A write that panics between
        // committing its row and returning would otherwise leave a job this token still calls
        // cancellable, and a cancellation that reported success over a row already in the store is
        // the one answer this gate exists to prevent. A write that comes back with a failure
        // published nothing, and the job goes back to being cancellable.
        *stage = Stage::Published;
        let written = write();
        if written.is_err() {
            *stage = Stage::Running;
        }
        Some(written)
    }

    /// Returns the stage, taking it as it stands from a thread that panicked while holding it.
    ///
    /// The stage is one of three values and a panic cannot leave it half written, so a poisoned
    /// lock is recovered rather than turned into a second failure in the middle of a job. What the
    /// panicking thread left behind is deliberate: [`Cancellation::publish_unless_cancelled`]
    /// records the publication before the write, so an interrupted write is read as published.
    fn stage(&self) -> std::sync::MutexGuard<'_, Stage> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::Cancellation;
    use std::sync::Arc;
    use std::sync::Barrier;
    use std::time::Duration;

    #[test]
    fn a_cancellation_that_arrives_first_stops_the_write() {
        let cancellation = Cancellation::new();
        assert!(cancellation.cancel());

        let mut written = false;
        let outcome = cancellation.publish_unless_cancelled(|| {
            written = true;
            Ok::<(), ()>(())
        });

        assert!(outcome.is_none(), "a cancelled job must not write");
        assert!(!written, "the write must not even be attempted");
        assert!(cancellation.is_cancelled());
    }

    #[test]
    fn a_cancellation_that_arrives_while_the_description_is_written_is_too_late() {
        let cancellation = Cancellation::new();
        let at_the_write = Arc::new(Barrier::new(2));

        let writing = {
            let cancellation = cancellation.clone();
            let at_the_write = at_the_write.clone();
            std::thread::spawn(move || {
                cancellation.publish_unless_cancelled(|| {
                    at_the_write.wait();
                    // The cancelling thread is inside `cancel` by now, or is about to be. Either
                    // way it waits for this write rather than interrupting it.
                    std::thread::sleep(Duration::from_millis(50));
                    Ok::<&str, ()>("published")
                })
            })
        };

        at_the_write.wait();
        let cancelled = cancellation.cancel();
        let written = writing.join().expect("writing thread");

        assert_eq!(written, Some(Ok("published")), "the write must complete");
        assert!(
            !cancelled,
            "a cancellation after the write must say it was too late"
        );
        assert!(
            !cancellation.is_cancelled(),
            "a published job is not retrospectively cancelled"
        );
    }

    #[test]
    fn a_write_that_fails_leaves_the_job_cancellable() {
        let cancellation = Cancellation::new();

        let outcome =
            cancellation.publish_unless_cancelled(|| Err::<(), &str>("the store refused"));

        assert_eq!(outcome, Some(Err("the store refused")));
        assert!(
            cancellation.cancel(),
            "nothing was published, so the job can still be cancelled"
        );
    }

    #[test]
    fn a_write_that_panics_leaves_the_job_published() {
        let cancellation = Cancellation::new();

        let panicked = {
            let cancellation = cancellation.clone();
            std::thread::spawn(move || {
                cancellation.publish_unless_cancelled(|| -> Result<(), ()> {
                    panic!("the store panicked after committing")
                })
            })
            .join()
        };

        assert!(panicked.is_err(), "the panic must reach the caller");
        assert!(
            !cancellation.cancel(),
            "nobody knows whether the row reached the store, so the job is past cancelling"
        );
    }

    #[test]
    fn cancelling_twice_is_the_same_as_cancelling_once() {
        let cancellation = Cancellation::new();

        assert!(cancellation.cancel());
        assert!(cancellation.cancel());
        assert!(cancellation.is_cancelled());
    }
}
