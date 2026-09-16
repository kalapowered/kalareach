//! Watching one session's root shell, and the processes it owns.
//!
//! Three things change a live session without anybody asking. The root shell exits, or crashes, and
//! the session closes with the reason that says which (§7). The login a desktop-bound session
//! belongs to ends, and the session ends with it. A job the shell started appears, and the closure
//! record has to be able to name it.
//!
//! The obvious way to notice any of them is to ask the kernel, and the obvious way to ask is often.
//! That is what this module exists to avoid. Twenty idle sessions asking ten times a second spend
//! more of a processor on watching nothing happen than KR-PERF-003 allows the whole host, and
//! almost every answer is the same as the one before it.
//!
//! So each question is asked when something that can have changed its answer has happened:
//!
//! | Question | What answers it | What is left on a clock |
//! | --- | --- | --- |
//! | has the root shell ended? | the signal the kernel sends a parent when a child of it does | a sweep, in case a signal is lost; the whole answer where no such signal exists |
//! | what does this session own? | input the session accepted and output it produced, which is where a new process usually comes from | the same sweep, for everything that comes from neither |
//! | is the desktop still there? | nothing this host can subscribe to | the same sweep. The reading is this worker's own environment, so a check ten times a second answered from the same values each time |
//!
//! The limits of the middle row are worth being exact about, because traffic is a *hint* rather
//! than a proof and the observation it asks for is a sample rather than a record of what happened.
//!
//! * Traffic is not the only way a process starts. An application that is already running can
//!   start and collect children on its own timer, on a filesystem event, or on something that
//!   arrived over a network, and print nothing while it does. Between two sweeps a session with a
//!   quiet application can do a great deal that nothing here sees.
//! * Even a process the session's own input started can be missed. Input is marked as it is queued
//!   for the terminal, so an observation can happen before the application has read those bytes; a
//!   process it then starts and finishes before anything else is marked is in no reading at all.
//! * So silence here is not evidence of idleness. Section 7 says as much where it matters: idle
//!   means a verified idle shell with no pending request and no active owned work, not merely
//!   absent output. Nothing in this module is that verification.
//!
//! What this is, then, is the best-effort accounting the ownership boundary already gives (§7). A
//! process that starts and ends between two observations is not recorded, so it is not in the
//! closure record's list of what was stopped; the record never claims every application was
//! discovered, and the coverage flag says which boundary produced it. What the event sources change
//! is *when* the window is narrow: a session that is visibly running something is observed within
//! [`OBSERVE_INTERVAL`], and the window is [`IDLE_SWEEP_INTERVAL`] wide when nothing is reaching the
//! terminal in either direction. Closure does not rest on any of it: it observes the boundary again
//! as it asks the processes to stop, as it forces what is left, and as it writes the record.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

/// The shortest time between two observations of what a session owns.
///
/// Enumerating the ownership boundary and reading each member's start identity is a kernel query
/// per process, so a session that is busy observes on a cadence rather than on every batch of
/// output. This is that cadence: after input or output, the next observation happens within it.
pub const OBSERVE_INTERVAL: Duration = Duration::from_secs(1);

/// How long a session with nothing happening goes between sweeps.
///
/// One wake serves every question left without an event source: a process that started without
/// producing output or consuming input, the login a desktop-bound session is tied to, and the root
/// shell's status where a child signal was lost. On a host with a child signal this is the only
/// thing an idle session wakes for, which is why it is this long.
pub const IDLE_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// How often the root shell is asked for its status where nothing reports its exit.
///
/// Windows reports a process ending on its handle rather than by a signal, and waiting on a handle
/// is not something this module can do, so there the shell's status is the one thing that stays on
/// a clock and the clock has to be short enough to close the session promptly. On a host that
/// delivers a child signal this interval is unused.
pub const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Whether anything that can have started a process has happened.
///
/// A session's own traffic is the event source for the set of processes it owns. A command that
/// starts a job is input the session accepted, and a job that is running writes something; both
/// pass through [`crate::runtime`], and both mark this.
#[derive(Debug, Default)]
pub struct Activity {
    happened: AtomicBool,
    woken: Notify,
}

impl Activity {
    /// Builds a mark nothing has happened on yet.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Marks that the session accepted input or produced output.
    ///
    /// Only the first mark after an observation wakes anything. A session printing steadily reaches
    /// this thousands of times a second, and waking the supervision on every one of them would cost
    /// more than the polling it replaces.
    pub fn note(&self) {
        if !self.happened.swap(true, Ordering::Release) {
            self.woken.notify_one();
        }
    }

    /// Takes the mark, and says whether there was one.
    fn take(&self) -> bool {
        self.happened.swap(false, Ordering::Acquire)
    }

    /// Waits for a mark to be made.
    ///
    /// A wait that is abandoned before it finishes loses nothing: the mark itself is what carries
    /// the information, and it is read again on the next wait.
    async fn marked(&self) {
        self.woken.notified().await;
    }
}

/// When the ownership boundary is next observed, and why.
#[derive(Debug)]
pub struct Sweep {
    activity: Arc<Activity>,
    /// When the boundary was last observed.
    observed: Instant,
    /// Whether the session has accepted input or produced output since then.
    marked: bool,
}

impl Sweep {
    /// Begins sweeping a session whose shell has just started.
    ///
    /// The boundary was recorded as it was established, so the first observation is due an interval
    /// from here rather than at once.
    #[must_use]
    pub fn begin(activity: Arc<Activity>, started: Instant) -> Self {
        Self {
            activity,
            observed: started,
            marked: false,
        }
    }

    /// Returns whether the set of owned processes is due to be observed, and records that it was.
    pub fn observation_due(&mut self, now: Instant) -> bool {
        if now < self.next_observation() {
            return false;
        }
        self.observed = now;
        self.marked = false;
        true
    }

    /// Takes whatever mark has been made and says when the next observation is due.
    ///
    /// A session that has accepted input or produced output is observed on the short cadence,
    /// because that is when a process it owns can have appeared. One that has done neither is swept
    /// slowly, because all that is left to find is a process that started without doing either.
    ///
    /// The mark is read here and nowhere else, so asking when the next observation is due is also
    /// what notices that one is wanted.
    pub fn next_observation(&mut self) -> Instant {
        self.marked |= self.activity.take();
        self.observed
            + if self.marked {
                OBSERVE_INTERVAL
            } else {
                IDLE_SWEEP_INTERVAL
            }
    }

    /// Whether the session has accepted input or produced output since the last observation.
    ///
    /// Only what has already been read by [`Sweep::next_observation`] counts here.
    #[must_use]
    pub const fn marked(&self) -> bool {
        self.marked
    }
}

/// The signal a parent is sent when one of its children ends.
///
/// `None` means this host will not deliver it, which comes to the same thing as a platform that has
/// no such signal: the shell's status goes back on a clock.
#[cfg(unix)]
struct ChildExits(Option<tokio::signal::unix::Signal>);

#[cfg(unix)]
impl ChildExits {
    fn open() -> Self {
        Self(tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child()).ok())
    }

    /// How long the supervision may wait before it asks the shell for its status anyway.
    fn patience(&self) -> Duration {
        if self.0.is_some() {
            IDLE_SWEEP_INTERVAL
        } else {
            CHILD_POLL_INTERVAL
        }
    }

    /// Waits until a child of this process has ended.
    async fn next(&mut self) {
        match self.0.as_mut() {
            Some(signal) => {
                signal.recv().await;
            }
            // Nothing will report it, so nothing is waited for here and the interval above is what
            // finds it.
            None => std::future::pending().await,
        }
    }
}

/// Windows reports a process ending on its handle, which this module cannot wait on, so the shell's
/// status stays on the clock there.
#[cfg(not(unix))]
struct ChildExits;

#[cfg(not(unix))]
impl ChildExits {
    const fn open() -> Self {
        Self
    }

    const fn patience(&self) -> Duration {
        CHILD_POLL_INTERVAL
    }

    async fn next(&mut self) {
        std::future::pending().await
    }
}

/// What one wake of a session's supervision is for.
///
/// Every wake asks the root shell for its status, and a desktop-bound session about its login: both
/// are cheap, and a wake is already rare. Observing the ownership boundary is a kernel query per
/// process, so it happens on the cadence [`Sweep`] keeps, and this is what carries that decision to
/// the loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wake {
    /// Look at the root shell, and at the login a desktop-bound session belongs to.
    Session,
    /// Look at both of those, and observe the processes the session owns.
    Ownership,
}

/// What one session's supervision waits on.
///
/// The loop that owns it waits on [`Supervision::next`], which is also what decides whether this
/// wake observes the ownership boundary. The two are one call on purpose: a wait that did not move
/// the schedule on would compute a deadline that had already passed and spin.
///
/// Build it inside the task that waits on it. Opening the child signal needs the runtime that task
/// runs on.
pub struct Supervision {
    sweep: Sweep,
    exits: ChildExits,
}

impl std::fmt::Debug for Supervision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Supervision")
            .field("sweep", &self.sweep)
            .finish_non_exhaustive()
    }
}

impl Supervision {
    /// Begins watching a session whose shell has just started.
    #[must_use]
    pub fn begin(activity: Arc<Activity>, started: Instant) -> Self {
        Self {
            sweep: Sweep::begin(activity, started),
            exits: ChildExits::open(),
        }
    }

    /// Waits until something this supervision has to look at can have changed, and says what the
    /// wake is for.
    pub async fn next(&mut self) -> Wake {
        let deadline = tokio::time::Instant::from_std(self.deadline(Instant::now()));
        // A session already waiting for its next observation has nothing to learn from another
        // mark, so it stops listening for one until that observation has been taken.
        let marked = self.sweep.marked();
        let activity = Arc::clone(&self.sweep.activity);
        let exits = &mut self.exits;
        let by_activity = tokio::select! {
            () = exits.next() => false,
            () = tokio::time::sleep_until(deadline) => false,
            () = activity.marked(), if !marked => true,
        };
        if by_activity {
            self.sweep.marked = true;
        }
        if self.sweep.observation_due(Instant::now()) {
            Wake::Ownership
        } else {
            Wake::Session
        }
    }

    /// When this supervision wants to be woken, whatever else happens first.
    fn deadline(&mut self, now: Instant) -> Instant {
        let observation = self.sweep.next_observation();
        observation.min(now + self.exits.patience())
    }
}

#[cfg(test)]
mod tests {
    use super::{Activity, IDLE_SWEEP_INTERVAL, OBSERVE_INTERVAL, Supervision, Sweep, Wake};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    #[test]
    fn a_session_with_nothing_happening_is_only_swept() {
        let started = Instant::now();
        let mut sweep = Sweep::begin(Activity::new(), started);

        assert_eq!(
            sweep.next_observation(),
            started + IDLE_SWEEP_INTERVAL,
            "nothing has happened, so the only observation left is the slow sweep"
        );
        assert!(
            !sweep.observation_due(started + OBSERVE_INTERVAL),
            "and the short cadence is not a reason to observe by itself"
        );
        assert!(
            sweep.observation_due(started + IDLE_SWEEP_INTERVAL),
            "the sweep still observes, for a process that started without input or output"
        );
    }

    #[test]
    fn input_or_output_brings_the_next_observation_forward() {
        let started = Instant::now();
        let activity = Activity::new();
        let mut sweep = Sweep::begin(Arc::clone(&activity), started);

        activity.note();
        assert!(
            !sweep.observation_due(started + OBSERVE_INTERVAL / 2),
            "never faster than the cadence"
        );
        assert_eq!(
            sweep.next_observation(),
            started + OBSERVE_INTERVAL,
            "a session that is running something is observed on the short cadence"
        );
        assert!(sweep.observation_due(started + OBSERVE_INTERVAL));
        assert_eq!(
            sweep.next_observation(),
            started + OBSERVE_INTERVAL + IDLE_SWEEP_INTERVAL,
            "and the mark is spent by the observation it caused"
        );
    }

    #[test]
    fn a_mark_made_during_an_observation_is_not_lost() {
        let started = Instant::now();
        let activity = Activity::new();
        let mut sweep = Sweep::begin(Arc::clone(&activity), started);

        activity.note();
        assert!(sweep.observation_due(started + OBSERVE_INTERVAL));
        // Output that arrived while the observation was being taken. What it may have started was
        // not necessarily in that reading, so the next observation is on the short cadence again.
        activity.note();
        let taken = started + OBSERVE_INTERVAL;
        assert_eq!(sweep.next_observation(), taken + OBSERVE_INTERVAL);
        assert!(sweep.observation_due(taken + OBSERVE_INTERVAL));
    }

    #[test]
    fn a_mark_is_taken_once() {
        let activity = Activity::new();
        activity.note();
        activity.note();

        assert!(activity.take(), "the mark is there to be taken");
        assert!(!activity.take(), "and taking it clears it");
    }

    /// Waits until the supervision asks for an observation, and says when that was.
    ///
    /// Other wakes are not failures and there is no bound on how many of them there are: a child
    /// of this process ending is one, a timer that came back a moment before its deadline is
    /// another, and on a host with no child signal the fallback is a third. What the supervision
    /// promises is that the observation itself happens, and that it happens on the cadence rather
    /// than the moment a mark is made.
    async fn observation(supervision: &mut Supervision) -> Instant {
        loop {
            if supervision.next().await == Wake::Ownership {
                return Instant::now();
            }
        }
    }

    #[tokio::test]
    async fn output_wakes_the_supervision_and_the_wake_observes() {
        let activity = Activity::new();
        // Begun an interval ago, so the observation the mark asks for is due when it arrives.
        let mut supervision =
            Supervision::begin(Arc::clone(&activity), Instant::now() - OBSERVE_INTERVAL);
        let noted = Arc::clone(&activity);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            noted.note();
        });

        // Far inside the sweep, so what ends this is the mark rather than the clock.
        tokio::time::timeout(IDLE_SWEEP_INTERVAL / 2, observation(&mut supervision))
            .await
            .expect("the mark reaches the supervision and it observes");
    }

    #[tokio::test]
    async fn a_marked_session_is_observed_on_the_cadence_rather_than_at_once() {
        let activity = Activity::new();
        let started = Instant::now();
        let mut supervision = Supervision::begin(Arc::clone(&activity), started);
        activity.note();

        let observed = tokio::time::timeout(IDLE_SWEEP_INTERVAL / 2, observation(&mut supervision))
            .await
            .expect("the mark is observed");

        let waited = observed.saturating_duration_since(started);
        assert!(
            waited >= OBSERVE_INTERVAL,
            "the cadence was waited out rather than the mark acted on at once: {waited:?}"
        );
    }
}
