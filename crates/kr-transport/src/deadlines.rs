//! The deadlines a data stream is held to, as futures its owner can start and a test can fire.
//!
//! A stream the peer opens costs the host a task, a place in a queue and memory for as long as it
//! stays open, so every wait on a peer has an end. There are five, each a [`DeadlineKind`]:
//!
//! | Kind | What it bounds |
//! | --- | --- |
//! | [`DeadlineKind::Header`] | Reading a stream's 1 KiB header |
//! | [`DeadlineKind::Admission`] | The host's own lookup that admits a stream, once it has the header |
//! | [`DeadlineKind::Idle`] | The wait for the next frame to begin |
//! | [`DeadlineKind::Stall`] | Progress while the bytes of one frame arrive |
//! | [`DeadlineKind::Write`] | Writing one frame to a peer that has to read it |
//!
//! A deadline is a future that resolves when it has passed. [`Deadlines`] is where those futures
//! come from: [`TimerDeadlines`] makes them from timers, and a test supplies a source of its own
//! whose futures resolve when the test says so, so that a case about a deadline waits on a
//! condition and never on a clock.

use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::listener::BoxFuture;

/// What a deadline bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DeadlineKind {
    /// Reading a stream's header.
    Header,
    /// The host's lookup that admits a stream whose header it has read.
    Admission,
    /// The wait for a frame to begin on a stream that is between frames.
    Idle,
    /// Progress while a frame's bytes arrive: each piece the reader takes has to come within it.
    Stall,
    /// Writing one frame, to a peer that has to read it for the write to finish.
    Write,
}

impl DeadlineKind {
    /// Every kind, in declaration order.
    pub const ALL: [Self; 5] = [
        Self::Header,
        Self::Admission,
        Self::Idle,
        Self::Stall,
        Self::Write,
    ];

    /// Returns the name a message gives this kind.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::Admission => "admission",
            Self::Idle => "idle",
            Self::Stall => "stall",
            Self::Write => "write",
        }
    }

    #[cfg(feature = "testing")]
    const fn index(self) -> usize {
        match self {
            Self::Header => 0,
            Self::Admission => 1,
            Self::Idle => 2,
            Self::Stall => 3,
            Self::Write => 4,
        }
    }
}

/// Where deadlines come from.
pub trait Deadlines: Send + Sync + Debug + 'static {
    /// Starts one deadline of `kind`. The future resolves once it has passed, and a deadline whose
    /// future is dropped has simply not been needed.
    fn start(&self, kind: DeadlineKind) -> BoxFuture<'static, ()>;
}

/// Deadlines made from timers, the ones a shipped host runs under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimerDeadlines {
    /// How long a peer has to send the 1 KiB header of a stream it opened.
    pub header: Duration,
    /// How long the host's lookup for a stream has.
    pub admission: Duration,
    /// How long a stream may be quiet between frames. A stream that is open and waiting for its
    /// next chunk is not idle for longer than this.
    pub idle: Duration,
    /// How long a frame may go without a further byte arriving once it has begun. It is a bound on
    /// each piece and not on the frame, so a slow link is never cut for the size of a chunk, and a
    /// peer that stops sending is.
    pub stall: Duration,
    /// How long a write of one frame may wait for the peer to read.
    pub write: Duration,
}

impl Default for TimerDeadlines {
    fn default() -> Self {
        Self {
            header: Duration::from_secs(5),
            admission: Duration::from_secs(10),
            idle: Duration::from_secs(60),
            stall: Duration::from_secs(30),
            write: Duration::from_secs(30),
        }
    }
}

impl Deadlines for TimerDeadlines {
    fn start(&self, kind: DeadlineKind) -> BoxFuture<'static, ()> {
        let after = match kind {
            DeadlineKind::Header => self.header,
            DeadlineKind::Admission => self.admission,
            DeadlineKind::Idle => self.idle,
            DeadlineKind::Stall => self.stall,
            DeadlineKind::Write => self.write,
        };
        Box::pin(tokio::time::sleep(after))
    }
}

/// One deadline in force, or none at all, as a future.
///
/// A stream that has no deadlines, a client's, waits as long as its peer does. The deadline that
/// is not in force never resolves and costs nothing to hold.
pub(crate) struct Deadline(Option<BoxFuture<'static, ()>>);

impl Deadline {
    /// Starts a deadline of `kind` from `source`, when there is one.
    pub(crate) fn start(source: Option<&Arc<dyn Deadlines>>, kind: DeadlineKind) -> Self {
        Self(source.map(|source| source.start(kind)))
    }
}

impl Future for Deadline {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        match self.0.as_mut() {
            Some(deadline) => deadline.as_mut().poll(context),
            None => Poll::Pending,
        }
    }
}

#[cfg(feature = "testing")]
pub use manual::ManualDeadlines;

#[cfg(feature = "testing")]
mod manual {
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::Mutex;

    use super::{BoxFuture, DeadlineKind, Deadlines};

    /// Deadlines a test fires.
    ///
    /// A future this source starts resolves when [`ManualDeadlines::fire`] is called for its kind
    /// after it was started, and at no other time. A deadline is fired by what the host is doing
    /// and never by how long it has been doing it: [`ManualDeadlines::fire_when_armed`] waits for
    /// a deadline of the kind to be in force, which is the host having reached the wait the
    /// deadline bounds, fires it, and waits until a deadline has seen the firing.
    #[derive(Debug, Default)]
    pub struct ManualDeadlines {
        shared: Arc<Shared>,
    }

    #[derive(Debug, Default)]
    struct Shared {
        state: Mutex<State>,
        changed: tokio::sync::Notify,
    }

    #[derive(Debug, Default)]
    struct State {
        /// How many times each kind has been fired.
        fired: [u64; 5],
        /// The deadlines of each kind in force, by the number each was started with: started,
        /// not yet dropped.
        armed: [BTreeSet<u64>; 5],
        /// How many deadlines of each kind have resolved.
        resolved: [u64; 5],
        /// The number the next deadline started gets.
        next: u64,
    }

    impl Shared {
        fn lock(&self) -> std::sync::MutexGuard<'_, State> {
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }
    }

    /// A deadline in force, which stops being so when its future is dropped.
    struct Armed {
        shared: Arc<Shared>,
        index: usize,
        number: u64,
    }

    impl Drop for Armed {
        fn drop(&mut self) {
            let mut state = self.shared.lock();
            state.armed[self.index].remove(&self.number);
            drop(state);
            self.shared.changed.notify_waiters();
        }
    }

    impl ManualDeadlines {
        /// Creates a source with nothing fired.
        #[must_use]
        pub fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        /// Resolves every deadline of `kind` that is in force now. One started afterwards is not
        /// affected.
        pub fn fire(&self, kind: DeadlineKind) {
            self.shared.lock().fired[kind.index()] += 1;
            self.shared.changed.notify_waiters();
        }

        /// How many deadlines of `kind` are in force: started, and neither resolved nor dropped.
        #[must_use]
        pub fn armed(&self, kind: DeadlineKind) -> usize {
            self.shared.lock().armed[kind.index()].len()
        }

        /// Waits until a deadline of `kind` is in force.
        pub async fn wait_armed(&self, kind: DeadlineKind) {
            loop {
                let changed = self.shared.changed.notified();
                if self.armed(kind) > 0 {
                    return;
                }
                changed.await;
            }
        }

        /// Waits until a deadline of `kind` is in force, fires it, and returns once a deadline has
        /// resolved because of it.
        ///
        /// A host that is about to leave a wait drops its deadline without looking at it again, and
        /// a firing that lands then has resolved nothing. When every deadline that was in force at
        /// the firing has gone without one resolving, this waits for the next to be started and
        /// fires that, so that a case which has to cut one wait is not left holding a firing that
        /// nobody saw.
        pub async fn fire_when_armed(&self, kind: DeadlineKind) {
            let index = kind.index();
            loop {
                self.wait_armed(kind).await;
                let (resolved_before, fired_at) = {
                    let state = self.shared.lock();
                    (state.resolved[index], state.armed[index].clone())
                };
                self.fire(kind);
                loop {
                    let changed = self.shared.changed.notified();
                    {
                        let state = self.shared.lock();
                        if state.resolved[index] > resolved_before {
                            return;
                        }
                        if state.armed[index].is_disjoint(&fired_at) {
                            break;
                        }
                    }
                    changed.await;
                }
            }
        }
    }

    impl Deadlines for ManualDeadlines {
        fn start(&self, kind: DeadlineKind) -> BoxFuture<'static, ()> {
            let index = kind.index();
            let shared = Arc::clone(&self.shared);
            let (started_after, number) = {
                let mut state = shared.lock();
                let number = state.next;
                state.next += 1;
                state.armed[index].insert(number);
                (state.fired[index], number)
            };
            shared.changed.notify_waiters();
            let armed = Armed {
                shared: Arc::clone(&shared),
                index,
                number,
            };
            Box::pin(async move {
                let _armed = armed;
                loop {
                    let changed = shared.changed.notified();
                    {
                        let mut state = shared.lock();
                        if state.fired[index] > started_after {
                            state.resolved[index] += 1;
                            drop(state);
                            shared.changed.notify_waiters();
                            return;
                        }
                    }
                    changed.await;
                }
            })
        }
    }
}
