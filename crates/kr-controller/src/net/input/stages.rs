//! Where a suite stops the door's stages and what it counts there.
//!
//! A build without the `testing` feature has none of it: the stage's calls are empty and a tally
//! is a unit value.

#[cfg(feature = "testing")]
pub(super) use with_seams::Tally;
#[cfg(feature = "testing")]
pub use with_seams::{InputStageCounts, InputStages};

#[cfg(not(feature = "testing"))]
pub(super) use without_seams::{InputStages, Tally};

#[cfg(feature = "testing")]
mod with_seams {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use tokio::sync::{oneshot, watch};

    use crate::service::net::chunks::Hold;

    /// A count of what a stage holds now, and the most it has held.
    #[derive(Debug, Default)]
    struct Gauge {
        now: AtomicU64,
        peak: AtomicU64,
    }

    impl Gauge {
        fn rise(&self) {
            let now = self.now.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
        }

        fn fall(&self) {
            self.now.fetch_sub(1, Ordering::SeqCst);
        }

        fn counts(&self) -> (u64, u64) {
            (
                self.now.load(Ordering::SeqCst),
                self.peak.load(Ordering::SeqCst),
            )
        }
    }

    /// One frame's place in a stage: it is counted for as long as the frame lives, wherever the
    /// frame is dropped.
    #[derive(Debug)]
    pub(in crate::service::net) struct Tally(Arc<Gauge>);

    impl Drop for Tally {
        fn drop(&mut self) {
            self.0.fall();
        }
    }

    /// What the door's stages hold, read from a suite.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct InputStageCounts {
        /// How many frames the door has read from streams, in all.
        pub read: u64,
        /// Frames read and not yet routed, now.
        pub held: u64,
        /// The most frames read and not yet routed at one time.
        pub held_peak: u64,
        /// Frames passed on for the worker's lane and not yet answered, now.
        pub unanswered: u64,
        /// The most frames passed on for the lane and not yet answered at one time.
        pub unanswered_peak: u64,
        /// How many times a detach that took effect, or may have, told the streams of an attachment.
        pub detaches: u64,
    }

    /// The stages of the terminal-input door that a suite can stop, and what it can count.
    #[derive(Debug)]
    pub struct InputStages {
        before_a_read: Hold,
        before_a_lane_write: Hold,
        before_a_lane_answer: Hold,
        before_an_ack_write: Hold,
        after_the_version_mark: Hold,
        before_a_frame_is_judged: Hold,
        before_a_release: Hold,
        held: Arc<Gauge>,
        unanswered: Arc<Gauge>,
        read: AtomicU64,
        detaches: AtomicU64,
        reads_full: watch::Sender<u64>,
        reads_ended: watch::Sender<u64>,
        drain_waits: watch::Sender<u64>,
    }

    impl Default for InputStages {
        fn default() -> Self {
            Self {
                before_a_read: Hold::default(),
                before_a_lane_write: Hold::default(),
                before_a_lane_answer: Hold::default(),
                before_an_ack_write: Hold::default(),
                after_the_version_mark: Hold::default(),
                before_a_frame_is_judged: Hold::default(),
                before_a_release: Hold::default(),
                held: Arc::default(),
                unanswered: Arc::default(),
                read: AtomicU64::new(0),
                detaches: AtomicU64::new(0),
                reads_full: watch::channel(0).0,
                reads_ended: watch::channel(0).0,
                drain_waits: watch::channel(0).0,
            }
        }
    }

    /// The two ends of a hold: the one that says a frame has arrived at it, and the one that lets
    /// the frame go.
    pub type Held = (oneshot::Receiver<()>, oneshot::Sender<()>);

    impl InputStages {
        /// Holds the stream task at its next turn that may read, before it reads. The hold fires
        /// once.
        #[must_use]
        pub fn hold_before_a_read(&self) -> Held {
            self.before_a_read.arm()
        }

        /// Holds the next frame the lane's writer has taken from its queue, after the host's
        /// decision for it and before the authority feed is asked and the frame is written. The hold
        /// fires once.
        #[must_use]
        pub fn hold_before_a_lane_write(&self) -> Held {
            self.before_a_lane_write.arm()
        }

        /// Holds the lane's reader at the next frame it has read from the worker, before it applies
        /// it. The hold fires once.
        #[must_use]
        pub fn hold_before_a_lane_answer(&self) -> Held {
            self.before_a_lane_answer.arm()
        }

        /// Holds the acknowledgement writer at the next acknowledgement it has taken, before it
        /// writes it. The hold fires once.
        #[must_use]
        pub fn hold_before_an_ack_write(&self) -> Held {
            self.before_an_ack_write.arm()
        }

        /// Holds the stream task at its next turn between the moment it marks the state's version
        /// and the moment it looks at whether the stream has ended. The hold fires once.
        #[must_use]
        pub fn hold_after_the_version_mark(&self) -> Held {
            self.after_the_version_mark.arm()
        }

        /// Holds the next frame the lane's writer has taken from its queue before the writer looks at
        /// whether the frame's epoch has been refused, which would discard it. The hold fires once.
        #[must_use]
        pub fn hold_before_a_frame_is_judged(&self) -> Held {
            self.before_a_frame_is_judged.arm()
        }

        /// Holds the next release of a connection's worker link before the release ends the
        /// connection's streams. The hold fires once.
        #[must_use]
        pub fn hold_before_a_release(&self) -> Held {
            self.before_a_release.arm()
        }

        /// What the stages hold now and the most they have held, across the streams of the host.
        #[must_use]
        pub fn counts(&self) -> InputStageCounts {
            let (held, held_peak) = self.held.counts();
            let (unanswered, unanswered_peak) = self.unanswered.counts();
            InputStageCounts {
                read: self.read.load(Ordering::SeqCst),
                held,
                held_peak,
                unanswered,
                unanswered_peak,
                detaches: self.detaches.load(Ordering::SeqCst),
            }
        }

        /// Counts the turns at which a stream task had read all it may and waited. A suite waits for
        /// the count to rise to know the host has stopped reading.
        #[must_use]
        pub fn reads_full(&self) -> watch::Receiver<u64> {
            self.reads_full.subscribe()
        }

        /// Counts the points at which a stream task stopped reading: once when it begins to wait for
        /// what it owes the device to be written, and once when it lets go of its read.
        #[must_use]
        pub fn reads_ended(&self) -> watch::Receiver<u64> {
            self.reads_ended.subscribe()
        }

        pub(in crate::service::net) async fn before_a_read(&self) {
            self.before_a_read.wait().await;
        }

        pub(in crate::service::net) async fn before_a_lane_write(&self) {
            self.before_a_lane_write.wait().await;
        }

        pub(in crate::service::net) async fn before_a_lane_answer(&self) {
            self.before_a_lane_answer.wait().await;
        }

        /// Counts the turns at which a stream task whose device has finished found frames still
        /// passed on and not answered, and waited for them. A suite waits for the count to rise to
        /// know the task is waiting for the stream to drain.
        #[must_use]
        pub fn drain_waits(&self) -> watch::Receiver<u64> {
            self.drain_waits.subscribe()
        }

        pub(in crate::service::net) async fn before_an_ack_write(&self) {
            self.before_an_ack_write.wait().await;
        }

        pub(in crate::service::net) async fn after_the_version_mark(&self) {
            self.after_the_version_mark.wait().await;
        }

        pub(in crate::service::net) async fn before_a_frame_is_judged(&self) {
            self.before_a_frame_is_judged.wait().await;
        }

        pub(in crate::service::net) async fn before_a_release(&self) {
            self.before_a_release.wait().await;
        }

        pub(in crate::service::net) fn frame_read(&self) {
            self.read.fetch_add(1, Ordering::SeqCst);
        }

        pub(in crate::service::net) fn held_frame(&self) -> Tally {
            self.held.rise();
            Tally(Arc::clone(&self.held))
        }

        pub(in crate::service::net) fn unanswered_frame(&self) -> Tally {
            self.unanswered.rise();
            Tally(Arc::clone(&self.unanswered))
        }

        pub(in crate::service::net) fn read_is_full(&self) {
            self.reads_full.send_modify(|turns| *turns += 1);
        }

        pub(in crate::service::net) fn read_ends(&self) {
            self.reads_ended.send_modify(|ends| *ends += 1);
        }

        pub(in crate::service::net) fn waits_to_drain(&self) {
            self.drain_waits.send_modify(|turns| *turns += 1);
        }

        pub(in crate::service::net) fn detach_told(&self) {
            self.detaches.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[cfg(not(feature = "testing"))]
mod without_seams {
    #[derive(Debug)]
    pub(in crate::service::net) struct Tally;

    #[derive(Debug, Default)]
    pub(in crate::service::net) struct InputStages;

    #[allow(clippy::unused_async, clippy::unused_self)]
    impl InputStages {
        pub(in crate::service::net) async fn before_a_read(&self) {}

        pub(in crate::service::net) async fn before_a_lane_write(&self) {}

        pub(in crate::service::net) async fn before_a_lane_answer(&self) {}

        pub(in crate::service::net) async fn before_an_ack_write(&self) {}

        pub(in crate::service::net) async fn after_the_version_mark(&self) {}

        pub(in crate::service::net) async fn before_a_frame_is_judged(&self) {}

        pub(in crate::service::net) async fn before_a_release(&self) {}

        pub(in crate::service::net) fn frame_read(&self) {}

        pub(in crate::service::net) fn held_frame(&self) -> Tally {
            Tally
        }

        pub(in crate::service::net) fn unanswered_frame(&self) -> Tally {
            Tally
        }

        pub(in crate::service::net) fn read_is_full(&self) {}

        pub(in crate::service::net) fn read_ends(&self) {}

        pub(in crate::service::net) fn waits_to_drain(&self) {}

        pub(in crate::service::net) fn detach_told(&self) {}
    }
}
