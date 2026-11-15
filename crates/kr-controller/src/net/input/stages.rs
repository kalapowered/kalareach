//! Where a suite stops the door's stages and what it counts there.
//!
//! A build without the `testing` feature has none of it: the stage's calls are empty and a tally
//! is a unit value.

#[cfg(feature = "testing")]
pub(super) use with_seams::Tally;
#[cfg(feature = "testing")]
pub use with_seams::{InputStageCounts, InputStages, SerialAnswer};

#[cfg(not(feature = "testing"))]
pub(super) use without_seams::{InputStages, Tally};

#[cfg(feature = "testing")]
mod with_seams {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};

    use kr_protocol::envelope::{MutationRequest, Outcome, Request, Response};
    use kr_protocol::error::ProtocolError;
    use kr_protocol::ids::RequestId;
    use kr_protocol::input::InputWriteParams;
    use tokio::sync::{oneshot, watch};

    use crate::error::{ControllerError, Result};
    use crate::service::net::chunks::Hold;
    use crate::service::net::proxy::Forwarded;

    /// What a suite's stand-in for a worker's link answers one call with.
    #[derive(Clone, Debug)]
    pub enum SerialAnswer {
        /// The worker answers with this outcome.
        Answered(Outcome),
        /// The worker answers with this error, and the answer carries the refusal of the link
        /// itself, which a worker gives after it has taken what it was sent, as well as before.
        Marked(ProtocolError),
        /// The worker's answer does not come in time.
        Silent,
        /// The link ends under the call.
        Lost,
    }

    /// The result of a call as the proxy would give it for what a suite scripts.
    fn forwarded_as(answer: SerialAnswer, request_id: RequestId) -> Result<Forwarded> {
        let answered = |outcome, link_fenced| {
            Ok(Forwarded {
                response: Response {
                    request_id,
                    outcome,
                },
                retained: false,
                link_fenced,
            })
        };
        match answer {
            SerialAnswer::Answered(outcome) => answered(outcome, false),
            SerialAnswer::Marked(error) => answered(Outcome::Error(error), true),
            SerialAnswer::Silent => Err(ControllerError::Uncertain {
                detail: "this session did not answer in time, so what became of the action is \
                         unknown"
                    .to_owned(),
            }),
            SerialAnswer::Lost => Err(ControllerError::supervision(
                "this session's link ended before it answered",
            )),
        }
    }

    type SerialScript = dyn Fn(InputWriteParams) -> Pin<Box<dyn Future<Output = SerialAnswer> + Send>>
        + Send
        + Sync;

    type DependentScript = dyn Fn(&MutationRequest) -> SerialAnswer + Send + Sync;

    /// A script a suite gives the door.
    struct Script<T: ?Sized>(Arc<T>);

    impl<T: ?Sized> Clone for Script<T> {
        fn clone(&self) -> Self {
            Self(Arc::clone(&self.0))
        }
    }

    impl<T: ?Sized> std::fmt::Debug for Script<T> {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a script")
        }
    }

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

        fn fall_by(&self, count: usize) {
            self.now.fetch_sub(count as u64, Ordering::SeqCst);
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
        /// Frames the host holds for the device, from the moment each is read until it is answered,
        /// refused or discarded, now.
        pub host_holds: u64,
        /// The most frames the host held at one time.
        pub host_holds_peak: u64,
        /// Epochs whose first refusal the host holds a record of, across the streams, now.
        pub records: u64,
        /// The most epochs the host held a record of at one time.
        pub records_peak: u64,
        /// How many times a detach that took effect, or may have, told the streams of an attachment.
        pub detaches: u64,
        /// How many times the task that ends a stream for a detach asked for the stream's graceful
        /// end, after its wait for the worker's notice was over.
        pub detach_ends: u64,
        /// How many requests the position check refused, with nothing forwarded.
        pub position_refusals: u64,
        /// How many times a stream was cut because its lane or its write failed or its worker did
        /// not answer (the bound of acknowledgements the device has not read is not counted).
        pub cuts: u64,
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
        after_a_graceful_look: Hold,
        before_a_serial_call: Hold,
        serial_script: Mutex<Option<Script<SerialScript>>>,
        dependent_script: Mutex<Option<Script<DependentScript>>>,
        held: Arc<Gauge>,
        unanswered: Arc<Gauge>,
        host_holds: Gauge,
        records: Gauge,
        read: AtomicU64,
        detaches: AtomicU64,
        detach_ends: AtomicU64,
        position_refusals: AtomicU64,
        cuts: AtomicU64,
        frame_deadline_ms: AtomicU64,
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
                after_a_graceful_look: Hold::default(),
                before_a_serial_call: Hold::default(),
                serial_script: Mutex::new(None),
                dependent_script: Mutex::new(None),
                held: Arc::default(),
                unanswered: Arc::default(),
                host_holds: Gauge::default(),
                records: Gauge::default(),
                read: AtomicU64::new(0),
                detaches: AtomicU64::new(0),
                detach_ends: AtomicU64::new(0),
                position_refusals: AtomicU64::new(0),
                cuts: AtomicU64::new(0),
                frame_deadline_ms: AtomicU64::new(0),
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

        /// Holds the acknowledgement writer at the next time it finds the stream's end graceful with
        /// nothing left to write, before it decides to finish the stream. The hold fires once.
        #[must_use]
        pub fn hold_after_a_graceful_look(&self) -> Held {
            self.after_a_graceful_look.arm()
        }

        /// Holds the serial adapter at its next frame, after the host's decision for it and before
        /// the call to the worker is made. The hold fires once.
        #[must_use]
        pub fn hold_before_a_serial_call(&self) -> Held {
            self.before_a_serial_call.arm()
        }

        /// Has the serial adapter's calls answered by `script`, which is given each call's
        /// parameters and answers when it is awaited, instead of calling the worker.
        pub fn script_serial_calls<F, Fut>(&self, script: F)
        where
            F: Fn(InputWriteParams) -> Fut + Send + Sync + 'static,
            Fut: Future<Output = SerialAnswer> + Send + 'static,
        {
            let script: Arc<SerialScript> = Arc::new(move |params| Box::pin(script(params)));
            *self
                .serial_script
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(Script(script));
        }

        /// Has a release, a detach and a launch that the host forwards answered by `script`, which
        /// is given the request as it would be sent to the worker, instead of sending it.
        pub fn script_dependent_requests(
            &self,
            script: impl Fn(&MutationRequest) -> Outcome + Send + Sync + 'static,
        ) {
            self.script_dependent_answers(move |request| SerialAnswer::Answered(script(request)));
        }

        /// As [`Self::script_dependent_requests`], for a script whose answer may be that none comes in
        /// time or that the link ends under the call.
        pub fn script_dependent_answers(
            &self,
            script: impl Fn(&MutationRequest) -> SerialAnswer + Send + Sync + 'static,
        ) {
            let script: Arc<DependentScript> = Arc::new(script);
            *self
                .dependent_script
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(Script(script));
        }

        /// Gives the frames that the host passes on from now a deadline of `deadline` from the moment
        /// they are passed on, instead of the door's own.
        pub fn set_frame_deadline(&self, deadline: std::time::Duration) {
            let millis = u64::try_from(deadline.as_millis())
                .unwrap_or(u64::MAX)
                .max(1);
            self.frame_deadline_ms.store(millis, Ordering::SeqCst);
        }

        /// What the stages hold now and the most they have held, across the streams of the host.
        #[must_use]
        pub fn counts(&self) -> InputStageCounts {
            let (held, held_peak) = self.held.counts();
            let (unanswered, unanswered_peak) = self.unanswered.counts();
            let (host_holds, host_holds_peak) = self.host_holds.counts();
            let (records, records_peak) = self.records.counts();
            InputStageCounts {
                host_holds,
                host_holds_peak,
                records,
                records_peak,
                read: self.read.load(Ordering::SeqCst),
                held,
                held_peak,
                unanswered,
                unanswered_peak,
                detaches: self.detaches.load(Ordering::SeqCst),
                detach_ends: self.detach_ends.load(Ordering::SeqCst),
                position_refusals: self.position_refusals.load(Ordering::SeqCst),
                cuts: self.cuts.load(Ordering::SeqCst),
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

        pub(in crate::service::net) async fn after_a_graceful_look(&self) {
            self.after_a_graceful_look.wait().await;
        }

        pub(in crate::service::net) async fn before_a_serial_call(&self) {
            self.before_a_serial_call.wait().await;
        }

        /// The call of the serial adapter that a suite scripts, as the proxy would give it, when it
        /// scripts them.
        pub(in crate::service::net) fn scripted_call(
            &self,
            request: &Request,
        ) -> Option<Pin<Box<dyn Future<Output = Result<Forwarded>> + Send>>> {
            let script = self
                .serial_script
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()?;
            let params = request.params.to_typed::<InputWriteParams>().ok()?;
            let answer = (script.0)(params);
            Some(Box::pin(async move {
                forwarded_as(answer.await, RequestId::new(0))
            }))
        }

        /// The result that a suite scripts for the call of a release, a detach or a launch, when it
        /// scripts them.
        pub(in crate::service::net) fn scripted_answer(
            &self,
            mutation: &MutationRequest,
        ) -> Option<Result<Forwarded>> {
            let script = self
                .dependent_script
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()?;
            Some(forwarded_as((script.0)(mutation), mutation.request_id))
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

        pub(in crate::service::net) fn position_refused(&self) {
            self.position_refusals.fetch_add(1, Ordering::SeqCst);
        }

        pub(in crate::service::net) fn detach_end_asked(&self) {
            self.detach_ends.fetch_add(1, Ordering::SeqCst);
        }

        pub(in crate::service::net) fn stream_cut(&self) {
            self.cuts.fetch_add(1, Ordering::SeqCst);
        }

        pub(in crate::service::net) fn frame_deadline(&self) -> std::time::Duration {
            match self.frame_deadline_ms.load(Ordering::SeqCst) {
                0 => super::super::FRAME_DEADLINE,
                millis => std::time::Duration::from_millis(millis),
            }
        }

        pub(in crate::service::net) fn frame_taken(&self) {
            self.host_holds.rise();
        }

        pub(in crate::service::net) fn frame_let_go(&self) {
            self.host_holds.fall();
        }

        pub(in crate::service::net) fn record_made(&self) {
            self.records.rise();
        }

        pub(in crate::service::net) fn records_fell(&self, count: usize) {
            self.records.fall_by(count);
        }

        /// A stream's state is gone: the frames it still held and the records it still kept are
        /// not the host's any more.
        pub(in crate::service::net) fn stream_torn_down(
            &self,
            holds: &std::collections::BTreeMap<u64, usize>,
            records: usize,
        ) {
            self.host_holds.fall_by(holds.values().sum());
            self.records.fall_by(records);
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

        pub(in crate::service::net) async fn after_a_graceful_look(&self) {}

        pub(in crate::service::net) async fn before_a_serial_call(&self) {}

        pub(in crate::service::net) fn scripted_answer(
            &self,
            _mutation: &kr_protocol::envelope::MutationRequest,
        ) -> Option<crate::error::Result<crate::service::net::proxy::Forwarded>> {
            None
        }

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

        pub(in crate::service::net) fn position_refused(&self) {}

        pub(in crate::service::net) fn detach_end_asked(&self) {}

        pub(in crate::service::net) fn stream_cut(&self) {}

        pub(in crate::service::net) fn frame_deadline(&self) -> std::time::Duration {
            super::super::FRAME_DEADLINE
        }

        pub(in crate::service::net) fn frame_taken(&self) {}

        pub(in crate::service::net) fn frame_let_go(&self) {}

        pub(in crate::service::net) fn record_made(&self) {}

        pub(in crate::service::net) fn records_fell(&self, _count: usize) {}

        pub(in crate::service::net) fn stream_torn_down(
            &self,
            _holds: &std::collections::BTreeMap<u64, usize>,
            _records: usize,
        ) {
        }
    }
}
