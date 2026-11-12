//! When the host last heard from each connection of a paired device.
//!
//! The host chooses the connection of a device to withdraw at its bound by this time, so it is
//! the time of the last frame the transport counted as received on the connection, keepalives
//! included, and not the last request the host served: a connection that is idle at the
//! application sends keepalives and is heard from.
//!
//! The transport keeps counters of the frames it has received and no time. The host dates the
//! packets itself: a reading of the counters that finds them moved stamps the time of the reading,
//! which is no earlier than the packet and no later than the reading. A task of its own reads them
//! for each connection once a [`SAMPLE_INTERVAL`] ([`follow_the_device`]), which keeps the time of a
//! connection that has gone quiet, and the host reads them again for each connection of a device
//! when it chooses one to withdraw, so that a packet received since the last reading counts as
//! received no later than the choice. A stamp can still be one reading late, and two connections
//! whose packets came within a reading of each other can be taken in either order.

use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{Connection, ConnectionStats};
use kr_protocol::limits::KEEPALIVE_INTERVAL;
use kr_transport::clock::{ContinuousClock, ContinuousInstant};

use super::DeviceConnections;

/// How often the host reads what its transport has received on a connection. It is a tenth of the
/// interval at which a live device sends a keepalive.
pub(super) const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

/// What the host allows for a keepalive that is late beyond the interval and the reading: a round
/// trip of two seconds and one retransmission on a poor path.
const DELAY_ALLOWANCE: Duration = Duration::from_secs(4);

/// How long a connection must have been silent, strictly more than this at the reading the host
/// makes when it chooses, before the host may withdraw it at the bound: a keepalive interval, one
/// reading and an allowance for delay. A live device on a path that works sends something at least
/// every keepalive interval, so a connection heard from inside this time is never withdrawn; the
/// transport ends a connection that has been silent for [`kr_transport::endpoint::IDLE_TIMEOUT`]
/// by itself.
///
/// The measure is the host's own: its clock counts the time the host spent asleep, which the
/// transport's timers do not, so after a sleep every connection reads as silent until it is heard
/// from again, and a connection that arrives before they are is served by withdrawing the
/// longest silent. A path that stops for a few seconds after the last keepalive of an idle
/// connection also leaves that connection silent for this long before the device's other
/// connections are, which is the case the allowance does not cover.
pub(super) const SILENT_FOR: Duration = Duration::from_millis(
    KEEPALIVE_INTERVAL.get()
        + SAMPLE_INTERVAL.as_secs() * 1_000
        + DELAY_ALLOWANCE.as_secs() * 1_000,
);

/// Which of a device's connections, counted first to last, the host withdraws to take a new one at
/// the bound, from their stamps and the time `now` read before them: the one with the oldest stamp
/// among those silent for strictly more than [`SILENT_FOR`], and of equal stamps the one counted
/// later, which is the newer; or none, when every connection has been heard from within that time.
///
/// A stamp can be later than `now`, because a periodic reading can date a packet after the choice
/// read the time, so the time a connection has been silent is taken from below at zero.
pub(super) fn to_withdraw(stamps: &[u64], now: u64) -> Option<usize> {
    let silent_for = u64::try_from(SILENT_FOR.as_nanos()).unwrap_or(u64::MAX);
    stamps
        .iter()
        .enumerate()
        .rev()
        .filter(|(_, stamp)| now.saturating_sub(**stamp) > silent_for)
        .min_by_key(|(_, stamp)| **stamp)
        .map(|(index, _)| index)
}

/// When the host last heard from a connection's device: the time, on the host's continuous clock,
/// at which a reading found that the transport had received more than at the reading before. The
/// clock is the host's own, which a person cannot set.
///
/// The stamp is read by the task that admits another connection of the same device, under the
/// table's lock, and written by the task that follows the connection and by the same admitting
/// task. Each takes the connection's mutex for the length of a read of the counters and a store,
/// never across an await, and the connection's request path takes no part in either. A reading
/// beside another returns the stamp from before or from after the other, each of them true of the
/// connection at some moment of the reading.
pub(super) struct Heard {
    pub(super) connection: Connection,
    clock: Arc<dyn ContinuousClock>,
    seen: std::sync::Mutex<Seen>,
}

/// What the last reading of a connection found.
struct Seen {
    /// How many frames the transport had received.
    frames: u64,
    /// The stamp: nanoseconds since the host clock's anchor.
    at: u64,
    /// Set by a case that stands in for a path that lost every packet of the connection: the
    /// frames the transport has received are read as this many from then on.
    #[cfg(feature = "testing")]
    frozen: Option<u64>,
}

impl Heard {
    /// A connection heard from now, which is when the host counted it.
    pub(super) fn new(connection: Connection, clock: Arc<dyn ContinuousClock>) -> Self {
        let seen = Seen {
            frames: frames_received(&connection),
            at: nanoseconds(clock.now()),
            #[cfg(feature = "testing")]
            frozen: None,
        };
        Self {
            connection,
            clock,
            seen: std::sync::Mutex::new(seen),
        }
    }

    fn seen(&self) -> std::sync::MutexGuard<'_, Seen> {
        self.seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Reads what the transport has received, stamps the time when more has come than at the last
    /// reading, and returns the stamp.
    pub(super) fn refresh(&self) -> u64 {
        let mut seen = self.seen();
        #[cfg(feature = "testing")]
        let frames = seen
            .frozen
            .unwrap_or_else(|| frames_received(&self.connection));
        #[cfg(not(feature = "testing"))]
        let frames = frames_received(&self.connection);
        if frames != seen.frames {
            seen.frames = frames;
            seen.at = nanoseconds(self.clock.now());
        }
        seen.at
    }

    /// The stamp of the last reading, for this host's own tests.
    #[cfg(feature = "testing")]
    pub(super) fn stamp(&self) -> u64 {
        self.seen().at
    }

    /// The host's clock now, as a stamp.
    pub(super) fn now(&self) -> u64 {
        nanoseconds(self.clock.now())
    }

    /// Lets the transport's counters be read again after [`Self::silence`], so that the packets
    /// the device sends from now on date the connection.
    #[cfg(feature = "testing")]
    pub(super) fn unsilence(&self) {
        self.seen().frozen = None;
    }

    /// Makes the connection one whose packets no longer arrive: it was heard from at `at`, and
    /// from then on its counters read as they do now.
    #[cfg(feature = "testing")]
    pub(super) fn silence(&self, at: u64) {
        let mut seen = self.seen();
        seen.frames = frames_received(&self.connection);
        seen.at = at;
        seen.frozen = Some(seen.frames);
    }
}

fn nanoseconds(at: ContinuousInstant) -> u64 {
    u64::try_from(at.since_anchor().as_nanos()).unwrap_or(u64::MAX)
}

fn widen<T: Into<u64>>(counter: T) -> u64 {
    counter.into()
}

/// Names every counter of the frames a connection's transport has received once, and builds from
/// the one list the sum of them and the table a case walks. The transport counts a frame only after
/// the packet that carried it was authenticated and found not to be a repeat, so a counter that
/// moves is a packet of the device.
macro_rules! received_counters {
    ($($field:ident),* $(,)?) => {
        /// How many frames the transport has received on a connection in all, which only grows:
        /// every counter of its received frames. A frame the transport counts moves one; a packet
        /// with no frame in it, padding alone, moves none.
        fn received_frames(stats: &ConnectionStats) -> u64 {
            [$(widen(stats.frame_rx.$field)),*]
                .into_iter()
                .fold(0, u64::saturating_add)
        }

        /// Each counter of the received frames by name, with the way to set it.
        #[cfg(test)]
        const RECEIVED_COUNTERS: &[(&str, fn(&mut ConnectionStats))] =
            &[$((stringify!($field), |stats| stats.frame_rx.$field = 1)),*];

        /// Each counter of the sent frames by name, with the way to set it.
        #[cfg(test)]
        const SENT_COUNTERS: &[(&str, fn(&mut ConnectionStats))] =
            &[$((stringify!($field), |stats| stats.frame_tx.$field = 1)),*];
    };
}

received_counters!(
    acks,
    path_acks,
    ack_frequency,
    crypto,
    connection_close,
    data_blocked,
    datagram,
    handshake_done,
    immediate_ack,
    max_data,
    max_stream_data,
    max_streams_bidi,
    max_streams_uni,
    new_connection_id,
    path_new_connection_id,
    new_token,
    path_challenge,
    path_response,
    ping,
    reset_stream,
    retire_connection_id,
    path_retire_connection_id,
    stream_data_blocked,
    streams_blocked_bidi,
    streams_blocked_uni,
    stop_sending,
    stream,
    observed_addr,
    path_abandon,
    path_status_available,
    path_status_backup,
    max_path_id,
    paths_blocked,
    path_cids_blocked,
    add_address,
    reach_out,
    remove_address,
);

/// How many frames the transport has received from the device on a connection. Reading them copies
/// the connection's statistics under the lock the transport's packet handling and its stream reads
/// and writes also take, once a second for each connection and once more for each connection of a
/// device that is at the bound when another arrives.
fn frames_received(connection: &Connection) -> u64 {
    received_frames(&connection.stats())
}

/// Dates the packets a connection's device sends, a [`SAMPLE_INTERVAL`] apart, from the time the
/// connection is counted until its task is ended with it. A case can hold the readings.
pub(super) async fn follow_the_device(heard: Arc<Heard>, table: Arc<DeviceConnections>) {
    #[cfg(feature = "testing")]
    let _running = table.1.counted();
    let mut interval = tokio::time::interval(SAMPLE_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        if !table.1.are_held() {
            heard.refresh();
        }
    }
}

/// Whether the periodic readings run. A case holds them so that the reading at the choice of a
/// connection to withdraw is what dates the packets it shows.
#[derive(Default)]
pub(super) struct Readings {
    #[cfg(feature = "testing")]
    held: std::sync::atomic::AtomicBool,
    /// How far a case has moved the time the readings are dated by, in nanoseconds.
    #[cfg(feature = "testing")]
    skew: Arc<std::sync::atomic::AtomicU64>,
    /// How many periodic readings run.
    #[cfg(feature = "testing")]
    running: Arc<std::sync::atomic::AtomicUsize>,
}

/// One periodic reading that runs, until it is dropped.
#[cfg(feature = "testing")]
struct RunningReading(Arc<std::sync::atomic::AtomicUsize>);

#[cfg(feature = "testing")]
impl Drop for RunningReading {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// The host's clock moved forward by what a case has moved it, so that a connection that went
/// silent reads as silent for as long as the case says without the case waiting that long.
#[cfg(feature = "testing")]
#[derive(Debug)]
struct Skewed {
    clock: Arc<dyn ContinuousClock>,
    skew: Arc<std::sync::atomic::AtomicU64>,
}

#[cfg(feature = "testing")]
impl ContinuousClock for Skewed {
    fn now(&self) -> ContinuousInstant {
        let now = self.clock.now();
        now.checked_add(Duration::from_nanos(
            self.skew.load(std::sync::atomic::Ordering::SeqCst),
        ))
        .unwrap_or(now)
    }
}

impl Readings {
    /// The clock a connection's packets are dated by: the host's own.
    #[cfg(not(feature = "testing"))]
    #[allow(clippy::unused_self)]
    pub(super) fn timed(&self, clock: Arc<dyn ContinuousClock>) -> Arc<dyn ContinuousClock> {
        clock
    }

    /// The clock a connection's packets are dated by: the host's own, moved forward by what a
    /// case has moved it.
    #[cfg(feature = "testing")]
    pub(super) fn timed(&self, clock: Arc<dyn ContinuousClock>) -> Arc<dyn ContinuousClock> {
        Arc::new(Skewed {
            clock,
            skew: Arc::clone(&self.skew),
        })
    }

    /// How many periodic readings run, for this host's own tests.
    #[cfg(feature = "testing")]
    pub(super) fn running(&self) -> usize {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Counts a periodic reading until the guard it returns is dropped, with the reading.
    #[cfg(feature = "testing")]
    fn counted(&self) -> RunningReading {
        self.running
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        RunningReading(Arc::clone(&self.running))
    }

    /// Moves the time the readings are dated by forward, for this host's own tests.
    #[cfg(feature = "testing")]
    pub(super) fn advance(&self, by: Duration) {
        let nanos = u64::try_from(by.as_nanos()).unwrap_or(u64::MAX);
        self.skew
            .fetch_add(nanos, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(feature = "testing")]
    fn are_held(&self) -> bool {
        self.held.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[cfg(not(feature = "testing"))]
    #[allow(clippy::unused_self)]
    const fn are_held(&self) -> bool {
        false
    }

    /// Holds the periodic readings, or lets them run again, for this host's own tests.
    #[cfg(feature = "testing")]
    pub(super) fn hold(&self, held: bool) {
        self.held.store(held, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: u64 = 1_000_000_000;

    /// KR-REQ-23.21: a connection is silent for long enough to be withdrawn at the bound only when
    /// it has been silent for more than a keepalive interval, one reading and the allowance for
    /// delay, which is fifteen seconds: exactly that is kept, and a tick more goes.
    #[test]
    fn a_connection_is_withdrawn_only_when_silent_for_more_than_fifteen_seconds() {
        assert_eq!(SILENT_FOR, Duration::from_secs(15));
        assert_eq!(to_withdraw(&[0], 15 * SECOND), None, "exactly 15 s is kept");
        assert_eq!(to_withdraw(&[0], 15 * SECOND + 1), Some(0), "more goes");
    }

    /// KR-REQ-23.21: a periodic reading can date a packet after the choice read the time, and such
    /// a connection has been silent for no time at all, not for a time below zero.
    #[test]
    fn a_stamp_later_than_the_time_read_is_not_silent() {
        assert_eq!(to_withdraw(&[100 * SECOND], 10 * SECOND), None);
        assert_eq!(
            to_withdraw(&[100 * SECOND, 0], 20 * SECOND),
            Some(1),
            "the connection that is silent goes, the one dated after the time was read does not"
        );
    }

    /// KR-REQ-23.21: a connection heard from inside the time is never withdrawn, however much older
    /// than the others it is.
    #[test]
    fn no_connection_heard_from_inside_the_time_is_withdrawn() {
        assert_eq!(
            to_withdraw(&[50 * SECOND, 55 * SECOND, 60 * SECOND], 60 * SECOND),
            None
        );
    }

    /// KR-REQ-23.21: of the connections that are silent the one silent the longest goes, and of
    /// equal stamps the one counted later, so that the connection counted first is the last to go.
    #[test]
    fn of_the_silent_connections_the_oldest_stamp_goes_and_of_equal_ones_the_later_counted() {
        assert_eq!(
            to_withdraw(&[20 * SECOND, 10 * SECOND, 30 * SECOND], 100 * SECOND),
            Some(1)
        );
        assert_eq!(
            to_withdraw(&[SECOND, SECOND, SECOND], 100 * SECOND),
            Some(2)
        );
        assert_eq!(
            to_withdraw(&[SECOND, 90 * SECOND, SECOND], 100 * SECOND),
            Some(2),
            "a connection heard from lately is passed over"
        );
    }

    /// A device's every frame moves the sum, whichever kind it is, and a frame the host sent
    /// moves none of it: a connection is heard from by what the device sends.
    #[test]
    fn every_frame_received_moves_the_sum_and_no_frame_sent_does() {
        for (name, receive) in RECEIVED_COUNTERS {
            let mut stats = ConnectionStats::default();
            receive(&mut stats);
            assert_eq!(received_frames(&stats), 1, "{name} received");
        }
        for (name, send) in SENT_COUNTERS {
            let mut stats = ConnectionStats::default();
            send(&mut stats);
            assert_eq!(received_frames(&stats), 0, "{name} sent");
        }
    }

    /// The sum names every counter the transport's received frames have. Its debug form lists
    /// each one by name, and the transport's own implementation names them all, so a counter it
    /// gains changes the number of fields in that form and fails this case until the sum takes it.
    /// The count rests on that implementation, which the transport writes by hand: a counter that
    /// formatter left out would not be seen here.
    #[test]
    fn the_sum_takes_every_counter_the_transport_keeps() {
        let counters = format!("{:?}", ConnectionStats::default().frame_rx)
            .matches(": ")
            .count();
        assert_eq!(
            RECEIVED_COUNTERS.len(),
            counters,
            "the transport's received frames have a counter the sum does not take"
        );
    }
}
