//! When the host last heard from each connection of a paired device.
//!
//! The host chooses the connection of a device to withdraw at its bound by this time, so it is
//! the time of the last authenticated packet the transport received on the connection, keepalives
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
use kr_transport::clock::{ContinuousClock, ContinuousInstant};

use super::DeviceConnections;

/// How often the host reads what its transport has received on a connection. It is a tenth of the
/// interval at which a live device sends a keepalive.
const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

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

    /// The host's clock now, as a stamp, for this host's own tests.
    #[cfg(feature = "testing")]
    pub(super) fn now(&self) -> u64 {
        nanoseconds(self.clock.now())
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
        /// every counter of its received frames, each of which an authenticated packet moves.
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
}

impl Readings {
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
