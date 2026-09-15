//! The application scheduler: control and receipts ahead of bulk transfers.
//!
//! Section 23 asks for two related things. The host's application scheduler prioritises control
//! and receipts over bulk transfers, and the number and queued bytes of bulk streams are limited
//! so connection flow control cannot consume the entire send budget. Both live here.
//!
//! Priority is a QUIC stream property, so a class is a number given to
//! [`crate::codec::FrameWriter::set_priority`]. Admission is ours: [`StreamBudget`] refuses a new
//! bulk stream, or a write that would push the queue past its ceiling, before anything is sent.
//! One keystroke behind a file transfer is the case both exist for.

use std::sync::{Arc, Mutex};

use kr_protocol::frame::StreamKind;
use kr_protocol::limits::MAX_SEND_QUEUE_BYTES;

use crate::error::{Result, TransportError};

/// How a stream kind is scheduled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StreamClass {
    /// Small and latency-critical: control, receipts and terminal input.
    Interactive,
    /// Steady but not latency-critical: terminal output and semantic updates.
    Live,
    /// Large and interruptible: attachment chunks.
    Bulk,
}

/// The send priority of an interactive stream.
pub const PRIORITY_INTERACTIVE: i32 = 20;

/// The send priority of a live stream.
pub const PRIORITY_LIVE: i32 = 0;

/// The send priority of a bulk stream.
///
/// Negative, so a bulk transfer yields to everything else on the connection rather than merely
/// sharing the link with it.
pub const PRIORITY_BULK: i32 = -20;

/// Returns how a stream kind is scheduled.
#[must_use]
pub const fn class_of(kind: StreamKind) -> StreamClass {
    match kind {
        // Control carries requests, responses and receipts; input carries keystrokes. Both are
        // small and both are what a person is waiting on.
        StreamKind::Control | StreamKind::TerminalInput => StreamClass::Interactive,
        StreamKind::TerminalOutput | StreamKind::SemanticUpdates => StreamClass::Live,
        StreamKind::AttachmentChunks => StreamClass::Bulk,
    }
}

/// Returns the send priority of a stream kind.
#[must_use]
pub const fn priority_of(kind: StreamKind) -> i32 {
    match class_of(kind) {
        StreamClass::Interactive => PRIORITY_INTERACTIVE,
        StreamClass::Live => PRIORITY_LIVE,
        StreamClass::Bulk => PRIORITY_BULK,
    }
}

/// Default maximum concurrent bulk streams on one connection.
///
/// A configurable resource limit, not a subscription restriction. Four is enough for a device to
/// move several attachments at once and small enough that no single peer can fill the connection
/// with transfers.
pub const DEFAULT_MAX_BULK_STREAMS: usize = 4;

/// The bounds a connection places on its bulk streams.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BulkLimits {
    /// Maximum concurrent bulk streams.
    pub max_streams: usize,
    /// Maximum bytes queued across all bulk streams at once.
    pub max_queued_bytes: usize,
}

impl Default for BulkLimits {
    fn default() -> Self {
        Self {
            max_streams: DEFAULT_MAX_BULK_STREAMS,
            max_queued_bytes: MAX_SEND_QUEUE_BYTES,
        }
    }
}

/// Tracks what the bulk streams of one connection are using.
///
/// A budget is shared by every task that writes on the connection, so it locks. The critical
/// section is an integer comparison; nothing is held across an await point.
#[derive(Debug)]
pub struct StreamBudget {
    limits: BulkLimits,
    state: Mutex<BudgetState>,
}

#[derive(Debug, Default)]
struct BudgetState {
    open_bulk_streams: usize,
    queued_bytes: usize,
}

impl StreamBudget {
    /// Creates a budget with the given limits.
    #[must_use]
    pub fn new(limits: BulkLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(BudgetState::default()),
        }
    }

    /// Returns the limits in force.
    #[must_use]
    pub const fn limits(&self) -> BulkLimits {
        self.limits
    }

    /// Admits one more bulk stream.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::LimitExceeded`] when the connection already has as many bulk
    /// streams as it is allowed.
    pub fn open_bulk(self: &Arc<Self>) -> Result<BulkStreamSlot> {
        let mut state = self.lock();
        if state.open_bulk_streams >= self.limits.max_streams {
            return Err(TransportError::LimitExceeded {
                what: "concurrent bulk streams",
                limit: self.limits.max_streams,
            });
        }
        state.open_bulk_streams += 1;
        drop(state);
        Ok(BulkStreamSlot {
            budget: Arc::clone(self),
        })
    }

    /// Reserves queue space for a bulk write.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::LimitExceeded`] when the write would push the connection's queued
    /// bulk bytes past the ceiling. The caller waits and tries again; nothing is dropped.
    pub fn reserve(self: &Arc<Self>, bytes: usize) -> Result<QueueReservation> {
        let mut state = self.lock();
        let queued = state.queued_bytes.saturating_add(bytes);
        if queued > self.limits.max_queued_bytes {
            return Err(TransportError::LimitExceeded {
                what: "queued bulk bytes",
                limit: self.limits.max_queued_bytes,
            });
        }
        state.queued_bytes = queued;
        drop(state);
        Ok(QueueReservation {
            budget: Arc::clone(self),
            bytes,
        })
    }

    /// Returns how many bulk streams are open.
    #[must_use]
    pub fn open_bulk_streams(&self) -> usize {
        self.lock().open_bulk_streams
    }

    /// Returns how many bulk bytes are queued.
    #[must_use]
    pub fn queued_bytes(&self) -> usize {
        self.lock().queued_bytes
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BudgetState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// One admitted bulk stream. The slot is returned when it is dropped.
#[derive(Debug)]
pub struct BulkStreamSlot {
    budget: Arc<StreamBudget>,
}

impl Drop for BulkStreamSlot {
    fn drop(&mut self) {
        let mut state = self.budget.lock();
        state.open_bulk_streams = state.open_bulk_streams.saturating_sub(1);
    }
}

/// Queue space reserved for one bulk write. It is released when the write completes.
#[derive(Debug)]
pub struct QueueReservation {
    budget: Arc<StreamBudget>,
    bytes: usize,
}

impl QueueReservation {
    /// Returns the reserved size.
    #[must_use]
    pub const fn bytes(&self) -> usize {
        self.bytes
    }
}

impl Drop for QueueReservation {
    fn drop(&mut self) {
        let mut state = self.budget.lock();
        state.queued_bytes = state.queued_bytes.saturating_sub(self.bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_and_input_outrank_bulk_transfers() {
        assert!(priority_of(StreamKind::Control) > priority_of(StreamKind::AttachmentChunks));
        assert!(priority_of(StreamKind::TerminalInput) > priority_of(StreamKind::AttachmentChunks));
        assert!(priority_of(StreamKind::Control) > priority_of(StreamKind::TerminalOutput));
        assert!(
            priority_of(StreamKind::TerminalOutput) > priority_of(StreamKind::AttachmentChunks)
        );
    }

    #[test]
    fn every_stream_kind_has_a_class() {
        for kind in StreamKind::ALL {
            let _ = class_of(*kind);
        }
        assert_eq!(class_of(StreamKind::AttachmentChunks), StreamClass::Bulk);
    }

    #[test]
    fn a_connection_admits_no_more_bulk_streams_than_its_limit() {
        let budget = Arc::new(StreamBudget::new(BulkLimits {
            max_streams: 2,
            max_queued_bytes: 1024,
        }));
        let first = budget.open_bulk().expect("the first slot");
        let second = budget.open_bulk().expect("the second slot");
        assert!(matches!(
            budget.open_bulk(),
            Err(TransportError::LimitExceeded {
                what: "concurrent bulk streams",
                limit: 2
            })
        ));
        drop(second);
        let _third = budget.open_bulk().expect("a freed slot is reusable");
        drop(first);
        assert_eq!(budget.open_bulk_streams(), 1);
    }

    #[test]
    fn queued_bulk_bytes_stay_inside_the_send_budget() {
        let budget = Arc::new(StreamBudget::new(BulkLimits {
            max_streams: 4,
            max_queued_bytes: 1000,
        }));
        let first = budget.reserve(600).expect("the first reservation");
        assert!(matches!(
            budget.reserve(600),
            Err(TransportError::LimitExceeded {
                what: "queued bulk bytes",
                ..
            })
        ));
        assert_eq!(first.bytes(), 600);
        drop(first);
        assert_eq!(budget.queued_bytes(), 0);
        let _second = budget.reserve(1000).expect("the whole budget at once");
    }

    #[test]
    fn the_default_queue_ceiling_is_the_protocol_send_budget() {
        assert_eq!(BulkLimits::default().max_queued_bytes, 8 * 1024 * 1024);
    }
}
