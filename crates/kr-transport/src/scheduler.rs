//! The application scheduler: control and receipts ahead of bulk transfers.
//!
//! Section 23 asks for two related things: the host's application scheduler prioritises control and
//! receipts over bulk transfers, and the number and queued bytes of bulk streams are limited so
//! connection flow control cannot consume the entire send budget. This module is where the
//! application's half of both lives, and neither half is absolute.
//!
//! Priority is a QUIC stream property, so a class is a number given to
//! [`crate::codec::FrameWriter::set_priority`], and what that number decides is which stream the
//! connection sends from *while it has capacity*. Once the connection's send window is full, a
//! control frame waits for the peer to acknowledge, not for a scheduler decision. Admission is
//! ours: [`StreamBudget`] refuses a stream, or a write, that would push a connection past one of
//! its ceilings before anything is sent. One keystroke behind a file transfer is the case both
//! exist for.
//!
//! Two ceilings, because one would not do the job. Every data-stream write is charged against the
//! peer's whole send budget, so no combination of data streams can hand the connection more than
//! the peer said it would accept. Bulk writes are charged again against a lower ceiling, which
//! leaves a mebibyte of that budget that a transfer can never occupy.
//!
//! What is not charged: control frames. They are written through the connection's single control
//! writer, which holds its lock across the write, so at most one control frame is outstanding at a
//! time and the mebibyte above is what it is for. That is an exclusion, not an accounting: a
//! control write is never refused by this budget.
//!
//! What the budget counts is what the application has handed the connection and the connection has
//! not yet taken: each frame, its length prefix and its stream header included, for as long as its
//! write is in progress. Two things it does not count. A message's encoding buffer exists for the
//! length of a synchronous encode before the reservation is taken, so it cannot accumulate across
//! blocked writes, and what it holds is a value this process already built rather than anything a
//! peer supplied. And bytes the connection has accepted but the peer has not yet acknowledged sit
//! in the QUIC send window, where nothing iroh exposes says when they leave. So this bounds what
//! the application offers the connection; it reserves no capacity inside the window itself.

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

/// The bounds a connection places on what it hands the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendLimits {
    /// Maximum concurrent bulk streams.
    pub max_bulk_streams: usize,
    /// Maximum bytes the application is handing the connection across all bulk streams at once.
    pub max_bulk_queued_bytes: usize,
    /// Maximum bytes the application is handing the connection across all data streams at once.
    pub max_queued_bytes: usize,
}

/// How much of the peer's declared send budget the application never hands to a bulk transfer.
///
/// Section 23 requires that bulk streams cannot consume the entire send budget. This is the part of
/// that budget the application will not give them. It is not a reservation inside the connection:
/// bytes the connection has already accepted still occupy its window until the peer acknowledges
/// them, and the transport has no way to observe when they drain.
pub const CONTROL_RESERVE_BYTES: usize = 1024 * 1024;

impl Default for SendLimits {
    fn default() -> Self {
        Self {
            max_bulk_streams: DEFAULT_MAX_BULK_STREAMS,
            max_bulk_queued_bytes: MAX_SEND_QUEUE_BYTES - CONTROL_RESERVE_BYTES,
            max_queued_bytes: MAX_SEND_QUEUE_BYTES,
        }
    }
}

impl SendLimits {
    /// Returns the largest complete frame a write of `class` can ever be admitted with.
    ///
    /// A message is encoded under this as well as under its stream kind's bound, so a frame the
    /// budget would refuse however idle the connection is refused as too large instead of being
    /// built first and rejected after.
    #[must_use]
    pub const fn ceiling_for(&self, class: StreamClass) -> usize {
        match class {
            StreamClass::Bulk if self.max_bulk_queued_bytes < self.max_queued_bytes => {
                self.max_bulk_queued_bytes
            }
            _ => self.max_queued_bytes,
        }
    }

    /// Returns these limits held to what the connection negotiated.
    ///
    /// A peer that declared a smaller send queue than the protocol default is held to what it
    /// declared, and bulk traffic is held to that less the control reserve, so a transfer never
    /// fills the budget that peer said it would accept.
    #[must_use]
    pub fn negotiated(self, limits: kr_protocol::hello::ReceiveLimits) -> Self {
        let declared = usize::try_from(limits.max_send_queue_bytes.get())
            .unwrap_or(usize::MAX)
            .max(1);
        Self {
            max_queued_bytes: declared.min(self.max_queued_bytes),
            max_bulk_queued_bytes: declared
                .saturating_sub(CONTROL_RESERVE_BYTES)
                .max(1)
                .min(self.max_bulk_queued_bytes),
            ..self
        }
    }
}

/// Tracks what the bulk streams of one connection are using.
///
/// A budget is shared by every task that writes on the connection, so it locks. The critical
/// section is an integer comparison; nothing is held across an await point.
#[derive(Debug)]
pub struct StreamBudget {
    limits: SendLimits,
    state: Mutex<BudgetState>,
}

#[derive(Debug, Default)]
struct BudgetState {
    open_bulk_streams: usize,
    queued_bytes: usize,
    bulk_queued_bytes: usize,
}

impl StreamBudget {
    /// Creates a budget with the given limits.
    #[must_use]
    pub fn new(limits: SendLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(BudgetState::default()),
        }
    }

    /// Returns the limits in force.
    #[must_use]
    pub const fn limits(&self) -> SendLimits {
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
        if state.open_bulk_streams >= self.limits.max_bulk_streams {
            return Err(TransportError::LimitExceeded {
                what: "concurrent bulk streams",
                limit: self.limits.max_bulk_streams,
            });
        }
        state.open_bulk_streams += 1;
        drop(state);
        Ok(BulkStreamSlot {
            budget: Arc::clone(self),
        })
    }

    /// Reserves queue space for one write of `class`.
    ///
    /// Every data-stream write is charged against the peer's whole send budget; a bulk write is
    /// charged again against the lower bulk ceiling. Both have to fit, and neither is charged
    /// until both do.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::LimitExceeded`] naming whichever ceiling the write would pass.
    /// The caller waits and tries again; nothing is dropped.
    pub fn reserve(self: &Arc<Self>, class: StreamClass, bytes: usize) -> Result<QueueReservation> {
        let mut state = self.lock();
        let queued = state.queued_bytes.saturating_add(bytes);
        if queued > self.limits.max_queued_bytes {
            return Err(TransportError::LimitExceeded {
                what: "queued bytes",
                limit: self.limits.max_queued_bytes,
            });
        }
        let bulk = if class == StreamClass::Bulk {
            let bulk = state.bulk_queued_bytes.saturating_add(bytes);
            if bulk > self.limits.max_bulk_queued_bytes {
                return Err(TransportError::LimitExceeded {
                    what: "queued bulk bytes",
                    limit: self.limits.max_bulk_queued_bytes,
                });
            }
            Some(bulk)
        } else {
            None
        };
        state.queued_bytes = queued;
        if let Some(bulk) = bulk {
            state.bulk_queued_bytes = bulk;
        }
        drop(state);
        Ok(QueueReservation {
            budget: Arc::clone(self),
            class,
            bytes,
        })
    }

    /// Returns how many bulk streams are open.
    #[must_use]
    pub fn open_bulk_streams(&self) -> usize {
        self.lock().open_bulk_streams
    }

    /// Returns how many bytes the application is handing the connection.
    #[must_use]
    pub fn queued_bytes(&self) -> usize {
        self.lock().queued_bytes
    }

    /// Returns how many of those bytes belong to bulk streams.
    #[must_use]
    pub fn bulk_queued_bytes(&self) -> usize {
        self.lock().bulk_queued_bytes
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
    class: StreamClass,
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
        if self.class == StreamClass::Bulk {
            state.bulk_queued_bytes = state.bulk_queued_bytes.saturating_sub(self.bytes);
        }
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
        let budget = Arc::new(StreamBudget::new(SendLimits {
            max_bulk_streams: 2,
            max_bulk_queued_bytes: 1024,
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
    fn queued_bulk_bytes_stay_inside_the_bulk_ceiling() {
        let budget = Arc::new(StreamBudget::new(SendLimits {
            max_bulk_streams: 4,
            max_bulk_queued_bytes: 1000,
            max_queued_bytes: 4000,
        }));
        let first = budget
            .reserve(StreamClass::Bulk, 600)
            .expect("the first reservation");
        assert!(matches!(
            budget.reserve(StreamClass::Bulk, 600),
            Err(TransportError::LimitExceeded {
                what: "queued bulk bytes",
                ..
            })
        ));
        assert_eq!(first.bytes(), 600);
        drop(first);
        assert_eq!(budget.queued_bytes(), 0);
        assert_eq!(budget.bulk_queued_bytes(), 0);
        let _second = budget
            .reserve(StreamClass::Bulk, 1000)
            .expect("the whole bulk ceiling at once");
    }

    #[test]
    fn every_class_is_charged_against_the_whole_send_budget() {
        let budget = Arc::new(StreamBudget::new(SendLimits {
            max_bulk_streams: 4,
            max_bulk_queued_bytes: 1000,
            max_queued_bytes: 1500,
        }));
        let interactive = budget
            .reserve(StreamClass::Interactive, 800)
            .expect("an interactive write");
        let live = budget
            .reserve(StreamClass::Live, 600)
            .expect("a live write");
        assert_eq!(budget.queued_bytes(), 1400);
        // Nothing above the bulk ceiling was charged to it.
        assert_eq!(budget.bulk_queued_bytes(), 0);
        assert!(matches!(
            budget.reserve(StreamClass::Bulk, 200),
            Err(TransportError::LimitExceeded {
                what: "queued bytes",
                limit: 1500
            })
        ));
        drop(live);
        let _bulk = budget
            .reserve(StreamClass::Bulk, 200)
            .expect("room freed by the finished write");
        assert_eq!(budget.bulk_queued_bytes(), 200);
        drop(interactive);
        assert_eq!(budget.queued_bytes(), 200);
    }

    #[test]
    fn a_refused_bulk_write_charges_neither_ceiling() {
        let budget = Arc::new(StreamBudget::new(SendLimits {
            max_bulk_streams: 4,
            max_bulk_queued_bytes: 100,
            max_queued_bytes: 4000,
        }));
        assert!(budget.reserve(StreamClass::Bulk, 200).is_err());
        assert_eq!(budget.queued_bytes(), 0);
        assert_eq!(budget.bulk_queued_bytes(), 0);
    }

    #[test]
    fn a_smaller_negotiated_send_budget_lowers_both_ceilings() {
        use kr_protocol::hello::ReceiveLimits;
        use kr_protocol::scalars::U64;
        let negotiated = ReceiveLimits {
            max_send_queue_bytes: U64::new(2 * 1024 * 1024),
            ..ReceiveLimits::default()
        };
        let limits = SendLimits::default().negotiated(negotiated);
        assert_eq!(limits.max_queued_bytes, 2 * 1024 * 1024);
        assert_eq!(limits.max_bulk_queued_bytes, 1024 * 1024);
        // A larger declaration never raises either ceiling above the protocol default.
        let generous = ReceiveLimits {
            max_send_queue_bytes: U64::new(64 * 1024 * 1024),
            ..ReceiveLimits::default()
        };
        let raised = SendLimits::default().negotiated(generous);
        assert_eq!(
            raised.max_queued_bytes,
            SendLimits::default().max_queued_bytes
        );
        assert_eq!(
            raised.max_bulk_queued_bytes,
            SendLimits::default().max_bulk_queued_bytes
        );
    }

    #[test]
    fn the_default_queue_ceiling_leaves_room_for_control_traffic() {
        let limits = SendLimits::default();
        assert_eq!(limits.max_queued_bytes, MAX_SEND_QUEUE_BYTES);
        assert_eq!(limits.max_bulk_queued_bytes, 7 * 1024 * 1024);
        assert!(
            limits.max_bulk_queued_bytes + CONTROL_RESERVE_BYTES <= limits.max_queued_bytes,
            "the application never hands a transfer the whole send budget"
        );
    }
}
