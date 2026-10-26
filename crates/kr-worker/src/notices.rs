//! What the worker saw of its session's own work, waiting to be written to the session's journal.
//!
//! The attention store reads an agent turn that ended and a command that failed from the journal's
//! host events, so each is written there before anything reads it. Two places see them: the broker,
//! which reads an agent's server say that a turn ended, and the session, which is told by the shell
//! that a command finished. Each queues under a lock of its own (the broker's state, the session),
//! so the queue's lock is the last a caller takes and takes no other while it is held: it is a
//! leaf, and neither place waits for the other.
//!
//! A notice leaves the queue only once the journal has taken it, so one the journal refuses waits
//! for the journal's recovery, and a closing session writes what is queued before it commits its
//! closure. A session with no journal has nowhere to write them and keeps none.

use std::collections::VecDeque;
use std::sync::{Mutex, PoisonError};

use kr_protocol::attention::SessionEventNotice;

/// The notices of one session that its journal has yet to take, oldest first.
#[derive(Debug, Default)]
pub struct SessionNotices {
    queue: Mutex<VecDeque<SessionEventNotice>>,
    queued: tokio::sync::Notify,
}

impl SessionNotices {
    /// Queues one notice and wakes the task that writes them.
    pub fn push(&self, notice: SessionEventNotice) {
        self.lock().push_back(notice);
        self.queued.notify_one();
    }

    /// Returns the oldest notice the journal has not taken, leaving it queued.
    #[must_use]
    pub fn front(&self) -> Option<SessionEventNotice> {
        self.lock().front().cloned()
    }

    /// Drops the oldest notice, which the journal has taken.
    pub fn taken(&self) {
        self.lock().pop_front();
    }

    /// Drops every notice, for a session that has no journal to take them.
    pub fn clear(&self) {
        self.lock().clear();
    }

    /// Whether no notice waits.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Waits until a notice may have been queued.
    pub async fn queued(&self) {
        self.queued.notified().await;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<SessionEventNotice>> {
        // Every change is one push or pop, so a panic elsewhere leaves nothing half done.
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
