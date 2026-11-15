//! What a read of a session answers while the session is held behind a storage call.
//!
//! The session is behind one lock, and the work that holds it for as long as a disk call takes can
//! stand still for as long as the disk does. A read that waited for that lock would stand still
//! with it, and the person who asked would not learn whether the session is running or closing. So
//! the session keeps a copy of its summary outside its own lock, a read takes the session for no
//! longer than [`TAKE_BOUND`], and a read that did not get it answers from the copy.
//!
//! The copy is set when the session launches, when it builds its record again, when it admits a
//! close and when it records its closure. It can therefore be older than the session: a close can
//! be admitted a moment before the copy says so. What the answer says about the lifecycle is for
//! that reason read from the input domain, which the admission of a close changes in the same
//! step, and never from the copy's own state.

use std::sync::Mutex;
use std::time::Duration;

use kr_protocol::session::SessionSummary;

use crate::input_domain::InputShared;

/// How long a read waits to take the session before it answers from the published summary.
pub const TAKE_BOUND: Duration = Duration::from_millis(250);

/// How long a bounded take waits between two tries.
pub(crate) const TAKE_STEP: Duration = Duration::from_millis(10);

/// The session's summary as it was last published, outside the session's lock.
#[derive(Debug, Default)]
pub struct PublishedSummary {
    /// Held for no longer than a clone or a replacement takes, never across a call that waits.
    latest: Mutex<Option<SessionSummary>>,
}

impl PublishedSummary {
    /// Replaces the published summary.
    pub(crate) fn set(&self, summary: SessionSummary) {
        *self
            .latest
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(summary);
    }

    /// Returns the summary as it was last published, with the lifecycle state it was published
    /// with, which may be older than the session's.
    ///
    /// # Panics
    ///
    /// Panics when no summary was ever published, which a session does as it is made.
    #[must_use]
    pub fn latest(&self) -> SessionSummary {
        self.latest
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .expect("a session publishes its summary as it is made")
    }

    /// Returns the answer to a read that could not take the session: the published summary with
    /// the lifecycle state read from the input domain.
    ///
    /// This is the one place where the answer takes what the session's own admission of a close
    /// holds. Today that is the state alone, which the domain changes in the step that admits a
    /// close. The closing reason and the durability that an admission carries are put into the
    /// answer here, and nowhere else.
    #[must_use]
    pub fn answer(&self, input: &InputShared) -> SessionSummary {
        let mut summary = self.latest();
        summary.state = input.lock().state();
        summary
    }
}
