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
//! be admitted a moment before the copy says so. What the answer says about the lifecycle, what the
//! application is doing, and how many launches wait for the reader, is for that reason read from
//! the input domain, which holds all three as they are, and never from the copy. The application's
//! producer writes what the application is doing there as each fact joins, and the task that reads
//! the fact waits for no storage call to do it, so a turn that begins while a storage call holds
//! the session is in the answer from the evidence loop's next read of the broker. A question cannot
//! begin then, because its creation runs with the session taken, and a launch that begins then is
//! not in the answer: it is registered under the session, which the request waits for.
//!
//! Three things the answer does not follow:
//!
//! - A root that exits while a storage call holds the session stays `Live` in the answer. Only the
//!   supervision sees the exit, and it waits for the session, so the domain still says `Live`, and
//!   the answer says so with the `root_process` of the root that has ended.
//! - An answer given between the domain's change to `Closed` and the closure's publication says
//!   `Closed` with no closure record, and with the application name the copy had. The application
//!   state, which the closure clears in the statement after it sets `Closed`, can in that moment
//!   be the one the session had before. For the host's sleep demand that is more demand, not less.
//! - A record of what a worker said, kept by a reader that asks again and again, can take an older
//!   copy of the same stage in the place of a newer one, because two answers of one stage are not
//!   ordered by anything the answer carries.

use std::sync::Mutex;
use std::time::Duration;

use kr_protocol::scalars::Nullable;
use kr_protocol::session::SessionSummary;

use crate::input_domain::InputShared;

/// How long a read waits to take the session before it answers from the published summary.
pub const TAKE_BOUND: Duration = Duration::from_millis(250);

/// How long a read that holds the session waits for the store to answer it before it stops
/// waiting. The read itself goes on, with the session, until the store answers.
pub const STORE_BOUND: Duration = TAKE_BOUND;

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
    fn copy(&self) -> SessionSummary {
        self.latest
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .expect("a session publishes its summary as it is made")
    }

    /// Returns the summary as it was last published, for this host's own tests. A read answers
    /// through [`Self::answer`] and never gives the copy's own state.
    ///
    /// # Panics
    ///
    /// Panics when no summary was ever published, which a session does as it is made.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn latest(&self) -> SessionSummary {
        self.copy()
    }

    /// Returns the answer to a read that could not take the session: the published summary with
    /// the lifecycle state and what the application is doing read from the input domain, and how
    /// many launches the domain holds for the reader to decide.
    ///
    /// This is the one place where the answer takes what the session's own admission of a close
    /// holds. Today that is the state alone, which the domain changes in the step that admits a
    /// close. The closing reason and the durability that an admission carries are put into the
    /// answer here, and nowhere else. The domain is taken once, so the state and the count are
    /// the domain's at one moment.
    #[must_use]
    pub fn answer(&self, input: &InputShared) -> Held {
        let mut summary = self.copy();
        let domain = input.lock();
        summary.state = domain.state();
        summary.application_state = Nullable(domain.application_state());
        let outstanding_launches = summary
            .state
            .is_running()
            .then(|| domain.outstanding_launches())
            .flatten();
        Held {
            summary,
            outstanding_launches,
        }
    }
}

/// What a read that could not take the session answers.
#[derive(Debug)]
pub struct Held {
    /// The published summary, with the lifecycle state the input domain holds now.
    pub summary: SessionSummary,
    /// How many callers wait for a launch the reader is deciding, for a running session with a
    /// managed root editor, and none otherwise, as a read that takes the session gives it.
    pub outstanding_launches: Option<u64>,
}
