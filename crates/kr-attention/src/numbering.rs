//! The cursors a reader whose history has a bound is shown.
//!
//! A session's change log counts every change the host recorded, so the first change a bounded
//! reader may be shown, at cursor 40, says forty things happened before its history began. Section
//! 10 keeps what lies before a grant's bound from a reader of it, and a count of it is something
//! about it. So a reader whose history does not reach every moment is shown each cursor as the
//! log's own, from where its history starts, plus an offset the reader cannot know: a keyed digest
//! of the session and of the moment its history reaches back to, under the store's own secret
//! ([`KeySecret::cursor_offset`]). It is the same whenever it is asked for, with nothing kept
//! beside the store, and it changes with the store.
//!
//! The reader gives these numbers back (`visit.acknowledge`), and a number that is not the offset's
//! sum with a cursor from where its history starts to the furthest it can have been shown is
//! refused as one this host did not give it. That is not where the log ends: a reader is not told
//! where it ends, and a refusal of every number past it would tell it. The store keeps the log's
//! own cursors, and so does every record of an answer.
//!
//! What this leaves is the difference between two cursors a reader is shown. A change recorded
//! after its history began but dated before it is not the reader's, and the place it holds in the
//! log is a step of one the reader sees between two changes. The owner and a reader whose history
//! starts at the beginning of time are shown the log's own cursors.

use kr_protocol::ids::SessionId;

use crate::key::KeySecret;

/// How one session's cursors are numbered for one reader whose history has a bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Numbering {
    /// What is added to a cursor to number it for this reader.
    offset: u64,
    /// The lowest cursor of a retained change this reader's history reaches, or where the log
    /// ends when it reaches none: no cursor is shown lower.
    floor: u64,
    /// The furthest this reader can have been shown: just past the last change its history
    /// reaches, or where its visit stands when that is further.
    ceiling: u64,
}

impl Numbering {
    /// Numbers `session_id`'s cursors for a reader whose history reaches back to
    /// `history_from_ms`, with the log starting for it at `floor` and reaching it as far as
    /// `ceiling`.
    #[must_use]
    pub fn new(
        secret: &KeySecret,
        session_id: SessionId,
        history_from_ms: u64,
        floor: u64,
        ceiling: u64,
    ) -> Self {
        Self {
            offset: secret.cursor_offset(session_id, history_from_ms),
            floor,
            ceiling,
        }
    }

    /// Returns the number this reader is shown for one of the log's cursors.
    ///
    /// A cursor below where the log starts for the reader is shown as that place: the reader is
    /// told nothing of what lies before it, and a position it has not got to yet is where its
    /// history starts.
    #[must_use]
    pub const fn shown(&self, cursor: u64) -> u64 {
        let place = if cursor < self.floor {
            self.floor
        } else {
            cursor
        };
        place.saturating_add(self.offset)
    }

    /// Returns the log's own cursor for a number this reader sends back, or none when the number
    /// is not one this host gives this reader: below the first number it is shown, or past the
    /// furthest it can have been shown.
    ///
    /// The lowest number taken is the first one shown, not the offset. A number between the two
    /// would be taken and one below the offset would not, and a reader that tried numbers down from
    /// its first would find the offset where the answer changed, and so how many changes the log
    /// held before its history.
    #[must_use]
    pub const fn cursor(&self, shown: u64) -> Option<u64> {
        match shown.checked_sub(self.offset) {
            Some(cursor) if cursor >= self.floor && cursor <= self.ceiling => Some(cursor),
            _ => None,
        }
    }
}
