//! The boundary between the raw byte stream and what a terminal of another size is shown.
//!
//! A worker owns the raw side: the bytes the application wrote, in order, with a cursor. It does
//! not own the *interpretation* of those bytes. Column counts decide where lines wrap and where
//! the cursor is, so a terminal of a different width cannot be sent the same bytes and be right.
//!
//! Section 8 names two presentations for a terminal attachment:
//!
//! | Presentation | What it receives | What it needs |
//! | --- | --- | --- |
//! | `direct` | the raw stream, unchanged | a terminal of exactly the canonical size |
//! | `viewport` | a rendering of the canonical grid, clipped to its own size | a terminal engine |
//!
//! Direct mode needs nothing but the raw stream, and this crate serves it. Viewport mode needs a
//! parser that holds the canonical grid, a renderer that projects it, and a restoration that puts a
//! reconnecting terminal into that state without the side effects the original bytes carried: no
//! replayed clipboard write, no replayed bell, no replayed query whose answer would arrive at the
//! wrong moment. That is the terminal engine, and it is a separate component.
//!
//! # What this module is
//!
//! The interface point. A session holds an optional [`TerminalProjection`]; when one is installed,
//! a viewport attachment is served through it. When none is installed, a viewport attachment is
//! **refused with an explicit reason** rather than being sent raw bytes that assume another width.
//! Refusing is the honest answer: sending them would produce wrapped lines and a cursor in the
//! wrong place, and the client would have no way to know.
//!
//! # What installing the engine adds
//!
//! Exactly three calls, all defined here: [`TerminalProjection::snapshot`] for an attachment that
//! is joining, [`TerminalProjection::project`] for each range of raw output it is shown, and
//! [`TerminalProjection::restore`] for a terminal that is reconnecting. Nothing else in this crate
//! changes: the raw stream, the cursor, the history and the input path are the same either way.

use kr_protocol::session::Dimensions;

use crate::error::Result;

/// A screen projected for one attachment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectedScreen {
    /// The cursor this projection was taken at.
    pub cursor: u64,
    /// The size it was projected for.
    pub dimensions: Dimensions,
    /// The bytes that draw it, with no side effect the original stream carried.
    pub bytes: Vec<u8>,
}

/// What a terminal engine provides so a session can serve a terminal of another size.
///
/// Every method takes the size it is projecting for, because the same session is shown to
/// attachments of different sizes at the same time and each one sees its own projection.
pub trait TerminalProjection: Send + Sync + std::fmt::Debug {
    /// Returns the screen an attachment joining at this cursor should be shown.
    ///
    /// This replaces replaying raw history into the attachment's terminal, which would replay
    /// whatever that history contained.
    ///
    /// # Errors
    ///
    /// Returns an error when the projection cannot be produced.
    fn snapshot(&self, cursor: u64, dimensions: Dimensions) -> Result<ProjectedScreen>;

    /// Returns the bytes an attachment of this size should receive for a range of raw output.
    ///
    /// # Errors
    ///
    /// Returns an error when the range cannot be projected.
    fn project(&self, from: u64, raw: &[u8], dimensions: Dimensions) -> Result<Vec<u8>>;

    /// Returns the bytes that put a reconnecting terminal into the session's current state.
    ///
    /// Side-effect-free: a clipboard write, a bell, a notification or a query that the original
    /// stream carried is not reissued, because the terminal has already had it once or must never
    /// have it at all.
    ///
    /// # Errors
    ///
    /// Returns an error when the state cannot be rendered.
    fn restore(&self, cursor: u64, dimensions: Dimensions) -> Result<ProjectedScreen>;
}

/// Why a presentation cannot be served.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresentationRefusal {
    /// A terminal of another size asked for a rendering and no engine is installed.
    NoProjection,
}

impl PresentationRefusal {
    /// Returns the sentence the caller is given.
    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::NoProjection => {
                "this terminal is not the session's size, so it needs a rendering of the session's \
                 screen rather than the raw stream; this host has no terminal engine installed. \
                 Attach at the session's size, or claim its geometry."
            }
        }
    }
}

impl core::fmt::Display for PresentationRefusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.detail())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_says_what_would_make_it_work() {
        let detail = PresentationRefusal::NoProjection.detail();
        assert!(detail.contains("claim its geometry"));
        assert!(detail.contains("terminal engine"));
    }
}
