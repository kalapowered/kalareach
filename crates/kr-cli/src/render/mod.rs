//! Drawing a projected session into the outer terminal.
//!
//! A projected attachment is not sent the application's bytes. It is sent the canonical grid as
//! state: one snapshot, its rows in bounded pages, then one bounded update per batch of output.
//! This module is the command's half of that: it holds the screen through
//! [`kr_client::projection`], which the companion application uses for the same purpose, and turns
//! each change into the bytes this terminal needs.
//!
//! Nothing here interprets the session's output. The rows arrive as rows, with the canonical column
//! of every cell, and they are drawn at those columns. That is what makes the projection
//! independent of this terminal's own width behaviour, and it is why a terminal of another size can
//! watch a session at all.
//!
//! # What this refuses to do
//!
//! * **Draw an incomplete screen.** A snapshot's pages are collected and the screen is replaced in
//!   one step when the last one arrives. Until then what the terminal is showing is the previous
//!   screen, which is the only honest thing to show.
//! * **Continue from a screen it does not hold.** Every update names the base it continues from,
//!   and one that does not match is refused. The command then asks for a fresh screen rather than
//!   drawing a change onto something else.
//! * **Hide what it could not carry.** A row clipped at the window's edge, a cluster the edge fell
//!   inside, a pending wrap that no cursor placement can reproduce: each is counted, and
//!   [`ProjectedDisplay::losses`] is what a caller reports instead of presenting an approximation
//!   as the session.

use kr_client::projection::paint::{Comparison, Window};
use kr_client::projection::{Applied, Projection, Refusal};
use kr_protocol::projection::{
    PROJECTION_DELTA_EVENT, PROJECTION_RESET_EVENT, PROJECTION_ROWS_EVENT,
    PROJECTION_SNAPSHOT_EVENT, ProjectionEvent,
};

/// Whether an event type belongs to the projection stream.
#[must_use]
pub const fn is_projection_event(event_type: &str) -> bool {
    matches!(
        event_type.as_bytes(),
        b"session.projection.reset"
            | b"session.projection.snapshot"
            | b"session.projection.rows"
            | b"session.projection.delta"
    )
}

/// Decodes one projection notification.
///
/// Returns `None` when the event type is not one of the four, or when its payload does not decode.
/// A payload that does not decode is not drawn and not guessed at: the caller asks for a fresh
/// screen, which is what it would do for any other update it cannot apply.
#[must_use]
pub fn decode(
    event_type: &str,
    payload: &kr_protocol::envelope::ParamsValue,
) -> Option<ProjectionEvent> {
    match event_type {
        PROJECTION_RESET_EVENT => payload.to_typed().ok().map(ProjectionEvent::Reset),
        PROJECTION_SNAPSHOT_EVENT => payload
            .to_typed()
            .ok()
            .map(|header| ProjectionEvent::Snapshot(Box::new(header))),
        PROJECTION_ROWS_EVENT => payload.to_typed().ok().map(ProjectionEvent::Rows),
        PROJECTION_DELTA_EVENT => payload
            .to_typed()
            .ok()
            .map(|delta| ProjectionEvent::Delta(Box::new(delta))),
        _ => None,
    }
}

/// What applying one event means for the terminal.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Drawn {
    /// The bytes to write, which may be none.
    pub bytes: Vec<u8>,
    /// Whether the command must ask the session for a fresh screen.
    pub resubscribe: bool,
}

/// One projected session, as this terminal is showing it.
#[derive(Debug, Default)]
pub struct ProjectedDisplay {
    projection: Projection,
    losses: Comparison,
    frames: u64,
    installs: u64,
}

impl ProjectedDisplay {
    /// A terminal showing nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Applies one event and returns what to write to the terminal.
    pub fn apply(&mut self, event: ProjectionEvent) -> Drawn {
        match self.projection.apply(event) {
            // A reset says what is on the screen is no longer the session. A snapshot follows, so
            // nothing is drawn here: clearing now would replace a screen with a blank one for as
            // long as the snapshot takes to arrive.
            Applied::Reset(_) | Applied::Installing => Drawn::default(),
            Applied::Installed => {
                let Some(screen) = self.projection.screen() else {
                    return Drawn::default();
                };
                let painted = kr_client::projection::paint::install(screen, Window::of(screen));
                self.losses.absorb(painted.comparison);
                self.frames += 1;
                self.installs += 1;
                Drawn {
                    bytes: painted.bytes,
                    resubscribe: false,
                }
            }
            Applied::Updated(rows) => {
                let Some(screen) = self.projection.screen() else {
                    return Drawn::default();
                };
                let painted =
                    kr_client::projection::paint::update(screen, Window::of(screen), &rows);
                self.losses.absorb(painted.comparison);
                self.frames += 1;
                Drawn {
                    bytes: painted.bytes,
                    resubscribe: false,
                }
            }
            // The session sent an update this terminal cannot apply: it continues from a screen
            // this terminal does not hold, or from another generation. Asking for a fresh screen is
            // what the contract says to do, and it is cheaper than reasoning about what was missed.
            Applied::Refused(_) => Drawn {
                bytes: Vec::new(),
                resubscribe: true,
            },
        }
    }

    /// Whether this terminal is holding a screen it can draw.
    #[must_use]
    pub fn holds_screen(&self) -> bool {
        self.projection.screen().is_some()
    }

    /// What every frame so far could not carry.
    #[must_use]
    pub const fn losses(&self) -> Comparison {
        self.losses
    }

    /// How many frames have been drawn, and how many of them were whole screens.
    #[must_use]
    pub const fn frames(&self) -> (u64, u64) {
        (self.frames, self.installs)
    }

    /// The hyperlink covering one canonical cell, as inert metadata.
    ///
    /// Reconnection restores these so a later click still works. Nothing here activates anything:
    /// a scheme that would launch an external application needs a policy of the client's own before
    /// anything happens, and this is only the lookup.
    #[must_use]
    pub fn hyperlink_at(&self, row: u64, column: u64) -> Option<&str> {
        self.projection.screen()?.hyperlink_at(row, column)
    }

    /// The sentence a person is shown when the projection could not carry everything.
    ///
    /// `None` when it carried all of it. The count is what makes it a report rather than a warning:
    /// a person told that something was clipped can ask for a wider window.
    #[must_use]
    pub fn degradation(&self) -> Option<String> {
        if self.losses.complete() {
            return None;
        }
        let mut parts = Vec::new();
        if self.losses.cells_clipped > 0 {
            parts.push(format!(
                "{} cells outside this window",
                self.losses.cells_clipped
            ));
        }
        if self.losses.clusters_replaced > 0 {
            parts.push(format!(
                "{} characters the window's edge fell inside",
                self.losses.clusters_replaced
            ));
        }
        if self.losses.runs_replaced > 0 {
            parts.push(format!(
                "{} runs this terminal cannot place",
                self.losses.runs_replaced
            ));
        }
        if self.losses.soft_wraps > 0 {
            parts.push(format!(
                "{} wrapped lines drawn as separate rows",
                self.losses.soft_wraps
            ));
        }
        if self.losses.truncated_rows > 0 {
            parts.push(format!(
                "{} rows the session had already shortened",
                self.losses.truncated_rows
            ));
        }
        if self.losses.pending_wrap {
            parts.push("a pending wrap".to_owned());
        }
        if self.losses.cursor_outside {
            parts.push("the cursor outside this window".to_owned());
        }
        Some(parts.join(", "))
    }
}

/// Whether a refusal means the screen is gone rather than merely stale.
#[must_use]
pub const fn discards_the_screen(refusal: Refusal) -> bool {
    matches!(
        refusal,
        Refusal::BaseMismatch | Refusal::WrongGeneration | Refusal::NoScreen
    )
}
