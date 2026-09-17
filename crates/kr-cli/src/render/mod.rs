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

use kr_client::projection::paint::{Comparison, Keyboard, Window};
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
    keyboard: Keyboard,
}

impl ProjectedDisplay {
    /// A terminal showing nothing yet, whose keyboard protocols may be installed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A terminal whose keyboard protocols are not this attachment's to change.
    ///
    /// What `--no-probe` chooses: nobody was allowed to ask this terminal what it had negotiated,
    /// so nothing installs a protocol that nothing could put back.
    #[must_use]
    pub fn without_the_keyboard() -> Self {
        Self {
            keyboard: Keyboard::Withhold,
            ..Self::default()
        }
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
                let painted = kr_client::projection::paint::install(
                    screen,
                    Window::of(screen),
                    self.keyboard,
                );
                self.losses.absorb(painted.comparison);
                self.frames += 1;
                self.installs += 1;
                Drawn {
                    bytes: painted.bytes,
                    resubscribe: false,
                }
            }
            Applied::Updated(changed) => {
                let Some(screen) = self.projection.screen() else {
                    return Drawn::default();
                };
                let painted = kr_client::projection::paint::update(
                    screen,
                    Window::of(screen),
                    &changed.rows,
                    changed.state,
                    self.keyboard,
                );
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

    /// Discards the screen, because the session has said this terminal's view is no longer it.
    ///
    /// Called when the command is told to resynchronise or cannot decode an update. Drawing what
    /// was held until the fresh screen arrives would be drawing something the session has already
    /// said is not the session.
    pub fn discard(&mut self) {
        self.projection.discard();
    }

    /// Whether the session has said it shortened content to stay inside a resident-state bound.
    #[must_use]
    pub fn session_degraded(&self) -> bool {
        self.projection
            .screen()
            .is_some_and(|screen| screen.degraded)
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
        if self.losses.complete() && !self.session_degraded() {
            return None;
        }
        let mut parts = Vec::new();
        if self.session_degraded() {
            // The session's own answer, not this terminal's: content it had to shorten to stay
            // inside a resident-state bound is content no window size can show.
            parts.push("content the session shortened to stay inside its own bounds".to_owned());
        }
        if self.losses.cells_clipped > 0 {
            let cells = usize::try_from(self.losses.cells_clipped).unwrap_or(usize::MAX);
            parts.push(format!(
                "{} outside this window",
                plural(cells, "cell", "cells")
            ));
        }
        if self.losses.clusters_replaced > 0 {
            parts.push(format!(
                "{} the window's edge fell inside",
                plural(self.losses.clusters_replaced, "character", "characters")
            ));
        }
        if self.losses.runs_replaced > 0 {
            parts.push(format!(
                "{} this terminal cannot place",
                plural(self.losses.runs_replaced, "run", "runs")
            ));
        }
        if self.losses.rows_outside > 0 {
            parts.push(format!(
                "{} of the session's rows outside this window, holding {}",
                self.losses.rows_outside,
                plural(
                    usize::try_from(self.losses.cells_outside).unwrap_or(usize::MAX),
                    "cell",
                    "cells"
                )
            ));
        }
        if self.losses.keyboard_withheld {
            parts.push(
                "the session's keyboard protocols, which this terminal was never asked about"
                    .to_owned(),
            );
        }
        if self.losses.keyboard_stack > 0 {
            parts.push(format!(
                "{} the session holds, installed as a state rather than a stack",
                plural(
                    self.losses.keyboard_stack,
                    "keyboard entry",
                    "keyboard entries"
                )
            ));
        }
        if self.losses.controls_dropped > 0 {
            parts.push(format!(
                "{} whose control bytes were dropped",
                plural(
                    self.losses.controls_dropped,
                    "title or link",
                    "titles or links"
                )
            ));
        }
        if self.losses.soft_wraps > 0 {
            parts.push(format!(
                "{} drawn as separate rows",
                plural(self.losses.soft_wraps, "wrapped line", "wrapped lines")
            ));
        }
        if self.losses.truncated_rows > 0 {
            parts.push(format!(
                "{} the session had already shortened",
                plural(self.losses.truncated_rows, "row", "rows")
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

/// Renders a count with the right form of its noun.
fn plural(count: usize, one: &str, many: &str) -> String {
    if count == 1 {
        format!("{count} {one}")
    } else {
        format!("{count} {many}")
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
