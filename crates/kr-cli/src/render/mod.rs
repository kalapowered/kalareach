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
use kr_protocol::projection::ProjectionEvent;

pub use kr_client::projection::{decode, is_projection_event};

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
    /// A terminal showing nothing yet, whose keyboard protocols may both be installed.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keyboard: Keyboard::EVERYTHING,
            ..Self::default()
        }
    }

    /// A terminal whose keyboard protocols are not this attachment's to change at all.
    ///
    /// What `--no-probe` on a terminal the host will not let type chooses: nobody was allowed to
    /// ask this terminal what it had negotiated, and nobody is going to type into it either, so
    /// nothing installs a protocol that nothing could put back and nothing would use.
    #[must_use]
    pub fn without_the_keyboard() -> Self {
        Self {
            keyboard: Keyboard::NOTHING,
            ..Self::default()
        }
    }

    /// A terminal showing nothing yet, with each keyboard protocol decided on its own terms.
    ///
    /// `level` is whether the person at this terminal can type, because the `modifyOtherKeys` level
    /// is the encoding the host advertises for them and `CSI > 4 m` puts any terminal back to its
    /// own. `flags` is whether this terminal reported its Kitty flags, because nothing else could
    /// put those back.
    #[must_use]
    pub fn with_keyboard(level: bool, flags: bool) -> Self {
        Self {
            keyboard: Keyboard { level, flags },
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

    /// Whether the buffer this terminal is showing is the one with a history above it.
    ///
    /// The shell's buffer keeps a scrollback; a full-screen application's does not, and its keys
    /// are its own. A terminal holding no screen at all answers true, because the session it is
    /// about to be shown starts on the shell's buffer.
    #[must_use]
    pub fn showing_history_buffer(&self) -> bool {
        self.projection.screen().is_none_or(|screen| {
            screen.active_buffer == kr_protocol::projection::ProjectedBuffer::Primary
        })
    }

    /// The stable row the window this terminal is showing starts at.
    ///
    /// `None` until a whole screen has arrived. It is where the window actually is, which is not
    /// always where this terminal last asked for: the session gives up its oldest rows, and a
    /// window that was over them is moved to the oldest ones that survive.
    #[must_use]
    pub fn window_top_row(&self) -> Option<u64> {
        self.projection
            .screen()
            .map(|screen| screen.viewport.top_row.get())
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
        report(self.losses, self.session_degraded())
    }
}

/// What an attachment could not establish about the terminal it borrowed.
///
/// Two things are read rather than assumed, and each can come back unread: the modes this
/// attachment changes and then owes back, and whether the destination measures a character the way
/// the session does. Neither stops an attachment - every mode has a documented default, and a
/// projection addresses every cluster absolutely - but each is a smaller promise than the one a
/// qualified terminal gets, and a person is told which promise was made rather than left to assume
/// the larger one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Qualification {
    /// The modes nothing could be read for, which are the ones a detach puts back to their default.
    pub defaulted_modes: Vec<kr_term::probe::SavedMode>,
    /// The declared identity of a destination that is not qualified for the session's width model.
    ///
    /// `None` for a qualified destination, and for an attachment that drew no projection: where the
    /// width model decides anything is where a projected renderer puts each cluster.
    pub width_unqualified: Option<String>,
}

impl Qualification {
    /// The sentence a person is shown, or `None` when everything was established.
    #[must_use]
    pub fn report(&self) -> Option<String> {
        let mut parts = Vec::new();
        if !self.defaulted_modes.is_empty() {
            let named: Vec<String> = self
                .defaulted_modes
                .iter()
                .map(|mode| format!("{} (mode {})", mode.description(), mode.number()))
                .collect();
            let (subject, verb) = if named.len() == 1 {
                ("", "was")
            } else {
                ("each of ", "were")
            };
            parts.push(format!(
                "{subject}{} {verb} put back to the documented default rather than to the value \
                 this terminal had, because it never reported one",
                named.join(", ")
            ));
        }
        if let Some(identity) = &self.width_unqualified {
            parts.push(format!(
                "it calls itself {identity}, which is not qualified for the character widths this \
                 session measures with, so a character it draws wider than the session does can \
                 cover the blank cell beside it, and every cluster after that one still lands on \
                 the column the session holds it at"
            ));
        }
        if parts.is_empty() {
            return None;
        }
        Some(parts.join("; "))
    }
}

/// The sentence one comparison deserves, if any.
///
/// Every field of a comparison has a phrase here. A comparison that is not complete and produces
/// no phrase would print an empty report, which tells a person that something is wrong and not
/// what, so the mapping is total by construction and checked by a test that walks it.
fn report(losses: Comparison, degraded: bool) -> Option<String> {
    {
        if losses.complete() && !degraded {
            return None;
        }
        let mut parts = Vec::new();
        if degraded {
            // The session's own answer, not this terminal's: content it had to shorten to stay
            // inside a resident-state bound is content no window size can show.
            parts.push("content the session shortened to stay inside its own bounds".to_owned());
        }
        if losses.cells_clipped > 0 {
            let cells = usize::try_from(losses.cells_clipped).unwrap_or(usize::MAX);
            parts.push(format!(
                "{} outside this window",
                plural(cells, "cell", "cells")
            ));
        }
        if losses.clusters_replaced > 0 {
            parts.push(format!(
                "{} the window's edge fell inside",
                plural(losses.clusters_replaced, "character", "characters")
            ));
        }
        if losses.runs_replaced > 0 {
            parts.push(format!(
                "{} this terminal cannot place",
                plural(losses.runs_replaced, "run", "runs")
            ));
        }
        if losses.rows_outside > 0 {
            parts.push(format!(
                "{} of the session's rows outside this window, holding {}",
                losses.rows_outside,
                plural(
                    usize::try_from(losses.cells_outside).unwrap_or(usize::MAX),
                    "cell",
                    "cells"
                )
            ));
        }
        if losses.keyboard_withheld {
            parts.push(
                "the session's keyboard protocols, which this terminal was never asked about"
                    .to_owned(),
            );
        }
        if losses.keyboard_stack > 0 {
            parts.push(format!(
                "{} the session holds, installed as a state rather than a stack",
                plural(losses.keyboard_stack, "keyboard entry", "keyboard entries")
            ));
        }
        if losses.controls_dropped > 0 {
            parts.push(format!(
                "{} whose control bytes were dropped",
                plural(losses.controls_dropped, "title or link", "titles or links")
            ));
        }
        if losses.soft_wraps > 0 {
            parts.push(format!(
                "{} drawn as separate rows",
                plural(losses.soft_wraps, "wrapped line", "wrapped lines")
            ));
        }
        if losses.truncated_rows > 0 {
            parts.push(format!(
                "{} the session had already shortened",
                plural(losses.truncated_rows, "row", "rows")
            ));
        }
        if losses.pending_wrap {
            parts.push("a pending wrap".to_owned());
        }
        if losses.cursor_outside {
            parts.push("the cursor outside this window".to_owned());
        }
        if losses.rows_unreachable > 0 {
            parts.push(format!(
                "{} of the session this window is too short to show",
                plural(losses.rows_unreachable, "row", "rows")
            ));
        }
        if losses.geometry_withheld {
            // A margin is a row and a column of the canonical grid, so a window showing part of
            // the grid has nowhere to put one. Everything drawn here is addressed absolutely and
            // is unaffected; what is affected is an application that writes to this terminal
            // itself, which is why it is reported rather than passed over.
            parts
                .push("the session's own scroll region, which this window cannot carry".to_owned());
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

#[cfg(test)]
mod tests {
    use super::*;

    /// One named loss, and the one field of a comparison that holds it.
    type Loss = (&'static str, fn(&mut Comparison));

    /// KR-REQ-08.40 and KR-ACC-023: a destination outside the session's width model is named.
    ///
    /// Section 8 pins the width table as a release-profile decision rather than something inferred
    /// from a name, so a destination this build has not measured is not qualified for it however it
    /// calls itself. Nothing is refused over that - every cluster is addressed absolutely, which is
    /// what keeps a disagreement to that cluster's own cell - but the person drawing a session onto
    /// it is told which of the two they have.
    #[test]
    fn a_destination_outside_the_width_model_is_named_in_the_report() {
        assert_eq!(
            Qualification::default().report(),
            None,
            "a terminal that answered everything, drawing nothing, has nothing to report"
        );
        let unqualified = Qualification {
            defaulted_modes: Vec::new(),
            width_unqualified: Some("xterm-256color".to_owned()),
        };
        let sentence = unqualified
            .report()
            .expect("an unqualified destination is reported");
        assert!(
            sentence.contains("xterm-256color"),
            "the report names the destination as it declared itself: {sentence}"
        );
        assert!(
            !kr_term::profile::width_qualified("xterm-256color"),
            "and a terminfo name is not a width table: nothing is qualified by calling itself one"
        );

        // Both facts in one sentence, because they are two halves of the same promise.
        let both = Qualification {
            defaulted_modes: vec![kr_term::probe::SavedMode::MouseClicks],
            width_unqualified: Some("xterm-256color".to_owned()),
        };
        let sentence = both.report().expect("both are reported");
        assert!(
            sentence.contains("mode 1000") && sentence.contains("xterm-256color"),
            "each is named: {sentence}"
        );
    }

    /// KR-ACC-023: a projection that could not carry something says what, in words, always.
    #[test]
    fn every_loss_a_comparison_can_hold_has_a_phrase() {
        assert_eq!(
            report(Comparison::default(), false),
            None,
            "a frame that carried everything says nothing"
        );
        assert_eq!(
            report(Comparison::default(), true).as_deref(),
            Some("content the session shortened to stay inside its own bounds"),
            "and the session's own shortening is this terminal's to report"
        );
        // One field at a time, because the interesting failure is a field nothing describes: the
        // report would be an empty sentence, which says that something is wrong and not what.
        let each: [Loss; 11] = [
            ("cells_clipped", |losses| losses.cells_clipped = 3),
            ("clusters_replaced", |losses| losses.clusters_replaced = 1),
            ("runs_replaced", |losses| losses.runs_replaced = 2),
            ("rows_outside", |losses| losses.rows_outside = 4),
            ("soft_wraps", |losses| losses.soft_wraps = 1),
            ("truncated_rows", |losses| losses.truncated_rows = 1),
            ("pending_wrap", |losses| losses.pending_wrap = true),
            ("cursor_outside", |losses| losses.cursor_outside = true),
            ("keyboard_withheld", |losses| {
                losses.keyboard_withheld = true;
            }),
            ("geometry_withheld", |losses| {
                losses.geometry_withheld = true;
            }),
            ("rows_unreachable", |losses| losses.rows_unreachable = 26),
        ];
        for (name, set) in each {
            let mut losses = Comparison::default();
            set(&mut losses);
            assert!(!losses.complete(), "{name} is a loss");
            let sentence = report(losses, false)
                .unwrap_or_else(|| panic!("{name} is reported rather than passed over"));
            assert!(!sentence.trim().is_empty(), "{name} has words of its own");
        }
        // Two fields are counts of something else's loss rather than losses of their own: a row is
        // only clipped when cells of it were, and a cell is only outside when its row is. They
        // travel with the field that reports them, so neither makes a frame incomplete by itself.
        let derived: [Loss; 2] = [
            ("rows_clipped", |losses| losses.rows_clipped = 1),
            ("cells_outside", |losses| losses.cells_outside = 40),
        ];
        for (name, set) in derived {
            let mut losses = Comparison::default();
            set(&mut losses);
            assert!(
                losses.complete(),
                "{name} counts another field's loss and reports nothing alone"
            );
        }
    }
}
