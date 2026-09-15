//! Snapshots, deltas and side-effect-free restoration.
//!
//! A snapshot is presentation state, not a serialised process and not a parser checkpoint. It
//! carries everything a client needs to put a screen back exactly as it is, and nothing that would
//! make something happen a second time.
//!
//! That second half is the important one. A terminal's history is full of things that were events
//! when they happened: a bell, a clipboard write, a notification, a query. Replaying the bytes
//! would do all of them again, to whoever happens to be attached now. So restoration does not
//! replay bytes. It emits [`RestoreOp`], a closed set of rendering operations with no member that
//! can ring, copy, notify, download, launch or ask anything.

use crate::budget::GridSize;
use crate::error::{Result, TermError};
use crate::grid::{GridRow, Rendition};
use crate::modes::ModeKind;
use crate::palette::{PaletteSource, Rgb};
use crate::title::{SavedTitle, TitleEntry};

/// Which screen buffer is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveBuffer {
    /// The primary buffer, with scrollback.
    Primary,
    /// The alternate buffer, without scrollback.
    Alternate,
}

/// The cursor, as a snapshot carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorState {
    /// Zero-based column.
    pub col: u32,
    /// Zero-based row within the visible page.
    pub row: u32,
    /// Whether the cursor is shown.
    pub visible: bool,
    /// The DECSCUSR style number.
    pub style: u32,
    /// Whether the next printable character wraps before it is placed.
    ///
    /// The same coordinates mean different things with and without it, so a restoration that left
    /// it out would put the next character in the wrong cell.
    pub pending_wrap: bool,
}

/// A saved cursor, from DECSC or the alternate-buffer switch.
///
/// A saved cursor is more than a position. DECSC saves the graphic rendition, the character sets
/// and origin mode with it, and a restore that put back only the position would leave an
/// application drawing in the wrong colours from the wrong origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedCursor {
    /// Which buffer saved it.
    pub buffer: ActiveBuffer,
    /// Zero-based column.
    pub col: u32,
    /// Zero-based row.
    pub row: u32,
    /// Whether the saved cursor had a pending wrap.
    pub pending_wrap: bool,
    /// The graphic rendition that was saved with it.
    pub rendition: Rendition,
    /// The character sets that were saved with it.
    pub charsets: Charsets,
    /// Whether origin mode was set when it was saved.
    pub origin_mode: bool,
    /// The DECSCUSR style that was saved with it.
    pub style: u32,
    /// The hyperlink that was open when it was saved.
    ///
    /// A saved pen carries the open link with it, so text printed after a restore belongs to the
    /// link the application had open when it saved.
    pub hyperlink: Option<String>,
}

/// The keyboard negotiation a reconnecting client has to be put back into.
///
/// An input encoder that does not know which protocol is active sends bytes the application does
/// not accept, which is exactly the failure `input.acquire` exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyboardSnapshot {
    /// The `modifyOtherKeys` level.
    pub modify_other_keys: u8,
    /// The primary buffer's Kitty keyboard negotiation.
    pub primary: KittyKeyboard,
    /// The alternate buffer's Kitty keyboard negotiation.
    ///
    /// The protocol gives each screen its own stack, so a full-screen application's negotiation
    /// cannot leak into the shell's when it exits. A restored session needs both, or leaving the
    /// alternate buffer would leave it speaking the wrong protocol.
    pub alternate: KittyKeyboard,
}

/// One buffer's Kitty keyboard negotiation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KittyKeyboard {
    /// The active flags, when the protocol is in use.
    pub flags: Option<u8>,
    /// The flag stack, oldest first.
    pub stack: Vec<u8>,
}

/// The scroll region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Margins {
    /// Top row, zero-based and inclusive.
    pub top: u32,
    /// Bottom row, zero-based and inclusive.
    pub bottom: u32,
    /// Left column, zero-based and inclusive.
    pub left: u32,
    /// Right column, zero-based and inclusive.
    pub right: u32,
}

/// The designated character sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Charsets {
    /// The G0 designation.
    pub g0: String,
    /// The G1 designation.
    pub g1: String,
    /// Whether the shift-out set is active.
    pub shift_out: bool,
}

/// One tracked mode and its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeEntry {
    /// Which spelling.
    pub kind: ModeKind,
    /// The mode number.
    pub mode: u16,
    /// Whether it is set.
    pub enabled: bool,
}

/// A hyperlink over a range of cells.
///
/// It is inert metadata. Reconnection restores it so a later click still works; it never activates
/// anything by itself, and a scheme that would launch an external application needs the client's
/// own policy before anything happens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HyperlinkRange {
    /// The stable row identifier.
    pub row: i64,
    /// First column, zero-based.
    pub start_col: u32,
    /// One past the last column.
    pub end_col: u32,
    /// The target.
    pub uri: String,
}

/// The palette a snapshot carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaletteSnapshot {
    /// Where the palette came from.
    pub source: PaletteSource,
    /// The default foreground.
    pub foreground: Rgb,
    /// The default background.
    pub background: Rgb,
    /// The cursor colour.
    pub cursor: Rgb,
    /// The mouse pointer foreground.
    pub pointer_foreground: Rgb,
    /// The mouse pointer background.
    pub pointer_background: Rgb,
    /// The selection background.
    pub selection_background: Rgb,
    /// The selection foreground.
    pub selection_foreground: Rgb,
    /// The indexed colours that differ from the profile default, by index.
    pub overrides: Vec<(u8, Rgb)>,
}

/// The part of the canonical grid a client is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Viewport {
    /// Stable identifier of the first row shown.
    pub top_row: i64,
    /// Rows shown.
    pub rows: u32,
    /// First column shown, for a display narrower than the canonical grid.
    pub left_col: u32,
    /// Columns shown.
    pub cols: u32,
}

/// One snapshot of presentation state.
#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    /// Increments whenever the projection is reset, such as on a buffer switch.
    pub projection_generation: u64,
    /// The monotonic output cursor this snapshot describes.
    pub output_cursor: u64,
    /// Which buffer is active.
    pub active_buffer: ActiveBuffer,
    /// Canonical dimensions.
    pub dimensions: GridSize,
    /// The viewport this snapshot was taken for.
    pub viewport: Viewport,
    /// The cursor.
    pub cursor: CursorState,
    /// The saved cursor of each buffer, primary first.
    ///
    /// Each buffer has its own, because the switch into the alternate buffer saves one of its own.
    /// `None` for a buffer means nothing has been saved for it.
    pub saved_cursors: [Option<SavedCursor>; 2],
    /// The scroll region.
    pub margins: Margins,
    /// The current graphic rendition.
    pub rendition: Rendition,
    /// Columns carrying a tab stop.
    pub tab_stops: Vec<u32>,
    /// The designated character sets.
    pub charsets: Charsets,
    /// Every tracked mode.
    pub modes: Vec<ModeEntry>,
    /// Whether the keypad is in application mode.
    pub keypad_application: bool,
    /// The keyboard protocol an input encoder has to reproduce.
    pub keyboard: KeyboardSnapshot,
    /// The current titles.
    pub title: TitleEntry,
    /// The virtual title stack, oldest first.
    pub title_stack: Vec<SavedTitle>,
    /// Hyperlink ranges in the rows carried here.
    pub hyperlinks: Vec<HyperlinkRange>,
    /// The hyperlink the next character printed would belong to.
    ///
    /// An application can open a link and print nothing before a client reconnects, and the link
    /// belongs to what it prints next. Without this the reconnecting client would leave that text
    /// outside the link.
    pub hyperlink: Option<String>,
    /// The palette.
    pub palette: PaletteSnapshot,
    /// The rows of the active buffer, with stable identifiers and wrap markers.
    pub rows: Vec<GridRow>,
    /// The rows of the buffer that is not active.
    ///
    /// Section 8 requires restoration to reproduce both buffers, so a client that reconnects while
    /// a full-screen application is running still has what the shell left behind, and sees it
    /// again when the application exits.
    pub inactive_rows: Vec<GridRow>,
    /// The oldest row still retained anywhere.
    pub oldest_retained_row: i64,
    /// Whether rows have been evicted since the session started.
    pub evicted: bool,
}

/// An update against a known base cursor.
///
/// A delta that does not name the cursor the client holds is not applied. The client asks for a
/// fresh snapshot instead, which is cheaper than reasoning about what it might have missed.
#[derive(Debug, Clone, PartialEq)]
pub struct Delta {
    /// The cursor this delta continues from.
    pub base_cursor: u64,
    /// The cursor after it.
    pub next_cursor: u64,
    /// The projection generation it belongs to.
    pub projection_generation: u64,
    /// Rows that changed, with their stable identifiers.
    pub rows: Vec<GridRow>,
    /// The cursor after the update.
    pub cursor: CursorState,
    /// Modes that changed since the base.
    pub modes: Vec<ModeEntry>,
    /// The scroll region, when the presentation state changed since the base.
    pub margins: Option<Margins>,
    /// The current graphic rendition, when the presentation state changed since the base.
    pub rendition: Option<Rendition>,
    /// The tab stops, when the presentation state changed since the base.
    pub tab_stops: Option<Vec<u32>>,
    /// The designated character sets, when the presentation state changed since the base.
    pub charsets: Option<Charsets>,
    /// Hyperlink ranges in the rows carried here.
    pub hyperlinks: Vec<HyperlinkRange>,
    /// The titles, when they changed since the base.
    pub title: Option<TitleEntry>,
    /// The keyboard negotiation, when it changed since the base.
    pub keyboard: Option<KeyboardSnapshot>,
    /// The palette, when it changed since the base.
    pub palette: Option<PaletteSnapshot>,
    /// The canonical dimensions, when they changed since the base.
    pub dimensions: Option<GridSize>,
    /// The virtual title stack, when the titles changed since the base.
    pub title_stack: Option<Vec<SavedTitle>>,
    /// The saved cursor of each buffer, when one was saved or restored since the base.
    ///
    /// A save changes what a later restore will do, and two sessions whose saved pens differ are
    /// two different sessions. `None` for a buffer means nothing is saved for it.
    pub saved_cursors: Option<[Option<SavedCursor>; 2]>,
    /// The hyperlink the next character would be part of, when the presentation state changed.
    ///
    /// `Some(None)` is an open link that closed. Without this a reconnecting client cannot put the
    /// next live character inside the link the application opened before it arrived.
    pub hyperlink: Option<Option<String>>,
}

impl Delta {
    /// Checks that this delta continues from `held`.
    ///
    /// # Errors
    ///
    /// Returns [`TermError::CursorGap`] when it does not, which the caller answers with a fresh
    /// snapshot.
    pub const fn check_base(&self, held: u64, generation: u64) -> Result<()> {
        // The generation is part of the base. A projection reset can happen without a byte
        // arriving, so the same cursor can name two different screens.
        if self.base_cursor == held && self.projection_generation == generation {
            return Ok(());
        }
        Err(TermError::CursorGap {
            requested: held,
            available: self.base_cursor,
        })
    }
}

/// A page of history rows.
#[derive(Debug, Clone, PartialEq)]
pub struct HistoryPage {
    /// The rows.
    pub rows: Vec<GridRow>,
    /// The oldest row still retained.
    pub oldest_retained_row: i64,
    /// Whether rows below `oldest_retained_row` have been evicted.
    pub evicted: bool,
    /// Whether more rows follow this page.
    pub more: bool,
}

/// One rendering operation a restoration may emit.
///
/// The set is closed on purpose. There is no variant that rings a bell, writes a clipboard, raises
/// a notification, asks a question, starts a download or launches anything, so a restoration cannot
/// do any of those however the history was built.
#[derive(Debug, Clone, PartialEq)]
pub enum RestoreOp {
    /// Discard whatever the client was showing and start again.
    ResetProjection {
        /// The generation the client is now on.
        generation: u64,
    },
    /// Set the canonical dimensions.
    SetDimensions {
        /// The dimensions.
        size: GridSize,
    },
    /// Select the active buffer.
    SelectBuffer {
        /// Which buffer.
        buffer: ActiveBuffer,
    },
    /// Set the palette.
    SetPalette {
        /// The palette.
        palette: PaletteSnapshot,
    },
    /// Set a tracked mode.
    SetMode {
        /// The mode.
        entry: ModeEntry,
    },
    /// Set the keypad mode.
    SetKeypad {
        /// Whether application mode is on.
        application: bool,
    },
    /// Set the keyboard protocol an input encoder must produce.
    SetKeyboard {
        /// The negotiated state.
        keyboard: KeyboardSnapshot,
    },
    /// Set the tab stops.
    SetTabStops {
        /// Columns carrying a stop.
        columns: Vec<u32>,
    },
    /// Set the designated character sets.
    SetCharsets {
        /// The designations.
        charsets: Charsets,
    },
    /// Set the scroll region.
    SetMargins {
        /// The region.
        margins: Margins,
    },
    /// Paint one row.
    PaintRow {
        /// The row.
        row: GridRow,
    },
    /// Record a hyperlink range as inert metadata.
    RecordHyperlink {
        /// The range.
        range: HyperlinkRange,
    },
    /// Set the current graphic rendition.
    SetRendition {
        /// The rendition.
        rendition: Rendition,
    },
    /// Place the cursor.
    SetCursor {
        /// The cursor.
        cursor: CursorState,
    },
    /// Restore a saved cursor.
    SetSavedCursor {
        /// The saved cursor.
        cursor: SavedCursor,
    },
    /// Set the titles and the virtual stack.
    /// Opens the hyperlink the next character belongs to, or closes the open one.
    SetHyperlink {
        /// The target, or nothing when no link is open.
        uri: Option<String>,
    },
    /// Paints a row of the buffer that is not active.
    PaintInactiveRow {
        /// The row.
        row: GridRow,
    },
    /// Restores the titles and the virtual title stack.
    SetTitle {
        /// The current titles.
        title: TitleEntry,
        /// The stack, oldest first.
        stack: Vec<SavedTitle>,
    },
}

/// Builds the rendering operations that restore `snapshot`.
///
/// Mode and buffer state come before the rows, because a client that painted first and switched
/// buffers afterwards would show the repaint in the wrong place. The cursor comes last, so the
/// screen is never left mid-repaint with a live cursor on it.
#[must_use]
pub fn restoration_operations(snapshot: &Snapshot) -> Vec<RestoreOp> {
    let mut ops = vec![
        RestoreOp::ResetProjection {
            generation: snapshot.projection_generation,
        },
        RestoreOp::SetDimensions {
            size: snapshot.dimensions,
        },
        RestoreOp::SelectBuffer {
            buffer: snapshot.active_buffer,
        },
        RestoreOp::SetPalette {
            palette: snapshot.palette.clone(),
        },
    ];
    for entry in &snapshot.modes {
        ops.push(RestoreOp::SetMode { entry: *entry });
    }
    ops.push(RestoreOp::SetKeypad {
        application: snapshot.keypad_application,
    });
    ops.push(RestoreOp::SetKeyboard {
        keyboard: snapshot.keyboard.clone(),
    });
    ops.push(RestoreOp::SetTabStops {
        columns: snapshot.tab_stops.clone(),
    });
    ops.push(RestoreOp::SetCharsets {
        charsets: snapshot.charsets.clone(),
    });
    ops.push(RestoreOp::SetMargins {
        margins: snapshot.margins,
    });
    // The buffer that is not showing is painted first, so that leaving the active buffer later
    // finds it as it was.
    for row in &snapshot.inactive_rows {
        ops.push(RestoreOp::PaintInactiveRow { row: row.clone() });
    }
    for row in &snapshot.rows {
        ops.push(RestoreOp::PaintRow { row: row.clone() });
    }
    for range in &snapshot.hyperlinks {
        ops.push(RestoreOp::RecordHyperlink {
            range: range.clone(),
        });
    }
    ops.push(RestoreOp::SetTitle {
        title: snapshot.title.clone(),
        stack: snapshot.title_stack.clone(),
    });
    ops.push(RestoreOp::SetRendition {
        rendition: snapshot.rendition,
    });
    ops.push(RestoreOp::SetHyperlink {
        uri: snapshot.hyperlink.clone(),
    });
    for cursor in snapshot.saved_cursors.iter().flatten() {
        ops.push(RestoreOp::SetSavedCursor {
            cursor: cursor.clone(),
        });
    }
    ops.push(RestoreOp::SetCursor {
        cursor: snapshot.cursor,
    });
    ops
}

/// The rule for entering live byte forwarding.
///
/// Forwarding may only start where the parser stands on ground, because starting anywhere else
/// would send a physical terminal the middle of an escape sequence. Output does not stop for the
/// handoff, so the attachment waits, and if 250 ms pass without a boundary it stays in projected
/// mode and tries again later. Waiting longer would not make the stream safer; it would only delay
/// showing the person their screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveForwardingHandoff {
    started_ms: u64,
    deadline_ms: u64,
}

/// How long a handoff waits for a parser-ground boundary.
pub const HANDOFF_WINDOW_MS: u64 = 250;

/// What a handoff decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffOutcome {
    /// No boundary yet; keep waiting.
    Waiting,
    /// A boundary arrived. Forwarding may start at this output cursor.
    Ready {
        /// The boundary.
        cursor: u64,
    },
    /// The window passed without a boundary. Stay in projected mode.
    StayProjected,
}

impl LiveForwardingHandoff {
    /// Starts a handoff at `now_ms`.
    #[must_use]
    pub const fn start(now_ms: u64) -> Self {
        Self {
            started_ms: now_ms,
            deadline_ms: now_ms + HANDOFF_WINDOW_MS,
        }
    }

    /// When the handoff started.
    #[must_use]
    pub const fn started_ms(&self) -> u64 {
        self.started_ms
    }

    /// Decides what to do at `now_ms`, given the parser's state.
    ///
    /// `boundary` is the output cursor of the most recent parser-ground boundary, when the parser
    /// is standing on one right now.
    #[must_use]
    pub const fn poll(&self, now_ms: u64, boundary: Option<u64>) -> HandoffOutcome {
        if let Some(cursor) = boundary {
            return HandoffOutcome::Ready { cursor };
        }
        if now_ms >= self.deadline_ms {
            return HandoffOutcome::StayProjected;
        }
        HandoffOutcome::Waiting
    }
}
