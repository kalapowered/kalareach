//! The viewport a client of another size looks through, and the switch between presentations.
//!
//! Section 8: a terminal the same size as the session can take its byte stream unchanged; any
//! other size is shown a clipped viewport of the canonical grid. Nothing is reflowed, so a smaller
//! display pans over the grid and a larger one leaves the unused area blank. That is a secondary
//! presentation, not a claim of byte-identical display at every size.
//!
//! Three rules hang off it, and each one is a mistake somebody would otherwise make:
//!
//! * **Pointer input is mapped before it is encoded.** The application addresses canonical cells,
//!   so a click at the top left of a panned window is not a click at the top left of the grid.
//!   Input outside the visible grid has no application effect at all.
//! * **Panning is a view-mode gesture.** In follow mode the wheel belongs to the application, which
//!   is what makes scrollback work inside a full-screen program. A client that panned on every
//!   wheel event would take the wheel away from everything running in the session.
//! * **A presentation change installs a snapshot at a cursor.** The client must not mix live output
//!   with an incomplete repaint, so what arrives while the repaint is being installed waits and is
//!   applied from that same cursor afterwards.
//!
//! Taking the keyboard is not in that list, deliberately. The input lease and the size are separate
//! ownerships: [`Display::took_the_keyboard`] records one and touches nothing about the other.

/// How a client is being shown the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presentation {
    /// The client's own size matches the canonical grid and it receives the filtered byte stream.
    Direct,
    /// The client displays a clipped viewport of the canonical grid.
    Viewport,
}

/// Whether the viewport follows the session or the person is panning it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PanMode {
    /// The window follows the cursor and the wheel belongs to the application.
    #[default]
    Follow,
    /// The person is panning the grid, and the pan controls apply.
    View,
}

/// A window onto the canonical grid.
///
/// Every measurement is in cells. The origin is the canonical cell drawn at the top left of the
/// window, so a window the size of the grid has an origin of zero and nothing to pan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Viewport {
    canonical_columns: u32,
    canonical_rows: u32,
    columns: u32,
    rows: u32,
    origin_column: u32,
    origin_row: u32,
}

impl Viewport {
    /// Builds a window of `columns` by `rows` onto a canonical grid of `canonical`.
    ///
    /// A zero in any dimension is raised to one: a window with no cells cannot be mapped into and
    /// every caller would then have to handle a case that means nothing.
    #[must_use]
    pub const fn new(canonical: (u32, u32), window: (u32, u32)) -> Self {
        Self {
            canonical_columns: if canonical.0 == 0 { 1 } else { canonical.0 },
            canonical_rows: if canonical.1 == 0 { 1 } else { canonical.1 },
            columns: if window.0 == 0 { 1 } else { window.0 },
            rows: if window.1 == 0 { 1 } else { window.1 },
            origin_column: 0,
            origin_row: 0,
        }
    }

    /// Returns the canonical grid's size.
    #[must_use]
    pub const fn canonical(self) -> (u32, u32) {
        (self.canonical_columns, self.canonical_rows)
    }

    /// Returns the window's own size.
    #[must_use]
    pub const fn window(self) -> (u32, u32) {
        (self.columns, self.rows)
    }

    /// Returns the canonical cell drawn at the window's top left.
    #[must_use]
    pub const fn origin(self) -> (u32, u32) {
        (self.origin_column, self.origin_row)
    }

    /// Returns how this client is shown the session at this size.
    ///
    /// Equal size is the only case that can take the byte stream, because wrapping and cursor
    /// coordinates depend on the column count. The host decides it too, and for the same reason;
    /// this is the client's own answer to the same question, which is what lets it know what it is
    /// about to be sent.
    #[must_use]
    pub const fn presentation(self) -> Presentation {
        if self.columns == self.canonical_columns && self.rows == self.canonical_rows {
            Presentation::Direct
        } else {
            Presentation::Viewport
        }
    }

    /// Returns how far the window can be panned in each direction.
    #[must_use]
    pub const fn pannable(self) -> (u32, u32) {
        (
            self.canonical_columns.saturating_sub(self.columns),
            self.canonical_rows.saturating_sub(self.rows),
        )
    }

    /// Maps a position in the window onto the canonical cell it is drawn from.
    ///
    /// `None` is a position with no canonical cell under it: outside the window, or inside a window
    /// larger than the grid, where the unused area is blank. Section 8: input outside the visible
    /// grid has no application effect, so `None` means send nothing rather than send something
    /// approximate.
    #[must_use]
    pub const fn map(self, column: u32, row: u32) -> Option<(u32, u32)> {
        if column >= self.columns || row >= self.rows {
            return None;
        }
        let canonical_column = self.origin_column + column;
        let canonical_row = self.origin_row + row;
        if canonical_column >= self.canonical_columns || canonical_row >= self.canonical_rows {
            // A window larger than the grid leaves the extra area blank. A click there is on
            // nothing.
            return None;
        }
        Some((canonical_column, canonical_row))
    }

    /// Follows the canonical grid to a new size.
    ///
    /// The origin is clamped, because a grid that shrank can leave the window looking past its
    /// right-hand edge, and a window showing blank columns it could fill is worse than one that
    /// moved.
    pub const fn canonical_resized(&mut self, canonical: (u32, u32)) {
        self.canonical_columns = if canonical.0 == 0 { 1 } else { canonical.0 };
        self.canonical_rows = if canonical.1 == 0 { 1 } else { canonical.1 };
        self.clamp();
    }

    /// Records that the client's own window changed size.
    pub const fn window_resized(&mut self, window: (u32, u32)) {
        self.columns = if window.0 == 0 { 1 } else { window.0 };
        self.rows = if window.1 == 0 { 1 } else { window.1 };
        self.clamp();
    }

    /// Moves the window by `columns` and `rows`, clamped to the grid.
    ///
    /// Returns whether the origin moved.
    pub const fn pan(&mut self, columns: i64, rows: i64) -> bool {
        let before = (self.origin_column, self.origin_row);
        self.origin_column = shift(self.origin_column, columns);
        self.origin_row = shift(self.origin_row, rows);
        self.clamp();
        before.0 != self.origin_column || before.1 != self.origin_row
    }

    /// Moves the window so that a canonical cell is inside it.
    ///
    /// This is what follow mode does with the application's cursor: the window moves the least it
    /// can to keep the cell visible, because a window that jumped to centre the cursor on every
    /// keystroke is unreadable.
    ///
    /// Returns whether the origin moved.
    pub const fn reveal(&mut self, column: u32, row: u32) -> bool {
        let before = (self.origin_column, self.origin_row);
        if column < self.origin_column {
            self.origin_column = column;
        } else if column >= self.origin_column + self.columns {
            self.origin_column = column + 1 - self.columns;
        }
        if row < self.origin_row {
            self.origin_row = row;
        } else if row >= self.origin_row + self.rows {
            self.origin_row = row + 1 - self.rows;
        }
        self.clamp();
        before.0 != self.origin_column || before.1 != self.origin_row
    }

    const fn clamp(&mut self) {
        let (columns, rows) = self.pannable();
        if self.origin_column > columns {
            self.origin_column = columns;
        }
        if self.origin_row > rows {
            self.origin_row = rows;
        }
    }
}

const fn shift(value: u32, delta: i64) -> u32 {
    let moved = value as i64 + delta;
    if moved < 0 {
        0
    } else if moved > u32::MAX as i64 {
        u32::MAX
    } else {
        moved as u32
    }
}

/// What a client does with one pointer event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PointerOutcome {
    /// Send it to the application, at this canonical cell.
    Application {
        /// The canonical column.
        column: u32,
        /// The canonical row.
        row: u32,
    },
    /// Pan the view by this much. Only view mode produces it.
    Pan {
        /// Columns to move by.
        columns: i64,
        /// Rows to move by.
        rows: i64,
    },
    /// Do nothing: the position has no canonical cell under it.
    Nothing,
}

/// One client's display of a session.
///
/// It owns the viewport, the pan mode and the one piece of state a presentation change needs: what
/// is waiting to be applied while a repaint is being installed.
#[derive(Clone, Debug)]
pub struct Display {
    viewport: Viewport,
    mode: PanMode,
    /// The cursor the installed state describes. Everything after it has been applied.
    cursor: u64,
    switching: Option<Switch>,
}

/// A presentation change in progress.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Switch {
    /// What the client will be when the snapshot is installed.
    into: Presentation,
    /// Live output that arrived while the snapshot was being fetched, in arrival order.
    held: Vec<(u64, Vec<u8>)>,
}

impl Display {
    /// Builds a display of `canonical` in a window of `window`, at output cursor `cursor`.
    #[must_use]
    pub const fn new(canonical: (u32, u32), window: (u32, u32), cursor: u64) -> Self {
        Self {
            viewport: Viewport::new(canonical, window),
            mode: PanMode::Follow,
            cursor,
            switching: None,
        }
    }

    /// Returns the viewport.
    #[must_use]
    pub const fn viewport(&self) -> Viewport {
        self.viewport
    }

    /// Returns the pan mode.
    #[must_use]
    pub const fn mode(&self) -> PanMode {
        self.mode
    }

    /// Returns the cursor the installed state describes.
    #[must_use]
    pub const fn cursor(&self) -> u64 {
        self.cursor
    }

    /// Returns how the client is currently being shown the session.
    #[must_use]
    pub const fn presentation(&self) -> Presentation {
        self.viewport.presentation()
    }

    /// Enters or leaves view mode.
    ///
    /// Leaving it puts the wheel back where it belongs, so the window follows again from wherever
    /// the person left it until the next thing it has to reveal.
    pub const fn set_mode(&mut self, mode: PanMode) {
        self.mode = mode;
    }

    /// Records that this client took the input lease.
    ///
    /// It returns the viewport, unchanged, because that is the whole content of the rule: section 8
    /// separates the two ownerships, and keyboard takeover does not also transfer geometry. Nothing
    /// here asks for a resize, and nothing here moves the window.
    pub const fn took_the_keyboard(&mut self) -> Viewport {
        self.viewport
    }

    /// Decides what one pointer event does.
    ///
    /// In follow mode every event is the application's, wheel included: that is what keeps
    /// scrollback working inside a full-screen program. In view mode the wheel pans and the rest
    /// still reaches the application at the cell it was mapped to.
    #[must_use]
    pub const fn pointer(&self, column: u32, row: u32, wheel: Option<i64>) -> PointerOutcome {
        if let Some(rows) = wheel
            && matches!(self.mode, PanMode::View)
        {
            return PointerOutcome::Pan { columns: 0, rows };
        }
        match self.viewport.map(column, row) {
            Some((column, row)) => PointerOutcome::Application { column, row },
            None => PointerOutcome::Nothing,
        }
    }

    /// Begins a change of presentation, and returns the cursor to take the snapshot at.
    ///
    /// From here until [`Display::install`] the display is painting: it has state that describes
    /// one cursor and is about to be given state that describes another, and drawing live output
    /// over a repaint that is not finished is the mixed display section 8 forbids. Output that
    /// arrives meanwhile is handed to [`Display::hold`] and applied afterwards.
    pub fn begin_switch(&mut self, into: Presentation) -> u64 {
        self.switching = Some(Switch {
            into,
            held: Vec::new(),
        });
        self.cursor
    }

    /// Returns true while a repaint is being installed.
    #[must_use]
    pub const fn is_painting(&self) -> bool {
        self.switching.is_some()
    }

    /// Takes one batch of live output.
    ///
    /// While the display is painting it is held; otherwise it is applied at once and the cursor
    /// moves past it. The return value is what the client draws now, which is nothing at all
    /// during a repaint.
    pub fn hold(&mut self, cursor: u64, bytes: Vec<u8>) -> Option<Vec<u8>> {
        match self.switching.as_mut() {
            Some(switch) => {
                switch.held.push((cursor, bytes));
                None
            }
            None => {
                self.cursor = cursor + bytes.len() as u64;
                Some(bytes)
            }
        }
    }

    /// Installs the snapshot the switch was waiting for, and returns what to draw after it.
    ///
    /// `at` is the cursor the snapshot describes, which is the one [`Display::begin_switch`]
    /// returned. Held output from before that cursor is discarded, because the snapshot already
    /// contains it; everything from it onwards is replayed in order, so the client resumes exactly
    /// where the installed state ends.
    ///
    /// # Errors
    ///
    /// Returns [`NotSwitching`] when no presentation change is in progress, because applying a
    /// snapshot nobody asked for would replace live state with older state.
    pub fn install(&mut self, at: u64, window: (u32, u32)) -> Result<Vec<Vec<u8>>, NotSwitching> {
        let switch = self.switching.take().ok_or(NotSwitching)?;
        self.viewport.window_resized(window);
        let _ = switch.into;
        self.cursor = at;
        let mut resumed = Vec::new();
        for (cursor, bytes) in switch.held {
            let end = cursor + bytes.len() as u64;
            if end <= at {
                // The snapshot was taken after these bytes, so it already describes them.
                continue;
            }
            let skip = usize::try_from(at.saturating_sub(cursor))
                .unwrap_or(bytes.len())
                .min(bytes.len());
            self.cursor = end;
            resumed.push(bytes[skip..].to_vec());
        }
        Ok(resumed)
    }

    /// Abandons a switch, keeping whatever was held so nothing is lost.
    ///
    /// A switch that cannot be completed - the snapshot never arrived, the connection went - has to
    /// leave the display drawing again rather than painting for ever.
    pub fn abandon_switch(&mut self) -> Vec<Vec<u8>> {
        let Some(switch) = self.switching.take() else {
            return Vec::new();
        };
        let mut resumed = Vec::new();
        for (cursor, bytes) in switch.held {
            self.cursor = cursor + bytes.len() as u64;
            resumed.push(bytes);
        }
        resumed
    }
}

/// Returned when a snapshot is installed with no presentation change in progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotSwitching;

impl std::fmt::Display for NotSwitching {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("this display is not changing presentation, so it installs no snapshot")
    }
}

impl std::error::Error for NotSwitching {}

#[cfg(test)]
mod tests {
    use super::*;

    /// KR-REQ-08.75, KR-REQ-08.76: equal size takes the stream; any other size is a window.
    #[test]
    fn only_a_window_the_size_of_the_grid_can_take_the_byte_stream() {
        assert_eq!(
            Viewport::new((80, 24), (80, 24)).presentation(),
            Presentation::Direct
        );
        for window in [(79, 24), (80, 23), (100, 30), (40, 12)] {
            assert_eq!(
                Viewport::new((80, 24), window).presentation(),
                Presentation::Viewport,
                "{window:?}"
            );
        }
    }

    /// KR-REQ-08.76: display coordinates are mapped to canonical cells before anything is encoded.
    #[test]
    fn a_pointer_position_is_mapped_onto_the_canonical_cell_it_is_drawn_from() {
        let mut viewport = Viewport::new((80, 24), (40, 12));
        assert_eq!(viewport.map(0, 0), Some((0, 0)));
        assert_eq!(viewport.map(39, 11), Some((39, 11)));
        // Panned, the same display position is a different canonical cell. A client that skipped
        // this would click on the wrong cell in every panned window.
        assert!(viewport.pan(20, 6));
        assert_eq!(viewport.origin(), (20, 6));
        assert_eq!(viewport.map(0, 0), Some((20, 6)));
        assert_eq!(viewport.map(39, 11), Some((59, 17)));
    }

    /// KR-REQ-08.76: input outside the visible grid has no application effect.
    #[test]
    fn a_position_with_no_canonical_cell_under_it_produces_nothing() {
        let viewport = Viewport::new((80, 24), (40, 12));
        assert_eq!(viewport.map(40, 0), None, "past the right of the window");
        assert_eq!(viewport.map(0, 12), None, "below it");
        // A window larger than the grid leaves the extra area blank, and a click there is on
        // nothing rather than on the nearest cell.
        let larger = Viewport::new((40, 12), (80, 24));
        assert_eq!(larger.map(39, 11), Some((39, 11)));
        assert_eq!(larger.map(40, 0), None);
        assert_eq!(larger.map(0, 12), None);
        assert_eq!(
            larger.pannable(),
            (0, 0),
            "and there is nothing to pan towards"
        );
    }

    /// KR-REQ-08.76: panning is clamped to the grid.
    #[test]
    fn panning_stops_at_the_edges_of_the_grid() {
        let mut viewport = Viewport::new((80, 24), (40, 12));
        assert_eq!(viewport.pannable(), (40, 12));
        assert!(viewport.pan(1_000, 1_000));
        assert_eq!(viewport.origin(), (40, 12), "clamped to the far edge");
        assert!(!viewport.pan(1_000, 1_000), "and it stays there");
        assert!(viewport.pan(-1_000, -1_000));
        assert_eq!(viewport.origin(), (0, 0));
        assert!(!viewport.pan(-5, -5));
    }

    /// KR-REQ-08.76: pan controls apply only in view mode, so the wheel stays the application's.
    #[test]
    fn the_wheel_belongs_to_the_application_until_the_person_enters_view_mode() {
        let mut display = Display::new((80, 24), (40, 12), 0);
        assert_eq!(display.mode(), PanMode::Follow);
        assert_eq!(
            display.pointer(3, 4, Some(-3)),
            PointerOutcome::Application { column: 3, row: 4 },
            "in follow mode a wheel event is the application's, which is what makes scrollback \
             work inside a full-screen program"
        );
        display.set_mode(PanMode::View);
        assert_eq!(
            display.pointer(3, 4, Some(-3)),
            PointerOutcome::Pan {
                columns: 0,
                rows: -3
            }
        );
        assert_eq!(
            display.pointer(3, 4, None),
            PointerOutcome::Application { column: 3, row: 4 },
            "and a click still reaches the application, at the cell it was mapped to"
        );
        assert_eq!(
            display.pointer(99, 99, None),
            PointerOutcome::Nothing,
            "outside the window, nothing"
        );
        display.set_mode(PanMode::Follow);
        assert_eq!(
            display.pointer(3, 4, Some(1)),
            PointerOutcome::Application { column: 3, row: 4 },
            "leaving view mode gives the wheel back"
        );
    }

    /// KR-REQ-08.76: taking the keyboard does not move the size.
    #[test]
    fn taking_the_keyboard_leaves_the_window_and_the_grid_exactly_as_they_were() {
        let mut display = Display::new((80, 24), (40, 12), 0);
        display.viewport.pan(10, 3);
        let before = display.viewport();
        let after = display.took_the_keyboard();
        assert_eq!(after, before, "the two ownerships are separate");
        assert_eq!(display.viewport().canonical(), (80, 24));
        assert_eq!(display.viewport().window(), (40, 12));
        assert_eq!(display.viewport().origin(), (10, 3));
    }

    /// KR-REQ-08.76: the window follows the application's cursor by the least it can.
    #[test]
    fn follow_mode_moves_the_window_the_least_it_can_to_keep_a_cell_visible() {
        let mut viewport = Viewport::new((80, 24), (40, 12));
        assert!(!viewport.reveal(10, 5), "already visible, so nothing moved");
        assert!(viewport.reveal(45, 5));
        assert_eq!(
            viewport.origin(),
            (6, 0),
            "the column is now the last one in the window, not the first"
        );
        assert!(viewport.reveal(0, 0));
        assert_eq!(viewport.origin(), (0, 0));
    }

    /// KR-REQ-08.77: a presentation change installs a snapshot at a cursor and mixes nothing.
    #[test]
    fn a_presentation_change_holds_live_output_until_the_repaint_is_installed() {
        let mut display = Display::new((80, 24), (80, 24), 100);
        assert_eq!(display.presentation(), Presentation::Direct);
        assert!(!display.is_painting());
        // Live output is drawn at once while nothing is being installed.
        assert_eq!(
            display.hold(100, b"abc".to_vec()),
            Some(b"abc".to_vec()),
            "an ordinary batch is drawn as it arrives"
        );
        assert_eq!(display.cursor(), 103);

        // The window changed size, so this client is about to become a viewport.
        let at = display.begin_switch(Presentation::Viewport);
        assert_eq!(
            at, 103,
            "the snapshot is taken at the cursor it has reached"
        );
        assert!(display.is_painting());
        // Everything that arrives now waits. Drawing it over an unfinished repaint is exactly the
        // mixed display the row forbids.
        assert_eq!(display.hold(103, b"de".to_vec()), None);
        assert_eq!(display.hold(105, b"fg".to_vec()), None);

        // The snapshot describes cursor 105, so the first held batch is already in it and the
        // second continues from it.
        let resumed = display.install(105, (40, 12)).expect("installs");
        assert_eq!(resumed, vec![b"fg".to_vec()]);
        assert!(!display.is_painting());
        assert_eq!(display.cursor(), 107);
        assert_eq!(display.presentation(), Presentation::Viewport);
    }

    /// KR-REQ-08.77: a snapshot taken part way through a held batch resumes inside it.
    #[test]
    fn a_snapshot_inside_a_held_batch_resumes_from_where_it_ends() {
        let mut display = Display::new((80, 24), (80, 24), 0);
        display.begin_switch(Presentation::Viewport);
        assert_eq!(display.hold(0, b"abcdef".to_vec()), None);
        let resumed = display.install(3, (40, 12)).expect("installs");
        assert_eq!(
            resumed,
            vec![b"def".to_vec()],
            "the snapshot describes the first three bytes, so the rest follows it"
        );
        assert_eq!(display.cursor(), 6);
    }

    /// KR-REQ-08.77: a snapshot nobody asked for is refused rather than replacing live state.
    #[test]
    fn a_snapshot_with_no_switch_in_progress_is_refused() {
        let mut display = Display::new((80, 24), (80, 24), 50);
        assert_eq!(display.install(10, (80, 24)), Err(NotSwitching));
        assert_eq!(display.cursor(), 50, "and the live state is untouched");
    }

    /// KR-REQ-08.77: a switch that cannot finish leaves the display drawing rather than painting.
    #[test]
    fn an_abandoned_switch_gives_back_what_it_was_holding() {
        let mut display = Display::new((80, 24), (80, 24), 0);
        display.begin_switch(Presentation::Viewport);
        display.hold(0, b"ab".to_vec());
        display.hold(2, b"cd".to_vec());
        let resumed = display.abandon_switch();
        assert_eq!(resumed, vec![b"ab".to_vec(), b"cd".to_vec()]);
        assert!(!display.is_painting());
        assert_eq!(display.cursor(), 4);
        assert!(display.abandon_switch().is_empty());
    }

    /// KR-REQ-08.76: the window follows the canonical grid when the session is resized.
    #[test]
    fn a_grid_that_shrank_pulls_the_window_back_inside_it() {
        let mut viewport = Viewport::new((200, 60), (40, 12));
        assert!(viewport.pan(150, 40));
        assert_eq!(viewport.origin(), (150, 40));
        viewport.canonical_resized((80, 24));
        assert_eq!(
            viewport.origin(),
            (40, 12),
            "the origin is clamped rather than left looking past the edge"
        );
        viewport.window_resized((80, 24));
        assert_eq!(viewport.origin(), (0, 0));
        assert_eq!(viewport.presentation(), Presentation::Direct);
    }
}
