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
        } else if column >= self.origin_column.saturating_add(self.columns) {
            self.origin_column = column.saturating_add(1).saturating_sub(self.columns);
        }
        if row < self.origin_row {
            self.origin_row = row;
        } else if row >= self.origin_row.saturating_add(self.rows) {
            self.origin_row = row.saturating_add(1).saturating_sub(self.rows);
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

/// Moves `value` by `delta`, saturating at both ends of a cell coordinate.
///
/// The arithmetic is done in the wider type and saturated rather than added, because a pan by
/// `i64::MAX` from a large origin overflows a signed addition and a wrapped origin is a window
/// somewhere else entirely.
const fn shift(value: u32, delta: i64) -> u32 {
    let moved = (value as i64).saturating_add(delta);
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

/// One batch the host delivered.
///
/// The two are not interchangeable and a client that added them up the same way would invent
/// cursors. A span of the raw stream advances the output cursor by its length. A rendering of the
/// canonical screen is *state at* one cursor, however many frames it takes, so it moves the cursor
/// to that cursor and not past it.
#[derive(Clone, PartialEq, Eq)]
pub enum Delivery {
    /// A span of the raw output stream, starting at this cursor.
    Bytes {
        /// Where the span starts.
        cursor: u64,
        /// The bytes.
        bytes: Vec<u8>,
    },
    /// A rendering of the canonical screen as it stood at this cursor.
    Screen {
        /// The cursor the screen describes.
        cursor: u64,
        /// The bytes that draw it.
        bytes: Vec<u8>,
    },
}

impl std::fmt::Debug for Delivery {
    /// Where the delivery ends and how long it is, never the bytes: they are what a person typed or
    /// what a terminal showed.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bytes { cursor, bytes } => formatter
                .debug_struct("Bytes")
                .field("cursor", cursor)
                .field("bytes", &bytes.len())
                .finish(),
            Self::Screen { cursor, bytes } => formatter
                .debug_struct("Screen")
                .field("cursor", cursor)
                .field("bytes", &bytes.len())
                .finish(),
        }
    }
}

impl Delivery {
    /// Returns the cursor this delivery leaves the client at.
    #[must_use]
    pub fn ends_at(&self) -> u64 {
        match self {
            Self::Bytes { cursor, bytes } => cursor.saturating_add(bytes.len() as u64),
            Self::Screen { cursor, .. } => *cursor,
        }
    }

    /// Returns the cursor this delivery begins at.
    #[must_use]
    pub const fn starts_at(&self) -> u64 {
        match self {
            Self::Bytes { cursor, .. } | Self::Screen { cursor, .. } => *cursor,
        }
    }

    /// Returns the bytes to draw.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Bytes { bytes, .. } | Self::Screen { bytes, .. } => bytes,
        }
    }

    fn len(&self) -> usize {
        self.bytes().len()
    }
}

/// How much output a display holds while a repaint is being installed.
///
/// The host bounds its own send queue and resynchronises a subscriber that fills it. A client that
/// drained that queue into an unbounded vector would have removed the protection rather than
/// respected it, so this is the client's own share of the same rule: past it the held state is
/// worthless and the display asks for a fresh snapshot instead.
pub const MAX_HELD_BYTES: usize = 4 * 1024 * 1024;

/// How many deliveries a display holds while a repaint is being installed.
///
/// A byte bound alone is not a bound: an unbounded number of empty deliveries costs memory and
/// spends none of it.
pub const MAX_HELD_DELIVERIES: usize = 4_096;

/// One client's display of a session.
///
/// It owns the viewport, the pan mode, the presentation the host selected, and the one piece of
/// state a presentation change needs: what is waiting to be applied while a repaint is installed.
#[derive(Clone, Debug)]
pub struct Display {
    viewport: Viewport,
    mode: PanMode,
    /// What the host says this client is being served.
    ///
    /// The host decides it, not the client: equal size is necessary and not sufficient, because a
    /// stream the engine cannot carry, or a screen a restoration could not carry, projects a
    /// terminal of exactly the right size. So this is what the host said rather than what the
    /// dimensions imply.
    presentation: Presentation,
    /// The cursor the installed state describes. Everything before it has been applied.
    cursor: u64,
    /// Whether the state on screen is unusable and only a snapshot can replace it.
    needs_snapshot: bool,
    /// The cursor up to which output has gone, when any has.
    ///
    /// A snapshot is a complete picture of the screen at one cursor, so one taken at or after this
    /// replaces everything that went. One taken before it does not: the client would resume with a
    /// hole in the middle of what it drew and no way to know there was one.
    missing_until: Option<u64>,
    switching: Option<Switch>,
    /// Counts the switches this display has begun, so a snapshot for an older one is refused.
    switch_generation: u64,
}

/// A presentation change in progress.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Switch {
    /// Which switch this is, so a snapshot that arrives for an earlier one is refused.
    generation: u64,
    /// What the host says the client will be once the snapshot is installed.
    into: Presentation,
    /// Live output that arrived while the snapshot was being fetched, in arrival order.
    held: Vec<Delivery>,
    /// How many bytes those deliveries hold.
    held_bytes: usize,
    /// Whether any of the repaint reached the screen before the switch was abandoned.
    partial: bool,
}

impl Display {
    /// Builds a display of `canonical` in a window of `window`, at output cursor `cursor`.
    ///
    /// `presentation` is what the host said it is serving this client.
    #[must_use]
    pub const fn new(
        canonical: (u32, u32),
        window: (u32, u32),
        cursor: u64,
        presentation: Presentation,
    ) -> Self {
        Self {
            viewport: Viewport::new(canonical, window),
            mode: PanMode::Follow,
            presentation,
            cursor,
            needs_snapshot: false,
            missing_until: None,
            switching: None,
            switch_generation: 0,
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

    /// Returns how the host says this client is being shown the session.
    #[must_use]
    pub const fn presentation(&self) -> Presentation {
        self.presentation
    }

    /// Returns true when the state on screen cannot be used and only a snapshot can replace it.
    #[must_use]
    pub const fn needs_snapshot(&self) -> bool {
        self.needs_snapshot
    }

    /// Enters or leaves view mode.
    ///
    /// Leaving it puts the wheel back where it belongs, so the window follows again from wherever
    /// the person left it until the next thing it has to reveal.
    pub const fn set_mode(&mut self, mode: PanMode) {
        self.mode = mode;
    }

    /// Moves the window, and returns whether it moved.
    ///
    /// Only view mode pans. In follow mode the window belongs to the session, so a pan request is
    /// refused rather than quietly applied: a client that panned while following would fight the
    /// application's own cursor.
    pub const fn pan(&mut self, columns: i64, rows: i64) -> bool {
        if matches!(self.mode, PanMode::Follow) {
            return false;
        }
        self.viewport.pan(columns, rows)
    }

    /// Moves the window the least it can to keep a canonical cell visible.
    ///
    /// This is what follow mode does with the application's cursor. In view mode the person is
    /// looking somewhere of their own choosing and the window stays where they left it.
    pub const fn reveal(&mut self, column: u32, row: u32) -> bool {
        if matches!(self.mode, PanMode::View) {
            return false;
        }
        self.viewport.reveal(column, row)
    }

    /// Records that this client's own window changed size.
    ///
    /// The presentation is the host's to decide, so this does not change it. What it changes is
    /// which part of the grid the window looks at.
    pub const fn window_resized(&mut self, window: (u32, u32)) {
        self.viewport.window_resized(window);
    }

    /// Records that the session's canonical grid changed size.
    pub const fn canonical_resized(&mut self, canonical: (u32, u32)) {
        self.viewport.canonical_resized(canonical);
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
    ///
    /// Beginning a second switch supersedes the first. The snapshot the first one asked for is then
    /// refused by [`Display::install`], because installing it would replace the state of a
    /// presentation this client has already left.
    pub fn begin_switch(&mut self, into: Presentation) -> u64 {
        self.switch_generation = self.switch_generation.saturating_add(1);
        let held = self
            .switching
            .take()
            .map_or_else(Vec::new, |switch| switch.held);
        let held_bytes = held.iter().map(Delivery::len).sum();
        self.switching = Some(Switch {
            generation: self.switch_generation,
            into,
            held,
            held_bytes,
            partial: false,
        });
        self.cursor
    }

    /// Returns true while a repaint is being installed.
    #[must_use]
    pub const fn is_painting(&self) -> bool {
        self.switching.is_some()
    }

    /// Takes one delivery from the host.
    ///
    /// While the display is painting it is held; otherwise it is applied at once and the cursor
    /// moves to where it ends. The return value is what the client draws now, which is nothing at
    /// all during a repaint.
    ///
    /// Past [`MAX_HELD_BYTES`] the held state is abandoned and the display asks for a snapshot,
    /// which is the same answer the host gives a subscriber that fills its queue.
    pub fn hold(&mut self, delivery: Delivery) -> Option<Vec<u8>> {
        match self.switching.as_mut() {
            Some(switch) => {
                switch.held_bytes = switch.held_bytes.saturating_add(delivery.len());
                if switch.held_bytes > MAX_HELD_BYTES || switch.held.len() >= MAX_HELD_DELIVERIES {
                    // What was being held goes, and with it any claim to be continuous with the
                    // stream. Where it reached is remembered, so a snapshot from before that cannot
                    // be mistaken for a replacement for it.
                    let reached = switch
                        .held
                        .iter()
                        .chain(std::iter::once(&delivery))
                        .map(Delivery::ends_at)
                        .max()
                        .unwrap_or(self.cursor);
                    switch.held.clear();
                    switch.held_bytes = 0;
                    switch.partial = true;
                    self.needs_snapshot = true;
                    self.missing_until = Some(
                        self.missing_until
                            .map_or(reached, |already| already.max(reached)),
                    );
                    return None;
                }
                switch.held.push(delivery);
                None
            }
            None if self.needs_snapshot => {
                // The state on screen describes nothing this delivery continues. Drawing over it is
                // the mixed display the row forbids, so nothing is drawn until a snapshot arrives,
                // and this delivery goes with everything else that has.
                let reached = delivery.ends_at();
                self.missing_until = Some(
                    self.missing_until
                        .map_or(reached, |already| already.max(reached)),
                );
                None
            }
            None => {
                self.cursor = delivery.ends_at();
                Some(delivery.bytes().to_vec())
            }
        }
    }

    /// Installs the snapshot the switch was waiting for, and returns what to draw after it.
    ///
    /// `at` is the cursor the snapshot describes, which is the one [`Display::begin_switch`]
    /// returned or a later one. Held output the snapshot already contains is discarded; everything
    /// from that cursor onwards is replayed in order, so the client resumes exactly where the
    /// installed state ends.
    ///
    /// `generation` is the value `begin_switch` returned alongside its cursor, obtained from
    /// [`Display::switch_generation`]. A snapshot for an earlier switch is refused.
    ///
    /// # Errors
    ///
    /// Returns [`NotSwitching`] when no presentation change is in progress, or when this snapshot
    /// belongs to one this display has already left. Applying either would replace live state with
    /// state for a presentation the client no longer has.
    pub fn install(
        &mut self,
        generation: u64,
        at: u64,
        window: (u32, u32),
    ) -> Result<Vec<Vec<u8>>, NotSwitching> {
        let switch = self.switching.take().ok_or(NotSwitching)?;
        if switch.generation != generation {
            // Put it back: the switch this snapshot is too late for is still the one in progress.
            self.switching = Some(switch);
            return Err(NotSwitching);
        }
        if self.missing_until.is_some_and(|until| at < until) {
            // Output up to `until` has gone and this snapshot describes the session before it.
            // Installing it would leave a hole in the middle of what the client draws and no way to
            // know there was one, so the switch stays open and waits for a later snapshot.
            self.switching = Some(switch);
            return Err(NotSwitching);
        }
        self.viewport.window_resized(window);
        self.presentation = switch.into;
        self.cursor = at;
        self.needs_snapshot = false;
        self.missing_until = None;
        let mut resumed = Vec::new();
        for delivery in switch.held {
            if delivery.ends_at() <= at {
                // The snapshot was taken after this, so it already describes it.
                continue;
            }
            match delivery {
                Delivery::Screen { cursor, bytes } => {
                    // A repaint of a screen the snapshot already replaced is worthless; one taken
                    // after it replaces the snapshot's own picture.
                    if cursor >= at {
                        self.cursor = cursor;
                        resumed.push(bytes);
                    }
                }
                Delivery::Bytes { cursor, bytes } => {
                    let skip = usize::try_from(at.saturating_sub(cursor))
                        .unwrap_or(bytes.len())
                        .min(bytes.len());
                    self.cursor = cursor.saturating_add(bytes.len() as u64);
                    resumed.push(bytes[skip..].to_vec());
                }
            }
        }
        Ok(resumed)
    }

    /// Returns the generation of the switch in progress, for [`Display::install`].
    #[must_use]
    pub const fn switch_generation(&self) -> u64 {
        self.switch_generation
    }

    /// Abandons a switch.
    ///
    /// A switch that cannot be completed - the snapshot never arrived, the connection went - has to
    /// leave the display drawing again rather than painting for ever. What it does **not** do is
    /// resume as though nothing happened when part of the repaint already reached the screen: that
    /// state describes neither cursor, so the display says it needs a snapshot and draws nothing
    /// until it has one.
    ///
    /// It also stays needed. A display that already needed a snapshot before this switch began
    /// still needs one after it: beginning a switch is asking for the snapshot, not having it.
    ///
    /// Returns the held output to draw, which is empty when a snapshot is needed instead.
    pub fn abandon_switch(&mut self, repaint_reached_the_screen: bool) -> Vec<Vec<u8>> {
        let Some(switch) = self.switching.take() else {
            return Vec::new();
        };
        if switch.partial || repaint_reached_the_screen || self.needs_snapshot {
            // The screen holds part of a repaint and part of something else, so it describes no
            // cursor at all. What was held is abandoned with it, and where that reached is what a
            // replacement snapshot has to cover.
            self.needs_snapshot = true;
            let reached = switch
                .held
                .iter()
                .map(Delivery::ends_at)
                .max()
                .unwrap_or(self.cursor);
            self.missing_until = Some(
                self.missing_until
                    .map_or(reached, |already| already.max(reached)),
            );
            return Vec::new();
        }
        let mut resumed = Vec::new();
        for delivery in switch.held {
            self.cursor = delivery.ends_at();
            resumed.push(delivery.bytes().to_vec());
        }
        resumed
    }
}

/// Returned when a snapshot is installed with no presentation change in progress.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NotSwitching;

impl crate::shown::Said for NotSwitching {
    fn said(&self) -> crate::shown::Shown {
        crate::shown::Shown::said(
            "this display is not changing presentation, so it installs no snapshot",
        )
    }
}

crate::display_as_said!(NotSwitching);
crate::debug_as_display!(NotSwitching);

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
        let mut display = Display::new((80, 24), (40, 12), 0, Presentation::Viewport);
        assert_eq!(display.mode(), PanMode::Follow);
        assert_eq!(
            display.pointer(3, 4, Some(-3)),
            PointerOutcome::Application { column: 3, row: 4 },
            "in follow mode a wheel event is the application's, which is what makes scrollback \
             work inside a full-screen program"
        );
        assert!(
            !display.pan(0, -3),
            "and a pan request in follow mode is refused rather than quietly applied"
        );
        display.set_mode(PanMode::View);
        assert_eq!(
            display.pointer(3, 4, Some(-3)),
            PointerOutcome::Pan {
                columns: 0,
                rows: -3
            }
        );
        // Which the client applies through the display, to the viewport the mapping uses.
        assert!(display.pan(0, 5));
        assert_eq!(display.viewport().origin(), (0, 5));
        assert_eq!(
            display.pointer(3, 4, None),
            PointerOutcome::Application { column: 3, row: 9 },
            "and a click still reaches the application, at the cell it was mapped to"
        );
        assert_eq!(
            display.pointer(99, 99, None),
            PointerOutcome::Nothing,
            "outside the window, nothing"
        );
        assert!(
            !display.reveal(0, 0),
            "in view mode the window stays where the person left it"
        );
        display.set_mode(PanMode::Follow);
        assert_eq!(
            display.pointer(3, 4, Some(1)),
            PointerOutcome::Application { column: 3, row: 9 },
            "leaving view mode gives the wheel back"
        );
        assert!(display.reveal(0, 0), "and the window follows again");
        assert_eq!(display.viewport().origin(), (0, 0));
    }

    /// KR-REQ-08.76: taking the keyboard does not move the size.
    #[test]
    fn taking_the_keyboard_leaves_the_window_and_the_grid_exactly_as_they_were() {
        let mut display = Display::new((80, 24), (40, 12), 0, Presentation::Viewport);
        display.set_mode(PanMode::View);
        display.pan(10, 3);
        let before = display.viewport();
        let after = display.took_the_keyboard();
        assert_eq!(after, before, "the two ownerships are separate");
        assert_eq!(display.viewport().canonical(), (80, 24));
        assert_eq!(display.viewport().window(), (40, 12));
        assert_eq!(display.viewport().origin(), (10, 3));
        assert_eq!(display.presentation(), Presentation::Viewport);
    }

    /// KR-REQ-08.75: the presentation is the host's answer, not the dimensions' implication.
    #[test]
    fn an_equal_sized_window_is_still_a_projection_when_the_host_says_so() {
        // The host projects a terminal of exactly the right size whenever the stream is not
        // carryable or the screen it was drawn could not carry the state the application will
        // address. A client that worked it out from its own dimensions would draw the wrong thing.
        let projected = Display::new((80, 24), (80, 24), 0, Presentation::Viewport);
        assert_eq!(projected.presentation(), Presentation::Viewport);
        assert_eq!(
            projected.viewport().presentation(),
            Presentation::Direct,
            "the size alone would have said otherwise"
        );
        let direct = Display::new((80, 24), (80, 24), 0, Presentation::Direct);
        assert_eq!(direct.presentation(), Presentation::Direct);
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
        // And a target at the far end of the coordinate space clamps rather than wrapping.
        let mut wide = Viewport::new((u32::MAX, u32::MAX), (40, 12));
        assert!(wide.reveal(u32::MAX, u32::MAX));
        assert_eq!(
            wide.origin(),
            (u32::MAX - 40, u32::MAX - 12),
            "which is as far as the window can be panned, and the last cell is inside it"
        );
        assert_eq!(wide.map(39, 11), Some((u32::MAX - 1, u32::MAX - 1)));
    }

    /// KR-REQ-08.76: a pan argument at the end of its range clamps rather than wrapping.
    #[test]
    fn an_extreme_pan_clamps_rather_than_wrapping_round() {
        let mut viewport = Viewport::new((u32::MAX, u32::MAX), (40, 12));
        assert!(viewport.pan(i64::MAX, i64::MAX));
        assert_eq!(viewport.origin(), (u32::MAX - 40, u32::MAX - 12));
        assert!(viewport.pan(i64::MIN, i64::MIN));
        assert_eq!(viewport.origin(), (0, 0));
    }

    /// KR-REQ-08.77: a presentation change installs a snapshot at a cursor and mixes nothing.
    #[test]
    fn a_presentation_change_holds_live_output_until_the_repaint_is_installed() {
        let mut display = Display::new((80, 24), (80, 24), 100, Presentation::Direct);
        assert!(!display.is_painting());
        // Live output is drawn at once while nothing is being installed.
        assert_eq!(
            display.hold(Delivery::Bytes {
                cursor: 100,
                bytes: b"abc".to_vec()
            }),
            Some(b"abc".to_vec()),
            "an ordinary span is drawn as it arrives"
        );
        assert_eq!(display.cursor(), 103);

        // The window changed size, so the host is about to serve this client a viewport.
        let at = display.begin_switch(Presentation::Viewport);
        let generation = display.switch_generation();
        assert_eq!(
            at, 103,
            "the snapshot is taken at the cursor it has reached"
        );
        assert!(display.is_painting());
        // Everything that arrives now waits. Drawing it over an unfinished repaint is exactly the
        // mixed display the row forbids.
        assert_eq!(
            display.hold(Delivery::Bytes {
                cursor: 103,
                bytes: b"de".to_vec()
            }),
            None
        );
        assert_eq!(
            display.hold(Delivery::Bytes {
                cursor: 105,
                bytes: b"fg".to_vec()
            }),
            None
        );

        // The snapshot describes cursor 105, so the first held span is already in it and the
        // second continues from it.
        let resumed = display
            .install(generation, 105, (40, 12))
            .expect("installs");
        assert_eq!(resumed, vec![b"fg".to_vec()]);
        assert!(!display.is_painting());
        assert_eq!(display.cursor(), 107);
        assert_eq!(display.presentation(), Presentation::Viewport);
        assert_eq!(display.viewport().window(), (40, 12));
    }

    /// KR-REQ-08.77: a repaint is state at one cursor, and does not advance it by its length.
    #[test]
    fn a_screen_is_state_at_a_cursor_rather_than_a_span_of_the_stream() {
        let mut display = Display::new((80, 24), (40, 12), 0, Presentation::Viewport);
        // A clipped repaint is thousands of bytes of cursor addressing describing the screen at
        // cursor 40. A client that added its length to the cursor would then ask for output from
        // somewhere the stream never reached.
        let repaint = vec![b'x'; 2_048];
        assert_eq!(
            display.hold(Delivery::Screen {
                cursor: 40,
                bytes: repaint.clone()
            }),
            Some(repaint)
        );
        assert_eq!(display.cursor(), 40);
        // A span, by contrast, moves it along by what it carried.
        display.hold(Delivery::Bytes {
            cursor: 40,
            bytes: b"abcd".to_vec(),
        });
        assert_eq!(display.cursor(), 44);
    }

    /// KR-REQ-08.77: a snapshot taken part way through a held span resumes inside it.
    #[test]
    fn a_snapshot_inside_a_held_batch_resumes_from_where_it_ends() {
        let mut display = Display::new((80, 24), (80, 24), 0, Presentation::Direct);
        display.begin_switch(Presentation::Viewport);
        let generation = display.switch_generation();
        assert_eq!(
            display.hold(Delivery::Bytes {
                cursor: 0,
                bytes: b"abcdef".to_vec()
            }),
            None
        );
        let resumed = display.install(generation, 3, (40, 12)).expect("installs");
        assert_eq!(
            resumed,
            vec![b"def".to_vec()],
            "the snapshot describes the first three bytes, so the rest follows it"
        );
        assert_eq!(display.cursor(), 6);
    }

    /// KR-REQ-08.77: a snapshot nobody asked for, or one for a switch already left, is refused.
    #[test]
    fn a_snapshot_for_no_switch_or_an_older_one_is_refused() {
        let mut display = Display::new((80, 24), (80, 24), 50, Presentation::Direct);
        assert_eq!(display.install(0, 10, (80, 24)), Err(NotSwitching));
        assert_eq!(display.cursor(), 50, "and the live state is untouched");

        // Two switches in a row: the person resized twice before the first snapshot arrived.
        display.begin_switch(Presentation::Viewport);
        let first = display.switch_generation();
        display.begin_switch(Presentation::Viewport);
        let second = display.switch_generation();
        assert_ne!(first, second);
        assert_eq!(
            display.install(first, 60, (40, 12)),
            Err(NotSwitching),
            "the snapshot for the switch this display has already left is refused"
        );
        assert!(
            display.is_painting(),
            "and the switch in progress is still waiting for its own"
        );
        display
            .install(second, 60, (20, 6))
            .expect("the current switch's snapshot installs");
        assert_eq!(display.viewport().window(), (20, 6));
    }

    /// KR-REQ-08.77: a switch abandoned after part of the repaint drew asks for a snapshot.
    #[test]
    fn an_abandoned_switch_gives_back_what_it_held_or_asks_for_a_snapshot() {
        let mut display = Display::new((80, 24), (80, 24), 0, Presentation::Direct);
        display.begin_switch(Presentation::Viewport);
        display.hold(Delivery::Bytes {
            cursor: 0,
            bytes: b"ab".to_vec(),
        });
        display.hold(Delivery::Bytes {
            cursor: 2,
            bytes: b"cd".to_vec(),
        });
        // Nothing of the repaint reached the screen, so what was held is still continuous with what
        // is on it.
        let resumed = display.abandon_switch(false);
        assert_eq!(resumed, vec![b"ab".to_vec(), b"cd".to_vec()]);
        assert!(!display.is_painting());
        assert!(!display.needs_snapshot());
        assert_eq!(display.cursor(), 4);
        assert!(display.abandon_switch(false).is_empty());

        // Part of the repaint did reach the screen: that state describes neither cursor, so the
        // held output is not drawn over it and the display says what it needs.
        display.begin_switch(Presentation::Viewport);
        display.hold(Delivery::Bytes {
            cursor: 4,
            bytes: b"ef".to_vec(),
        });
        assert!(display.abandon_switch(true).is_empty());
        assert!(display.needs_snapshot());
        assert!(!display.is_painting());
    }

    /// KR-REQ-08.77: held output is bounded, and past it only a later snapshot will do.
    #[test]
    fn held_output_is_bounded_rather_than_drained_into_the_client() {
        let mut display = Display::new((80, 24), (80, 24), 0, Presentation::Direct);
        display.begin_switch(Presentation::Viewport);
        let generation = display.switch_generation();
        let mut cursor = 0_u64;
        let batch = vec![b'x'; 1024 * 1024];
        for _ in 0..5 {
            display.hold(Delivery::Bytes {
                cursor,
                bytes: batch.clone(),
            });
            cursor += batch.len() as u64;
        }
        assert!(
            display.needs_snapshot(),
            "the client bounds its own share of what the host bounds"
        );
        // A snapshot taken before the output that went cannot replace it: the client would resume
        // with a hole in the middle of what it drew and no way to know there was one.
        assert_eq!(
            display.install(generation, 0, (40, 12)),
            Err(NotSwitching),
            "an older snapshot is refused rather than papered over a gap"
        );
        assert!(display.is_painting(), "so the switch is still waiting");
        let resumed = display
            .install(generation, cursor, (40, 12))
            .expect("a snapshot from after what went installs");
        assert!(
            resumed.is_empty(),
            "and what it was holding went, because the snapshot replaces it"
        );
        assert!(!display.needs_snapshot());
        assert_eq!(display.cursor(), cursor);
    }

    /// KR-REQ-08.77: nothing is drawn over state that only a snapshot can replace.
    #[test]
    fn output_after_an_abandoned_repaint_is_not_drawn_over_what_is_on_the_screen() {
        let mut display = Display::new((80, 24), (80, 24), 0, Presentation::Direct);
        display.begin_switch(Presentation::Viewport);
        display.hold(Delivery::Bytes {
            cursor: 0,
            bytes: b"ab".to_vec(),
        });
        // Part of the repaint drew, and then the switch could not be finished.
        assert!(display.abandon_switch(true).is_empty());
        assert!(display.needs_snapshot());
        assert!(!display.is_painting());
        // Live output now has nothing continuous to be drawn onto.
        assert_eq!(
            display.hold(Delivery::Bytes {
                cursor: 2,
                bytes: b"cd".to_vec()
            }),
            None,
            "which is the mixed display the row forbids"
        );
        assert!(display.needs_snapshot(), "and it still needs a snapshot");

        // A resynchronisation is asked for the same way a presentation change is, with the
        // presentation the host is already serving.
        let at = display.begin_switch(display.presentation());
        let generation = display.switch_generation();
        assert_eq!(at, display.cursor());
        display
            .install(generation, 4, (80, 24))
            .expect("a snapshot from after what went installs");
        assert!(!display.needs_snapshot());
        assert_eq!(
            display.hold(Delivery::Bytes {
                cursor: 4,
                bytes: b"ef".to_vec()
            }),
            Some(b"ef".to_vec()),
            "and the display draws again"
        );
    }

    /// KR-REQ-08.77: a bound on deliveries as well as on their bytes.
    #[test]
    fn an_unbounded_number_of_empty_deliveries_is_bounded_too() {
        let mut display = Display::new((80, 24), (80, 24), 0, Presentation::Direct);
        display.begin_switch(Presentation::Viewport);
        for cursor in 0..u64::try_from(MAX_HELD_DELIVERIES).expect("fits") + 1 {
            display.hold(Delivery::Bytes {
                cursor,
                bytes: Vec::new(),
            });
        }
        assert!(
            display.needs_snapshot(),
            "a byte bound alone is not a bound when a delivery can carry no bytes"
        );
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
