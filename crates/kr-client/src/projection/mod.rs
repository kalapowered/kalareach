//! The client-side projection: the screen a client holds, and the renderer that draws it.
//!
//! A projected attachment is not sent the application's bytes. It is sent the canonical grid as
//! state: one snapshot, its rows in bounded pages, then one bounded update per batch of output.
//! This module is the other half of that contract, and it is deliberately in the client library
//! rather than in the command, because the CLI, the desktop application and the companion app all
//! draw the same session and none of them should reimplement what a screen is.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`self`] | The screen a client holds, and what it does with each event |
//! | [`paint`] | Turning that screen into bytes for a destination terminal |
//!
//! # What holding a screen means
//!
//! A [`Projection`] holds nothing until a snapshot completes. Section 8 forbids mixing live output
//! with an incomplete repaint, so the pages of a snapshot are collected and the screen is replaced
//! in one step when the last page arrives. Until then the previous screen is what a client draws,
//! which is the only thing it can honestly show.
//!
//! # Why an update can be refused
//!
//! Every update names the base it continues from: an output cursor *and* a projection generation.
//! A cursor alone is not a position in a screen's history, because a reset can happen without a
//! byte arriving. An update that does not match both is refused, and the client asks for a fresh
//! snapshot rather than applying a change to a screen it never had.

pub mod paint;

use std::collections::BTreeMap;

use kr_protocol::projection::{
    CellRendition, CharsetState, HyperlinkRange, MarginState, PaletteState, ProjectedBuffer,
    ProjectedCursor, ProjectedKeyboard, ProjectedMode, ProjectedRow, ProjectedTitle,
    ProjectedViewport, ProjectionDelta, ProjectionEvent, ProjectionReset, ProjectionResetReason,
    ProjectionRowPage, ProjectionSnapshot, SavedCursorState, SavedTitleEntry,
};
use kr_protocol::session::Dimensions;

/// The base a client holds: a cursor in the output stream and the generation it belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Base {
    /// The output cursor the held screen describes.
    pub cursor: u64,
    /// The projection generation it belongs to.
    pub generation: u64,
}

/// One screen, as a client holds it.
///
/// The rows are held per buffer and keyed by their stable identifiers, because that is what every
/// update names. A scroll moves which identifiers the viewport holds without changing a row, so
/// the two are kept apart: [`Screen::rows`] is what exists, [`Screen::viewport`] is what is shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Screen {
    /// The generation this screen belongs to.
    pub generation: u64,
    /// The output cursor it describes.
    pub cursor_at: u64,
    /// Which buffer is showing.
    pub active_buffer: ProjectedBuffer,
    /// The canonical dimensions.
    pub dimensions: Dimensions,
    /// The window this client is showing.
    pub viewport: ProjectedViewport,
    /// The cursor.
    pub cursor: ProjectedCursor,
    /// The cursor each buffer has saved.
    pub saved_cursors: Vec<SavedCursorState>,
    /// The scroll region.
    pub margins: MarginState,
    /// The pen the next character would be drawn with.
    pub rendition: CellRendition,
    /// The columns carrying a tab stop.
    pub tab_stops: Vec<u64>,
    /// The designated character sets.
    pub charsets: CharsetState,
    /// Every tracked mode.
    pub modes: BTreeMap<(ProjectedModeSpelling, u64), bool>,
    /// Whether the keypad is in application mode.
    pub keypad_application: bool,
    /// The keyboard negotiation an input encoder has to reproduce.
    pub keyboard: ProjectedKeyboard,
    /// The current titles.
    pub title: ProjectedTitle,
    /// The virtual title stack, oldest first.
    pub title_stack: Vec<SavedTitleEntry>,
    /// The hyperlink the next character printed belongs to.
    pub hyperlink: Option<String>,
    /// The canonical palette and where it came from.
    pub palette: PaletteState,
    /// The rows of each buffer, by stable identifier.
    pub rows: BTreeMap<(ProjectedBuffer, u64), ProjectedRow>,
    /// The hyperlink ranges, by the row they belong to.
    pub hyperlinks: BTreeMap<u64, Vec<HyperlinkRange>>,
    /// The oldest row still retained anywhere.
    pub oldest_retained_row: u64,
    /// Whether rows below `oldest_retained_row` have been evicted.
    pub evicted: bool,
}

/// Which spelling a tracked mode has, in a form a map can be keyed by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProjectedModeSpelling {
    /// An ANSI mode.
    Ansi,
    /// A DEC private mode.
    Dec,
}

impl From<kr_protocol::projection::ProjectedModeKind> for ProjectedModeSpelling {
    fn from(value: kr_protocol::projection::ProjectedModeKind) -> Self {
        match value {
            kr_protocol::projection::ProjectedModeKind::Ansi => Self::Ansi,
            kr_protocol::projection::ProjectedModeKind::Dec => Self::Dec,
        }
    }
}

impl Screen {
    /// Whether a tracked mode is set.
    #[must_use]
    pub fn mode(&self, spelling: ProjectedModeSpelling, mode: u64) -> bool {
        self.modes
            .get(&(spelling, mode))
            .copied()
            .unwrap_or_default()
    }

    /// Whether the session has autowrap on, which a restoration has to put back.
    #[must_use]
    pub fn autowrap(&self) -> bool {
        // Mode 7 defaults to set, so an absent entry is on rather than off.
        self.modes
            .get(&(ProjectedModeSpelling::Dec, 7))
            .copied()
            .unwrap_or(true)
    }

    /// The row with this stable identifier in the buffer that is showing.
    #[must_use]
    pub fn row(&self, row: u64) -> Option<&ProjectedRow> {
        self.rows.get(&(self.active_buffer, row))
    }

    /// The stable identifiers the viewport is showing, top to bottom.
    #[must_use]
    pub fn visible_rows(&self) -> Vec<u64> {
        let top = self.viewport.top_row.get();
        (0..self.viewport.rows.get())
            .map(|offset| top.saturating_add(offset))
            .collect()
    }

    /// The hyperlink covering one canonical cell, as inert metadata.
    ///
    /// Reconnection restores these so a later click still works. Nothing here activates anything:
    /// a scheme that would launch an external application needs the client's own policy first.
    #[must_use]
    pub fn hyperlink_at(&self, row: u64, column: u64) -> Option<&str> {
        self.hyperlinks.get(&row)?.iter().find_map(|range| {
            (range.start_column.get() <= column && column < range.end_column.get())
                .then_some(range.uri.as_str())
        })
    }

    /// The base this screen is, for the next update to continue from.
    #[must_use]
    pub const fn base(&self) -> Base {
        Base {
            cursor: self.cursor_at,
            generation: self.generation,
        }
    }
}

/// What applying one event did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Applied {
    /// The screen was discarded. A snapshot follows.
    Reset(ProjectionResetReason),
    /// A snapshot has begun and is not complete. Nothing is drawn from it yet.
    Installing,
    /// A snapshot completed and replaced the screen. Everything is drawn.
    Installed,
    /// An update was applied. These stable row identifiers changed.
    Updated(Vec<u64>),
    /// The event was refused, and the client must ask for a fresh snapshot.
    Refused(Refusal),
}

/// Why an event was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The update continues from a base this client does not hold.
    BaseMismatch,
    /// The event belongs to a generation this client is not on.
    WrongGeneration,
    /// A page arrived for a snapshot this client is not installing.
    UnexpectedPage,
    /// An update arrived before any snapshot completed.
    NoScreen,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let detail = match self {
            Self::BaseMismatch => "the update continues from a screen this client does not hold",
            Self::WrongGeneration => "the update belongs to another projection generation",
            Self::UnexpectedPage => "a page arrived for a snapshot that is not being installed",
            Self::NoScreen => "an update arrived before a snapshot completed",
        };
        formatter.write_str(detail)
    }
}

/// A snapshot whose pages are still arriving.
#[derive(Clone, Debug)]
struct Installing {
    header: Box<ProjectionSnapshot>,
    rows: BTreeMap<(ProjectedBuffer, u64), ProjectedRow>,
    hyperlinks: BTreeMap<u64, Vec<HyperlinkRange>>,
}

/// One client's projection of a session.
#[derive(Clone, Debug, Default)]
pub struct Projection {
    screen: Option<Screen>,
    installing: Option<Installing>,
    /// The generation the last reset named, so a page or a delta from before it is refused.
    generation: Option<u64>,
}

impl Projection {
    /// A client holding nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The screen this client holds, once a snapshot has completed.
    #[must_use]
    pub const fn screen(&self) -> Option<&Screen> {
        self.screen.as_ref()
    }

    /// The base the next update must continue from.
    #[must_use]
    pub fn base(&self) -> Option<Base> {
        self.screen.as_ref().map(Screen::base)
    }

    /// Whether a snapshot is part way through arriving.
    #[must_use]
    pub const fn installing(&self) -> bool {
        self.installing.is_some()
    }

    /// Applies one event.
    pub fn apply(&mut self, event: ProjectionEvent) -> Applied {
        match event {
            ProjectionEvent::Reset(reset) => self.reset(reset),
            ProjectionEvent::Snapshot(header) => self.begin(header),
            ProjectionEvent::Rows(page) => self.page(page),
            ProjectionEvent::Delta(delta) => self.delta(*delta),
        }
    }

    fn reset(&mut self, reset: ProjectionReset) -> Applied {
        // The screen goes now rather than when the snapshot completes. A reset means what is held
        // is no longer the session, and drawing it for another moment would be drawing something
        // the host has already said is wrong.
        self.screen = None;
        self.installing = None;
        self.generation = Some(reset.projection_generation.get());
        Applied::Reset(reset.reason)
    }

    fn begin(&mut self, header: Box<ProjectionSnapshot>) -> Applied {
        self.generation = Some(header.projection_generation.get());
        self.installing = Some(Installing {
            header,
            rows: BTreeMap::new(),
            hyperlinks: BTreeMap::new(),
        });
        Applied::Installing
    }

    fn page(&mut self, page: ProjectionRowPage) -> Applied {
        let Some(installing) = self.installing.as_mut() else {
            return Applied::Refused(Refusal::UnexpectedPage);
        };
        if page.projection_generation != installing.header.projection_generation
            || page.output_cursor != installing.header.output_cursor
        {
            return Applied::Refused(Refusal::WrongGeneration);
        }
        for row in page.rows {
            installing.rows.insert((page.buffer, row.row.get()), row);
        }
        if page.more {
            return Applied::Installing;
        }
        let Some(installing) = self.installing.take() else {
            return Applied::Refused(Refusal::UnexpectedPage);
        };
        self.screen = Some(screen_of(installing));
        Applied::Installed
    }

    fn delta(&mut self, delta: ProjectionDelta) -> Applied {
        let Some(screen) = self.screen.as_mut() else {
            return Applied::Refused(Refusal::NoScreen);
        };
        if delta.projection_generation.get() != screen.generation {
            return Applied::Refused(Refusal::WrongGeneration);
        }
        if delta.base_cursor.get() != screen.cursor_at {
            return Applied::Refused(Refusal::BaseMismatch);
        }
        let mut changed: Vec<u64> = Vec::with_capacity(delta.rows.len());
        // The viewport is applied before the rows. A scroll moves which identifiers are shown
        // without changing one of them, so a client that drew the rows against the old window
        // would put every one of them on the wrong line.
        let scrolled = screen.viewport != delta.viewport;
        screen.viewport = delta.viewport;
        screen.active_buffer = delta.buffer;
        for row in delta.rows {
            changed.push(row.row.get());
            screen.rows.insert((delta.buffer, row.row.get()), row);
        }
        for range in delta.hyperlinks {
            screen
                .hyperlinks
                .entry(range.row.get())
                .or_default()
                .retain(|held| {
                    held.end_column <= range.start_column || held.start_column >= range.end_column
                });
            screen
                .hyperlinks
                .entry(range.row.get())
                .or_default()
                .push(range);
        }
        screen.cursor = delta.cursor;
        screen.cursor_at = delta.next_cursor.get();
        for mode in delta.modes {
            screen
                .modes
                .insert((mode.kind.into(), mode.mode.get()), mode.enabled);
        }
        if let Some(margins) = delta.margins.0 {
            screen.margins = margins;
        }
        if let Some(rendition) = delta.rendition.0 {
            screen.rendition = rendition;
        }
        if let Some(stops) = delta.tab_stops.0 {
            screen.tab_stops = stops.into_iter().map(|at| at.get()).collect();
        }
        if let Some(charsets) = delta.charsets.0 {
            screen.charsets = charsets;
        }
        if let Some(change) = delta.hyperlink.0 {
            screen.hyperlink = change.uri.0;
        }
        if let Some(title) = delta.title.0 {
            screen.title = title;
        }
        if let Some(stack) = delta.title_stack.0 {
            screen.title_stack = stack;
        }
        if let Some(keyboard) = delta.keyboard.0 {
            screen.keyboard = keyboard;
        }
        if let Some(palette) = delta.palette.0 {
            screen.palette = palette;
        }
        if let Some(dimensions) = delta.dimensions.0 {
            screen.dimensions = dimensions;
        }
        if let Some(saved) = delta.saved_cursors.0 {
            screen.saved_cursors = saved;
        }
        screen.oldest_retained_row = delta.oldest_retained_row.get();
        screen.evicted = delta.evicted;
        // Rows below the oldest retained one are gone from the session, so holding them would be
        // holding something no later update can name.
        let oldest = screen.oldest_retained_row;
        screen.rows.retain(|(_, row), _| *row >= oldest);
        screen.hyperlinks.retain(|row, _| *row >= oldest);
        if scrolled {
            // Every visible line moved, so every one of them is redrawn. Nothing was reflowed and
            // no row changed; what changed is which rows the window holds.
            let mut visible = screen.visible_rows();
            visible.extend(changed);
            visible.sort_unstable();
            visible.dedup();
            return Applied::Updated(visible);
        }
        changed.sort_unstable();
        changed.dedup();
        Applied::Updated(changed)
    }
}

fn screen_of(installing: Installing) -> Screen {
    let header = installing.header;
    let mut modes = BTreeMap::new();
    for mode in &header.modes {
        modes.insert((mode.kind.into(), mode.mode.get()), mode.enabled);
    }
    let mut hyperlinks = installing.hyperlinks;
    // A run that is inside a link carries the target, so the ranges follow from the rows rather
    // than being sent twice. Reconnection restores them as inert metadata: a later click works,
    // and nothing here activates anything.
    for row in installing.rows.values() {
        for run in &row.runs {
            if let Some(uri) = run.hyperlink.as_ref() {
                hyperlinks
                    .entry(row.row.get())
                    .or_default()
                    .push(HyperlinkRange {
                        row: row.row,
                        start_column: run.column,
                        end_column: kr_protocol::scalars::U64::new(
                            run.column.get().saturating_add(run.cells.get()),
                        ),
                        uri: uri.clone(),
                    });
            }
        }
    }
    Screen {
        generation: header.projection_generation.get(),
        cursor_at: header.output_cursor.get(),
        active_buffer: header.active_buffer,
        dimensions: header.dimensions,
        viewport: header.viewport,
        cursor: header.cursor,
        saved_cursors: header.saved_cursors,
        margins: header.margins,
        rendition: header.rendition,
        tab_stops: header.tab_stops.iter().map(|at| at.get()).collect(),
        charsets: header.charsets,
        modes,
        keypad_application: header.keypad_application,
        keyboard: header.keyboard,
        title: header.title,
        title_stack: header.title_stack,
        hyperlink: header.hyperlink.0,
        palette: header.palette,
        rows: installing.rows,
        hyperlinks,
        oldest_retained_row: header.oldest_retained_row.get(),
        evicted: header.evicted,
    }
}

/// Every mode a projected client tracks, for a caller that wants the list.
#[must_use]
pub fn mode_entries(screen: &Screen) -> Vec<ProjectedMode> {
    screen
        .modes
        .iter()
        .map(|((spelling, mode), enabled)| ProjectedMode {
            kind: match spelling {
                ProjectedModeSpelling::Ansi => kr_protocol::projection::ProjectedModeKind::Ansi,
                ProjectedModeSpelling::Dec => kr_protocol::projection::ProjectedModeKind::Dec,
            },
            mode: kr_protocol::scalars::U64::new(*mode),
            enabled: *enabled,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::projection::{
        CellRendition, CellRun, CharsetState, HyperlinkChange, MarginState, PaletteProvenance,
        PaletteState, ProjectedMode, ProjectedModeKind, Rgb,
    };
    use kr_protocol::scalars::{Nullable, U64};

    fn palette(source: PaletteProvenance) -> PaletteState {
        let colour = Rgb {
            red: 1,
            green: 2,
            blue: 3,
        };
        PaletteState {
            source,
            foreground: colour,
            background: colour,
            cursor: colour,
            pointer_foreground: colour,
            pointer_background: colour,
            selection_background: colour,
            selection_foreground: colour,
            overrides: Vec::new(),
        }
    }

    fn header(generation: u64, cursor: u64) -> Box<ProjectionSnapshot> {
        Box::new(ProjectionSnapshot {
            projection_generation: U64::new(generation),
            output_cursor: U64::new(cursor),
            active_buffer: ProjectedBuffer::Primary,
            dimensions: Dimensions::new(4, 2),
            viewport: ProjectedViewport {
                top_row: U64::ZERO,
                rows: U64::new(2),
                left_column: U64::ZERO,
                columns: U64::new(4),
            },
            cursor: ProjectedCursor {
                column: U64::ZERO,
                row: U64::ZERO,
                visible: true,
                style: U64::new(1),
                pending_wrap: false,
            },
            saved_cursors: Vec::new(),
            margins: MarginState {
                top: U64::ZERO,
                bottom: U64::new(1),
                left: U64::ZERO,
                right: U64::new(3),
            },
            rendition: CellRendition::PLAIN,
            tab_stops: vec![U64::ZERO],
            charsets: CharsetState {
                g0: "Ascii".to_owned(),
                g1: "Ascii".to_owned(),
                shift_out: false,
            },
            modes: vec![ProjectedMode {
                kind: ProjectedModeKind::Dec,
                mode: U64::new(7),
                enabled: true,
            }],
            keypad_application: false,
            keyboard: ProjectedKeyboard {
                modify_other_keys: U64::ZERO,
                primary: kr_protocol::projection::KittyKeyboardState {
                    flags: Nullable::null(),
                    stack: Vec::new(),
                },
                alternate: kr_protocol::projection::KittyKeyboardState {
                    flags: Nullable::null(),
                    stack: Vec::new(),
                },
            },
            title: ProjectedTitle::default(),
            title_stack: Vec::new(),
            hyperlink: Nullable::null(),
            palette: palette(PaletteProvenance::DarkPreset),
            oldest_retained_row: U64::ZERO,
            evicted: false,
        })
    }

    fn row(id: u64, text: &str, link: Option<&str>) -> ProjectedRow {
        ProjectedRow {
            row: U64::new(id),
            soft_wrapped: false,
            truncated: false,
            runs: vec![CellRun {
                column: U64::ZERO,
                cells: U64::new(text.chars().count() as u64),
                text: text.to_owned(),
                rendition: CellRendition::PLAIN,
                hyperlink: Nullable(link.map(str::to_owned)),
            }],
        }
    }

    fn page(
        generation: u64,
        cursor: u64,
        rows: Vec<ProjectedRow>,
        more: bool,
    ) -> ProjectionRowPage {
        ProjectionRowPage {
            projection_generation: U64::new(generation),
            output_cursor: U64::new(cursor),
            buffer: ProjectedBuffer::Primary,
            rows,
            oldest_retained_row: U64::ZERO,
            evicted: false,
            more,
        }
    }

    fn delta(
        base: u64,
        next: u64,
        generation: u64,
        rows: Vec<ProjectedRow>,
    ) -> Box<ProjectionDelta> {
        Box::new(ProjectionDelta {
            base_cursor: U64::new(base),
            next_cursor: U64::new(next),
            projection_generation: U64::new(generation),
            buffer: ProjectedBuffer::Primary,
            viewport: ProjectedViewport {
                top_row: U64::ZERO,
                rows: U64::new(2),
                left_column: U64::ZERO,
                columns: U64::new(4),
            },
            rows,
            cursor: ProjectedCursor {
                column: U64::new(1),
                row: U64::ZERO,
                visible: true,
                style: U64::new(1),
                pending_wrap: false,
            },
            modes: Vec::new(),
            margins: Nullable::null(),
            rendition: Nullable::null(),
            tab_stops: Nullable::null(),
            charsets: Nullable::null(),
            hyperlinks: Vec::new(),
            hyperlink: Nullable::null(),
            title: Nullable::null(),
            title_stack: Nullable::null(),
            keyboard: Nullable::null(),
            palette: Nullable::null(),
            dimensions: Nullable::null(),
            saved_cursors: Nullable::null(),
            oldest_retained_row: U64::ZERO,
            evicted: false,
        })
    }

    /// KR-REQ-08.83: the snapshot's own fields, and rows that arrive in pages with their markers.
    #[test]
    fn a_snapshot_holds_nothing_until_its_last_page_arrives() {
        let mut projection = Projection::new();
        assert!(projection.screen().is_none());
        assert_eq!(
            projection.apply(ProjectionEvent::Snapshot(header(3, 40))),
            Applied::Installing
        );
        assert!(
            projection.screen().is_none(),
            "an incomplete repaint is not a screen"
        );
        assert_eq!(
            projection.apply(ProjectionEvent::Rows(page(
                3,
                40,
                vec![row(0, "ab", None)],
                true
            ))),
            Applied::Installing
        );
        assert!(projection.screen().is_none());
        assert_eq!(
            projection.apply(ProjectionEvent::Rows(page(
                3,
                40,
                vec![row(1, "cd", None)],
                false
            ))),
            Applied::Installed
        );
        let screen = projection.screen().expect("a screen");
        assert_eq!(screen.generation, 3);
        assert_eq!(screen.cursor_at, 40);
        assert_eq!(screen.active_buffer, ProjectedBuffer::Primary);
        assert_eq!(screen.dimensions, Dimensions::new(4, 2));
        assert_eq!(screen.visible_rows(), vec![0, 1]);
        assert!(screen.autowrap(), "the snapshot's mode state is installed");
        assert_eq!(screen.palette.source, PaletteProvenance::DarkPreset);
        assert_eq!(
            projection.base(),
            Some(Base {
                cursor: 40,
                generation: 3
            })
        );
    }

    /// KR-REQ-08.83: a delta that names another base is refused rather than applied.
    #[test]
    fn a_delta_against_another_base_is_refused() {
        let mut projection = Projection::new();
        projection.apply(ProjectionEvent::Snapshot(header(3, 40)));
        projection.apply(ProjectionEvent::Rows(page(
            3,
            40,
            vec![row(0, "ab", None)],
            false,
        )));

        assert_eq!(
            projection.apply(ProjectionEvent::Delta(delta(
                39,
                41,
                3,
                vec![row(0, "zz", None)]
            ))),
            Applied::Refused(Refusal::BaseMismatch),
            "a cursor that is not the one this client holds"
        );
        assert_eq!(
            projection.apply(ProjectionEvent::Delta(delta(
                40,
                41,
                4,
                vec![row(0, "zz", None)]
            ))),
            Applied::Refused(Refusal::WrongGeneration),
            "the same cursor in another generation is another screen"
        );
        let screen = projection.screen().expect("a screen");
        assert_eq!(screen.cursor_at, 40, "nothing refused was applied");
        assert_eq!(
            screen.row(0).expect("row 0").runs[0].text,
            "ab",
            "and the row the client holds is untouched"
        );

        assert_eq!(
            projection.apply(ProjectionEvent::Delta(delta(
                40,
                48,
                3,
                vec![row(0, "zz", None)]
            ))),
            Applied::Updated(vec![0])
        );
        let screen = projection.screen().expect("a screen");
        assert_eq!(screen.cursor_at, 48);
        assert_eq!(screen.row(0).expect("row 0").runs[0].text, "zz");
    }

    /// KR-REQ-08.80: an update before any snapshot is refused, and a reset discards the screen.
    #[test]
    fn a_reset_discards_the_screen_and_an_update_without_one_is_refused() {
        let mut projection = Projection::new();
        assert_eq!(
            projection.apply(ProjectionEvent::Delta(delta(0, 1, 1, Vec::new()))),
            Applied::Refused(Refusal::NoScreen)
        );
        projection.apply(ProjectionEvent::Snapshot(header(1, 0)));
        projection.apply(ProjectionEvent::Rows(page(
            1,
            0,
            vec![row(0, "ab", None)],
            false,
        )));
        assert!(projection.screen().is_some());
        assert_eq!(
            projection.apply(ProjectionEvent::Reset(ProjectionReset {
                projection_generation: U64::new(2),
                cursor: U64::new(9),
                reason: ProjectionResetReason::BufferSwitch,
            })),
            Applied::Reset(ProjectionResetReason::BufferSwitch)
        );
        assert!(
            projection.screen().is_none(),
            "what the client held is no longer the session"
        );
        assert_eq!(
            projection.apply(ProjectionEvent::Rows(page(1, 0, Vec::new(), false))),
            Applied::Refused(Refusal::UnexpectedPage)
        );
    }

    /// KR-REQ-08.83: a scroll moves the window without changing a row, so every line is redrawn.
    #[test]
    fn a_scroll_redraws_every_line_and_reflows_nothing() {
        let mut projection = Projection::new();
        projection.apply(ProjectionEvent::Snapshot(header(1, 0)));
        projection.apply(ProjectionEvent::Rows(page(
            1,
            0,
            vec![row(0, "ab", None), row(1, "cd", None)],
            false,
        )));
        let mut scrolled = delta(0, 5, 1, vec![row(2, "ef", None)]);
        scrolled.viewport.top_row = U64::new(1);
        match projection.apply(ProjectionEvent::Delta(scrolled)) {
            Applied::Updated(rows) => assert_eq!(rows, vec![1, 2]),
            other => panic!("the window moved: {other:?}"),
        }
        let screen = projection.screen().expect("a screen");
        assert_eq!(screen.visible_rows(), vec![1, 2]);
        assert_eq!(
            screen.row(0).expect("row 0 is still held").runs[0].text,
            "ab",
            "a row that left the window is not a row that changed"
        );
    }

    /// KR-ACC-002: a hyperlink survives a reconnection and stays inert metadata.
    #[test]
    fn a_hyperlink_survives_a_reconnection_and_activates_nothing() {
        let mut projection = Projection::new();
        projection.apply(ProjectionEvent::Snapshot(header(1, 0)));
        projection.apply(ProjectionEvent::Rows(page(
            1,
            0,
            vec![row(0, "docs", Some("https://example.invalid/guide"))],
            false,
        )));
        let screen = projection.screen().expect("a screen");
        assert_eq!(
            screen.hyperlink_at(0, 2),
            Some("https://example.invalid/guide"),
            "the range is restored from the rows the snapshot carried"
        );
        assert_eq!(screen.hyperlink_at(0, 9), None, "and covers only its cells");

        // A reconnection is a fresh snapshot of the same session, and the link is there again.
        let mut reconnected = Projection::new();
        reconnected.apply(ProjectionEvent::Snapshot(header(2, 12)));
        reconnected.apply(ProjectionEvent::Rows(page(
            2,
            12,
            vec![row(0, "docs", Some("https://example.invalid/guide"))],
            false,
        )));
        assert_eq!(
            reconnected.screen().expect("a screen").hyperlink_at(0, 0),
            Some("https://example.invalid/guide")
        );
    }

    /// KR-REQ-08.79: rows below the oldest retained one are given up rather than held for ever.
    #[test]
    fn an_eviction_drops_the_rows_the_session_no_longer_holds() {
        let mut projection = Projection::new();
        projection.apply(ProjectionEvent::Snapshot(header(1, 0)));
        projection.apply(ProjectionEvent::Rows(page(
            1,
            0,
            vec![row(0, "old", None), row(1, "new", None)],
            false,
        )));
        let mut evicting = delta(0, 3, 1, Vec::new());
        evicting.oldest_retained_row = U64::new(1);
        evicting.evicted = true;
        projection.apply(ProjectionEvent::Delta(evicting));
        let screen = projection.screen().expect("a screen");
        assert!(screen.evicted);
        assert_eq!(screen.oldest_retained_row, 1);
        assert!(
            screen.rows.keys().all(|(_, row)| *row >= 1),
            "an evicted row is not a row a later update can name"
        );
    }

    /// KR-REQ-08.83: an open hyperlink that closed is a change, not an absence.
    #[test]
    fn a_closed_hyperlink_is_told_apart_from_one_that_was_never_mentioned() {
        let mut projection = Projection::new();
        let mut open = header(1, 0);
        open.hyperlink = Nullable::some("https://example.invalid/open".to_owned());
        projection.apply(ProjectionEvent::Snapshot(open));
        projection.apply(ProjectionEvent::Rows(page(1, 0, Vec::new(), false)));
        assert_eq!(
            projection.screen().expect("a screen").hyperlink.as_deref(),
            Some("https://example.invalid/open")
        );

        let unmentioned = delta(0, 1, 1, Vec::new());
        projection.apply(ProjectionEvent::Delta(unmentioned));
        assert!(
            projection.screen().expect("a screen").hyperlink.is_some(),
            "a delta that says nothing about the link leaves it open"
        );

        let mut closed = delta(1, 2, 1, Vec::new());
        closed.hyperlink = Nullable::some(HyperlinkChange {
            uri: Nullable::null(),
        });
        projection.apply(ProjectionEvent::Delta(closed));
        assert!(
            projection.screen().expect("a screen").hyperlink.is_none(),
            "and one that says it closed closes it"
        );
    }
}
