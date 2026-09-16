//! Turning the engine's own state into the projection wire types.
//!
//! The engine describes a screen in its own vocabulary, with `i64` row identifiers, `Option`
//! fields and Rust enums. The wire needs canonical numbers a JavaScript consumer cannot lose
//! precision on, explicit nulls and stable strings. This module is that translation and nothing
//! else: it makes no decision about what to send, only about how to spell it.
//!
//! One conversion can fail. A stable row identifier is signed in the engine, because the grid
//! library's own index is, and it is unsigned on the wire because a row identifier counts
//! forwards from the first row a session ever had. Every identifier this engine produces starts at
//! zero and only increases, so the conversion is total in practice; it returns an error rather
//! than clamping, because a clamped identifier would name the wrong row and a client would apply
//! an update to it.

use kr_protocol::projection::{
    CellBlink, CellColour, CellRendition, CellRun, CellUnderline, CellVerticalAlign, CharsetState,
    HyperlinkRange, MarginState, PaletteOverride, PaletteProvenance, PaletteState, ProjectedBuffer,
    ProjectedCursor, ProjectedKeyboard, ProjectedMode, ProjectedModeKind, ProjectedRow,
    ProjectedTitle, ProjectedViewport, Rgb, SavedCursorState, SavedTitleEntry,
};
use kr_protocol::scalars::{Nullable, U64};
use kr_term::grid::{Blink, Colour, GridRow, Rendition, Run, UnderlineStyle, VerticalPosition};
use kr_term::palette::PaletteSource;
use kr_term::snapshot::{
    ActiveBuffer, Charsets, CursorState, KeyboardSnapshot, Margins, ModeEntry, PaletteSnapshot,
    SavedCursor, Viewport,
};
use kr_term::title::{SavedTitle, TitleEntry};

use crate::error::{Result, WorkerError};

/// Converts a stable row identifier.
///
/// # Errors
///
/// Returns [`WorkerError::InvalidArgument`] for a negative identifier, which this engine cannot
/// produce: its identifiers begin at zero and only increase.
pub fn row_id(stable_id: i64) -> Result<U64> {
    u64::try_from(stable_id).map(U64::new).map_err(|_| {
        WorkerError::InvalidArgument(format!(
            "row {stable_id} is before the first row of the grid"
        ))
    })
}

/// Converts a column or a cell count.
#[must_use]
pub const fn cells(value: u32) -> U64 {
    U64::new(value as u64)
}

/// Converts a buffer.
#[must_use]
pub const fn buffer(value: ActiveBuffer) -> ProjectedBuffer {
    match value {
        ActiveBuffer::Primary => ProjectedBuffer::Primary,
        ActiveBuffer::Alternate => ProjectedBuffer::Alternate,
    }
}

/// Converts a colour.
#[must_use]
pub const fn colour(value: kr_term::palette::Rgb) -> Rgb {
    Rgb {
        red: value.r,
        green: value.g,
        blue: value.b,
    }
}

/// Converts a cell colour.
#[must_use]
pub const fn cell_colour(value: Colour) -> CellColour {
    match value {
        Colour::Default => CellColour::Default,
        Colour::Indexed(index) => CellColour::Indexed(index),
        Colour::Direct(rgb) => CellColour::Direct(colour(rgb)),
    }
}

/// Converts a rendition.
#[must_use]
pub const fn rendition(value: Rendition) -> CellRendition {
    CellRendition {
        foreground: cell_colour(value.foreground),
        background: cell_colour(value.background),
        underline_colour: cell_colour(value.underline_colour),
        underline: match value.underline {
            UnderlineStyle::None => CellUnderline::None,
            UnderlineStyle::Single => CellUnderline::Single,
            UnderlineStyle::Double => CellUnderline::Double,
            UnderlineStyle::Curly => CellUnderline::Curly,
            UnderlineStyle::Dotted => CellUnderline::Dotted,
            UnderlineStyle::Dashed => CellUnderline::Dashed,
        },
        blink: match value.blink {
            Blink::None => CellBlink::None,
            Blink::Slow => CellBlink::Slow,
            Blink::Rapid => CellBlink::Rapid,
        },
        vertical_align: match value.vertical_align {
            VerticalPosition::Baseline => CellVerticalAlign::Baseline,
            VerticalPosition::Superscript => CellVerticalAlign::Superscript,
            VerticalPosition::Subscript => CellVerticalAlign::Subscript,
        },
        bold: value.bold,
        faint: value.faint,
        italic: value.italic,
        reverse: value.reverse,
        invisible: value.invisible,
        strikethrough: value.strikethrough,
        overline: value.overline,
    }
}

/// Converts one run of cells.
#[must_use]
pub fn run(value: &Run) -> CellRun {
    CellRun {
        column: cells(value.column),
        cells: cells(value.cells),
        text: value.text.clone(),
        rendition: rendition(value.rendition),
        hyperlink: Nullable(value.hyperlink.clone()),
    }
}

/// Converts one row.
///
/// # Errors
///
/// Returns an error when the row's stable identifier is not a forward count.
pub fn row(value: &GridRow) -> Result<ProjectedRow> {
    Ok(ProjectedRow {
        row: row_id(value.stable_id)?,
        soft_wrapped: value.soft_wrapped,
        truncated: value.truncated,
        runs: value.runs.iter().map(run).collect(),
    })
}

/// Converts a list of rows.
///
/// # Errors
///
/// Returns an error when any row's stable identifier is not a forward count.
pub fn rows(values: &[GridRow]) -> Result<Vec<ProjectedRow>> {
    values.iter().map(row).collect()
}

/// Converts the cursor.
#[must_use]
pub const fn cursor(value: CursorState) -> ProjectedCursor {
    ProjectedCursor {
        column: cells(value.col),
        row: cells(value.row),
        visible: value.visible,
        style: cells(value.style),
        pending_wrap: value.pending_wrap,
    }
}

/// Converts a viewport.
///
/// # Errors
///
/// Returns an error when the top row's identifier is not a forward count.
pub fn viewport(value: Viewport) -> Result<ProjectedViewport> {
    Ok(ProjectedViewport {
        top_row: row_id(value.top_row)?,
        rows: cells(value.rows),
        left_column: cells(value.left_col),
        columns: cells(value.cols),
    })
}

/// Converts the scroll region.
#[must_use]
pub const fn margins(value: Margins) -> MarginState {
    MarginState {
        top: cells(value.top),
        bottom: cells(value.bottom),
        left: cells(value.left),
        right: cells(value.right),
    }
}

/// Converts the designated character sets.
#[must_use]
pub fn charsets(value: &Charsets) -> CharsetState {
    CharsetState {
        g0: value.g0.clone(),
        g1: value.g1.clone(),
        shift_out: value.shift_out,
    }
}

/// Converts one tracked mode.
#[must_use]
pub const fn mode(value: ModeEntry) -> ProjectedMode {
    ProjectedMode {
        kind: match value.kind {
            kr_term::modes::ModeKind::Ansi => ProjectedModeKind::Ansi,
            kr_term::modes::ModeKind::Dec => ProjectedModeKind::Dec,
        },
        mode: U64::new(value.mode as u64),
        enabled: value.enabled,
    }
}

/// Converts the keyboard negotiation.
#[must_use]
pub fn keyboard(value: &KeyboardSnapshot) -> ProjectedKeyboard {
    let buffer =
        |state: &kr_term::snapshot::KittyKeyboard| kr_protocol::projection::KittyKeyboardState {
            flags: Nullable(state.flags.map(|flags| U64::new(u64::from(flags)))),
            stack: state
                .stack
                .iter()
                .map(|flags| U64::new(u64::from(*flags)))
                .collect(),
        };
    ProjectedKeyboard {
        modify_other_keys: U64::new(u64::from(value.modify_other_keys)),
        primary: buffer(&value.primary),
        alternate: buffer(&value.alternate),
    }
}

/// Converts the palette and its provenance.
#[must_use]
pub fn palette(value: &PaletteSnapshot) -> PaletteState {
    PaletteState {
        source: provenance(value.source),
        foreground: colour(value.foreground),
        background: colour(value.background),
        cursor: colour(value.cursor),
        pointer_foreground: colour(value.pointer_foreground),
        pointer_background: colour(value.pointer_background),
        selection_background: colour(value.selection_background),
        selection_foreground: colour(value.selection_foreground),
        overrides: value
            .overrides
            .iter()
            .map(|(index, rgb)| PaletteOverride {
                index: *index,
                colour: colour(*rgb),
            })
            .collect(),
    }
}

/// Converts the palette's provenance.
#[must_use]
pub const fn provenance(value: PaletteSource) -> PaletteProvenance {
    match value {
        PaletteSource::ProfileDefault => PaletteProvenance::ProfileDefault,
        PaletteSource::ClientPreference => PaletteProvenance::ClientPreference,
        PaletteSource::LightPreset => PaletteProvenance::LightPreset,
        PaletteSource::DarkPreset => PaletteProvenance::DarkPreset,
        PaletteSource::ExplicitChange => PaletteProvenance::ExplicitChange,
    }
}

/// Converts the saved cursors of both buffers, leaving out a buffer that has saved none.
///
/// # Errors
///
/// Returns an error when a saved cursor cannot be converted.
pub fn saved_cursors(values: &[Option<SavedCursor>; 2]) -> Vec<SavedCursorState> {
    values.iter().flatten().map(saved_cursor).collect()
}

/// Converts one saved cursor.
#[must_use]
pub fn saved_cursor(value: &SavedCursor) -> SavedCursorState {
    SavedCursorState {
        buffer: buffer(value.buffer),
        column: cells(value.col),
        row: cells(value.row),
        pending_wrap: value.pending_wrap,
        rendition: rendition(value.rendition),
        charsets: kr_protocol::projection::CharsetDesignations {
            g0: value.charsets.g0.clone(),
            g1: value.charsets.g1.clone(),
        },
        origin_mode: value.origin_mode,
        style: cells(value.style),
        hyperlink: Nullable(value.hyperlink.clone()),
    }
}

/// Converts the current titles.
#[must_use]
pub fn title(value: &TitleEntry) -> ProjectedTitle {
    ProjectedTitle {
        icon: value.icon.clone(),
        window: value.window.clone(),
    }
}

/// Converts one entry of the virtual title stack.
#[must_use]
pub fn saved_title(value: &SavedTitle) -> SavedTitleEntry {
    SavedTitleEntry {
        icon: Nullable(value.icon.clone()),
        window: Nullable(value.window.clone()),
    }
}

/// Converts the hyperlink ranges of a set of rows.
///
/// # Errors
///
/// Returns an error when a range names a row that is not a forward count.
pub fn hyperlinks(values: &[kr_term::snapshot::HyperlinkRange]) -> Result<Vec<HyperlinkRange>> {
    values
        .iter()
        .map(|range| {
            Ok(HyperlinkRange {
                row: row_id(range.row)?,
                start_column: cells(range.start_col),
                end_column: cells(range.end_col),
                uri: range.uri.clone(),
            })
        })
        .collect()
}

/// How many bytes one row costs a page.
///
/// It counts everything the row carries rather than only its text, because a row of short runs
/// with long hyperlink targets costs many times what its characters do. The figure is the wire
/// cost of the row as this module spells it, which is what a page bound is about.
#[must_use]
pub fn row_bytes(value: &ProjectedRow) -> u64 {
    /// What a row costs before any run: the identifier, two markers and the list envelope.
    const ROW_ENVELOPE: u64 = 32;
    /// What a run costs before its text: two counts, the rendition and the link envelope.
    const RUN_ENVELOPE: u64 = 48;
    value.runs.iter().fold(ROW_ENVELOPE, |total, run| {
        total
            .saturating_add(RUN_ENVELOPE)
            .saturating_add(run.text.len() as u64)
            .saturating_add(run.hyperlink.as_ref().map_or(0, |uri| uri.len() as u64))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_negative_row_identifier_is_refused_rather_than_clamped() {
        assert!(row_id(-1).is_err());
        assert_eq!(row_id(0).expect("the first row").get(), 0);
    }

    #[test]
    fn a_rows_cost_counts_its_link_targets_and_not_only_its_text() {
        let plain = ProjectedRow {
            row: U64::ZERO,
            soft_wrapped: false,
            truncated: false,
            runs: vec![CellRun {
                column: U64::ZERO,
                cells: U64::new(2),
                text: "ab".to_owned(),
                rendition: CellRendition::PLAIN,
                hyperlink: Nullable::null(),
            }],
        };
        let mut linked = plain.clone();
        linked.runs[0].hyperlink =
            Nullable::some("https://example.invalid/a-long-target".to_owned());
        assert!(row_bytes(&linked) > row_bytes(&plain));
    }
}
