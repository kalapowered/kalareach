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

/// Converts a buffer identity back, for a caller reading one buffer's rows out of the engine.
#[must_use]
pub const fn active_buffer(value: ProjectedBuffer) -> ActiveBuffer {
    match value {
        ProjectedBuffer::Primary => ActiveBuffer::Primary,
        ProjectedBuffer::Alternate => ActiveBuffer::Alternate,
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

/// Converts the keyboard state one client's authority reaches.
///
/// Section 10's live-screen exception is the screen that is showing. The Kitty protocol keeps a
/// flag set and a stack *per buffer*, so a client narrowed to the live screen is sent the state of
/// the buffer it is looking at and nothing of the other one. A rendered restoration never installs
/// the other buffer's negotiation either - there is no sequence for it that does not switch buffers
/// - so what a projection may say about it is nothing.
#[must_use]
pub fn keyboard_within(
    value: &KeyboardSnapshot,
    active: ActiveBuffer,
    scope: crate::render::Scope,
) -> ProjectedKeyboard {
    let mut projected = keyboard(value);
    if scope == crate::render::Scope::LiveScreen {
        let withheld = kr_protocol::projection::KittyKeyboardState {
            flags: Nullable(None),
            stack: Vec::new(),
        };
        match active {
            ActiveBuffer::Primary => projected.alternate = withheld,
            ActiveBuffer::Alternate => projected.primary = withheld,
        }
    }
    projected
}

/// Converts the saved cursors one client's authority reaches.
///
/// A saved cursor belongs to a buffer and carries that buffer's rendition, its character sets and
/// the hyperlink the pen was inside. A client narrowed to the live screen is sent the one that
/// belongs to the screen it is looking at.
#[must_use]
pub fn saved_cursors_within(
    values: &[Option<SavedCursor>; 2],
    active: ActiveBuffer,
    scope: crate::render::Scope,
) -> Vec<SavedCursorState> {
    values
        .iter()
        .flatten()
        .filter(|cursor| scope == crate::render::Scope::WholeScreen || cursor.buffer == active)
        .map(saved_cursor)
        .collect()
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

/// What something costs the wire.
///
/// Both numbers matter, because both are bounds a frame has to stay inside: the encoded length
/// against the control-frame limit, and the number of values against the codec's own item limit. A
/// page of one run per cell reaches the second long before the first, so counting bytes alone
/// would build a page nothing could decode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cost {
    /// Encoded bytes.
    pub bytes: usize,
    /// Values, counting every scalar, array, map and key, the way the codec counts them.
    pub items: usize,
}

impl Cost {
    /// Takes another cost into this one.
    pub const fn absorb(&mut self, other: Self) {
        self.bytes = self.bytes.saturating_add(other.bytes);
        self.items = self.items.saturating_add(other.items);
    }

    /// Whether this cost is inside both bounds.
    #[must_use]
    pub const fn fits(self, bytes: usize, items: usize) -> bool {
        self.bytes <= bytes && self.items <= items
    }
}

/// Measures what one value costs the wire, by encoding it.
///
/// Measured rather than estimated. An estimate of a structure this shape is wrong by an order of
/// magnitude - a plain run encodes to about two hundred bytes and forty values, not to the length
/// of its text - and a page built from a wrong estimate is a frame the transport refuses to carry,
/// which leaves a client with no screen and no marker telling it so.
///
/// Returns nothing for a value the codec cannot represent, which nothing in this module produces.
#[must_use]
pub fn measure<T: serde::Serialize + ?Sized>(value: &T) -> Option<Cost> {
    let encoded = kr_cbor::to_canonical_value(value).ok()?;
    Some(Cost {
        bytes: kr_cbor::encode(&encoded).len(),
        items: values_in(&encoded),
    })
}

/// Counts the values in an encoded message, the way the codec's own limit counts them.
fn values_in(value: &kr_cbor::CanonicalValue) -> usize {
    match value {
        kr_cbor::CanonicalValue::Array(items) => 1 + items.iter().map(values_in).sum::<usize>(),
        kr_cbor::CanonicalValue::Map(entries) => {
            1 + entries
                .entries()
                .iter()
                .map(|(_, held)| 1 + values_in(held))
                .sum::<usize>()
        }
        _ => 1,
    }
}

/// What one row costs a page.
///
/// Measured, for the reason [`measure`] gives. A row the codec cannot represent is reported at the
/// largest cost there is, so it is cut rather than built into a frame nothing can decode.
#[must_use]
pub fn row_cost(value: &ProjectedRow) -> Cost {
    measure(value).unwrap_or(Cost {
        bytes: usize::MAX,
        items: usize::MAX,
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
    fn a_rows_cost_is_what_it_encodes_to_rather_than_the_length_of_its_text() {
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
        let cost = row_cost(&plain);
        // The encoded form of one run is the rendition's whole map and the row's own fields, which
        // is two orders of magnitude more than its two characters. A bound taken from the text
        // would build a page the transport refuses.
        assert!(
            cost.bytes > 100,
            "one run of two characters encodes to {} bytes",
            cost.bytes
        );
        assert!(
            cost.items > 20,
            "and to {} values, which is what the codec's item limit counts",
            cost.items
        );
        assert_eq!(
            cost,
            measure(&plain).expect("a row the codec can represent"),
            "the row's cost is the measurement of the row"
        );

        let mut linked = plain.clone();
        linked.runs[0].hyperlink =
            Nullable::some("https://example.invalid/a-long-target".to_owned());
        let linked = row_cost(&linked);
        assert!(
            linked.bytes > cost.bytes,
            "a link target is bytes on the wire: {linked:?} against {cost:?}"
        );
        assert_eq!(
            linked.items, cost.items,
            "and one value either way, present or null, which is why both are counted"
        );
    }
}
