//! The pinned Unicode width model.
//!
//! Section 8 pins this rather than inferring it from a library name: ambiguous characters occupy
//! one cell, combining characters add none, and the table revision is a release-profile pin. The
//! model is stated here and measured by the pinned terminal library's own width function, so there
//! is one width model in the system.
//!
//! It lives in a crate of its own because the terminal state library that keeps the canonical grid
//! depends on a terminal-mode crate with no target for Apple's mobile systems, while the width
//! function is in a smaller crate of the same library that builds everywhere. A client that paints
//! a screen it was sent measures text with this crate on every platform, and the terminal engine
//! measures with the same functions.

use wezterm_cell::{UnicodeVersion, grapheme_column_width};

/// The width model kr-vt/1 pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnicodeModel {
    /// The `wcwidth` table generation. Version 9 is the last generation before the Unicode 14
    /// emoji presentation selectors changed the width of existing sequences.
    pub width_table_generation: u8,
    /// Whether East Asian Ambiguous characters take two cells. kr-vt/1 says one.
    pub ambiguous_are_wide: bool,
    /// Whether the profile claims mode 2027 grapheme clustering. kr-vt/1 says no.
    pub grapheme_clustering: bool,
}

impl UnicodeModel {
    /// The kr-vt/1 model: generation 9, ambiguous narrow, no grapheme-clustering claim.
    pub const KR_VT_1: Self = Self {
        width_table_generation: 9,
        ambiguous_are_wide: false,
        grapheme_clustering: false,
    };

    /// The same model expressed for the pinned terminal state library.
    #[must_use]
    pub fn to_library(self) -> UnicodeVersion {
        UnicodeVersion {
            version: self.width_table_generation,
            ambiguous_are_wide: self.ambiguous_are_wide,
            cell_widths: None,
        }
    }
}

impl Default for UnicodeModel {
    fn default() -> Self {
        Self::KR_VT_1
    }
}

/// The zero-width joiner, which glues the scalar after it to the cluster before it.
pub const ZERO_WIDTH_JOINER: char = '\u{200d}';

/// Whether a scalar occupies no cells of its own.
///
/// Combining marks, joiners and variation selectors all belong to whatever came before them. The
/// answer comes from the profile's own pinned table, so there is one width model in the system
/// rather than two that can drift apart.
#[must_use]
pub fn is_zero_width(scalar: char) -> bool {
    // Nothing below U+0300 has zero width once the controls are out of the way, and that covers
    // almost every scalar a terminal ever prints. Checking it first keeps the table lookup off the
    // path most output takes.
    if (scalar as u32) < 0x0300 {
        return false;
    }
    let mut buf = [0u8; 4];
    let text: &str = scalar.encode_utf8(&mut buf);
    grapheme_column_width(text, Some(&UnicodeModel::KR_VT_1.to_library())) == 0
}

/// Whether the library's cluster reducer could disagree with this model about `text`.
///
/// It can only disagree about scalars outside ASCII, so ordinary output answers this without
/// decoding anything.
#[must_use]
pub fn may_join(text: &str) -> bool {
    !text.is_ascii()
}

/// Byte length of the run of zero-width scalars at the start of `text`.
///
/// These belong to whatever the previous text run ended with, which may already be on the screen.
#[must_use]
pub fn leading_zero_width(text: &str) -> usize {
    text.char_indices()
        .find(|&(_, scalar)| !is_zero_width(scalar))
        .map_or(text.len(), |(index, _)| index)
}

/// How many cells `text` occupies under the pinned width model.
///
/// The model is per scalar, so this sums the widths rather than asking the library what one cluster
/// is worth. For one cell it is the width of that cell.
#[must_use]
pub fn cells_for(text: &str) -> usize {
    text.chars()
        .map(|scalar| {
            let mut buffer = [0u8; 4];
            let encoded: &str = scalar.encode_utf8(&mut buffer);
            grapheme_column_width(encoded, Some(&UnicodeModel::KR_VT_1.to_library()))
        })
        .sum()
}

/// Byte offset where the last cell of `text` starts.
///
/// A cell is one scalar with a width of its own, plus the zero-width scalars after it. `text` must
/// not be empty.
#[must_use]
pub fn last_cell_start(text: &str) -> usize {
    if text.is_ascii() {
        return text.len() - 1;
    }
    let mut start = 0;
    for (index, scalar) in text.char_indices() {
        if !is_zero_width(scalar) {
            start = index;
        }
    }
    start
}
