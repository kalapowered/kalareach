//! The pinned Unicode width and clustering model.
//!
//! Section 8 pins this rather than inferring it from a library name: ambiguous characters occupy
//! one cell, combining characters add none, and the table revision is a release-profile pin. A
//! terminal state library that clusters differently cannot serve the profile without a qualified
//! change, so the model is stated here and checked against the pinned library by fixture.

use wezterm_term::{UnicodeVersion, grapheme_column_width};

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

/// One accessor the profile needs and the pinned revision does not expose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequiredPatch {
    /// The state the profile needs to read.
    pub state: &'static str,
    /// Why the profile needs it.
    pub reason: &'static str,
    /// What the session does until the patch lands.
    pub interim: &'static str,
}

/// The record of why the pinned terminal state revision may serve kr-vt/1.
///
/// Section 4 requires a conformance-qualified revision rather than an upstream feature list, and
/// requires a narrow published patch where the revision cannot serve the profile as it stands.
/// This record says which it is, and the qualification fixtures prove each claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LibraryQualification {
    /// The upstream repository.
    pub repository: &'static str,
    /// The pinned revision.
    pub revision: &'static str,
    /// How the profile keeps the library inside its bounds.
    pub notes: &'static [&'static str],
    /// Behaviour that differs from xterm and therefore constrains the direct compatibility profile.
    pub direct_mode_constraints: &'static [&'static str],
    /// The accessors the profile needs and the revision does not expose.
    pub required_patch: &'static [RequiredPatch],
}

/// The qualification record for the pinned revision.
pub const LIBRARY: LibraryQualification = LibraryQualification {
    repository: "https://github.com/wezterm/wezterm",
    revision: "699fd77b44641c43476c945054cfae6518dbd632",
    notes: &[
        "The revision accepts already-parsed actions, so the engine parses once and the library \
         never re-frames a byte. That is what makes a second parse unnecessary rather than merely \
         discouraged.",
        "The width model is configuration, not a fork: generation 9 with narrow ambiguous \
         characters is exactly the pinned kr-vt/1 model.",
        "In-band resize and DECCOLM never reach the library, because the policy layer classifies \
         them before the reducer sees anything. The library's own support for them is therefore \
         not part of the profile.",
        "The library's cluster reducer runs on ordinary text and is more modern than the pinned \
         width model: it folds an emoji sequence into one cell where this model gives each scalar \
         with a width of its own a cell of its own. The qualified change is in what the library is \
         given, not in the library: a text run is cut before every scalar the reducer would fold, \
         so the two never arrive in the same call and the cell count follows the pinned model. \
         Zero-width scalars are left where they are, because folding those is exactly what the \
         model asks for.",
        "Raster graphics are disabled in configuration and no image sequence is ever forwarded, so \
         the library's sixel, iTerm2 and Kitty image paths stay unreachable.",
        "The library is built with a writer that accepts no bytes. Every reply comes from the \
         query broker, and the fixtures fail if the library ever writes one.",
        "A sequence the library marks unspecified, at any nesting, is not applied and not \
         forwarded. The mapping is therefore checked by what the library does with it rather than \
         by whether it parsed.",
        "The library clusters the text of one call to its action interface, so the engine holds \
         the final cell of a text run until it knows what follows, and draws that cell again with \
         the marks on it when a combining mark arrives after the screen has settled. Without \
         both, the same bytes would produce different screens depending on where a read happened \
         to split them, or on whether the stream went quiet in the middle of a cell.",
    ],
    direct_mode_constraints: &[
        "Cells follow the pinned legacy codepoint-width model, so a multi-scalar emoji sequence \
         takes one cell per scalar that has a width of its own. A physical terminal that applies \
         its own grapheme clustering to the same bytes draws fewer cells and every later column \
         on the row disagrees, so it is not qualified for direct mode whatever it reports.",
        "A wide cell may overhang the right margin. Writing a two-cell character in the last \
         column leaves a row one cell wider than the grid and sets the pending wrap, where xterm \
         blanks the last column and wraps the character. A projected renderer clips or safely \
         replaces the overhanging cell.",
    ],
    required_patch: &[
        RequiredPatch {
            state: "TerminalState::pending_wrap()",
            reason: "section 8 lists pending wrap among the state a snapshot restores",
            interim: "the snapshot carries None and a reconnecting client re-derives it from the \
                      next character it places",
        },
        RequiredPatch {
            state: "TerminalState::saved_cursor() as a shared reference, with the saved rendition \
                    and character sets among its public fields",
            reason: "section 8 lists saved cursors among the state a snapshot restores, and a \
                     saved cursor that carries only a position restores the wrong colours",
            interim: "the snapshot carries None; a restored session behaves as though nothing was \
                      saved until the application saves again",
        },
        RequiredPatch {
            state: "TerminalState::inactive_screen(), the buffer that is not active",
            reason: "section 8 requires a restoration sequence to reproduce both buffer states, \
                     and the accessor the revision exposes returns whichever buffer is active",
            interim: "the snapshot carries the active buffer and None for the other; a client that \
                      reconnects during a full-screen application has no primary-buffer content \
                      until that application exits and the shell redraws",
        },
    ],
};
