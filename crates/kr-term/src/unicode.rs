//! The pinned Unicode width and clustering model.
//!
//! Section 8 pins this rather than inferring it from a library name: ambiguous characters occupy
//! one cell, combining characters add none, and the table revision is a release-profile pin. A
//! terminal state library that clusters differently cannot serve the profile without a qualified
//! change, so the model is stated in `kr-width`, which measures with the pinned library's own width
//! function, and checked against the pinned library here by fixture and by a corpus.

pub use kr_width::{
    UnicodeModel, ZERO_WIDTH_JOINER, cells_for, is_zero_width, last_cell_start, leading_zero_width,
    may_join,
};

/// One accessor the pinned revision adds to the upstream tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QualifiedAddition {
    /// The state the profile reads.
    pub state: &'static str,
    /// Why the profile needs it.
    pub reason: &'static str,
}

/// The record of why the pinned terminal state revision may serve kr-vt/1.
///
/// Section 4 requires a conformance-qualified revision rather than an upstream feature list, and
/// requires a narrow published patch where the revision cannot serve the profile as it stands.
/// This record says which it is, and the qualification fixtures prove each claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LibraryQualification {
    /// The repository the pinned revision comes from.
    pub repository: &'static str,
    /// The pinned revision.
    pub revision: &'static str,
    /// The upstream repository the pinned revision follows.
    pub upstream: &'static str,
    /// The upstream revision the pinned revision is built on.
    pub upstream_revision: &'static str,
    /// How the profile keeps the library inside its bounds.
    pub notes: &'static [&'static str],
    /// Behaviour that constrains the direct compatibility profile.
    pub direct_mode_constraints: &'static [&'static str],
    /// The accessors the pinned revision adds to the upstream tree.
    pub qualified_additions: &'static [QualifiedAddition],
    /// The accessors the profile needs and the pinned revision does not expose.
    ///
    /// Empty: the pinned revision exposes everything section 8 asks a snapshot to carry.
    pub required_patch: &'static [QualifiedAddition],
}

/// The qualification record for the pinned revision.
pub const LIBRARY: LibraryQualification = LibraryQualification {
    repository: "https://github.com/kalapowered/wezterm",
    revision: "9a9015119497fd5803c35a10ea4ffc503f2a7dfb",
    upstream: "https://github.com/wezterm/wezterm",
    upstream_revision: "699fd77b44641c43476c945054cfae6518dbd632",
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
         width model: it folds emoji sequences, Hangul jamo and more into one cell where this \
         model gives each scalar with a width of its own a cell of its own. The qualified change \
         is in what the library is given rather than in the library: a run that is not plain ASCII \
         is cut at every cell, so the reducer never sees two of them in one call. Zero-width \
         scalars are left where they are, because folding those is exactly what the model asks \
         for.",
        "The library keeps a row in one of two representations and converts a row to the compact \
         one when it scrolls. The compact one stores the row as a single string, and the pinned \
         revision has it record where the cells are whenever clustering that string again would \
         not give them back, so a row keeps the cells it was given whichever representation it is \
         in and whether it is on screen or in the scrollback.",
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
        "A wide character that ends exactly on the last column leaves the library's cursor on the \
         character's first cell, one column short of the last, where xterm and the terminals \
         measured against the grid report the last column. The grid reports the library's \
         column, so the difference is recorded and not corrected.",
        "A soft reset leaves a terminal on the buffer that is showing, where the library returns to \
         the primary buffer. A direct attachment reading a soft reset while the alternate buffer is \
         showing is moved to projection at that point, and the canonical grid is what it is shown.",
        "A soft reset clears the saved cursor of both buffers, where xterm saves a fresh cursor in \
         the buffer that is showing, at home and with the wrap that was pending, and keeps the \
         other buffer's. A restore in the buffer the reset leaves showing goes home with the ASCII \
         sets and the shift in, in both. They differ in a wrap pending at the reset, in the faint, \
         crossed-out and doubly underlined states of the rendition, which xterm's reset leaves \
         set, and in a cursor saved in the other buffer before the reset and not saved again \
         since, which xterm gives back there. A wrap pending at the reset needs no rule of its \
         own: every soft reset redraws each direct attachment from the canonical screen, and an \
         attachment redrawn with a wrap pending is shown a projection.",
    ],
    qualified_additions: &[
        QualifiedAddition {
            state: "TerminalState::pending_wrap()",
            reason: "section 8 lists pending wrap among the state a snapshot restores, and the \
                     same cursor coordinates place the next character in different cells with and \
                     without it",
        },
        QualifiedAddition {
            state: "TerminalState::saved_cursor(), a shared reference to either buffer's saved \
                    cursor, with the saved rendition and character sets among its public fields",
            reason: "section 8 lists saved cursors among the state a snapshot restores, and a \
                     saved cursor that carries only a position restores the wrong colours from the \
                     wrong origin",
        },
        QualifiedAddition {
            state: "TerminalState::inactive_screen(), the buffer that is not active",
            reason: "section 8 requires a restoration sequence to reproduce both buffer states, \
                     and the accessor the upstream revision exposes returns whichever buffer is \
                     active",
        },
        QualifiedAddition {
            state: "Line::compress_for_scrollback() keeping the cells, attributes and wrap \
                    markers it was given",
            reason: "the pinned width model gives a cell to every scalar that has a width of its \
                     own, and a compact row that worked out where its cells are by clustering its \
                     text again would join adjacent scalars and drop the columns they held, so the \
                     compact form keeps the cell boundaries it was given",
        },
    ],
    required_patch: &[],
};
