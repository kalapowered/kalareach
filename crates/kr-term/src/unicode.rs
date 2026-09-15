//! The pinned Unicode width and clustering model.
//!
//! Section 8 pins this rather than inferring it from a library name: ambiguous characters occupy
//! one cell, combining characters add none, and the table revision is a release-profile pin. A
//! terminal state library that clusters differently cannot serve the profile without a qualified
//! change, so the model is stated here and checked against the pinned library by fixture.

use wezterm_term::UnicodeVersion;

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
    /// Whether a patch is required on top of the revision.
    pub patch_required: bool,
    /// How the profile keeps the library inside its bounds.
    pub notes: &'static [&'static str],
}

/// The qualification record for the pinned revision.
pub const LIBRARY: LibraryQualification = LibraryQualification {
    repository: "https://github.com/wezterm/wezterm",
    revision: "699fd77b44641c43476c945054cfae6518dbd632",
    patch_required: false,
    notes: &[
        "The revision accepts already-parsed actions, so the engine parses once and the library \
         never re-frames a byte. That is what makes a second parse unnecessary rather than \
         merely discouraged.",
        "The width model is configuration, not a fork: generation 9 with narrow ambiguous \
         characters is exactly the pinned kr-vt/1 model.",
        "Grapheme clustering, in-band resize and DECCOLM never reach the library, because the \
         policy layer classifies them before the reducer sees anything. The library's own support \
         for them is therefore not part of the profile.",
        "Raster graphics are disabled in configuration and no image sequence is ever forwarded, \
         so the library's sixel, iTerm2 and Kitty image paths stay unreachable.",
        "The library is built with a writer that accepts no bytes. Every reply comes from the \
         query broker, and the fixtures fail if the library ever writes one.",
    ],
};
