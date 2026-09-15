//! The `kr-vt/1` virtual terminal profile.
//!
//! The session advertises this profile, not the terminal a person happens to be attached from. A
//! later attachment may come from a different terminal, so the child process must never learn the
//! physical identity of the current one.
//!
//! Everything a query can reveal is a constant here or a field of the canonical state. Nothing is
//! inferred from an observed output sequence: observing a sequence is not evidence that the
//! profile supports it.

use crate::unicode::UnicodeModel;

/// The profile name carried in the identity reply.
pub const PROFILE_NAME: &str = "kr-vt";

/// The profile revision. A new sequence class or capability needs a new revision before release.
pub const PROFILE_REVISION: u32 = 1;

/// The value of `TERM` in a session's environment.
pub const TERM: &str = "xterm-256color";

/// The XTVERSION reply body, without the `DCS > |` introducer and the terminator.
pub const XTVERSION_IDENTITY: &str = "KalaReach(kr-vt/1)";

/// The DA3 unit identifier, eight hex digits: `KR` followed by the profile revision.
pub const DA3_UNIT_ID: &str = "4B520001";

/// Primary device attributes, as the parameter list of the `CSI ? ... c` reply.
///
/// * `62` — VT220-class device, the level the profile implements.
/// * `1` — 132-column mode, which the canonical grid supports as an ordinary resize.
/// * `22` — ANSI colour.
///
/// Two absences are deliberate. Sixel (`4`) is missing because terminal raster graphics stay
/// disabled, and selective erase (`6`) is missing because nothing in the profile implements DECSCA;
/// an application that asks is told no rather than left to find out by trying.
pub const DA1_PARAMS: &[u16] = &[62, 1, 22];

/// Secondary device attributes: device class, firmware revision and cartridge.
///
/// The class says what the profile behaves like; it is not an identity. The identity lives in
/// XTVERSION, which names KalaReach outright.
pub const DA2_PARAMS: &[u16] = &[41, PROFILE_REVISION as u16, 0];

/// A capability the profile advertises, with the name used in the capability manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    /// Cursor movement, positioning and shape.
    CursorOperations,
    /// Primary and alternate screen buffers.
    BothScreenBuffers,
    /// Top/bottom and left/right scroll regions.
    ScrollRegions,
    /// Bracketed paste, DEC mode 2004.
    BracketedPaste,
    /// Focus reporting, DEC mode 1004.
    FocusEvents,
    /// SGR mouse reporting, DEC mode 1006, with the tracking modes.
    SgrMouse,
    /// OSC 8 hyperlinks.
    Hyperlinks,
    /// Synchronised output, DEC mode 2026.
    SynchronisedOutput,
    /// xterm modifier keys, including modifyOtherKeys and meta mode 1034.
    XtermModifierKeys,
    /// The qualified subset of the Kitty keyboard protocol.
    KittyKeyboardSubset,
    /// 24-bit colour in SGR.
    TrueColour,
    /// The 256-colour palette and its dynamic colours.
    IndexedPalette,
}

impl Capability {
    /// The manifest name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CursorOperations => "cursor-operations",
            Self::BothScreenBuffers => "both-screen-buffers",
            Self::ScrollRegions => "scroll-regions",
            Self::BracketedPaste => "bracketed-paste",
            Self::FocusEvents => "focus-events",
            Self::SgrMouse => "sgr-mouse",
            Self::Hyperlinks => "hyperlinks",
            Self::SynchronisedOutput => "synchronised-output",
            Self::XtermModifierKeys => "xterm-modifier-keys",
            Self::KittyKeyboardSubset => "kitty-keyboard-subset",
            Self::TrueColour => "true-colour",
            Self::IndexedPalette => "indexed-palette",
        }
    }
}

/// Every capability kr-vt/1 advertises.
pub const CAPABILITIES: &[Capability] = &[
    Capability::CursorOperations,
    Capability::BothScreenBuffers,
    Capability::ScrollRegions,
    Capability::BracketedPaste,
    Capability::FocusEvents,
    Capability::SgrMouse,
    Capability::Hyperlinks,
    Capability::SynchronisedOutput,
    Capability::XtermModifierKeys,
    Capability::KittyKeyboardSubset,
    Capability::TrueColour,
    Capability::IndexedPalette,
];

/// A feature kr-vt/1 deliberately does not have, and the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Withheld {
    /// What is withheld.
    pub feature: &'static str,
    /// Why.
    pub reason: &'static str,
}

/// Features the profile refuses, with their reasons.
///
/// These are not gaps waiting to be filled by a library that happens to implement them. Each one
/// would make a promise across the projection boundary that the profile cannot keep.
pub const WITHHELD: &[Withheld] = &[
    Withheld {
        feature: "sixel-graphics",
        reason: "terminal raster graphics are disabled; images travel through the file protocol",
    },
    Withheld {
        feature: "kitty-graphics",
        reason: "terminal raster graphics are disabled; images travel through the file protocol",
    },
    Withheld {
        feature: "iterm2-inline-images",
        reason: "terminal raster graphics are disabled; images travel through the file protocol",
    },
    Withheld {
        feature: "grapheme-clustering-mode-2027",
        reason: "a physical terminal on the other side may cluster differently",
    },
    Withheld {
        feature: "in-band-resize-mode-2048",
        reason: "resize travels over the PTY or ConPTY notification, not a second in-band channel",
    },
    Withheld {
        feature: "deccolm-mode-3",
        reason: "rows and columns belong to the geometry owner",
    },
    Withheld {
        feature: "selective-erase",
        reason: "DECSCA is not implemented, so DA1 does not claim it",
    },
    Withheld {
        feature: "title-reporting",
        reason: "reporting the title back into the stream lets output become input",
    },
    Withheld {
        feature: "answerback",
        reason: "kr-vt/1 has no answerback string, so ENQ is answered with silence",
    },
];

/// The complete profile description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    /// The Unicode width and clustering model.
    pub unicode: UnicodeModel,
}

impl Profile {
    /// The kr-vt/1 profile.
    pub const KR_VT_1: Self = Self {
        unicode: UnicodeModel::KR_VT_1,
    };

    /// The profile identity string, `kr-vt/1`.
    #[must_use]
    pub fn identity(&self) -> String {
        format!("{PROFILE_NAME}/{PROFILE_REVISION}")
    }

    /// Whether the profile advertises `capability`.
    #[must_use]
    pub fn advertises(&self, capability: Capability) -> bool {
        CAPABILITIES.contains(&capability)
    }
}

impl Default for Profile {
    fn default() -> Self {
        Self::KR_VT_1
    }
}
