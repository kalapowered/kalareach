//! The five normative sequence classes.
//!
//! Section 8 fixes the vocabulary: every byte the terminal engine reads belongs to exactly one
//! class, and the class decides what happens to it. Nothing is "passed through" because nobody
//! recognised it; an unrecognised sequence is [`SequenceClass::Extension`], which is consumed.

use core::fmt;

/// The class of one lexed sequence.
///
/// | Class | Letter | What happens |
/// | --- | --- | --- |
/// | [`Display`](SequenceClass::Display) | `D` | Applied to the canonical grid; original bytes forwarded in direct mode |
/// | [`Mode`](SequenceClass::Mode) | `M` | State tracked and forwarded live |
/// | [`Query`](SequenceClass::Query) | `Q` | Consumed; the worker is the only responder |
/// | [`SideEffect`](SequenceClass::SideEffect) | `S` | Consumed; routed to one named destination under policy |
/// | [`Extension`](SequenceClass::Extension) | `X` | Consumed with a rate-limited diagnostic |
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SequenceClass {
    /// `D`: display output. Tracked in the canonical grid and forwarded unchanged in direct mode.
    Display,
    /// `M`: a mode change. Tracked and forwarded live.
    Mode,
    /// `Q`: a query. Consumed here; the query broker is the sole responder.
    Query,
    /// `S`: a side effect. Consumed here and routed to one named destination under host policy.
    SideEffect,
    /// `X`: an extension or an unclassified sequence. Consumed, with a rate-limited diagnostic.
    Extension,
}

impl SequenceClass {
    /// The single letter section 8 uses for this class.
    #[must_use]
    pub const fn letter(self) -> char {
        match self {
            Self::Display => 'D',
            Self::Mode => 'M',
            Self::Query => 'Q',
            Self::SideEffect => 'S',
            Self::Extension => 'X',
        }
    }

    /// Parses the single letter section 8 uses for this class.
    #[must_use]
    pub const fn from_letter(letter: char) -> Option<Self> {
        match letter {
            'D' => Some(Self::Display),
            'M' => Some(Self::Mode),
            'Q' => Some(Self::Query),
            'S' => Some(Self::SideEffect),
            'X' => Some(Self::Extension),
            _ => None,
        }
    }

    /// Whether the canonical grid reducer may apply this class at all.
    ///
    /// Only `D` and `M` reach the grid. A snapshot therefore replays `D`/`M` state and never
    /// `Q`/`S` traffic.
    #[must_use]
    pub const fn reaches_grid(self) -> bool {
        matches!(self, Self::Display | Self::Mode)
    }
}

impl fmt::Display for SequenceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Display => "D",
            Self::Mode => "M",
            Self::Query => "Q",
            Self::SideEffect => "S",
            Self::Extension => "X",
        })
    }
}
