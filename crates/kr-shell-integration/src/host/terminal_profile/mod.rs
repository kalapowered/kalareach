//! The optional terminal profile: one profile named `KalaReach` in one terminal emulator's own
//! profile mechanism, whose command is `kr new --attach --hold-on-failure`, so that each window or
//! tab opened through it is a session of its own.
//!
//! The profile is available and is never made the emulator's default, and nothing here writes a
//! shell startup file. What an install wrote is kept in a record of its own ([`record`]) that is
//! written before the profile, and removal works from that record alone.

pub mod record;

use serde::{Deserialize, Serialize};

/// A terminal emulator a profile can be written into.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProfileTerminal {
    /// iTerm2 (macOS): a Dynamic Profiles file.
    #[serde(rename = "iterm2")]
    Iterm2,
    /// Terminal.app (macOS): an entry of its `Window Settings` preference.
    #[serde(rename = "apple-terminal")]
    AppleTerminal,
    /// GNOME Terminal (Linux): gsettings.
    #[serde(rename = "gnome-terminal")]
    GnomeTerminal,
    /// Ptyxis (Linux): gsettings.
    #[serde(rename = "ptyxis")]
    Ptyxis,
    /// Konsole (Linux): a profile file.
    #[serde(rename = "konsole")]
    Konsole,
    /// Windows Terminal (Windows): a fragment file.
    #[serde(rename = "windows-terminal")]
    WindowsTerminal,
}

impl ProfileTerminal {
    /// Every emulator, in the order they are listed.
    pub const ALL: [Self; 6] = [
        Self::Iterm2,
        Self::AppleTerminal,
        Self::GnomeTerminal,
        Self::Ptyxis,
        Self::Konsole,
        Self::WindowsTerminal,
    ];

    /// The identifier a person names it by: the one `kr host terminal` prints where it prints one.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Iterm2 => "iterm2",
            Self::AppleTerminal => "apple-terminal",
            Self::GnomeTerminal => "gnome-terminal",
            Self::Ptyxis => "ptyxis",
            Self::Konsole => "konsole",
            Self::WindowsTerminal => "windows-terminal",
        }
    }

    /// The emulator a person's identifier names, or `None` for any other text.
    #[must_use]
    pub fn from_id(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|terminal| terminal.id() == text)
    }
}
