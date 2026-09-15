//! The canonical session palette.
//!
//! A palette query always describes the session, never the terminal a person happens to be
//! attached from. That matters twice: a client's private colour preferences are not disclosed to
//! the application by accident, and a second attachment from a differently themed terminal does not
//! silently change what the application believes the background is.
//!
//! Where the palette came from is recorded, because "the user's terminal told us during the probe"
//! and "the profile default" are different facts and the session has to be able to say which.

use crate::error::TermError;

/// An sRGB colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rgb {
    /// Red.
    pub r: u8,
    /// Green.
    pub g: u8,
    /// Blue.
    pub b: u8,
}

impl Rgb {
    /// Builds a colour.
    #[must_use]
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    /// The `rgb:RRRR/GGGG/BBBB` form a colour report uses.
    #[must_use]
    pub fn to_report(self) -> String {
        let scale = |v: u8| u16::from(v) * 0x101;
        format!(
            "rgb:{:04x}/{:04x}/{:04x}",
            scale(self.r),
            scale(self.g),
            scale(self.b)
        )
    }

    /// Parses the colour specifications kr-vt/1 accepts: `rgb:R/G/B` with 1 to 4 hex digits per
    /// component, and `#RGB`, `#RRGGBB` or `#RRRRGGGGBBBB`.
    #[must_use]
    pub fn parse(spec: &str) -> Option<Self> {
        if let Some(rest) = spec.strip_prefix("rgb:") {
            let mut parts = rest.split('/');
            let r = scale_component(parts.next()?)?;
            let g = scale_component(parts.next()?)?;
            let b = scale_component(parts.next()?)?;
            if parts.next().is_some() {
                return None;
            }
            return Some(Self::new(r, g, b));
        }
        let hex = spec.strip_prefix('#')?;
        if hex.len() % 3 != 0 || hex.is_empty() || hex.len() > 12 {
            return None;
        }
        let width = hex.len() / 3;
        let r = scale_component(hex.get(0..width)?)?;
        let g = scale_component(hex.get(width..width * 2)?)?;
        let b = scale_component(hex.get(width * 2..)?)?;
        Some(Self::new(r, g, b))
    }
}

fn scale_component(text: &str) -> Option<u8> {
    if text.is_empty() || text.len() > 4 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let value = u32::from_str_radix(text, 16).ok()?;
    let max = (1u32 << (4 * text.len())) - 1;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the quotient of a value by its own maximum, times 255, is at most 255"
    )]
    Some(((value * 255 + max / 2) / max) as u8)
}

/// Where the session's initial palette came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaletteSource {
    /// The profile's own default palette.
    ProfileDefault,
    /// A client's stated foreground and background, shared during the bounded probe.
    ClientPreference,
    /// The light preset, selected for a no-probe or invisible creation.
    LightPreset,
    /// The dark preset, selected for a no-probe or invisible creation.
    DarkPreset,
    /// An authorised, explicit palette change made after creation.
    ExplicitChange,
}

/// The dynamic colours OSC 10 to 19 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicColour {
    /// OSC 10, the default foreground.
    Foreground,
    /// OSC 11, the default background.
    Background,
    /// OSC 12, the cursor colour.
    Cursor,
    /// OSC 13, the mouse pointer foreground.
    PointerForeground,
    /// OSC 14, the mouse pointer background.
    PointerBackground,
    /// OSC 17, the selection background.
    SelectionBackground,
    /// OSC 19, the selection foreground.
    SelectionForeground,
}

impl DynamicColour {
    /// The colour an OSC selector addresses, when kr-vt/1 has one.
    ///
    /// OSC 15, 16 and 18 address Tektronix colours, which the profile has no state for.
    #[must_use]
    pub const fn from_selector(selector: u32) -> Option<Self> {
        match selector {
            10 => Some(Self::Foreground),
            11 => Some(Self::Background),
            12 => Some(Self::Cursor),
            13 => Some(Self::PointerForeground),
            14 => Some(Self::PointerBackground),
            17 => Some(Self::SelectionBackground),
            19 => Some(Self::SelectionForeground),
            _ => None,
        }
    }

    /// The OSC selector for this colour.
    #[must_use]
    pub const fn selector(self) -> u32 {
        match self {
            Self::Foreground => 10,
            Self::Background => 11,
            Self::Cursor => 12,
            Self::PointerForeground => 13,
            Self::PointerBackground => 14,
            Self::SelectionBackground => 17,
            Self::SelectionForeground => 19,
        }
    }

    /// The reset selector, OSC 110 to 119.
    #[must_use]
    pub const fn reset_selector(self) -> u32 {
        self.selector() + 100
    }
}

/// The canonical palette: 256 indexed colours plus the dynamic colours.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Palette {
    indexed: Vec<Rgb>,
    defaults: Vec<Rgb>,
    foreground: Rgb,
    background: Rgb,
    cursor: Rgb,
    pointer_foreground: Rgb,
    pointer_background: Rgb,
    selection_background: Rgb,
    selection_foreground: Rgb,
    source: PaletteSource,
}

/// The sixteen system colours of the profile's dark preset.
const SYSTEM_DARK: [Rgb; 16] = [
    Rgb::new(0x00, 0x00, 0x00),
    Rgb::new(0xcd, 0x00, 0x00),
    Rgb::new(0x00, 0xcd, 0x00),
    Rgb::new(0xcd, 0xcd, 0x00),
    Rgb::new(0x00, 0x00, 0xee),
    Rgb::new(0xcd, 0x00, 0xcd),
    Rgb::new(0x00, 0xcd, 0xcd),
    Rgb::new(0xe5, 0xe5, 0xe5),
    Rgb::new(0x7f, 0x7f, 0x7f),
    Rgb::new(0xff, 0x00, 0x00),
    Rgb::new(0x00, 0xff, 0x00),
    Rgb::new(0xff, 0xff, 0x00),
    Rgb::new(0x5c, 0x5c, 0xff),
    Rgb::new(0xff, 0x00, 0xff),
    Rgb::new(0x00, 0xff, 0xff),
    Rgb::new(0xff, 0xff, 0xff),
];

const CUBE_LEVELS: [u8; 6] = [0x00, 0x5f, 0x87, 0xaf, 0xd7, 0xff];

fn build_indexed() -> Vec<Rgb> {
    let mut colours = Vec::with_capacity(256);
    colours.extend_from_slice(&SYSTEM_DARK);
    for r in CUBE_LEVELS {
        for g in CUBE_LEVELS {
            for b in CUBE_LEVELS {
                colours.push(Rgb::new(r, g, b));
            }
        }
    }
    for step in 0..24u8 {
        let level = 8 + step * 10;
        colours.push(Rgb::new(level, level, level));
    }
    colours
}

impl Palette {
    /// The profile's default palette.
    #[must_use]
    pub fn new(source: PaletteSource) -> Self {
        let indexed = build_indexed();
        let (foreground, background) = match source {
            PaletteSource::LightPreset => (Rgb::new(0x1a, 0x1a, 0x1a), Rgb::new(0xff, 0xff, 0xff)),
            _ => (Rgb::new(0xe5, 0xe5, 0xe5), Rgb::new(0x00, 0x00, 0x00)),
        };
        Self {
            defaults: indexed.clone(),
            indexed,
            foreground,
            background,
            cursor: foreground,
            pointer_foreground: foreground,
            pointer_background: background,
            selection_background: Rgb::new(0x44, 0x44, 0x44),
            selection_foreground: foreground,
            source,
        }
    }

    /// Adopts a client's stated foreground and background as the session's initial palette.
    #[must_use]
    pub fn from_client_preference(foreground: Rgb, background: Rgb) -> Self {
        let mut palette = Self::new(PaletteSource::ClientPreference);
        palette.foreground = foreground;
        palette.background = background;
        palette.cursor = foreground;
        palette.pointer_foreground = foreground;
        palette.pointer_background = background;
        palette.selection_foreground = foreground;
        palette
    }

    /// Where this palette came from.
    #[must_use]
    pub const fn source(&self) -> PaletteSource {
        self.source
    }

    /// Records that an authorised actor changed the palette after creation.
    pub const fn mark_explicit_change(&mut self) {
        self.source = PaletteSource::ExplicitChange;
    }

    /// An indexed colour.
    #[must_use]
    pub fn indexed(&self, index: u8) -> Rgb {
        self.indexed[usize::from(index)]
    }

    /// Sets an indexed colour.
    pub fn set_indexed(&mut self, index: u8, colour: Rgb) {
        self.indexed[usize::from(index)] = colour;
    }

    /// Resets one indexed colour to the profile default.
    pub fn reset_indexed(&mut self, index: u8) {
        self.indexed[usize::from(index)] = self.defaults[usize::from(index)];
    }

    /// Resets every indexed colour.
    pub fn reset_all_indexed(&mut self) {
        self.indexed.clone_from(&self.defaults);
    }

    /// A dynamic colour.
    #[must_use]
    pub const fn dynamic(&self, which: DynamicColour) -> Rgb {
        match which {
            DynamicColour::Foreground => self.foreground,
            DynamicColour::Background => self.background,
            DynamicColour::Cursor => self.cursor,
            DynamicColour::PointerForeground => self.pointer_foreground,
            DynamicColour::PointerBackground => self.pointer_background,
            DynamicColour::SelectionBackground => self.selection_background,
            DynamicColour::SelectionForeground => self.selection_foreground,
        }
    }

    /// Sets a dynamic colour.
    pub const fn set_dynamic(&mut self, which: DynamicColour, colour: Rgb) {
        match which {
            DynamicColour::Foreground => self.foreground = colour,
            DynamicColour::Background => self.background = colour,
            DynamicColour::Cursor => self.cursor = colour,
            DynamicColour::PointerForeground => self.pointer_foreground = colour,
            DynamicColour::PointerBackground => self.pointer_background = colour,
            DynamicColour::SelectionBackground => self.selection_background = colour,
            DynamicColour::SelectionForeground => self.selection_foreground = colour,
        }
    }

    /// Resets a dynamic colour to the profile default for this palette's source.
    pub fn reset_dynamic(&mut self, which: DynamicColour) {
        let defaults = Self::new(self.source);
        self.set_dynamic(which, defaults.dynamic(which));
    }

    /// Parses a colour specification, naming the failure.
    ///
    /// # Errors
    ///
    /// Returns [`TermError::ColourSpec`] when the specification is not one kr-vt/1 accepts.
    pub fn parse_spec(spec: &str) -> Result<Rgb, TermError> {
        Rgb::parse(spec).ok_or_else(|| TermError::ColourSpec {
            spec: spec.to_owned(),
        })
    }
}

impl Default for Palette {
    fn default() -> Self {
        Self::new(PaletteSource::ProfileDefault)
    }
}
