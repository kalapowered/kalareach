//! Choosing the palette a new session starts with.
//!
//! Section 8 fixes a session's palette at creation and records where it came from. There are three
//! honest answers: the profile's own default, one of the two presets, and the foreground and
//! background the terminal the person is sitting at reported during a bounded probe. Only the last
//! of those needs a terminal, which is why an invisible creation cannot ask for it: colours
//! attributed to a probe nobody ran would be a provenance the session made up.

use kr_protocol::session::{PalettePreset, PaletteRequest, Presentation, ProbedPalette};

use crate::error::{CliError, Result};
use crate::terminal::ControllingTerminal;

/// What `--palette` was given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaletteChoice {
    /// The light preset.
    Light,
    /// The dark preset.
    Dark,
    /// Ask this terminal for its own foreground and background, inside the bounded probe.
    Probe,
}

impl PaletteChoice {
    /// Reads the option's value.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Usage`] for anything else.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "light" => Ok(Self::Light),
            "dark" => Ok(Self::Dark),
            "probe" => Ok(Self::Probe),
            other => Err(CliError::Usage(format!(
                "--palette takes light, dark or probe, not {other}"
            ))),
        }
    }

    /// Returns the value a person typed.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Dark => "dark",
            Self::Probe => "probe",
        }
    }
}

/// Turns the option into the palette a create request carries.
///
/// A preset needs nothing from the terminal. The probe form asks this terminal for its default
/// foreground and background through the same bounded exchange an attach uses, and a terminal that
/// does not answer both has not shared a palette: the failure says so rather than inventing one.
///
/// # Errors
///
/// Returns [`CliError::Usage`] when an invisible creation asks for probed colours, and
/// [`CliError::TerminalProbeFailed`] when this terminal could not be asked or did not answer.
pub fn resolve(choice: PaletteChoice, presentation: Presentation) -> Result<PaletteRequest> {
    match choice {
        PaletteChoice::Light => Ok(PaletteRequest::Preset(PalettePreset::Light)),
        PaletteChoice::Dark => Ok(PaletteRequest::Preset(PalettePreset::Dark)),
        PaletteChoice::Probe => {
            if presentation == Presentation::Invisible {
                return Err(CliError::Usage(
                    "--palette probe asks this terminal for its colours, and an invisible session \
                     has no terminal; choose light or dark"
                        .to_owned(),
                ));
            }
            probed()
        }
    }
}

/// Asks this terminal for its own default foreground and background.
///
/// The same bounded exchange an attach runs: one second for the whole of it, the replies never
/// reach an application, and the typing around them comes back. Nothing else here reads what it
/// found, so the answer this takes is the pair of colours.
fn probed() -> Result<PaletteRequest> {
    let terminal = ControllingTerminal::open()?;
    let context = crate::terminal::input_context(&terminal);
    let probe = terminal.probe(context, None)?;
    let Some((foreground, background)) = probe.palette else {
        return Err(CliError::TerminalProbeFailed(
            "this terminal did not report both its default foreground and its default background, \
             so there is no shared palette to record; choose light or dark"
                .to_owned(),
        ));
    };
    Ok(PaletteRequest::Probe(ProbedPalette {
        foreground: colour(foreground),
        background: colour(background),
    }))
}

/// The wire form of a colour the terminal reported.
const fn colour(value: kr_term::palette::Rgb) -> kr_protocol::projection::Rgb {
    kr_protocol::projection::Rgb {
        red: value.r,
        green: value.g,
        blue: value.b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_option_takes_three_values_and_says_so_for_anything_else() {
        for (value, expected) in [
            ("light", PaletteChoice::Light),
            ("dark", PaletteChoice::Dark),
            ("probe", PaletteChoice::Probe),
        ] {
            assert_eq!(
                PaletteChoice::parse(value).expect("the option takes this value"),
                expected
            );
        }
        let Err(refusal) = PaletteChoice::parse("solarized") else {
            panic!("only three values are taken");
        };
        assert!(
            refusal.to_string().contains("light, dark or probe"),
            "the refusal names what the option takes: {refusal}"
        );
    }

    /// KR-REQ-08.44: a preset is what a no-probe or invisible creation selects.
    #[test]
    fn a_preset_needs_no_terminal_and_carries_its_own_provenance() {
        let Ok(light) = resolve(PaletteChoice::Light, Presentation::Invisible) else {
            panic!("a preset needs no terminal");
        };
        assert_eq!(light, PaletteRequest::Preset(PalettePreset::Light));
        let Ok(dark) = resolve(PaletteChoice::Dark, Presentation::Invisible) else {
            panic!("a preset needs no terminal");
        };
        assert_eq!(dark, PaletteRequest::Preset(PalettePreset::Dark));
    }

    /// KR-REQ-08.44: an invisible creation has no terminal, so it cannot share probed colours.
    #[test]
    fn an_invisible_creation_cannot_ask_for_probed_colours() {
        let Err(refusal) = resolve(PaletteChoice::Probe, Presentation::Invisible) else {
            panic!("an invisible session has no terminal to probe");
        };
        assert!(
            matches!(refusal, CliError::Usage(_)),
            "the refusal is a usage failure: {refusal}"
        );
        assert!(
            refusal.to_string().contains("no terminal"),
            "and it says why: {refusal}"
        );
    }
}
