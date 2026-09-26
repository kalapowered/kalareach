//! Choosing the palette a new session starts with.
//!
//! Section 8 fixes a session's palette at creation and records where it came from. There are three
//! honest answers: the profile's own default, one of the two presets, and the foreground and
//! background the terminal the person is sitting at reported during a bounded probe. Only the last
//! of those needs a terminal, which is why an invisible creation cannot ask for it: colours
//! attributed to a probe nobody ran would be a provenance the session made up.

use kr_client::shown::Shown;
use kr_protocol::session::{PalettePreset, PaletteRequest, Presentation, ProbedPalette};

use crate::attach::RestorationGuard;
use crate::error::{CliError, Result};
use crate::terminal::ControllingTerminal;

/// What the palette this session starts with cost to establish.
#[derive(Clone, PartialEq, Eq)]
pub struct Chosen {
    /// The palette the create request carries.
    pub palette: PaletteRequest,
    /// What the person typed while the terminal was being asked, in the order they typed it.
    ///
    /// Section 8 keeps this separate rather than discarding it or letting it pass for a reply. It
    /// is the first input the attachment that follows forwards, so a person who started typing
    /// before the prompt appeared gets what they typed.
    pub typed: Vec<u8>,
}

impl std::fmt::Debug for Chosen {
    /// The palette, and how many bytes were typed while it was chosen. Never those bytes.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Chosen")
            .field("palette", &self.palette)
            .field("typed", &self.typed.len())
            .finish()
    }
}

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
            _ => Err(CliError::Usage(Shown::said(
                "--palette takes light, dark or probe",
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
pub fn resolve(choice: PaletteChoice, presentation: Presentation) -> Result<Chosen> {
    let preset = |preset| {
        Ok(Chosen {
            palette: PaletteRequest::Preset(preset),
            typed: Vec::new(),
        })
    };
    match choice {
        PaletteChoice::Light => preset(PalettePreset::Light),
        PaletteChoice::Dark => preset(PalettePreset::Dark),
        PaletteChoice::Probe => {
            if presentation == Presentation::Invisible {
                return Err(CliError::Usage(Shown::said(
                    "--palette probe asks this terminal for its colours, and an invisible session \
                     has no terminal; choose light or dark",
                )));
            }
            probed()
        }
    }
}

/// The questions this exchange asks, in the order they are written.
///
/// The two colours and the terminator, and nothing else. A session's palette is the only thing
/// being established here, and a question a profile does not document an answer to is a question
/// this command has no business writing into somebody's stream.
const QUESTIONS: &[kr_term::probe::ProbeItem] = &[
    kr_term::probe::ProbeItem::Foreground,
    kr_term::probe::ProbeItem::Background,
    kr_term::probe::ProbeItem::DeviceAttributes,
];

/// Asks this terminal for its own default foreground and background.
///
/// The same bounded exchange an attach runs: one second for the whole of it, the replies never
/// reach an application, and the typing around them comes back. The exchange puts this terminal
/// into raw mode to read the answers, so a guard holds its state first: a process killed in the
/// middle of the exchange must still leave a terminal somebody can put back.
fn probed() -> Result<Chosen> {
    let terminal = ControllingTerminal::open()?;
    let context = crate::terminal::input_context(&terminal);
    let saved = terminal.modes()?;
    let guard = RestorationGuard::arm(
        &crate::attach::guard_program(),
        &terminal,
        &crate::terminal::SavedModes::from_state(&saved),
    )?;
    let probe = match terminal.probe_asking(context, QUESTIONS) {
        Ok(probe) => {
            // The exchange put the terminal back itself, so the guard owes only the keyboard.
            guard.release();
            probe
        }
        Err(error) => {
            // It did not, or could not say whether it did. The guard puts the whole terminal back,
            // and this waits for it rather than leaving a person to find out.
            guard.hand_back();
            return Err(error);
        }
    };
    let Some((foreground, background)) = probe.palette else {
        // The exchange finished, so the person's own typing came back with it, and this refusal is
        // where it stops: no session exists to forward it to. They are owed the number.
        let _owed = crate::session::UndeliveredTyping::new(probe.typed.len());
        return Err(CliError::TerminalProbeFailed(Shown::said(
            "this terminal did not report both its default foreground and its default background, \
             so there is no shared palette to record; choose light or dark",
        )));
    };
    Ok(Chosen {
        palette: PaletteRequest::Probe(ProbedPalette {
            foreground: colour(foreground),
            background: colour(background),
        }),
        typed: probe.typed,
    })
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
        assert_eq!(light.palette, PaletteRequest::Preset(PalettePreset::Light));
        assert!(
            light.typed.is_empty(),
            "and it asks the terminal nothing, so there is nothing to have been typed around it"
        );
        let Ok(dark) = resolve(PaletteChoice::Dark, Presentation::Invisible) else {
            panic!("a preset needs no terminal");
        };
        assert_eq!(dark.palette, PaletteRequest::Preset(PalettePreset::Dark));
    }

    /// The exchange asks for exactly the two colours a session's palette is made of.
    #[test]
    fn the_creation_exchange_asks_for_the_colours_and_nothing_else() {
        use kr_term::probe::ProbeItem;

        assert_eq!(
            QUESTIONS,
            &[
                ProbeItem::Foreground,
                ProbeItem::Background,
                ProbeItem::DeviceAttributes
            ],
            "the two colours, and the terminator that ends the exchange"
        );
        assert!(
            QUESTIONS.contains(&ProbeItem::Foreground)
                && QUESTIONS.contains(&ProbeItem::Background),
            "a exchange that asked neither could never establish a palette"
        );
        assert_eq!(
            QUESTIONS.last(),
            Some(&ProbeItem::DeviceAttributes),
            "device attributes are last, and nothing may follow them"
        );
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
