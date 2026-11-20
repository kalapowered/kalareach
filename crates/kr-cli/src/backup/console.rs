//! The Windows console as a dialogue holds it.
//!
//! A dialogue that reads lines needs line input, echo and processed input, and a console that
//! another program left raw has none of them. The guard sets them, and puts both mode words back
//! when it is dropped, attempting both even if one fails, and then throws away what is still
//! waiting in the console's queue, as a separate step, so that text pasted past the last answer
//! never reaches the shell. It writes no sequence: a console without virtual-terminal output would
//! show one as text.
//!
//! The guarantee is for the endings that run this drop, and for input already in the console's
//! queue when the discard succeeds. It does not cover a forced end, a crash, input still in the
//! pseudo-console's pipe after the discard, or the console's command history; and putting the modes
//! back or throwing the input away can fail, which nothing in a drop can say.

use crate::error::{CliError, Result};
use crate::platform::{ControllingTerminal, SavedModes};

/// The console's modes as they were found, and the console they are put back on.
pub struct Console {
    terminal: ControllingTerminal,
    saved: SavedModes,
}

impl Console {
    /// Takes hold of the console: all three standard handles must be one, and its modes are set
    /// for a dialogue.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::NotATerminal`] when a standard handle is not a console, and a terminal
    /// failure when the modes cannot be read or set.
    pub fn hold() -> Result<Self> {
        if !ControllingTerminal::standard_handles_are_a_console() {
            return Err(CliError::NotATerminal);
        }
        let (terminal, saved) = hold_over(
            ControllingTerminal::open,
            ControllingTerminal::enter_dialogue_modes,
        )?;
        Ok(Self { terminal, saved })
    }
}

/// Opens the console with `open` and sets its modes with `enter`. A failure of either is the
/// person's to read as the call that failed said it: a mode that cannot be read and a mode that
/// cannot be set are not the same fault.
fn hold_over<T>(
    open: impl FnOnce() -> Result<T>,
    enter: impl FnOnce(&T) -> Result<SavedModes>,
) -> Result<(T, SavedModes)> {
    let terminal = open()?;
    let saved = enter(&terminal)?;
    Ok((terminal, saved))
}

impl Drop for Console {
    fn drop(&mut self) {
        let _ = self.terminal.put_modes_back(&self.saved);
        let _ = self.terminal.discard_input();
    }
}

#[cfg(test)]
mod tests {
    use kr_client::shown::{Said as _, Shown};

    use super::*;

    /// A console whose modes cannot be set gives the person the words of the failed call, and one
    /// whose modes cannot be read gives theirs; neither is changed into the other.
    #[test]
    fn a_console_that_cannot_be_held_says_what_its_own_call_said() {
        let Err(set) = hold_over(
            || Ok(()),
            |()| {
                Err(CliError::Terminal(Shown::said(
                    "set the console's mode: the console refused",
                )))
            },
        ) else {
            panic!("a failed set held the console");
        };
        assert_eq!(
            set.said().as_str(),
            "set the console's mode: the console refused"
        );

        let Err(read) = hold_over(
            || Ok(()),
            |()| {
                Err(CliError::Terminal(Shown::said(
                    "read the console's mode: the console did not answer",
                )))
            },
        ) else {
            panic!("a failed read held the console");
        };
        assert_eq!(
            read.said().as_str(),
            "read the console's mode: the console did not answer"
        );

        let Err(open) = hold_over(
            || -> Result<()> { Err(CliError::NotATerminal) },
            |()| unreachable!("nothing is set on a console that did not open"),
        ) else {
            panic!("a console that did not open was held");
        };
        assert!(matches!(open, CliError::NotATerminal));
    }
}
