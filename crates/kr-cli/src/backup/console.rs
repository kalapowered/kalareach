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

use kr_client::shown;
use kr_client::shown::Shown;

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
        let terminal = ControllingTerminal::open()?;
        let saved = terminal.enter_dialogue_modes().map_err(|_| {
            CliError::Terminal(shown!(
                "the terminal's modes could not be read: {}",
                Shown::io(&std::io::Error::last_os_error())
            ))
        })?;
        Ok(Self { terminal, saved })
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        let _ = self.terminal.put_modes_back(&self.saved);
        let _ = self.terminal.discard_input();
    }
}
