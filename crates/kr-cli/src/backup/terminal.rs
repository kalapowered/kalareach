//! The terminal calls `kr backup setup` makes, one half for each family of systems.
//!
//! | Item | What it does |
//! | --- | --- |
//! | [`keep_out_of_a_dump`] | Keeps this process out of the dump a crash would make, before the seed exists: a core dump on Unix; on Windows the narrower guard against Windows Error Reporting, as the Windows module says |
//! | [`Terminal`] | Holds the terminal's modes as found and puts them back, with the waiting input discarded |
//! | [`open_output`] | Opens the terminal itself for writing, so the kit reaches it through no buffer of ours |
//! | `Prompt` (Windows only) | The console's modes while the kit or an answer is typed, and what is read from it |
//! | [`Turn`] | What one read of the terminal found: text, a quiet turn, or input that holds no text |
//! | [`KIT_FOLLOWS`] | What is said before the kit, including how long the console keeps it |

/// What one read of a terminal found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Turn {
    /// Text, as many bytes as are given.
    Text(usize),
    /// A turn that passed with no input at all: the input has stopped, for now.
    Quiet,
    /// The read met input that holds no text and stopped at its own limit on work, with more
    /// possibly still to come. The input has not stopped, so a caller that is waiting for it to
    /// stop goes on, and one that has checks of its own makes them first.
    Busy,
}

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{KIT_FOLLOWS, Terminal, keep_out_of_a_dump, open_output};
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{
    KIT_FOLLOWS, Prompt, Terminal, discard_typed_ahead, keep_out_of_a_dump, open_output, read_line,
};
