//! The terminal calls `kr backup setup` makes, one half for each family of systems.
//!
//! | Item | What it does |
//! | --- | --- |
//! | [`keep_out_of_a_dump`] | Keeps this process out of the dump a crash would make, before the seed exists |
//! | [`Terminal`] | Holds the terminal's modes as found and puts them back, with the waiting input discarded |
//! | [`open_output`] | Opens the terminal itself for writing, so the kit reaches it through no buffer of ours |
//! | [`KIT_FOLLOWS`] | What is said before the kit, including how long the screen keeps it |

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{KIT_FOLLOWS, Terminal, keep_out_of_a_dump, open_output};
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{KIT_FOLLOWS, Terminal, keep_out_of_a_dump, open_output};
