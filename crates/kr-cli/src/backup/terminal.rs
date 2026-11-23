//! The terminal calls `kr backup setup` makes, one half for each family of systems.
//!
//! | Item | What it does |
//! | --- | --- |
//! | [`keep_out_of_a_dump`] | Keeps this process out of the dump a crash would make, before the seed exists |
//! | [`Terminal`] | Holds the terminal's modes as found and puts them back, with the waiting input discarded |
//! | [`open_output`] | Opens the terminal itself for writing, so the kit reaches it through no buffer of ours |

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{Terminal, keep_out_of_a_dump, open_output};
