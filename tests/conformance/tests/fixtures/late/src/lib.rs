//! The file the macro writes while this library compiles.

/// What the macro wrote.
pub static WRITTEN: &[u8] = embed::embed!();
