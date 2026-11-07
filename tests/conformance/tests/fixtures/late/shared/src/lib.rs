//! The file the macro writes while this library compiles, which the package's two test programs
//! read through their own expansion of the macro.

/// What the macro wrote.
pub static WRITTEN: &[u8] = embed::embed!();
