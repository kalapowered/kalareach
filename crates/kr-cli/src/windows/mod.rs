//! What only Windows has in this command: console key records, and the console modes a session
//! must be given back.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`records`] | Reading `ReadConsoleInputW` records from the console and turning them into the documented encoding |
//!
//! Section 8 puts a local attach client on this platform on a different footing from every other
//! one. A terminal emulator on Unix hands this command bytes, and bytes are all there ever were.
//! A Windows console hands it *records*: a virtual key, the scan code the keyboard sent, one
//! UTF-16 code unit, whether the key went down or came up, the modifier state and a repeat count.
//! Turning those into bytes loses the half of them that bytes cannot carry, and the backend in the
//! session may have asked for exactly that half.
//!
//! So this reads records when the session's backend asked for them, and reads bytes when it did
//! not. Neither path pretends to be the other: [`kr_term::win32::Fidelity`] is what says which one
//! the input came through, and it is reported rather than assumed.

#![cfg(windows)]

pub mod records;
