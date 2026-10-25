//! What only Windows has in this command: console key records, and the console modes a session
//! must be given back.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`records`] | Reading `ReadConsoleInputW` records from the console and handing them on as the records they are |
//!
//! Section 8 puts a local attach client on this platform on a different footing from every other
//! one. A terminal emulator on Unix hands this command bytes, and bytes are all there ever were.
//! A Windows console hands it *records*: a virtual key, the scan code the keyboard sent, one
//! UTF-16 code unit, whether the key went down or came up, the modifier state and a repeat count.
//! Turning those into bytes loses the half of them that bytes cannot carry, and the backend in the
//! session may have asked for exactly that half.
//!
//! So this reads records and hands them on as they are. What they are sent as is the worker's
//! decision, made where it knows what the session's backend asked for: the documented encoding of
//! each record when the backend asked for records, and legacy VT input when it did not
//! ([`kr_term::win32::records_within`], [`kr_term::win32::legacy_within`]). Neither path pretends to
//! be the other, and a reader that spelled keys itself could not know which one the session needs.

#![cfg(windows)]

pub mod records;
