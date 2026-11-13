//! The boundary of the network door: where an answer a service gave goes into what a device is
//! told.
//!
//! The network door asks a decision of its own before it writes a kept answer (the grant's read
//! right, the clock lease), so it takes an answer from its service together with where the answer
//! came from and ends in the decision the answer is written under.

use super::{Given, Origin, Recorded};

/// What a service gave, noting in `origin` when the service read it from a record, or read the
/// record and withheld it.
pub(crate) fn noting<T>(origin: &mut Origin, given: Given<T>) -> T {
    origin.note(given.origin());
    given.into_answer()
}

/// What a lookup read from a record, once the decision this door writes it under has been asked.
///
/// The door asks it (`kept_answer`'s check, or a read right) before it calls this, and tells the
/// device that the answer is a read of a record whatever the record holds.
pub(crate) fn kept<T>(recorded: Recorded<T>) -> T {
    recorded.copied().into_answer()
}
