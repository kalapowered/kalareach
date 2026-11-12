//! What a refusal of an entry of the boundary's data directory tells the person to do.
//!
//! The remedy comes from two facts that a lookup or the entry's own handle showed, and never from
//! the words of the reason that refused it:
//!
//! - whether the manifest is there ([`Presence`]), and
//! - who made the entry, as its handle shows it ([`Origin`]): the system's class, another account
//!   (an owner that is neither the system nor the Administrators, a link, or a second name), or
//!   nothing at all, because the handle could not be opened or read.
//!
//! An entry that the layout gives as a record is corrected into place only when its handle shows the
//! system's class and the manifest is not confirmed absent, since correcting what another account
//! wrote would make it the installation's own record. It is removed only when it is no record of
//! the layout, or when the manifest is confirmed absent and the handle shows the system's class.
//! When nothing is known of who made it, neither is offered.

/// Whether something is there, as a lookup shows it: confirmed absent only by an answer of not
/// found. Any other error leaves it unknown, and nothing that could destroy a record is offered
/// then.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Presence {
    /// The lookup found it.
    Present,
    /// The lookup answered that it is not there.
    Absent,
    /// The lookup failed for another reason, which the text carries.
    Unknown(String),
}

/// Who made an entry, as its own handle shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    /// One name, no link, and an owner of the system's class (the system or the Administrators).
    System,
    /// The installation did not make it: another account owns it, it is a link, it is not the kind
    /// of object the installation makes there, or a file has more than one name.
    Foreign,
    /// The handle could not be opened or read, so nothing is known of who made it. The text carries
    /// the platform's error.
    Unknown(String),
}

/// What the person is told to do about one refused entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Remedy {
    /// Remove the entry: it is no record of the layout, or the manifest is confirmed absent and the
    /// system's class owns it, so no installation's records are in it.
    Remove,
    /// Correct the entry's owner and list: the system's class owns it and a manifest is there.
    Correct,
    /// Move the entry out of the data directory: the handle shows that the installation did not make
    /// it, so it is neither removed nor corrected into place.
    MoveAside,
    /// Neither remove nor correct: nothing is known of who made it, so the entry is read again once
    /// what stops the reading is gone.
    Unreadable,
}

/// The remedy for a refused entry. `is_record` says whether the layout gives the name as a record or
/// a directory of records, `origin` is what the entry's handle showed, and `manifest` is the
/// lookup of the manifest.
#[must_use]
pub fn choose(is_record: bool, origin: &Origin, manifest: &Presence) -> Remedy {
    if !is_record {
        return Remedy::Remove;
    }
    match origin {
        Origin::Foreign => Remedy::MoveAside,
        Origin::Unknown(_) => Remedy::Unreadable,
        Origin::System if matches!(manifest, Presence::Absent) => Remedy::Remove,
        Origin::System => Remedy::Correct,
    }
}
