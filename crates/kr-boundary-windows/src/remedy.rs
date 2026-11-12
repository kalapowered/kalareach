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

/// What a refusal of the folder above the data directory is cured by, which its reason decides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParentCure {
    /// Another program holds the folder open: closing that program cures it, and a change of owner
    /// or list does not.
    Close,
    /// The handle shows that the installation did not make the folder (a link, not a folder, or an
    /// owner that is not the system's class): move it aside, and do not correct it into place.
    MoveAside,
    /// The system's class owns it and its list is wrong: correct the list. Whether it holds the
    /// data directory is known only from a lookup, which decides whether removal is offered.
    Correct(Presence),
}

/// The words that tell the person what to do about a refused folder above the data directory, one
/// remedy for the state its handle and a lookup showed.
#[must_use]
pub fn parent_advice(cure: &ParentCure) -> String {
    match cure {
        ParentCure::Close => "Close the program that holds it open, then run the setup program again: a change of its owner or its list does not close a handle. Do not remove it.".to_owned(),
        ParentCure::MoveAside => "The installation did not make this folder, and it can hold files that another account wrote. Do not correct its content into place unless you know that your own installation wrote it. Move the folder aside (rename it, which keeps everything in it), then run the setup program again: the installation makes the folder new.".to_owned(),
        ParentCure::Correct(Presence::Unknown(error)) => format!("Whether it holds the data directory could not be read ({error}), so removal is not offered: it can hold the manifest, the journals and the private roots of an installation. Correct it instead: give it to the Administrators group or the system, with a protected list that only the system and the Administrators group can change, then run the setup program again."),
        ParentCure::Correct(Presence::Present) => "Do not remove it: it holds the data directory, with the manifest, the journals and the private roots of an installation, and removing it would destroy what they say. Correct it instead: give it to the Administrators group or the system, with a protected list that only the system and the Administrators group can change, then run the setup program again.".to_owned(),
        ParentCure::Correct(Presence::Absent) => "It holds no data directory, so removing it loses nothing. Remove the folder, then run the setup program again.".to_owned(),
    }
}
