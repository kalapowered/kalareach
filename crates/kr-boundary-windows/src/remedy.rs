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
    /// A program holds it open, so the handle could not be had. The text carries the platform's
    /// error. Closing the program cures it, and nothing says who made the entry.
    Held(String),
    /// The entry's own list refuses the administrator's open. The installation's lists never do, so
    /// it did not make the entry. The text carries the platform's error.
    Refused(String),
    /// The handle could not be opened or read for another reason, so nothing is known of who made
    /// it. The text carries the platform's error.
    Unknown(String),
}

/// The origin that an open which failed with this platform error number shows: a sharing or lock
/// violation is a program that holds it, an access error is a list that refuses, and any other
/// error shows nothing. `text` is the error as it is shown to the person.
#[must_use]
pub fn origin_of_open_error(code: u32, text: &str) -> Origin {
    const ERROR_ACCESS_DENIED: u32 = 5;
    const ERROR_SHARING_VIOLATION: u32 = 32;
    const ERROR_LOCK_VIOLATION: u32 = 33;
    match code {
        ERROR_ACCESS_DENIED => Origin::Refused(text.to_owned()),
        ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION => Origin::Held(text.to_owned()),
        _ => Origin::Unknown(text.to_owned()),
    }
}

/// What an entry of the data directory is, by the name the layout gives it and the place it is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    /// The manifest.
    Manifest,
    /// The earlier-state record.
    Prior,
    /// A replacement of the manifest that a crash or a failed write left.
    Replacement,
    /// The staging directory.
    Staging,
    /// The journal's directory.
    Journal,
    /// The directory of the private roots.
    Run,
    /// A journal file in the journal's directory.
    JournalFile,
    /// A private root that a journal names as unfinished work.
    NamedRoot,
    /// A private root that no journal names.
    UnnamedRoot,
    /// Anything else: a name the layout does not give, or what is inside `staging`.
    Other,
}

/// What the person is told to do about one refused entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Remedy {
    /// Remove the entry: it is no record of the layout, or the system's class owns it and nothing
    /// is recorded about it (no manifest, or a root that no journal names).
    Remove,
    /// Correct the entry's owner and list: the system's class owns it and a manifest is there.
    Correct,
    /// Move the entry out of the data directory: the handle shows, or the entry's own list shows,
    /// that the installation did not make it, or nothing shows who made it.
    MoveAside,
    /// Close the program that holds the entry open: nothing says who made it until it is read.
    Unreadable,
}

/// The remedy for a refused entry of the given kind, from what its handle showed (`origin`) and
/// from the lookup of the manifest. A record is corrected into place only when its handle shows the
/// system's class and a manifest may be there; it is removed only when its handle shows the system's
/// class and nothing records it. A name that the layout does not give is removed whatever its
/// handle showed.
#[must_use]
pub fn choose(kind: EntryKind, origin: &Origin, manifest: &Presence) -> Remedy {
    if kind == EntryKind::Other {
        return Remedy::Remove;
    }
    match origin {
        Origin::Foreign | Origin::Refused(_) | Origin::Unknown(_) => Remedy::MoveAside,
        Origin::Held(_) => Remedy::Unreadable,
        Origin::System if kind == EntryKind::UnnamedRoot => Remedy::Remove,
        Origin::System if matches!(manifest, Presence::Absent) => Remedy::Remove,
        Origin::System => Remedy::Correct,
    }
}

/// The words that end the refusal of an entry: the one remedy, with what the next run then finds.
/// The manifest and the journal are said to stay only where a manifest is there and the entry is
/// not the journal; "the next run makes it new" is said only of what the installation makes.
#[must_use]
pub fn ending(
    entry: &std::path::Path,
    remedy: Remedy,
    origin: &Origin,
    kind: EntryKind,
    manifest: &Presence,
) -> String {
    let entry = entry.display();
    match remedy {
        Remedy::Remove => {
            if matches!(manifest, Presence::Present) && kind != EntryKind::Journal {
                format!(
                    "Remove {entry}, and nothing else, then run the setup program again: the manifest and the journal stay where they are."
                )
            } else {
                format!("Remove {entry}, and nothing else, then run the setup program again.")
            }
        }
        Remedy::MoveAside => {
            let basis = match origin {
                Origin::Refused(error) => format!(
                    "The permission list of {entry} refuses the Administrators group ({error}), which no list of the installation's does, so the installation did not make it."
                ),
                Origin::Unknown(error) => format!(
                    "Nothing shows who made {entry}, because it could not be read ({error})."
                ),
                _ => format!("The handle of {entry} shows that the installation did not make it."),
            };
            let next = match kind {
                EntryKind::Manifest => {
                    "The directory then holds no manifest, and the next run refuses what else is in it: with no manifest nothing records those entries, and it names each to remove."
                }
                EntryKind::Prior | EntryKind::Staging | EntryKind::Journal | EntryKind::Run => {
                    "The next run finds the entry absent and makes it new."
                }
                EntryKind::Replacement
                | EntryKind::JournalFile
                | EntryKind::NamedRoot
                | EntryKind::UnnamedRoot => {
                    "The next run finds the entry absent, and the installation does not make it again."
                }
                EntryKind::Other => "The next run finds the entry absent.",
            };
            format!(
                "{basis} Do not correct its content into place unless you know that your own installation wrote it, and do not remove it. Move it aside: out of the data directory, to a folder that is not inside it (a new name beside it is a name the layout does not give, and the next run asks you to remove that), then run the setup program again. {next}"
            )
        }
        Remedy::Unreadable => format!(
            "Nothing shows who made {entry}, because a program holds it open and it could not be read. Do not correct its owner or its list, and do not remove it: either would hide what it is. Close the program that holds it open, then run the setup program again, which reads it again."
        ),
        Remedy::Correct => format!(
            "Correct what the reason names (the Administrators group, or the system, owns it, and the system and the Administrators group are the only entries of its list), then run the setup program again. Do not remove {entry}: the manifest and the journal record what is installed and stay where they are."
        ),
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
    /// The folder could not be opened to be checked, for a reason that is no program holding it
    /// open (that is [`ParentCure::Close`]): nothing shows who made it, so it is neither corrected
    /// nor removed, and moving it aside keeps everything in it.
    Unreadable,
}

/// The words that tell the person what to do about a refused folder above the data directory, one
/// remedy for the state its handle and a lookup showed.
#[must_use]
pub fn parent_advice(cure: &ParentCure) -> String {
    match cure {
        ParentCure::Unreadable => "Nothing shows who made this folder, because it could not be opened to be checked. Do not correct its owner or its list, and do not remove it: either would hide what it is. Move the folder aside (rename it, which keeps everything in it), then run the setup program again: the installation makes the folder new.".to_owned(),
        ParentCure::Close => "Close the program that holds it open, then run the setup program again: a change of its owner or its list does not close a handle. Do not remove it.".to_owned(),
        ParentCure::MoveAside => "The installation did not make this folder, and it can hold files that another account wrote. Do not correct its content into place unless you know that your own installation wrote it. Move the folder aside (rename it, which keeps everything in it), then run the setup program again: the installation makes the folder new.".to_owned(),
        ParentCure::Correct(Presence::Unknown(error)) => format!("Whether it holds the data directory could not be read ({error}), so removal is not offered: it can hold the manifest, the journals and the private roots of an installation. Correct it instead: give it to the Administrators group or the system, with a protected list that only the system and the Administrators group can change, then run the setup program again."),
        ParentCure::Correct(Presence::Present) => "Do not remove it: it holds the data directory, with the manifest, the journals and the private roots of an installation, and removing it would destroy what they say. Correct it instead: give it to the Administrators group or the system, with a protected list that only the system and the Administrators group can change, then run the setup program again.".to_owned(),
        ParentCure::Correct(Presence::Absent) => "It holds no data directory, so removing it loses nothing. Remove the folder, then run the setup program again.".to_owned(),
    }
}
