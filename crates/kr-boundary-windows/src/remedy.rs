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
//! wrote would make it the installation's own record. It is removed only when the handle shows the
//! system's class and the entry is no record of the layout, or the manifest is confirmed absent. A
//! name that the layout does not give takes the same four states as a record. When nothing is
//! known of who made it, neither is offered.

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

/// What an opened entry is, as its own handle shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// A reparse point of any kind, a junction or a symbolic link among them.
    Link,
    /// A file, with the number of names it has.
    File {
        /// How many names the file has.
        names: u32,
    },
    /// A directory that is not a link.
    Directory,
}

impl EntryKind {
    /// What object the layout gives at this kind of name: a file, a directory, or none in
    /// particular (`None`, for a name that the layout does not give).
    #[must_use]
    pub fn layout_shape(self) -> Option<Shape> {
        match self {
            EntryKind::Manifest
            | EntryKind::Prior
            | EntryKind::Replacement
            | EntryKind::JournalFile => Some(Shape::File { names: 1 }),
            EntryKind::Staging
            | EntryKind::Journal
            | EntryKind::Run
            | EntryKind::NamedRoot
            | EntryKind::UnnamedRoot => Some(Shape::Directory),
            EntryKind::Other => None,
        }
    }
}

/// Who made an opened entry, from its own handle: a link, a file with a second name, and an object
/// of another kind than the layout gives at that name (a directory at a record file's name, a
/// plain file at a private root's name) are none of them the installation's, and the owner is not
/// read for them. Any other entry is read for its owner, which `owner` does.
#[must_use]
pub fn origin_of_shape(kind: EntryKind, shape: Shape, owner: &dyn Fn() -> Origin) -> Origin {
    let wrong_kind = matches!(
        (kind.layout_shape(), shape),
        (_, Shape::Link | Shape::File { names: 2.. })
            | (Some(Shape::File { .. }), Shape::Directory)
            | (Some(Shape::Directory), Shape::File { .. })
    );
    if wrong_kind { Origin::Foreign } else { owner() }
}

/// What the person is told to do about one refused entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Remedy {
    /// Remove the entry: its handle shows the system's class, and it is no record of the layout, or
    /// nothing is recorded about it (no manifest, or a root that no journal names).
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
/// class and nothing records it. A name that the layout does not give is no record, and takes the
/// same four states: it is removed when its handle shows the system's class, moved aside when it
/// shows another account's, a link or a second name or when its list refuses the check, and
/// closed on when a program holds it.
#[must_use]
pub fn choose(kind: EntryKind, origin: &Origin, manifest: &Presence) -> Remedy {
    match origin {
        Origin::Foreign | Origin::Refused(_) | Origin::Unknown(_) => Remedy::MoveAside,
        Origin::Held(_) => Remedy::Unreadable,
        Origin::System if matches!(kind, EntryKind::Other | EntryKind::UnnamedRoot) => {
            Remedy::Remove
        }
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
                    "The directory then holds no manifest, and nothing records what else is in it: the next run reads those entries one at a time on their own handles, and for the first it finds says to remove it, when its handle shows the system's class, to move it aside, when its handle shows that the installation did not make it or shows nothing of who made it (its list refuses the check, it could not be read, or it changed or moved while it was read), or to close the program that holds it open."
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
                "{basis} Do not correct its content into place unless you know that your own installation wrote it, and do not remove it. Move it aside: out of the data directory, to a folder that is not inside it (a new name beside it is a name the layout does not give: the next run reads it on its own handle like every other entry, and says what to do about it), then run the setup program again. {next}"
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

/// Which of the installation's two trees a refused folder above it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tree {
    /// The data directory: the manifest, the journal and the roots of the operations.
    Data,
    /// The program directory: the program that the service runs as the system.
    Program,
}

/// The rights of a permission-list entry that let an account replace a folder or what is in it,
/// said in words. A right that replaces nothing (read, add a file, add a subdirectory) is not said.
#[must_use]
pub fn rights_in_words(mask: u32) -> String {
    const DELETE_CHILD: u32 = 0x0000_0040;
    const DELETE: u32 = 0x0001_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    let mut parts = Vec::new();
    if mask & (GENERIC_ALL | MAXIMUM_ALLOWED) != 0 {
        parts.push("every right on it");
    } else if mask & GENERIC_WRITE != 0 {
        parts.push("the right to change it");
    }
    if mask & DELETE_CHILD != 0 {
        parts.push("the right to delete or rename an entry in it");
    }
    if mask & DELETE != 0 {
        parts.push("the right to delete it");
    }
    if mask & WRITE_DAC != 0 {
        parts.push("the right to change its list");
    }
    if mask & WRITE_OWNER != 0 {
        parts.push("the right to take its ownership");
    }
    parts.join(", ")
}

/// An identity as the refusal names it: by its account name where the system resolves one, with the
/// identifier beside it, and by the identifier alone where it does not.
#[must_use]
pub fn identity_text(name: Option<&str>, sid: &str) -> String {
    match name {
        Some(name) if !name.is_empty() => format!("{name} ({sid})"),
        _ => sid.to_owned(),
    }
}

/// What the check of a folder above the trees says of an entry that gives an identity outside the
/// system's class a right that lets it replace the folder or what is in it.
#[must_use]
pub fn rights_finding(identity: &str, mask: u32) -> String {
    format!(
        "{identity} is allowed {} (rights 0x{mask:x})",
        rights_in_words(mask)
    )
}

/// Whether a drive's root, as the path that was supplied names it, is the root of the volume itself:
/// the final path of the opened root has no other drive letter and no folder after it. A substituted
/// or redirected letter opens as a folder of another volume, and its final path says which. The
/// comparison ignores case, a trailing backslash and the `\\?\` prefix of the extended form.
#[must_use]
pub fn is_the_volumes_own_root(supplied: &str, final_path: &str) -> bool {
    let plain = |text: &str| {
        text.strip_prefix(r"\\?\")
            .unwrap_or(text)
            .trim_end_matches('\\')
            .to_ascii_lowercase()
    };
    plain(supplied) == plain(final_path)
}

/// Why a folder above the installation's trees is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AncestorFault<'a> {
    /// A link or a mounted folder: the installation does not go through either above its trees.
    Link,
    /// Not a folder.
    NotAFolder,
    /// A drive letter that is no volume's root: the final path of its opened root.
    Alias(&'a str),
    /// The folder could not be opened or read: the platform's error.
    Unreadable(&'a str),
    /// The owner or the list is refused: the check's own sentence, which names the identity and the
    /// rights.
    List(&'a str),
}

/// The refusal of a folder above the data directory or the program directory, up to the volume's
/// root: the folder, the tree below it, why it is refused and what to do. Nothing is removed or
/// moved: the folder holds other things, and a link or a mounted folder above the trees is the
/// administrator's own, so it is never said to be removed.
#[must_use]
pub fn ancestor_refusal(folder: &str, tree: Tree, fault: &AncestorFault<'_>) -> String {
    let below = match tree {
        Tree::Data => "data directory (its manifest, its journal and the roots of its operations)",
        Tree::Program => "program directory (the program that the service runs as the system)",
    };
    let keep = "Do not remove or move it: it holds other things.";
    match fault {
        AncestorFault::Alias(found) => format!(
            "{folder} is a drive letter that is not the root of its volume: it leads to {found}. The installation reads every folder above the boundary's {below} up to the root of the volume, and a tree reached through {folder} would leave the folders above {found} unread. Nothing was changed. Install on the real path, which is {found}, and not through the drive letter, then run the setup program again."
        ),
        AncestorFault::Link => format!(
            "{folder} is a folder above the boundary's {below}. It is refused because it is a link or a mounted folder. The installation does not go through a link or a mounted folder above its trees: the folders above the place that the link leads to are not the ones that it read. Nothing was changed. The system's default places have none. If this folder was moved or a volume was mounted on it, install on the real path, then run the setup program again. {keep}"
        ),
        AncestorFault::NotAFolder => format!(
            "{folder} is a folder above the boundary's {below}. It is refused because it is not a folder. The system's default places are folders. Nothing was changed. Correct the path, then run the setup program again. {keep}"
        ),
        AncestorFault::Unreadable(error) => format!(
            "{folder} is a folder above the boundary's {below}. It is refused because it could not be opened or read to be checked ({error}). Nothing was changed. Close the program that holds it open or correct who may open it, then run the setup program again. {keep}"
        ),
        AncestorFault::List(why) => format!(
            "{folder} is a folder above the boundary's {below}. It is refused because {why}. An identity that may delete the folder, delete or rename an entry in it, change its list or take its ownership could swap a folder below it for a link after the installation has read that folder, and the installation or the removal would then act on another place. Nothing was changed. If the reason names an owner, make the system, the Administrators group or the installer service its owner. If it names a right, take away from every other identity the right to delete the folder, to delete or rename an entry in it, to change its list and to take its ownership, and the generic forms that hold them (generic write, generic all and maximum allowed); the right to add an entry is what the system gives by default, and it stays allowed. Then run the setup program again. {keep}"
        ),
    }
}

/// What to do about an entry of the program directory that the installation does not make there.
/// Only the system's class can write in that directory, so the entry is removed, whichever owner it
/// shows. A link is removed as the link itself: the shell's recursive removal follows a junction
/// into what it leads to, so the words name the removals that do not.
#[must_use]
pub fn program_removal_advice(entry: &str, link: bool) -> String {
    if link {
        format!(
            "Remove the link {entry} itself, and not what it points to (`rmdir` without `/s` removes a link to a folder, and `del` a link to a file), and nothing else: it is not something that the installation makes there, and a change of its owner or its list does not cure that. A repair makes the program files again. Then run the setup program again."
        )
    } else {
        format!(
            "Remove {entry}, and nothing else: it is not something that the installation makes there, and a change of its owner or its list does not cure that. A repair makes the program files again. Then run the setup program again."
        )
    }
}
