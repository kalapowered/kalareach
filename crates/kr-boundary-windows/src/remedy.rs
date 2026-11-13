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
    /// The installation did not make it: it is a link, it is not the kind of object the
    /// installation makes there, or a file has more than one name. The owner is not read for these.
    Foreign,
    /// The owner was read, and it is an account that the installation does not set: not the system
    /// and not the Administrators group. The text is the owner's identifier as the handle showed
    /// it. The owner alone does not show who made the entry, only who owns it now.
    Owned(String),
    /// A program holds it open, so the handle could not be had. The text carries the platform's
    /// error. Closing the program cures it, and nothing says who made the entry.
    Held(String),
    /// The entry's own list refuses the administrator's open. The installation's lists never do, so
    /// it did not make the entry. The text carries the platform's error.
    Refused(String),
    /// The handle could not be opened or read for another reason, so nothing is known of who made
    /// it. The text carries the platform's error.
    Unknown(String),
    /// The open succeeded and showed another object, or the object in another place, than the
    /// listing named: nothing is known of who made the entry. The text carries the reason.
    Changed(String),
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

/// What the setup program is doing when it reads the installation. The purpose decides whether an
/// ending may tell an administrator to take an object that stands on the way to the installation's
/// records out of its place: see [`Grounds::clearance`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// An installation.
    Install,
    /// A repair of an installation.
    Repair,
    /// A removal.
    Remove,
    /// A status report.
    Status,
}

/// What the setup program is doing and how it finds out what its reads showed of the rest of the
/// installation. The reads are made only when the answer can matter: a removal, a repair and a status
/// report never read for it. The reads are made once, at the first question.
pub struct Grounds<'a> {
    purpose: Purpose,
    reads: &'a dyn Fn() -> Standing,
    answer: std::cell::OnceCell<Standing>,
}

impl<'a> Grounds<'a> {
    /// The purpose of the run, and the reads that show what the computer holds of the installation
    /// (made only for an installation, and only when an ending asks).
    #[must_use]
    pub fn new(purpose: Purpose, reads: &'a dyn Fn() -> Standing) -> Self {
        Self {
            purpose,
            reads,
            answer: std::cell::OnceCell::new(),
        }
    }

    /// The purpose of the run.
    #[must_use]
    pub fn purpose(&self) -> Purpose {
        self.purpose
    }

    /// The one way to get a [`Clearance`]: only an installation whose reads found nothing of the
    /// installation has one. A removal, a repair and a status report have none, and neither has an
    /// installation where a read found a part of the installation or failed.
    #[must_use]
    pub fn clearance(&self) -> Option<Clearance> {
        matches!(self.standing(), Some(Standing::NothingFound)).then_some(Clearance(()))
    }

    /// Where the run is an installation and a read found a part of the installation or failed: what
    /// that read showed, which is the reason that no move is named.
    #[must_use]
    // text: withheld
    pub fn withheld(&self) -> Option<&str> {
        match self.standing() {
            Some(Standing::MayBeInstalled(why)) => Some(why),
            _ => None,
        }
    }

    /// What the reads showed, made at the first question and only for an installation.
    fn standing(&self) -> Option<&Standing> {
        (self.purpose == Purpose::Install).then(|| self.answer.get_or_init(|| (self.reads)()))
    }
}

/// What lets an ending tell an administrator to move, rename or remove an object that stands on the
/// way to the installation's records (the folder above the data directory, the data directory, the
/// manifest, the journal and every other entry in it). It cannot be made except by
/// [`Grounds::clearance`], and every ending that names such a step takes one, so no ending of a
/// removal, a repair or a status report, and none where a read failed or found a part of the
/// installation, can name one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clearance(());

/// What the person is told to do about one refused entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Remedy {
    /// Remove the entry: its handle shows the system's class, and it is no record of the layout, or
    /// nothing is recorded about it (no manifest, or a root that no journal names).
    Remove(Clearance),
    /// Correct the entry's owner and list: the system's class owns it and a manifest is there.
    Correct,
    /// Move the entry out of the data directory: the handle shows that the installation did not
    /// make it, or the manifest holds no record of it.
    MoveAside(Clearance),
    /// Give the ownership back: another account owns the entry (the text is the owner's
    /// identifier, as the handle showed it). The one step rests on what the administrator knows.
    OwnerStep(String),
    /// Close the program that holds the entry open: nothing says who made it until it is read.
    Unreadable,
    /// No step: the words name what was read, and where a read failed, that it failed.
    NoStep,
}

/// What the manifest's own record showed of a refused entry, where the refusal read it: the
/// manifest was read and either records the entry or holds no record of it. A refusal that did not
/// read the manifest's record passes none, and its remedy comes from the entry's own handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Record {
    /// The manifest was read and records the entry.
    Recorded,
    /// The manifest was read and holds no record of the entry, so nothing records what is in it.
    NotRecorded,
}

/// The remedy for a refused entry of the given kind, from what its handle showed (`origin`), from
/// what the manifest's record of it showed (`record`) and from the lookup of the manifest. A step
/// that takes an entry out of its place (a move or a removal) exists only where the run has a
/// [`Clearance`]; without one the entry's records are never told to go: another account's owner
/// gets the one step that gives the ownership back, and every other state gets no step. Where the
/// origin rests on a failed read (the entry's own list refused the open, the read failed, or the
/// object changed while it was read), no step exists for any purpose. A record is corrected into
/// place only when its handle shows the system's class and a manifest may be there. A name that the
/// layout does not give is no record, and takes the same states: with a clearance it is removed when
/// its handle shows the system's class and moved aside when it shows a link, a second name or
/// another account's owner, and a program that holds it open is closed on.
#[must_use]
pub fn choose(
    grounds: &Grounds<'_>,
    kind: EntryKind,
    origin: &Origin,
    manifest: &Presence,
    record: Option<Record>,
) -> Remedy {
    let aside = || {
        grounds
            .clearance()
            .map_or(Remedy::NoStep, Remedy::MoveAside)
    };
    let removed = || grounds.clearance().map_or(Remedy::NoStep, Remedy::Remove);
    if record == Some(Record::NotRecorded) {
        return aside();
    }
    match origin {
        Origin::Foreign => aside(),
        Origin::Owned(owner) => grounds
            .clearance()
            .map_or_else(|| Remedy::OwnerStep(owner.clone()), Remedy::MoveAside),
        Origin::Refused(_) | Origin::Unknown(_) | Origin::Changed(_) => Remedy::NoStep,
        Origin::Held(_) => Remedy::Unreadable,
        Origin::System if matches!(kind, EntryKind::Other | EntryKind::UnnamedRoot) => removed(),
        Origin::System if matches!(manifest, Presence::Absent) => removed(),
        Origin::System => Remedy::Correct,
    }
}

/// What the reads of the run showed, said where a step that takes an object out of its place
/// stands: the run is an installation, and every read found nothing of the installation. The move
/// itself rests on what the administrator knows, which no read of this program shows.
const FOUND_NOTHING: &str = "The reads of this run found no service of the installation's name, no account of the installation's two names and none that carries its comment, and none of its rules. They do not see an account that was renamed and whose comment was changed.";

/// Why no move is named at an installation where a read found a part of the installation or failed:
/// the reads did not show that nothing of an installation is left. `why` is what the read showed.
fn withheld_words(why: Option<&str>) -> String {
    why.map_or_else(String::new, |why| {
        format!(
            " The reads of this run did not show that nothing of an installation is left: {why}."
        )
    })
}

/// The one step for an object that another account owns, where the run has no clearance to move
/// it. It rests on what the administrator knows and on no read of this program, and it says all that
/// it rests on: that the administrator made the change, and that no program of that account could
/// have changed the object or what is in it while that account owned it. It gives the ownership back
/// for the object and everything in it, since a change of the owner of a directory is made for the
/// directory and everything in it. `what` names the object ("the data directory", "this folder").
fn owner_step(what: &str) -> String {
    format!(
        "If you made that change, and you know that no program of that account could have changed {what} or anything in it while that account owned it, give the ownership of {what} and of everything in it back to the Administrators group, then run the setup program again."
    )
}

/// The words that end the refusal of an entry: the one remedy, with what the next run then finds.
/// The manifest is said to stay only where the lookup found one; nothing is said of the journal or
/// of what the entry holds, which no read showed; "the next run makes it new" is said only of what
/// the installation makes. A remedy that takes the entry out of its place carries a [`Clearance`],
/// so these words name no move and no removal for a removal, a repair or a status report.
#[must_use]
// text: ending
pub fn ending(
    entry: &std::path::Path,
    remedy: &Remedy,
    origin: &Origin,
    kind: EntryKind,
    manifest: &Presence,
    record: Option<Record>,
) -> String {
    let data = entry.parent().map(|data| data.display().to_string());
    let entry = entry.display();
    let not_recorded = record == Some(Record::NotRecorded);
    if not_recorded && kind == EntryKind::Manifest {
        // The reason is all that the read shows: the manifest was read and holds no record of its
        // own data directory. No step is named, since the setup program has none for it, and no
        // forecast is made of what a run after any change of the manifest says.
        let data = data.unwrap_or_default();
        return format!(
            "The manifest in {data} holds no record of {data} itself. The setup program names no step for this state."
        );
    }
    let basis = match origin {
        _ if not_recorded => format!(
            "The manifest holds no record of {entry}, and {entry} holds entries: nothing shows what wrote them."
        ),
        Origin::Refused(error) => format!(
            "Nothing shows who made {entry}: it could not be opened ({error}). A permission list that refuses the Administrators group gives that error, and no list of the installation's does; an entry with a delete pending gives it too."
        ),
        Origin::Unknown(error) => {
            format!("Nothing shows who made {entry}, because it could not be read ({error}).")
        }
        Origin::Changed(error) => format!(
            "Nothing shows who made {entry}: it changed or moved while it was read ({error})."
        ),
        Origin::System => format!(
            "The handle of {entry} shows an owner of the system's class, and nothing shows that the installation made it."
        ),
        _ => format!(
            "The handle of {entry} shows what the installation does not leave there: an owner that is not the system or the Administrators group, a reparse point, a second name for a file, or another kind of object than its layout gives at that name."
        ),
    };
    match remedy {
        Remedy::Remove(_) => {
            if matches!(manifest, Presence::Present) {
                format!(
                    "Remove {entry}, and nothing else, then run the setup program again: the entry at the manifest's name stays where it is."
                )
            } else {
                format!("Remove {entry}, and nothing else, then run the setup program again.")
            }
        }
        Remedy::NoStep => format!("{basis} The setup program names no step for it."),
        Remedy::OwnerStep(owner) => format!(
            "The handle of {entry} shows an owner that is not the system or the Administrators group: {owner}. The setup program does not use it while that account owns it. {}",
            owner_step("the data directory")
        ),
        Remedy::MoveAside(_) => {
            let next = match kind {
                EntryKind::Manifest => {
                    "The directory then holds no manifest, and nothing records what else is in it: the next run reads those entries one at a time on their own handles, and says what the handle of the first it finds shows."
                }
                EntryKind::Prior | EntryKind::Staging | EntryKind::Journal | EntryKind::Run => {
                    "An installation or a repair run next finds the entry absent and makes it new."
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
                "{basis} {FOUND_NOTHING} Do not correct its content into place unless you know that your own installation wrote it, and do not remove it. Move it aside only if you know that nothing of an installation is left: out of the data directory, to a folder that is not inside it (a new name beside it is a name the layout does not give: the next run reads it on its own handle like every other entry, and says what to do about it), then run the setup program again. {next}"
            )
        }
        Remedy::Unreadable => format!(
            "Nothing shows who made {entry}, because a program holds it open and it could not be read. Do not correct its owner or its list, and do not remove it: either would hide what it is. Close the program that holds it open, then run the setup program again, which reads it again."
        ),
        Remedy::Correct => format!(
            "Correct what the reason names (the Administrators group, or the system, owns it, and the system and the Administrators group are the only entries of its list), then run the setup program again. Do not remove {entry}: by its name it is one of the installation's own entries, which may hold records of what is installed."
        ),
    }
}

/// What a refusal of the folder above the data directory is cured by, which its reason decides. No
/// cure moves, renames or removes the folder, for any purpose: it holds the data directory, and the
/// reads that would show that nothing of an installation is left run a program in a working
/// directory under this folder, which is the object that was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParentCure {
    /// Another program holds the folder open: closing that program cures it, and a change of owner
    /// or list does not.
    Close,
    /// The handle shows an owner that is not the system's class (the text is the owner's identifier,
    /// as the handle showed it): the one step is to give the ownership back, which rests on what the
    /// administrator knows. The folder is never corrected into place.
    Owned(String),
    /// The handle shows no directory bit: what is at the folder's name is not a folder. No step is
    /// named.
    NotAFolder,
    /// The system's class owns it and its list is wrong: correct the list. Only a lookup of the
    /// data directory's name in it is known: an entry at that name is not read, so it is said to be
    /// something that can hold an installation.
    Correct(Presence),
    /// A reparse point (a link or a mounted folder) is at the folder's place: the folder is the
    /// installation's own, so the words are those of an own folder of the program tree that is a
    /// reparse point, with what the setup program does and does not change.
    Link(Stage),
    /// The folder could not be opened to be checked, for a reason that is no program holding it
    /// open (that is [`ParentCure::Close`]): nothing shows who made it, and a failed read gives no
    /// step for any purpose.
    Unreadable,
}

/// The words that tell the person what to do about a refused folder above the data directory, one
/// remedy for the state its handle and a lookup showed.
#[must_use]
// text: parent_advice
pub fn parent_advice(cure: &ParentCure) -> String {
    match cure {
        ParentCure::Unreadable => "Nothing shows who made this folder, because it could not be opened to be checked. Do not correct its owner or its list, and do not remove it: either would hide what it is. The setup program names no step for it.".to_owned(),
        ParentCure::Close => "Close the program that holds it open, then run the setup program again: a change of its owner or its list does not close a handle. Do not remove it.".to_owned(),
        ParentCure::Link(stage) => own_link_words(*stage),
        ParentCure::Owned(owner) => format!("The handle of this folder shows an owner that is not the system or the Administrators group: {owner}. It can hold files that another account wrote. The setup program does not use what is in it while that account owns it. {}", owner_step("this folder")),
        ParentCure::NotAFolder => "What is at this folder's name is not a folder, and the layout gives a folder there. The setup program names no step for it.".to_owned(),
        ParentCure::Correct(Presence::Unknown(error)) => format!("Whether it holds the data directory could not be read ({error}), so removal is not offered: it can hold the manifest, the journals and the private roots of an installation. Correct its list instead: give it a protected list that only the system and the Administrators group can change, then run the setup program again."),
        ParentCure::Correct(Presence::Present) =>"Do not remove it: something is at the data directory's name in it, and that can hold the manifest, the journals and the private roots of an installation, which removing this folder would destroy. Correct its list instead: give it a protected list that only the system and the Administrators group can change, then run the setup program again.".to_owned(),
        ParentCure::Correct(Presence::Absent) => "Nothing is at the data directory's name in it. Correct its list: give it a protected list that only the system and the Administrators group can change, then run the setup program again.".to_owned(),
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
// text: rights_in_words
pub fn rights_in_words(mask: u32) -> String {
    const DELETE_CHILD: u32 = 0x0000_0040;
    const DELETE: u32 = 0x0001_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    let mut parts = Vec::new();
    if mask & GENERIC_ALL != 0 {
        parts.push("every right on it");
    } else if mask & GENERIC_WRITE != 0 {
        parts.push("the right to change it");
    }
    if mask & MAXIMUM_ALLOWED != 0 {
        parts.push("the maximum-allowed bit, which this check counts as every right");
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
// text: identity_text
pub fn identity_text(name: Option<&str>, sid: &str) -> String {
    match name {
        Some(name) if !name.is_empty() => format!("{name} ({sid})"),
        _ => sid.to_owned(),
    }
}

/// What the permission check found in an object's owner and list, as one of two kinds. The words
/// of each say which state was read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Finding {
    /// The object gives an account outside the system's own class a right that counts, of one of
    /// four kinds.
    Granted(Grant),
    /// The check cannot evaluate what the object's list grants: an entry of a type that it does not
    /// interpret, or one too small to hold its identifier. No right is known to be given.
    Unevaluated(String),
}

/// The state that the check read, when it counts a right for an account outside the system's class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Grant {
    /// The owner is outside the class.
    Owner(String),
    /// The object has no permission list at all.
    NoList,
    /// An entry that allows rights is for inheritance alone: it gives them over what is made in
    /// the object and none over the object.
    OnWhatIsMade(String),
    /// An entry that allows rights over the object itself.
    Allows(String),
}

impl std::fmt::Display for Finding {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Finding::Granted(Grant::NoList) => {
                out.write_str("it has no permission list, which by itself refuses nobody")
            }
            Finding::Granted(
                Grant::Owner(words) | Grant::OnWhatIsMade(words) | Grant::Allows(words),
            )
            | Finding::Unevaluated(words) => out.write_str(words),
        }
    }
}

/// What the setup program says of one of Git's files, or of a folder above them, whose permissions
/// the check found a state in: `replacement` is true for a folder above the files, where the check
/// asks only whether the folder or what it holds can be replaced. The outer sentence follows the
/// kind of the state: an owner, no list at all, an entry for what is made in the folder, or an
/// entry that allows the change. Each kind with entries says that the rights of an entry that
/// denies are not weighed; a list that the check cannot evaluate is said to be one that the setup
/// program cannot read.
#[must_use]
// text: git_permissions_refusal
pub fn git_permissions_refusal(path: &str, finding: &Finding, replacement: bool) -> String {
    let what = if replacement { "replaced" } else { "changed" };
    match finding {
        Finding::Granted(Grant::Owner(words)) => {
            format!("A look at {path} found an owner outside the system's class: {words}.")
        }
        Finding::Granted(Grant::NoList) => {
            format!("A look at {path} found that {finding}.")
        }
        Finding::Granted(Grant::OnWhatIsMade(words)) => format!(
            "A look at {path} found an entry of its list that applies only to what is made in it, and that allows what is made in it to be {what} by an account outside the system's class: {words}. The rights of an entry that denies are not weighed."
        ),
        Finding::Granted(Grant::Allows(words)) => format!(
            "A look at {path} found an entry of its list that allows it to be {what} by an account outside the system's class: {words}. The rights of an entry that denies are not weighed."
        ),
        Finding::Unevaluated(words) => {
            format!("The setup program cannot tell whether {path} can be {what} by others: {words}")
        }
    }
}

/// What the check of a folder above the trees says of an entry that gives an identity outside the
/// system's class a right that lets it replace the folder or what is in it.
#[must_use]
// text: rights_finding
pub fn rights_finding(identity: &str, mask: u32) -> String {
    format!(
        "an entry of its list allows {identity} {} (rights 0x{mask:x})",
        rights_in_words(mask)
    )
}

/// What the check says of an entry that it counted for a folder's own content or for a replacement:
/// the identifier and the rights of the entry, which can hold on the object or, through
/// inheritance, on what is made in it. An entry for inheritance alone is counted (`on_it` is false
/// for it, and the words say that it applies only to what is made in the object), and the rights of
/// a deny entry are not weighed, so the words give the entry and claim no result.
#[must_use]
// text: entry_rights_finding
pub fn entry_rights_finding(sid: &str, mask: u32, on_it: bool) -> String {
    let scope = if on_it {
        "on it"
    } else {
        "only on what is made in it"
    };
    format!("an entry of its list allows {sid} rights 0x{mask:x} ({scope})")
}

/// The reason that a volume that is reached over the network is not used: the words of the volume check's
/// refusal and of the shape check's, which reads a share in a final path.
// text: REMOTE_VOLUME
pub const REMOTE_VOLUME: &str =
    "the volume is reached over the network, and only local volumes are supported";

/// Whether a folder's final path, as the system gives it, is on a network share
/// (`\\?\UNC\server\share`). The folders above a share are the server's, not the ones that the
/// installation read, so no check that compares a final path with a supplied path accepts one.
#[must_use]
pub fn is_on_a_network_share(final_path: &str) -> bool {
    final_path.to_ascii_lowercase().starts_with(r"\\?\unc\")
}

/// Whether a path as the system gave it names a network share: a path that begins with two
/// backslashes and is not a local device path (`\\?\C:\`, `\\.\`), or the extended form of one.
fn names_a_share(given: &str) -> bool {
    is_on_a_network_share(given)
        || (given.starts_with(r"\\") && !given.starts_with(r"\\?\") && !given.starts_with(r"\\.\"))
}

/// Whether a drive's root, as the path that was supplied names it, is the root of the volume itself:
/// the final path of the opened root, as the system gives it, has no other drive letter and no folder
/// after it, and is not on a network share. A substituted or redirected letter opens as a folder of
/// another volume, and its final path says which. The comparison ignores case, a trailing backslash
/// and the `\\?\` prefix of the extended form.
#[must_use]
pub fn is_the_volumes_own_root(supplied: &str, final_path: &str) -> bool {
    !is_on_a_network_share(final_path) && plain_path(supplied) == plain_path(final_path)
}

/// A path as the comparisons read it: with a forward slash as a backslash, without the `\\?\` prefix
/// of the extended form and without a trailing backslash, and in lower case.
fn plain_path(text: &str) -> String {
    let text = text.replace('/', r"\");
    text.strip_prefix(r"\\?\")
        .unwrap_or(&text)
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

/// Whether the folder that a path leads to is the one that was asked for: its final path, as the
/// system gives it, is the supplied path, and is not on a network share. The two are compared in
/// the forms that the system itself writes for one folder, on both sides: with or without the `\\?\`
/// prefix of the extended form, in any case of ASCII letters, with or without a trailing backslash
/// (the root of a drive keeps its backslash: `E:` is not `E:\`). A forward slash, a short name, a
/// link or an alias above the folder leads somewhere else. A volume mounted at the folder gives the
/// folder's own path, so it is the place asked for here, and the walks refuse it as a reparse point.
#[must_use]
pub fn is_the_place_asked_for(supplied: &str, final_path: &str) -> bool {
    /// The path without the extended prefix and without a trailing backslash that is not a drive's own.
    fn bare(path: &str) -> &str {
        let path = path.strip_prefix(r"\\?\").unwrap_or(path);
        match path.strip_suffix('\\') {
            Some(shorter) if !is_a_drive_name(shorter) => shorter,
            _ => path,
        }
    }
    !is_on_a_network_share(final_path) && bare(supplied).eq_ignore_ascii_case(bare(final_path))
}

/// Whether a text is a drive's name (`C:`), with no folder and no backslash after it.
fn is_a_drive_name(text: &str) -> bool {
    matches!(text.as_bytes(), [letter, b':'] if letter.is_ascii_alphabetic())
}

/// What was found at a folder of the walk that reads the folders above and around the
/// installation's trees. Whose folder it is, and so the form of its words, is the [`Subject`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AncestorFault<'a> {
    /// A link or a mounted folder: the installation does not go through either above its trees.
    Link,
    /// Not a folder.
    NotAFolder,
    /// A known folder that is the root of a volume: it has no folder above it, and the setup
    /// program installs only in a known folder below a root.
    VolumeRoot,
    /// A known folder that overlaps the system's other known folder: the same folder, or one that
    /// lies at or below the other tree's own folder. The other known folder.
    Overlap(&'a str),
    /// A known folder whose path, as the system gave it, is not the final path of the folder that
    /// it opens: a link or a mounted folder at it, a short name, a forward slash, a substituted
    /// letter and another form of its letters all end here. The final path, as a person can use it.
    Leads(&'a str),
    /// A drive letter that is no volume's root: the final path of its opened root.
    Alias(&'a str),
    /// The folder is on a volume that the installation does not use: why, as the volume check says
    /// it. No change of the folder cures it.
    Volume(&'a str),
    /// The folder could not be opened or read: the platform's error. No cause is named: the error
    /// can be any of many.
    Unreadable(&'a str),
    /// The query for what the folder's volume is failed: the platform's error.
    VolumeUnanswered(&'a str),
    /// The root of the folder's volume is not there: the open of the root answered "not found". The
    /// platform's error.
    RootMissing(&'a str),
    /// The owner or the list is refused: the check's own sentence, which names the identity and the
    /// rights.
    List(&'a str),
    /// The owner or the list of a folder from the program directory's top down to its parent is
    /// refused: the folders on the way to the program also refuse the right to add to them.
    Writable(&'a str),
}

/// A fault at one folder, and whose folder it is, which decides the form of its words. The folder,
/// the fault and whose it is stay behind private fields: a subject is made by [`Subject::shared`]
/// or [`Subject::at`] and is never taken apart or paired with another fault or folder.
///
/// A folder that the installation does not make (a known folder itself, every folder above it up
/// to the root of its volume, a drive letter) is shared with other programs. Its words are built by
/// one function from what was found, and say what a supported layout is or, for a state that can
/// pass, what to try that changes no folder. They hold no instruction to change that folder. A
/// folder that the installation makes (strictly below a known folder) is the only one whose words
/// can tell the administrator what to correct, and only [`Subject::at`] makes such a subject.
#[derive(Debug, PartialEq, Eq)]
pub struct Subject<'a> {
    folder: &'a str,
    fault: AncestorFault<'a>,
    whose: Whose,
}

/// Whose a folder is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Whose {
    /// Shared with other programs.
    Shared,
    /// The installation's own.
    Own,
}

impl<'a> Subject<'a> {
    /// A fault at a folder that the installation does not make.
    #[must_use]
    pub fn shared(folder: &'a str, fault: AncestorFault<'a>) -> Self {
        Subject {
            folder,
            fault,
            whose: Whose::Shared,
        }
    }

    /// A fault at `folder` where `known` is the known folder that the walk starts from: a folder
    /// strictly below the known folder is the installation's own, and the known folder itself and
    /// every folder above it are shared.
    #[must_use]
    pub fn at(folder: &'a str, known: &str, fault: AncestorFault<'a>) -> Self {
        let whose = if is_below(folder, known) {
            Whose::Own
        } else {
            Whose::Shared
        };
        Subject {
            folder,
            fault,
            whose,
        }
    }

    /// Whether the folder is one that the installation makes, so that its words may say what to
    /// correct.
    #[must_use]
    pub fn is_the_installations_own(&self) -> bool {
        self.whose == Whose::Own
    }
}

/// Whether `folder` lies strictly below `known`: the known folder itself, a folder above it and a
/// sibling whose name only begins with the known folder's name are not below it. The comparison
/// ignores case, a trailing backslash and the `\\?\` prefix of the extended form.
#[must_use]
pub fn is_below(folder: &str, known: &str) -> bool {
    let (folder, known) = (plain_path(folder), plain_path(known));
    folder.len() > known.len()
        && folder.starts_with(&known)
        && folder.as_bytes()[known.len()] == b'\\'
}

/// What the installer says when the broker's hello fails. Only a failure that the read's deadline
/// ended can mean that other elevated sessions hold the administrators' pipe: they keep the broker's
/// connections, so it does not answer in time. Any other failure (a write that failed, a frame that
/// is malformed, a pipe that the broker closed at its stop) has another cause, and the words do not
/// send the person looking for sessions.
#[must_use]
// text: hello_failure
pub fn hello_failure(failure: &crate::frame::FrameError) -> String {
    use crate::frame::FrameError;
    let deadline = matches!(
        failure,
        FrameError::Io(error) if error.kind() == std::io::ErrorKind::TimedOut
    );
    if deadline {
        format!("{failure}. Other elevated sessions may hold the administrators' pipe.")
    } else {
        failure.to_string()
    }
}

/// The words of the opens of the broker's pipe that found no free instance in `seconds`. Each open
/// found the pipe busy; the wait between two opens is not read, so an instance that listened and
/// was taken by another client in between is not excluded, and the words claim only the opens.
/// Every connection that the broker serves may be in use, or the broker may have failed to make the
/// next instance, and the words claim neither. The platform's error follows them after a colon, so they
/// end with no full stop. Only the administrators' pipe says that other elevated sessions may hold
/// it: the persons' pipe is held by persons, which the words do not claim.
#[must_use]
// text: busy_pipe
pub fn busy_pipe(seconds: u64, administrators: bool) -> String {
    let held_by = if administrators {
        " (other elevated sessions may hold the administrators' pipe)"
    } else {
        ""
    };
    format!(
        "the broker's pipe stayed busy: every open of it in {seconds} seconds found no free instance{held_by}"
    )
}

/// When in a run a folder of the walk is refused, so that the words claim only what is so.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// The run has changed nothing yet: the folder is read before anything is made, written or
    /// stopped.
    Before,
    /// An installation had already made changes when the folder was read again: the manifest
    /// records the objects that it laid down, and not the earlier-state record or the folder that
    /// holds the data directory.
    After,
    /// A repair had already made changes when the folder was read again. A repair has no rollback.
    AfterRepair {
        /// Whether the repair stopped the broker or found it stopped, which is the only case in
        /// which the words say that the broker stays stopped.
        broker_stopped: bool,
    },
    /// The run had made the folder that holds the data directory with its own call, and nothing
    /// else, when that folder was read again. No manifest records it, and a later rollback leaves
    /// it. The words say nothing of what is in it, which nothing has looked at yet.
    DataParentMade,
    /// A removal that undoes an installation that failed read the folder. The removal had removed
    /// nothing yet.
    Rollback,
}

impl Stage {
    /// What the refusal says of the run's changes.
    fn changes(self) -> &'static str {
        match self {
            Stage::Before => "Nothing was changed.",
            Stage::After => {
                "This run had already made changes before it read the folder again. The manifest records the objects that it laid down; it does not record the earlier-state record or the folder that holds the data directory, which this run may have made."
            }
            Stage::AfterRepair {
                broker_stopped: true,
            } => {
                "This run had already made changes before it read the folder again. A repair has no rollback. The broker stays stopped."
            }
            Stage::AfterRepair {
                broker_stopped: false,
            } => {
                "This run had already made changes before it read the folder again. A repair has no rollback."
            }
            Stage::DataParentMade => {
                "This run had already made the folder that holds the data directory before it read the folder again, and the folder stays."
            }
            Stage::Rollback => {
                "This removal, which undoes the installation that failed, had removed nothing when it read the folder."
            }
        }
    }
}

/// What a supported layout is, in one sentence that says where the boundary installs: the tree's
/// own known folder, at the path that the system gives for it (its own final path), with that
/// folder and every folder above it plain, on a fixed, local NTFS volume.
#[must_use]
// text: supported_layout
pub fn supported_layout(tree: Tree) -> String {
    let (tree, known) = match tree {
        Tree::Data => ("data directory", "ProgramData"),
        Tree::Program => ("program directory", "Program Files"),
    };
    format!(
        "This layout is not supported: the setup program installs the boundary's {tree} only in the system's {known} folder, and only where the path that the system gives for that folder is its own final path and that folder and every folder above it, up to the root of its volume, are plain folders on a fixed, local NTFS volume that only the system, the Administrators group and the installer service own or can replace."
    )
}

/// The one sentence that ends the words of every folder that the installation does not make.
const SHARED_CLOSING: &str =
    "The setup program directs no change to a folder that other programs share.";

/// How the words of a folder that the installation does not make end, before the run's changes.
/// Every ending is fixed: a fault chooses one and cannot add words of its own, and neither names a
/// cause.
#[derive(Clone, Copy)]
enum Ending {
    /// The layout is not supported.
    Layout,
    /// A state that can pass: the call may succeed another time.
    Retry,
}

impl Ending {
    fn words(self, tree: Tree) -> String {
        match self {
            Ending::Layout => supported_layout(tree),
            Ending::Retry => "Run the setup program again when it can be read.".to_owned(),
        }
    }
}

/// The refusal of a folder in the walk that reads the folders above and around the data directory
/// and the program directory: the folder, the tree, why it is refused, what the run changed, and, by
/// whose folder it is, what a supported layout is or what to correct. Nothing is removed or moved: a
/// link or a mounted folder above the trees is the administrator's own layout, which the
/// installation does not support and tells no one to change. `stage` says whether the run had
/// changed anything.
#[must_use]
// text: ancestor_refusal
pub fn ancestor_refusal(subject: &Subject<'_>, tree: Tree, stage: Stage) -> String {
    match subject.whose {
        Whose::Shared => shared_refusal(subject.folder, tree, &subject.fault, stage),
        Whose::Own => own_refusal(subject.folder, tree, &subject.fault, stage),
    }
}

/// The words of a tree in a refusal.
fn below(tree: Tree) -> &'static str {
    match tree {
        Tree::Data => "data directory (its manifest, its journal and the roots of its operations)",
        Tree::Program => "program directory (the program that the service runs as the system)",
    }
}

/// The one function that builds the words of a folder that the installation does not make: what was
/// found, then one fixed ending (what a supported layout is, or what to try that changes no
/// folder), the program directory's keeping where the tree is the program's, what the run changed,
/// and the closing sentence. A fault supplies what was found and chooses its ending; no fault can
/// add an instruction to change the folder.
fn shared_refusal(folder: &str, tree: Tree, fault: &AncestorFault<'_>, stage: Stage) -> String {
    let below = below(tree);
    let head = format!("{folder} is on the path above the boundary's {below}.");
    let (found, ending) = match fault {
        AncestorFault::Alias(found) => (
            format!(
                "{folder} is a drive letter whose root opens as {found}. The installation reads every folder above the boundary's {below} up to the root of a volume, and a tree reached through {folder} would leave the folders above {found}, if there are any, unread."
            ),
            Ending::Layout,
        ),
        AncestorFault::Volume(reason) => (
            format!("{head} It is on a volume that the installation does not use ({reason})."),
            Ending::Layout,
        ),
        AncestorFault::Link => (
            format!(
                "{head} It is refused because it is a reparse point, such as a link or a mounted folder. The installation does not go through a reparse point at or above its trees: the folders above the place that it leads to are not the ones that it read."
            ),
            Ending::Layout,
        ),
        AncestorFault::NotAFolder => (
            format!("{head} It is refused because it is not a folder."),
            Ending::Layout,
        ),
        AncestorFault::List(why) => (
            format!(
                "{head} It is refused because {why}. An identity that may change the folder, its entries, its list or its ownership could swap a folder below it for a link after the installation has read that folder, and the installation or the removal would then act on a different folder than the one that it checked."
            ),
            Ending::Layout,
        ),
        AncestorFault::Writable(why) => (
            format!(
                "{head} It is refused because {why}. Whoever owns it, or can add to it, or change its entries or its list, could replace that program."
            ),
            Ending::Layout,
        ),
        AncestorFault::Unreadable(error) => (
            format!(
                "{head} It is refused because it could not be opened or read to be checked ({error})."
            ),
            Ending::Retry,
        ),
        AncestorFault::VolumeRoot => (
            format!(
                "{head} It is refused because it is the root of a volume, and the setup program installs only in a known folder below a root."
            ),
            Ending::Layout,
        ),
        AncestorFault::Overlap(other) => (
            format!(
                "{head} It is refused because it overlaps {other}, the system's other known folder: the same folder, or the place of the boundary's own folder in it, so the two trees cannot be kept apart."
            ),
            Ending::Layout,
        ),
        AncestorFault::Leads(found) => (
            format!(
                "{head} It is refused because the path that the system gives for it is not the final path of the folder that it opens: that folder's own path is {found}."
            ),
            Ending::Layout,
        ),
        AncestorFault::VolumeUnanswered(error) => (
            format!(
                "{head} It is refused because its volume could not be asked what it is ({error})."
            ),
            Ending::Retry,
        ),
        AncestorFault::RootMissing(error) => (
            format!("{head} It is refused because the root of its volume is not there ({error})."),
            Ending::Retry,
        ),
    };
    let ending = ending.words(tree);
    let kept = match tree {
        Tree::Program => "Do not remove the program directory. ",
        Tree::Data => "",
    };
    let changes = stage.changes();
    format!("{found} {ending} {kept}{changes} {SHARED_CLOSING}")
}

/// The words of a folder that the installation makes, which can tell the administrator what to
/// correct. A fault that no such folder can have, and a volume that the installation does not use,
/// say what they say for a folder that the installation does not make.
fn own_refusal(folder: &str, tree: Tree, fault: &AncestorFault<'_>, stage: Stage) -> String {
    let below = below(tree);
    let changes = stage.changes();
    let kept = match tree {
        Tree::Program => "Do not remove the program directory.",
        Tree::Data => "",
    };
    match fault {
        AncestorFault::Link => format!(
            "{folder} is on the path above the boundary's {below}. It is refused because it is a reparse point, such as a link or a mounted folder. {} {kept}",
            own_link_words(stage)
        ),
        AncestorFault::NotAFolder => format!(
            "{folder} is on the path above the boundary's {below}. It is refused because it is not a folder, and the setup program makes this folder itself, as a plain folder. {changes} Remove or rename what is in its place if nothing else needs it, then run the setup program again. {kept}"
        ),
        AncestorFault::Leads(found) => format!(
            "{folder} is on the path above the boundary's {below}. It is refused because the folder that it opens is at {found}, not at {folder}. {changes} The setup program makes this folder itself, as a plain folder, at its own path in the system's own known folder, and it directs no change to a folder that other programs share. {kept}"
        ),
        AncestorFault::Unreadable(error) => format!(
            "{folder} is on the path above the boundary's {below}. It is refused because it could not be opened or read to be checked ({error}). {changes} If a program holds it open, close that program. If its list refuses the open, correct who may open it. Then run the setup program again. {kept}"
        ),
        AncestorFault::Writable(why) => format!(
            "{folder} is on the path above the boundary's {below}. It is refused because {why}. Whoever owns it, or can add to it, or change its entries or its list, could replace that program. {changes} Make the Administrators group, the system or the installer service its owner and leave only them able to change it, then run the setup program again. {kept}"
        ),
        AncestorFault::Alias(_)
        | AncestorFault::Volume(_)
        | AncestorFault::VolumeUnanswered(_)
        | AncestorFault::RootMissing(_)
        | AncestorFault::VolumeRoot
        | AncestorFault::Overlap(_)
        | AncestorFault::List(_) => shared_refusal(folder, tree, fault, stage),
    }
}

/// What the setup program does and does not do about a reparse point (a link or a mounted folder)
/// at a folder that it makes itself, in either tree: the one form that the program tree's folders
/// and the folder that holds the data directory share. It tells the administrator to change
/// nothing that other programs share and to remove nothing.
fn own_link_words(stage: Stage) -> String {
    let changes = stage.changes();
    format!(
        "The installation does not go through a reparse point at or above its trees: the folders above the place that it leads to are not the ones that it read. This layout is not supported. {changes} The setup program makes this folder itself, as a plain folder, in the system's own known folder. It does not follow or change a link or a mounted folder in its place, and it directs no change to a folder that other programs share."
    )
}

/// The words the refusal of the data directory itself ends with when its handle shows the system's
/// class as its owner: what the administrator does. Nothing the installation recorded is removed.
const DATA_REMEDY: &str = "Leave the system and the Administrators group as the only entries of its list, then run the setup program again. Nothing in it is removed.";

/// The words that tell an administrator to move the data directory aside. They stand only at an
/// installation where reads that succeeded found nothing of the installation, and where the handle shows that the installation did not make the directory.
const DATA_NOT_MADE: &str = "The directory can hold files that another account wrote. Do not correct its content into place unless you know that your own installation wrote it, and do not remove it. Move it aside only if you know that nothing of an installation is left (rename it, which keeps everything in it), then run the setup program again: the installation makes the directory new.";

/// What the handle of a data directory shows when it is a link or not a directory.
const DATA_KIND: &str = "The handle of this directory shows a reparse point or an object that is not a directory, which the installation does not leave there.";

/// The words that end the refusal of a data directory at a removal or a repair, or where a part of
/// the installation may be on the computer, when the handle shows a link or another kind of object:
/// the records in it are not used, and no step is named.
const DATA_KIND_STANDS: &str =
    "The setup program does not use the records in it. It names no step for it.";

/// The words the refusal of a data directory that separates names by case ends with, when the
/// system's class owns it.
const CASE_REMEDY: &str = "Turn the flag off (`fsutil.exe file setCaseSensitiveInfo <the directory> disable`), then run the setup program again. Nothing in it is removed.";

/// Why a data directory is refused when it separates names that differ only by case.
// text: CASE_SENSITIVE_WHY
pub const CASE_SENSITIVE_WHY: &str = "it separates names that differ only by case, and the installation compares names without regard to case";

/// What an owner or a list that others can use does to the data directory while the broker runs as
/// the system: said only where a read of the directory's owner and list succeeded.
const DATA_CAN_BE_CHANGED: &str = "Whoever owns it, or can change its list, could put data of their own in it while the broker runs as the system.";

/// What the reads of one run showed of the rest of the installation. Only an installation can have
/// [`Standing::NothingFound`]: see [`Grounds::clearance`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Standing {
    /// An installation, and every read of the service, of the two accounts and of the policy
    /// succeeded and found nothing of the installation.
    NothingFound,
    /// A read found a part of the installation or failed: the records in the data directory may be
    /// the only record of what is on the computer. The text says which read found what, or failed
    /// with which error.
    MayBeInstalled(String),
}

/// The words that end the refusal of the data directory itself, from what its own handle showed
/// (`origin`), whether the reason is the directory's case-sensitive flag, and the run's grounds. One
/// refusal gets one remedy. Only a directory that the system's class owns is told what to correct.
/// The words that tell the administrator to move it aside stand only where the run has a
/// [`Clearance`] (an installation whose every read found nothing of the installation) and the handle
/// shows that the installation did not set what it found (a link, another kind of object, or an
/// owner outside the system's class): otherwise the records in the directory may be the only record
/// of what is installed, so no ending takes the directory away. An owner that was read is named, with
/// the one step that rests on the administrator's own knowledge. Where a read failed, nothing is
/// established about who made the directory or what it holds: the words name the failed read and its
/// error and give no step and no forecast.
#[must_use]
// text: data_ending
pub fn data_ending(grounds: &Grounds<'_>, origin: &Origin, case_sensitive: bool) -> String {
    match origin {
        Origin::Foreign => match grounds.clearance() {
            Some(_) => format!("{DATA_KIND} {FOUND_NOTHING} {DATA_NOT_MADE}"),
            None => format!(
                "{DATA_KIND}{} {DATA_KIND_STANDS}",
                withheld_words(grounds.withheld())
            ),
        },
        Origin::Owned(owner) => match grounds.clearance() {
            Some(_) => format!(
                "{DATA_CAN_BE_CHANGED} Its owner is {owner}, which is not the system or the Administrators group. {FOUND_NOTHING} {DATA_NOT_MADE}"
            ),
            None => format!(
                "{DATA_CAN_BE_CHANGED} Its owner is {owner}, which is not the system or the Administrators group.{} The setup program does not use the records in it while that account owns it. {}",
                withheld_words(grounds.withheld()),
                owner_step("the data directory")
            ),
        },
        Origin::System if case_sensitive => format!("{DATA_CAN_BE_CHANGED} {CASE_REMEDY}"),
        Origin::System => format!("{DATA_CAN_BE_CHANGED} {DATA_REMEDY}"),
        Origin::Held(failure) | Origin::Refused(failure) | Origin::Unknown(failure) => {
            format!(
                "A read of it failed ({failure}), so nothing shows who made it. The setup program names no step for it."
            )
        }
        // The data directory is opened by its own path, so no loss of a listed child reaches it.
        Origin::Changed(reason) => format!(
            "It changed or moved while it was read ({reason}), so nothing shows who made it. The setup program names no step for it."
        ),
    }
}

/// The words that end the failure of a step after this run made the data directory, or the folder
/// above it: what the run did with what it made. They name no step, since a failure after the run
/// made them leaves nothing of the run for the person to move or to correct. `directory_gone` says
/// that the data directory that this run made was marked for removal (or that this run made none),
/// and `stayed` is each object of the run that the platform did not let it mark, with its reason.
#[must_use]
// text: data_made_ending
pub fn data_made_ending(directory_gone: bool, stayed: &[String]) -> String {
    if stayed.is_empty() {
        "This run removed what it made, so nothing of it is left.".to_owned()
    } else if directory_gone {
        format!(
            "This run removed the data directory that it made. It could not remove the folder above it that it also made: {}. That folder stays.",
            stayed.join("; ")
        )
    } else {
        format!(
            "This run could not remove what it made: {}.",
            stayed.join("; ")
        )
    }
}

/// Why a private root is refused when no journal names it: what the journals say, and nothing of
/// what the broker is doing. `damaged` holds the invocations whose journal is damaged, each with
/// its identifier and what is wrong with it: those journals were read only up to the damage.
#[must_use]
// text: unnamed_root_why
pub fn unnamed_root_why(damaged: &[(&str, &str)]) -> String {
    if damaged.is_empty() {
        return "no journal that could be read names it as unfinished work".to_owned();
    }
    let each: Vec<String> = damaged
        .iter()
        .map(|(id, damage)| {
            format!(
                "the journal of the invocation {id} is damaged ({damage}), and its rows after the damage were not read"
            )
        })
        .collect();
    format!(
        "no journal names it as unfinished work in the rows that were read; {}",
        each.join("; ")
    )
}

/// What a refusal in the program directory says is kept: the program directory or the entry in it
/// is not removed, and the manifest is said to record the installation and stay only where one was
/// read (`recorded`).
#[must_use]
// text: program_keeping
pub fn program_keeping(recorded: bool, whole_directory: bool) -> &'static str {
    match (recorded, whole_directory) {
        (true, false) => {
            "Do not remove it: the manifest records the installation and stays where it is."
        }
        (false, false) => "Do not remove it.",
        (true, true) => {
            "Do not remove the program directory: the manifest records the installation and stays where it is."
        }
        (false, true) => "Do not remove the program directory.",
    }
}

/// What to do about an entry of the program directory that could not be opened to be checked. No
/// word says that a program holds it: every cause is a condition, and the one that applies is for
/// the person to find. `keeping` is what the refusal keeps ([`program_keeping`]).
#[must_use]
// text: program_open_advice
pub fn program_open_advice(entry: &str, keeping: &str) -> String {
    format!(
        "If a program holds {entry} open, close that program. If its list refuses the check, correct who may open it. Then run the setup program again. {keeping}"
    )
}

/// What to do about an entry of the program directory that the installation does not make there.
/// Only the system's class can write in that directory, so the entry is removed, whichever owner it
/// shows. A link is removed as the link itself: the shell's recursive removal follows a junction
/// into what it leads to, so the words name the removals that do not. `repair` says whether a
/// repair can make the program files again, which it can only where an installation is recorded.
#[must_use]
// text: program_removal_advice
pub fn program_removal_advice(entry: &str, link: bool, repair: bool) -> String {
    let after = if repair {
        "A repair makes the program files again. Then run the setup program again."
    } else {
        "Then run the setup program again."
    };
    if link {
        format!(
            "{entry} is a reparse point (a link, a mounted folder or another kind), which the installation does not make there. Remove {entry} itself, and not what it points to (`rmdir` without `/s` removes a reparse point to a folder, and `del` one to a file), and nothing else: a change of its owner or its list does not cure that. {after}"
        )
    } else {
        format!(
            "Remove {entry}, and nothing else: it is not something that the installation makes there, and a change of its owner or its list does not cure that. {after}"
        )
    }
}

/// Whether a final path is the root of its volume: nothing is after the volume's name (a drive
/// letter or a volume's identifier).
fn is_a_volume_root(path: &str) -> bool {
    !plain_path(path).contains('\\')
}

/// Whether `folder` is `base` or lies below it.
fn is_at_or_below(folder: &str, base: &str) -> bool {
    plain_path(folder) == plain_path(base) || is_below(folder, base)
}

/// A known folder as the shape check reads it: the path that the system gave for it, and what the
/// open of that path showed.
#[derive(Clone, Copy, Debug)]
pub struct KnownFolder<'a> {
    /// The path that the system gave for the known folder.
    pub given: &'a str,
    /// What the open of the path showed: the final path of the folder that it opens, with every
    /// link followed, as the system gives it (with the `\\?\` prefix of its extended form), or the
    /// platform's error of the open or of the read of that final path.
    pub opened: Result<&'a str, &'a str>,
}

/// The refusal of a layout whose known folders cannot hold the two trees, read before any walk by
/// every installation, repair and removal. The words are the shared form. The decision is made in
/// this order:
///
/// 1. a known folder that could not be opened is refused with the words of a folder that could not
///    be opened;
/// 2. a known folder whose path names a network share, and whose final path is on one, is refused
///    with the words of a volume that the installation does not use;
/// 3. a known folder whose path is not its own final path is refused with what it leads to: a link
///    at it (a local path whose folder opens on a share included), a short name, a forward slash,
///    a substituted letter and another form of its letters all end here, and the root and overlap
///    tests never read a spelling. A path that is its own final path in the forms that the system
///    writes (with or without the extended prefix, in any case of ASCII letters, with or without a
///    trailing backslash) is not refused for that, and neither is a volume mounted at the folder,
///    whose final path is the folder's own: the walks refuse that one for its reparse point;
/// 4. the final paths alone are then compared: a known folder that is the root of a volume (so no
///    folder is above it), and known folders that overlap (the same folder, or one at or below the
///    other tree's own folder, `<known>\KalaReach`).
///
/// After it, a folder strictly below a known folder is the installation's own and the first folder
/// of a walk above a known folder is a volume's root.
#[must_use]
// text: shape_refusal
pub fn shape_refusal(
    program_files: &KnownFolder<'_>,
    program_data: &KnownFolder<'_>,
    stage: Stage,
) -> Option<String> {
    let mut finals = [""; 2];
    for (at, (known, tree)) in [(program_files, Tree::Program), (program_data, Tree::Data)]
        .into_iter()
        .enumerate()
    {
        let leads_to;
        let fault = match known.opened {
            Err(error) => AncestorFault::Unreadable(error),
            // A path that names a share is on a volume that is reached over the network whatever its spelling
            // says: its words come before any comparison of the two paths, so that it never gets
            // words about a path that leads elsewhere.
            Ok(found) if is_on_a_network_share(found) && names_a_share(known.given) => {
                AncestorFault::Volume(REMOTE_VOLUME)
            }
            // The words that a path leads elsewhere are for two paths that, as shown, differ. A
            // local path whose folder opens on a share is one of them: the path itself is on a local
            // volume, and what it leads to is the share.
            Ok(found) if !is_the_place_asked_for(known.given, found) => {
                leads_to = dos_path_of(found);
                AncestorFault::Leads(&leads_to)
            }
            Ok(found) => {
                finals[at] = found;
                continue;
            }
        };
        return Some(shared_refusal(known.given, tree, &fault, stage));
    }
    let [files, data] = finals;
    let own_of = |known: &str| format!(r"{}\KalaReach", known.trim_end_matches('\\'));
    let (folder, tree, fault) = if is_a_volume_root(files) {
        (
            program_files.given,
            Tree::Program,
            AncestorFault::VolumeRoot,
        )
    } else if is_a_volume_root(data) {
        (program_data.given, Tree::Data, AncestorFault::VolumeRoot)
    } else if is_at_or_below(files, &own_of(data))
        || is_at_or_below(data, &own_of(files))
        || plain_path(files) == plain_path(data)
    {
        (
            program_files.given,
            Tree::Program,
            AncestorFault::Overlap(program_data.given),
        )
    } else {
        return None;
    };
    Some(shared_refusal(folder, tree, &fault, stage))
}

/// The setup program's line for a known folder that cannot be read: which folder, the platform's
/// error in the system's own form (`status`: its code in hexadecimal and, where the system has one,
/// its message) and that nothing was changed, and at a removal the limit that it has. What stays is
/// said on a condition, since nothing was read of an installation. No words tell anyone to remove
/// what stays by hand: the policy's rules are shared with other programs.
#[must_use]
// text: known_folder_unreadable
pub fn known_folder_unreadable(folder: &str, status: &str, removal: bool) -> String {
    let limit = if removal {
        format!(
            " A removal reads what to remove from the manifest in the data directory and checks the program directory before it deletes anything, so it cannot go on while the {folder} folder cannot be read. If the boundary is installed, the broker's service, its two accounts and its rules in the policy stay. If the volume of the {folder} folder is gone for good, the setup program cannot remove them."
        )
    } else {
        String::new()
    };
    format!(
        "The system's {folder} folder could not be read: {status}. Nothing was changed.{limit} {SHARED_CLOSING}"
    )
}

/// A state of the broker's service, as the service manager reports it, said apart from the
/// platform's numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceState {
    /// The service is stopped.
    Stopped,
    /// The service is on its way to running or to stopped: the manager refuses a stop request there.
    Pending,
    /// The service is running.
    Running,
    /// The service is paused.
    Paused,
    /// The service is on its way from running to paused.
    PausePending,
    /// The service is on its way from paused to running.
    ContinuePending,
    /// A state number that the setup program does not know. A stop request is the way to the
    /// stopped state from here, as from the other states that are not pending.
    Unknown(u32),
}

/// What a run does next about the broker's service, which is stopped before the program directory
/// changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopStep {
    /// The service is stopped.
    Done,
    /// The service is pending: wait, and read again.
    Wait,
    /// Ask the service to stop.
    Request,
}

/// The step that a state decides.
#[must_use]
pub fn stop_step(state: ServiceState) -> StopStep {
    match state {
        ServiceState::Stopped => StopStep::Done,
        ServiceState::Pending => StopStep::Wait,
        ServiceState::Running
        | ServiceState::Paused
        | ServiceState::PausePending
        | ServiceState::ContinuePending
        | ServiceState::Unknown(_) => StopStep::Request,
    }
}

/// Why the stop of the broker's service failed, apart from a service that did not reach the stopped
/// state: the error is the platform's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopFailure<E> {
    /// A read of the service's state failed: nothing shows what state it is in.
    Read(E),
    /// The service refused the request to stop, and a read after that showed it neither stopped
    /// nor on its way to running or to stopped: the error is the request's, and the state is what
    /// that last read returned.
    Refused(E, ServiceState),
}

/// Stops the broker's service and waits for it, bounded: reads its state, asks it to stop where the
/// state accepts a request, waits where it is pending (running is waited for as well as stopped, and
/// a service that runs again is asked again), and returns `Ok(true)` at the first read that says
/// stopped, never otherwise. `wait` pauses for one poll and says whether the bound has not run out;
/// where it has, one last read decides: `Ok(true)` if it says stopped, `Ok(false)` if not. A request
/// that is refused is followed by a read: stopped ends the run with success, pending is waited for,
/// and any other state ends it with the request's error.
///
/// # Errors
///
/// Returns [`StopFailure::Read`] for a read that failed, and [`StopFailure::Refused`] for a request
/// that was refused while the service stayed in a state that accepts one.
pub fn stop_broker<E>(
    mut read: impl FnMut() -> Result<ServiceState, E>,
    mut request: impl FnMut() -> Result<(), E>,
    mut wait: impl FnMut() -> bool,
) -> Result<bool, StopFailure<E>> {
    loop {
        match stop_step(read().map_err(StopFailure::Read)?) {
            StopStep::Done => return Ok(true),
            StopStep::Wait => {}
            StopStep::Request => {
                // A refusal where the service has moved on since the read is a race, and the read
                // after it decides.
                if let Err(error) = request() {
                    let after = read().map_err(StopFailure::Read)?;
                    match stop_step(after) {
                        StopStep::Done => return Ok(true),
                        StopStep::Wait => {}
                        StopStep::Request => return Err(StopFailure::Refused(error, after)),
                    }
                }
            }
        }
        if !wait() {
            let last = read().map_err(StopFailure::Read)?;
            return Ok(stop_step(last) == StopStep::Done);
        }
    }
}

/// What a run says when the broker's service did not reach the stopped state, chosen by the run: a
/// repair says that what it had changed stays and that it has no rollback; an installation says only
/// that it stopped before it changed the program directory, since its own failure path says what is
/// undone.
#[must_use]
// text: broker_not_stopped
pub fn broker_not_stopped(repair: bool) -> String {
    let first = "The broker's service did not reach the stopped state, so this run stopped before it changed the program directory.";
    if repair {
        format!(
            "{first} What it had already changed stays, and a repair has no rollback. Run the setup program again when the service is stopped."
        )
    } else {
        first.to_owned()
    }
}

/// The state that a read of the broker's service returned, in words that say only that.
fn service_state_words(state: ServiceState) -> String {
    match state {
        ServiceState::Stopped => "stopped".to_owned(),
        ServiceState::Pending => "on its way to running or to stopped".to_owned(),
        ServiceState::Running => "running".to_owned(),
        ServiceState::Paused => "paused".to_owned(),
        ServiceState::PausePending => "changing from running to paused".to_owned(),
        ServiceState::ContinuePending => "changing from paused to running".to_owned(),
        ServiceState::Unknown(number) => {
            format!("in a state that the setup program does not know ({number})")
        }
    }
}

/// What a repair says when the request to stop the broker's service failed: the platform's error,
/// the state that the read after it returned, and what the run left. A repair has no rollback; an
/// installation's own failure path says what is undone, so only a repair uses these words. The last
/// sentence gives no condition on the service's state: the state that the read returned can be one
/// that such a condition names.
#[must_use]
// text: broker_stop_refused
pub fn broker_stop_refused(error: &str, last: ServiceState) -> String {
    let state = service_state_words(last);
    format!(
        "The request to stop the broker's service failed ({error}), and a read of its state after that showed it {state}, so this run stopped before it changed the program directory. What it had already changed stays, and a repair has no rollback. Run the setup program again."
    )
}

/// What a read of a file that the policy needs showed when it gave no answer: absence is said only
/// for the platform's "not found", and any other failure says that the read failed, with its error.
fn not_reached(what: &str, absent: &str, error: &std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::NotFound {
        format!("{what} {absent}")
    } else {
        format!("{what} could not be read: {error}")
    }
}

/// The refusal for a program of Git that the policy names and the read of which gave no answer.
#[must_use]
// text: git_program_not_reached
pub fn git_program_not_reached(path: &str, error: &std::io::Error) -> String {
    not_reached(
        &format!("Git's program {path}"),
        "is not where the policy expects it",
        error,
    )
}

/// The refusal for a file of the payload directory whose lookup gave no answer.
#[must_use]
// text: payload_file_not_reached
pub fn payload_file_not_reached(path: &str, error: &std::io::Error) -> String {
    not_reached(path, "is not in the payload directory", error)
}

/// What a repair says where the executable collection holds rules whose identifiers are none of the
/// installation's own: that they are there, with their identifiers, and what a repair would do to
/// them. The read shows the identifiers and nothing of who made the rules or when.
#[must_use]
// text: foreign_rules_refusal
pub fn foreign_rules_refusal(ids: &[&str]) -> String {
    match ids {
        [one] => format!(
            "a rule that the installation did not make is in the executable collection (identifier {one}), so a repair would change what that rule means"
        ),
        _ => format!(
            "rules that the installation did not make are in the executable collection (identifiers {}), so a repair would change what those rules mean",
            ids.join(", ")
        ),
    }
}

/// A failed platform call in words: what was being done and, where the platform returned a number
/// for the failure, the number. A failure that no call returned (a check that the setup program made
/// itself) carries the code 0, which no failed call returns, and its words have no number.
#[must_use]
// text: platform_error
pub fn platform_error(what: &str, code: u32) -> String {
    if code == 0 {
        what.to_owned()
    } else {
        format!("{what}: Windows error {code}")
    }
}

/// What the setup program says of Smart App Control's state value, or of its absence: nothing for
/// the value 0 (off). The values 1 and 2 are on and evaluating, which is the state's own meaning; a
/// value outside those three is one that the setup program does not know, and it is refused as
/// that, with the value. `None` is a key or a value that is not there.
#[must_use]
// text: smart_app_control_refusal
pub fn smart_app_control_refusal(state: Option<u32>) -> Option<String> {
    match state {
        Some(0) => None,
        Some(on @ (1 | 2)) => Some(format!(
            "Smart App Control is on or evaluating on this computer (state {on})"
        )),
        Some(other) => Some(format!(
            "Smart App Control's state value is {other}, which the setup program does not know"
        )),
        None => Some(
            "Smart App Control's state could not be found where the system keeps it: the CI policy key, or its VerifiedAndReputablePolicyState value, is not there".to_owned(),
        ),
    }
}

/// How a field of the code-integrity listing is said not to be what the setup program reads: it is
/// not there, or it is something else, with what it is.
fn field_not_understood(entry: &serde_json::Value, field: &str, expected: &str) -> String {
    let found = match entry.get(field) {
        None => "is missing".to_owned(),
        Some(value) => {
            let shown = value.to_string();
            let shown = if shown.chars().count() > 60 {
                format!("{}...", shown.chars().take(60).collect::<String>())
            } else {
                shown
            };
            format!("is {shown}, not {expected}")
        }
    };
    format!(
        "an entry of the code-integrity policy listing has a value that the setup program does not understand: its {field} {found}"
    )
}

/// What the setup program says of the code-integrity policies that the listing holds, or nothing
/// where each is the system's own and none is Smart App Control's enforcing policy. Each entry
/// needs its `IsSystemPolicy` and, for a system policy, its `FriendlyName`, and for Smart App
/// Control's (a name that starts with `VerifiedAndReputable`) its `IsEnforced`, each as the type
/// that it has in the listing. An entry without one, or with another type, is refused as one that
/// the setup program does not understand, with the field and its value: no value stands in for one
/// that is not there.
#[must_use]
// text: code_integrity_refusal
pub fn code_integrity_refusal(policies: &[serde_json::Value]) -> Option<String> {
    for entry in policies {
        let Some(system) = entry
            .get("IsSystemPolicy")
            .and_then(serde_json::Value::as_bool)
        else {
            return Some(field_not_understood(
                entry,
                "IsSystemPolicy",
                "true or false",
            ));
        };
        let name = entry
            .get("FriendlyName")
            .and_then(serde_json::Value::as_str);
        if !system {
            return Some(match name {
                Some(name) => {
                    format!("a code-integrity policy beyond the system's is present: {name}")
                }
                None => "a code-integrity policy beyond the system's is present".to_owned(),
            });
        }
        let Some(name) = name else {
            return Some(field_not_understood(entry, "FriendlyName", "a name"));
        };
        if name.starts_with("VerifiedAndReputable") {
            let Some(enforced) = entry.get("IsEnforced").and_then(serde_json::Value::as_bool)
            else {
                return Some(field_not_understood(entry, "IsEnforced", "true or false"));
            };
            if enforced {
                return Some("Smart App Control is enforcing".to_owned());
            }
        }
    }
    None
}

/// The refusal for an effective application control policy that is not empty: the collections that
/// it enforces and the collections that hold rules, as the read of the policy showed them, and
/// what this run had already changed before it read the policy: the data directory and the
/// directories in it, which the manifest records, and the folder that holds the data directory,
/// which no manifest records.
#[must_use]
// text: application_control_set
pub fn application_control_set(enforced: &[&str], ruled: &[&str]) -> String {
    let mut facts = Vec::new();
    if !enforced.is_empty() {
        facts.push(format!("it enforces {}", enforced.join(", ")));
    }
    if !ruled.is_empty() {
        facts.push(format!("it holds rules in {}", ruled.join(", ")));
    }
    format!(
        "The effective application control policy is not empty: {}. The installation does not go on beside a policy that is not empty. This run had already made or protected the data directory and the directories in it before it read the policy, and the manifest records them. The folder that holds the data directory is one that this run made unless it was already there, and no manifest records that folder.",
        facts.join(" and ")
    )
}

/// Why a configuration file that the installation makes empty is refused: it is not empty.
// text: CONFIG_NOT_EMPTY_WHY
pub const CONFIG_NOT_EMPTY_WHY: &str =
    "it is not empty, and the installation's own configuration is empty";

/// What to do about a configuration file that is not empty: remove it, and a repair makes it again.
#[must_use]
// text: empty_config_advice
pub fn empty_config_advice(entry: &str, repair: bool) -> String {
    let again = if repair {
        "A repair makes it again, empty. "
    } else {
        ""
    };
    format!(
        "Remove {entry}, and nothing else: the installation makes it empty, and a configuration that is not empty may hold settings that the Git that the boundary's accounts run would read, and a change of its owner or its list does not cure that. {again}Then run the setup program again."
    )
}

/// The removal's line on the Application Identity service's start type where it puts nothing back,
/// from the three values that it read: the start type now, the one the installation recorded
/// (`start=<number>`), and the one in the earlier-state record. A value that is equal to the others
/// was changed by nobody.
#[must_use]
// text: appid_start_type_left
pub fn appid_start_type_left(current: u32, recorded: Option<&str>, prior: u32) -> String {
    let number = recorded.and_then(|detail| detail.strip_prefix("start="));
    match number {
        Some(number) if number == current.to_string() && current == prior => format!(
            "the Application Identity service's start type is {current}, the same as the installation recorded and the earlier-state record holds: there is nothing to put back"
        ),
        Some(number) => format!(
            "the Application Identity service's start type is {current}, not the {number} that the installation recorded, so it is left alone"
        ),
        None => match recorded {
            Some(detail) => format!(
                "the Application Identity service's start type is {current}, and the installation's record for it is not a start type ({detail}), so it is left alone"
            ),
            None => format!(
                "the Application Identity service's start type is {current}, and the installation recorded no start type for it, so it is left alone"
            ),
        },
    }
}

/// A folder's final path as a person can use it: without the `\\?\` prefix of the extended form, and
/// with the form of a network path (`\\?\UNC\server\share`) as `\\server\share`.
#[must_use]
// text: dos_path_of
pub fn dos_path_of(final_path: &str) -> String {
    match final_path.strip_prefix(r"\\?\") {
        Some(rest) => match rest.strip_prefix(r"UNC\") {
            Some(network) => format!(r"\\{network}"),
            None => rest.to_owned(),
        },
        None => final_path.to_owned(),
    }
}
