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

/// Whether a folder's final path, as the system gives it, is on a network share
/// (`\\?\UNC\server\share`). The folders above a share are the server's, not the ones that the
/// installation read, so no check that compares a final path with a supplied path accepts one.
#[must_use]
pub fn is_on_a_network_share(final_path: &str) -> bool {
    final_path.to_ascii_lowercase().starts_with(r"\\?\unc\")
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

/// A path as the comparisons read it: without the `\\?\` prefix of the extended form and without a
/// trailing backslash, and in lower case.
fn plain_path(text: &str) -> String {
    text.strip_prefix(r"\\?\")
        .unwrap_or(text)
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

/// Whether the folder that a path leads to is the one that was asked for: its final path, as the
/// system gives it, is the supplied path, ignoring case and the `\\?\` prefix of the extended form,
/// and is not on a network share. A link, a mounted folder or an alias above the folder leads
/// somewhere else.
#[must_use]
pub fn is_the_place_asked_for(supplied: &str, final_path: &str) -> bool {
    !is_on_a_network_share(final_path)
        && final_path
            .strip_prefix(r"\\?\")
            .unwrap_or(final_path)
            .eq_ignore_ascii_case(supplied)
}

/// What was found at a folder of the walk that reads the folders above and around the
/// installation's trees. Whose folder it is, and so the form of its words, is the [`Subject`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AncestorFault<'a> {
    /// A link or a mounted folder: the installation does not go through either above its trees.
    Link,
    /// Not a folder.
    NotAFolder,
    /// A drive letter that is no volume's root: the final path of its opened root.
    Alias(&'a str),
    /// The folder is on a volume that the installation does not use: why, as the volume check says
    /// it. No change of the folder cures it.
    Volume(&'a str),
    /// The folder could not be opened or read: the platform's error.
    Unreadable(&'a str),
    /// The folder's volume did not answer: the query for what the volume is failed, or the open of
    /// the volume's root failed with an error other than "not found". The platform's error.
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

impl<'a> AncestorFault<'a> {
    /// What an open that failed with an error other than "not found" found: at the root of a
    /// volume the volume did not answer, and at any folder above it the folder could not be opened
    /// or read, which a program that holds it open can cause.
    #[must_use]
    pub fn open_failed(root: bool, error: &'a str) -> Self {
        if root {
            AncestorFault::VolumeUnanswered(error)
        } else {
            AncestorFault::Unreadable(error)
        }
    }
}

/// Whose folder a refusal is about, which decides the form of its words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Subject<'a> {
    /// A folder that the installation does not make: a known folder itself, every folder above it
    /// up to the root of its volume, a drive letter. Other programs share it. Its words are built
    /// by one function from what was found, and say what a supported layout is or, for a state that
    /// can pass, what to try that changes no folder. They hold no instruction to change that
    /// folder.
    Shared(AncestorFault<'a>),
    /// A folder that the installation makes: strictly below a known folder. Only its words can tell
    /// the administrator what to correct.
    Own(AncestorFault<'a>),
}

impl<'a> Subject<'a> {
    /// The subject of a fault at `folder` where `known` is the known folder that the walk starts
    /// from: a folder strictly below the known folder is the installation's own, and the known
    /// folder itself and every folder above it are shared.
    #[must_use]
    pub fn at(folder: &str, known: &str, fault: AncestorFault<'a>) -> Self {
        if is_below(folder, known) {
            Subject::Own(fault)
        } else {
            Subject::Shared(fault)
        }
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

/// The words of an open of the broker's pipe that found no instance listening for `seconds`. Every
/// connection that the broker serves may be in use, or the broker may have failed to make the next
/// instance, and the words claim neither. The platform's error follows them after a colon, so they
/// end with no full stop. Only the administrators' pipe says that other elevated sessions may hold
/// it: the persons' pipe is held by persons, which the words do not claim.
#[must_use]
pub fn busy_pipe(seconds: u64, administrators: bool) -> String {
    let held_by = if administrators {
        " (other elevated sessions may hold the administrators' pipe)"
    } else {
        ""
    };
    format!(
        "the broker's pipe stayed busy: no instance of it was listening for {seconds} seconds{held_by}"
    )
}

/// When in a run a folder of the walk is refused, so that the words claim only what is so.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// The run has changed nothing yet: the folder is read before anything is made, written or
    /// stopped.
    Before,
    /// An installation had already made changes, which the manifest records, when the folder was
    /// read again.
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
    /// A removal that undoes an installation that failed read the folder. The removal has changed
    /// nothing; what the installation had made before it failed is still there.
    Rollback,
}

impl Stage {
    /// What the refusal says of the run's changes.
    fn changes(self) -> &'static str {
        match self {
            Stage::Before => "Nothing was changed.",
            Stage::After => {
                "This run had already made changes before it read the folder again, and the manifest records them."
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
                "This removal, which undoes the installation that failed, had changed nothing when it read the folder: whatever that installation had already made is still there."
            }
        }
    }
}

/// What a run that reads the folders of a tree is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// An installation or a repair: it makes things in the tree.
    Install,
    /// A removal: it takes things out of the tree.
    Remove,
}

/// What a walk does where the root of a tree's volume is not there (the open of the root answers
/// "not found").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MissingRoot {
    /// Refuse before any change.
    Refuse,
    /// Go on, and say at the end what could not be reached.
    GoOn,
}

/// What a run does about a root that is not there. An installation and a repair refuse: nothing can
/// be made on a disk that is gone. A removal of the program tree goes on, since a removal that
/// refuses there can never finish: the policy goes back and the accounts, the service and the data
/// go, and its last words name the program directory that it could not reach. The data tree's root
/// still refuses a removal, since with it gone the removal reads no manifest.
#[must_use]
pub fn missing_root(purpose: Purpose, tree: Tree) -> MissingRoot {
    match (purpose, tree) {
        (Purpose::Remove, Tree::Program) => MissingRoot::GoOn,
        _ => MissingRoot::Refuse,
    }
}

/// The last words of a removal that went on past a program tree's root that is not there.
#[must_use]
pub fn program_unreached(program: &str) -> String {
    format!(
        "{program} could not be reached: the root of its volume is not there, so nothing in it was checked or removed. If that volume comes back, remove the program directory then."
    )
}

/// What a supported layout is, in one sentence that says where the boundary installs: the tree's
/// own known folder, with that folder and every folder above it plain, on a fixed, local NTFS
/// volume.
#[must_use]
pub fn supported_layout(tree: Tree) -> String {
    let (tree, known) = match tree {
        Tree::Data => ("data directory", "ProgramData"),
        Tree::Program => ("program directory", "Program Files"),
    };
    format!(
        "This layout is not supported: the setup program installs the boundary's {tree} only in the system's {known} folder, and only where that folder and every folder above it, up to the root of its volume, are plain folders on a fixed, local NTFS volume that only the system, the Administrators group and the installer service own or can replace."
    )
}

/// The one sentence that ends the words of every folder that the installation does not make.
const SHARED_CLOSING: &str =
    "The setup program directs no change to a folder that other programs share.";

/// How the words of a folder that the installation does not make end, before the run's changes.
/// Every ending is fixed: a fault chooses one and cannot add words of its own.
#[derive(Clone, Copy)]
enum Ending {
    /// The layout is not supported.
    Layout,
    /// The volume did not answer, or its root is not there: it can come back.
    VolumeAnswers,
    /// The folder could not be opened or read: a program may hold it, or its volume may not answer.
    HeldOrAnswers,
}

impl Ending {
    fn words(self, tree: Tree) -> String {
        match self {
            Ending::Layout => supported_layout(tree),
            Ending::VolumeAnswers => {
                "Check that the volume is there and answers, then run the setup program again."
                    .to_owned()
            }
            Ending::HeldOrAnswers => {
                "Close the program that holds it open, or check that its volume is there and answers, then run the setup program again."
                    .to_owned()
            }
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
pub fn ancestor_refusal(folder: &str, tree: Tree, subject: &Subject<'_>, stage: Stage) -> String {
    match subject {
        Subject::Shared(fault) => shared_refusal(folder, tree, fault, stage),
        Subject::Own(fault) => own_refusal(folder, tree, fault, stage),
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
    let head = format!("{folder} is a folder above the boundary's {below}.");
    let (found, ending) = match fault {
        AncestorFault::Alias(found) => (
            format!(
                "{folder} is a drive letter that is not the root of its volume: it leads to {found}. The installation reads every folder above the boundary's {below} up to the root of the volume, and a tree reached through {folder} would leave the folders above {found} unread."
            ),
            Ending::Layout,
        ),
        AncestorFault::Volume(reason) => (
            format!("{head} It is on a volume that the installation does not use ({reason})."),
            Ending::Layout,
        ),
        AncestorFault::Link => (
            format!(
                "{head} It is refused because it is a link or a mounted folder. The installation does not go through a link or a mounted folder at or above its trees: the folders above the place that the link leads to are not the ones that it read."
            ),
            Ending::Layout,
        ),
        AncestorFault::NotAFolder => (
            format!("{head} It is refused because it is not a folder."),
            Ending::Layout,
        ),
        AncestorFault::List(why) => (
            format!(
                "{head} It is refused because {why}. An identity that may delete the folder, delete or rename an entry in it, change its list or take its ownership could swap a folder below it for a link after the installation has read that folder, and the installation or the removal would then act on a different folder than the one that it checked."
            ),
            Ending::Layout,
        ),
        AncestorFault::Writable(why) => (
            format!(
                "{head} It is refused because {why}. Whoever owns it, or can add to it, rename or delete in it or change its list, could replace that program."
            ),
            Ending::Layout,
        ),
        AncestorFault::Unreadable(error) => (
            format!(
                "{head} It is refused because it could not be opened or read to be checked ({error})."
            ),
            Ending::HeldOrAnswers,
        ),
        AncestorFault::VolumeUnanswered(error) => (
            format!(
                "{head} It is refused because its volume did not answer ({error}). A drive that is being removed, a disk that has failed or a network share that has gone does not answer."
            ),
            Ending::VolumeAnswers,
        ),
        AncestorFault::RootMissing(error) => (
            format!(
                "{head} It is refused because the root of its volume is not there ({error}). A drive that has been removed or a disk that has failed leaves no root."
            ),
            Ending::VolumeAnswers,
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
            "{folder} is a folder above the boundary's {below}. It is refused because it is a link or a mounted folder. The installation does not go through a link or a mounted folder at or above its trees: the folders above the place that the link leads to are not the ones that it read. This layout is not supported. {changes} The setup program makes this folder itself, as a plain folder, in the system's own known folder. It does not follow or change a link or a mounted folder in its place, and it directs no change to a folder that other programs share. {kept}"
        ),
        AncestorFault::NotAFolder => format!(
            "{folder} is a folder above the boundary's {below}. It is refused because it is not a folder, and the setup program makes this folder itself, as a plain folder. {changes} Remove or rename what is in its place if nothing else needs it, then run the setup program again. {kept}"
        ),
        AncestorFault::Unreadable(error) => format!(
            "{folder} is a folder above the boundary's {below}. It is refused because it could not be opened or read to be checked ({error}). {changes} Close the program that holds it open or correct who may open it, then run the setup program again. {kept}"
        ),
        AncestorFault::Writable(why) => format!(
            "{folder} is a folder above the boundary's {below}. It is refused because {why}. Whoever owns it, or can add to it, rename or delete in it or change its list, could replace that program. {changes} Make the Administrators group, the system or the installer service its owner and leave only them able to change it, then run the setup program again. {kept} Do not move this folder: it holds other things."
        ),
        AncestorFault::Alias(_)
        | AncestorFault::Volume(_)
        | AncestorFault::VolumeUnanswered(_)
        | AncestorFault::RootMissing(_)
        | AncestorFault::List(_) => shared_refusal(folder, tree, fault, stage),
    }
}

/// What to do about an entry of the program directory that the installation does not make there.
/// Only the system's class can write in that directory, so the entry is removed, whichever owner it
/// shows. A link is removed as the link itself: the shell's recursive removal follows a junction
/// into what it leads to, so the words name the removals that do not. `repair` says whether a
/// repair can make the program files again, which it can only where an installation is recorded.
#[must_use]
pub fn program_removal_advice(entry: &str, link: bool, repair: bool) -> String {
    let after = if repair {
        "A repair makes the program files again. Then run the setup program again."
    } else {
        "Then run the setup program again."
    };
    if link {
        format!(
            "Remove the link {entry} itself, and not what it points to (`rmdir` without `/s` removes a link to a folder, and `del` a link to a file), and nothing else: it is not something that the installation makes there, and a change of its owner or its list does not cure that. {after}"
        )
    } else {
        format!(
            "Remove {entry}, and nothing else: it is not something that the installation makes there, and a change of its owner or its list does not cure that. {after}"
        )
    }
}

/// A folder's final path as a person can use it: without the `\\?\` prefix of the extended form, and
/// with the form of a network path (`\\?\UNC\server\share`) as `\\server\share`.
#[must_use]
pub fn dos_path_of(final_path: &str) -> String {
    match final_path.strip_prefix(r"\\?\") {
        Some(rest) => match rest.strip_prefix(r"UNC\") {
            Some(network) => format!(r"\\{network}"),
            None => rest.to_owned(),
        },
        None => final_path.to_owned(),
    }
}
