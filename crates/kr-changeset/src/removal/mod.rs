//! Making and taking away the two names one apply stages a path through.
//!
//! Everything this host removes beside a destination is one of two objects it made itself: the
//! single file it writes inside its own staging directory, and that directory once it is empty.
//! This module owns the step a name alone cannot carry, which is that a removal reaches the object
//! this host proved was its own rather than whatever the name reaches at the moment of it.
//!
//! **The staged file.** Windows removes it through the handle its identity was read from. The
//! disposition is set on the open object, so the removal is conditioned on identity by
//! construction: a name re-pointed between the comparison and the removal cannot redirect it,
//! because the name takes no part in it. Unix has no such call, and no platform offers one, so the
//! removal is made as narrow as the platform allows: `unlinkat` against the open handle of the
//! directory the file is in, never a path, and only while that directory is one this host can
//! prove is shut. Shut means, asked of that same handle: it is a directory, this account owns it,
//! its mode admits nobody else, and on Apple platforms it carries no access-control list, because
//! a list there admits accounts the mode bits do not mention. A staging directory that is not all
//! of those is one whose contents this host cannot promise anything about, so the file stays and
//! the path is reported.
//!
//! **The staging directory.** It is removed only while it is empty, so anything another writer put
//! inside keeps it rather than being taken away with it, and only while it is the object the
//! journal recorded. Windows takes it away through its own handle where the volume carries the
//! call that does so. Unix has no such call for a directory either, so the name is removed against
//! the open handle of the directory that holds it, and only after this host has established, of
//! that handle, that this account owns it and that it is not one every account on the machine may
//! write in.
//!
//! **The boundary is stated rather than implied.** Where a removal is by name, the one writer that
//! can still put something else at that name in the moment between the comparison and the removal
//! is a process running as this same account, which already holds every authority this product has
//! over that tree. That is the limit of what a removal in user space can promise, and
//! `docs/project/README.md` says so in the same terms.

#[cfg(not(any(unix, windows)))]
compile_error!(
    "an apply stages a path through a directory handle and removes through that handle; this host \
     implements that for Unix and for Windows"
);

#[cfg(target_os = "macos")]
mod apple;
#[cfg(windows)]
mod windows;

use std::io::Result;

use cap_std::fs::{Dir, File};

/// Creates the staging directory, exclusively, admitting nobody but this account.
///
/// A name that is already taken is a refusal, never a removal: this host stages through a
/// directory it made or it stages nothing at all.
///
/// # Errors
///
/// Returns the creation failure, which includes the name already being taken.
#[cfg(unix)]
pub(crate) fn make_exclusively(here: &Dir, entry: &str) -> Result<()> {
    // The mode asked for is this host's own rather than the one the name would inherit, and the
    // account's file-creation mask can only narrow it further. What that mask cannot do is widen
    // it, so the directory never admits another account for an instant. Whether the filesystem
    // kept the mode is not assumed: it is read back from the handle before anything is written
    // inside, and a directory that did not keep it is one this host stages nothing through.
    rustix::fs::mkdirat(here, entry, rustix::fs::Mode::RWXU).map_err(Into::into)
}

/// Creates the staging directory, exclusively.
///
/// The list the directory carries is the destination's own, because this host creates it against
/// the destination's directory handle rather than by a path. Nothing about the removal of the file
/// inside rests on that list: it goes through the handle this host verified, which no account's
/// rights can point somewhere else.
///
/// # Errors
///
/// Returns the creation failure, which includes the name already being taken.
#[cfg(windows)]
pub(crate) fn make_exclusively(here: &Dir, entry: &str) -> Result<()> {
    here.create_dir(entry)
}

/// Whether this host may take away what it staged inside this directory.
///
/// Asked of the handle the caller holds, never of a name. The caller has already compared the
/// directory's identity with the one the journal recorded; this is the rest of it, and it is what
/// bounds who could have replaced the file inside since this host wrote it.
#[cfg(unix)]
pub(crate) fn may_take_content_from(directory: &Dir) -> bool {
    shut(directory, rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO)
}

/// Whether this host may take away what it staged inside this directory.
///
/// Always: the removal is conditioned on the object this host verified rather than on the name or
/// on who may reach it, so there is nothing here for an account's rights to decide.
#[cfg(windows)]
pub(crate) const fn may_take_content_from(_directory: &Dir) -> bool {
    true
}

/// Whether an account other than this one is shut out of this directory.
///
/// Three questions of one handle, and on Apple platforms a fourth. The mode's group and other bits
/// are the whole answer on Linux even where a list exists, because a list there is bounded by the
/// group bits; on Apple platforms a list is beside the mode bits and can admit an account the mode
/// does not mention, so a directory that carries one is one this host cannot call shut.
#[cfg(unix)]
fn shut(directory: &Dir, forbidden: rustix::fs::Mode) -> bool {
    let Ok(status) = rustix::fs::fstat(directory) else {
        return false;
    };
    if verdict(
        rustix::fs::FileType::from_raw_mode(status.st_mode),
        rustix::fs::Mode::from_raw_mode(status.st_mode),
        status.st_uid,
        rustix::process::geteuid().as_raw(),
        forbidden,
    )
    .is_err()
    {
        return false;
    }
    !carries_access_control(directory)
}

/// Whether this directory carries protection beyond its mode bits.
#[cfg(target_os = "macos")]
fn carries_access_control(directory: &Dir) -> bool {
    use std::os::fd::AsFd as _;

    apple::carries_access_control(directory.as_fd())
}

/// Whether this directory carries protection beyond its mode bits.
///
/// A list on this platform is bounded by the mode's own group bits, which the caller has already
/// required to be clear, so there is no second question to ask.
#[cfg(all(unix, not(target_os = "macos")))]
const fn carries_access_control(_directory: &Dir) -> bool {
    false
}

/// Why a directory is not one this host may remove something from.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotShut {
    /// The handle does not name a directory any more.
    NotADirectory,
    /// Another account owns it.
    AnotherAccount,
    /// Its mode admits an account besides its owner.
    AdmitsOthers,
}

/// Judges one directory from what its own handle says about it.
#[cfg(unix)]
fn verdict(
    kind: rustix::fs::FileType,
    mode: rustix::fs::Mode,
    owner: u32,
    ours: u32,
    forbidden: rustix::fs::Mode,
) -> std::result::Result<(), NotShut> {
    if kind != rustix::fs::FileType::Directory {
        return Err(NotShut::NotADirectory);
    }
    if owner != ours {
        return Err(NotShut::AnotherAccount);
    }
    if mode.intersects(forbidden) {
        return Err(NotShut::AdmitsOthers);
    }
    Ok(())
}

/// Takes away the one file this host wrote inside its own staging directory.
///
/// The removal names the directory by the handle this host holds on it, never by a path, so a
/// directory moved in above it cannot redirect the removal.
///
/// # Errors
///
/// Returns the removal failure.
#[cfg(unix)]
pub(crate) fn take_content(directory: &Dir, name: &str, _verified: &File) -> Result<()> {
    rustix::fs::unlinkat(directory, name, rustix::fs::AtFlags::empty()).map_err(Into::into)
}

/// Takes away the one file this host wrote inside its own staging directory.
///
/// Through the handle the caller has just compared with the journal's record, so what goes is that
/// object and can be nothing else.
///
/// # Errors
///
/// Returns the removal failure.
#[cfg(windows)]
pub(crate) fn take_content(_directory: &Dir, _name: &str, verified: &File) -> Result<()> {
    windows::dispose_of(verified)
}

/// Takes the staging directory away through the handle this host verified, where the platform has
/// a call that does so.
///
/// [`None`] means the platform has none, which sends the caller to the removal by name below.
#[cfg(unix)]
pub(crate) const fn take_directory_by_handle(_verified: &Dir) -> Option<Result<()>> {
    None
}

/// Takes the staging directory away through the handle this host verified, where the platform has
/// a call that does so.
///
/// [`None`] means the volume does not carry the call, which sends the caller to the removal by
/// name below. The call refuses a directory that is not empty, so anything another writer put
/// inside keeps the directory as it does everywhere else.
#[cfg(windows)]
pub(crate) fn take_directory_by_handle(verified: &Dir) -> Option<Result<()>> {
    windows::dispose_of_directory(verified)
}

/// Takes away the staging directory by its name in the directory that holds it.
///
/// An empty-directory removal, so anything another writer put inside keeps the directory rather
/// than being taken away with it. The name is removed against the parent's own open handle, and
/// only once this host has established of that handle that this account owns it and that it is not
/// one every account on the machine may write in.
///
/// A parent the person shares with a group is **not** refused, and that is deliberate. Whoever may
/// write in a working tree can already rewrite the destination this apply publishes, so they are
/// inside the boundary the module's own documentation states rather than something a removal could
/// exclude. A directory every account may write in is not a grant the person made to anybody in
/// particular, and there this host reports the name instead of removing it.
///
/// # Errors
///
/// Returns the removal failure, which includes the directory not being empty, or a refusal because
/// the parent is one this host cannot show belongs to the person.
#[cfg(unix)]
pub(crate) fn take_directory(here: &Dir, entry: &str) -> Result<()> {
    if !shut(here, rustix::fs::Mode::WOTH) {
        return Err(std::io::Error::other(
            "the directory this name is in is not one this host can show belongs to this account \
             alone, so it cannot show that the name is still its own",
        ));
    }
    rustix::fs::unlinkat(here, entry, rustix::fs::AtFlags::REMOVEDIR).map_err(Into::into)
}

/// Takes away the staging directory by its name in the directory that holds it.
///
/// An empty-directory removal against the parent's own handle, so anything another writer put
/// inside keeps the directory rather than being taken away with it. This is the answer only on a
/// volume that does not carry the removal through the directory's own handle; there the same
/// boundary holds as on Unix, and `docs/project/README.md` states it.
///
/// # Errors
///
/// Returns the removal failure, which includes the directory not being empty.
#[cfg(windows)]
pub(crate) fn take_directory(here: &Dir, entry: &str) -> Result<()> {
    here.remove_dir(entry)
}

#[cfg(all(test, unix))]
mod tests {
    use rustix::fs::{FileType, Mode};

    use super::{NotShut, verdict};

    /// What a staging directory must be for this host to take the file it wrote inside away.
    const STAGING: Mode = Mode::from_bits_retain(Mode::RWXG.bits() | Mode::RWXO.bits());

    /// What the directory holding a staged name must be for this host to remove that name.
    const PARENT: Mode = Mode::WOTH;

    /// A directory of this account's own, admitting nobody else, is one this host may remove from.
    #[test]
    fn a_directory_this_account_owns_alone_is_shut() {
        assert_eq!(
            verdict(
                FileType::Directory,
                Mode::from_raw_mode(0o700),
                501,
                501,
                STAGING
            ),
            Ok(())
        );
    }

    /// The owner refusal, which no test can reach through the filesystem: putting another account's
    /// name on a directory is a privileged operation, so the judgement is proved here instead.
    #[test]
    fn a_directory_another_account_owns_is_never_removed_from() {
        assert_eq!(
            verdict(
                FileType::Directory,
                Mode::from_raw_mode(0o700),
                0,
                501,
                STAGING
            ),
            Err(NotShut::AnotherAccount)
        );
    }

    /// A staging directory that lets a group or anybody else in at all is one this host can promise
    /// nothing about, because another account could have replaced the file inside it.
    #[test]
    fn a_staging_mode_that_admits_anybody_else_is_never_removed_from() {
        for mode in [0o750, 0o705, 0o770, 0o777, 0o701, 0o710] {
            assert_eq!(
                verdict(
                    FileType::Directory,
                    Mode::from_raw_mode(mode),
                    501,
                    501,
                    STAGING
                ),
                Err(NotShut::AdmitsOthers),
                "{mode:o} admits an account besides the owner"
            );
        }
    }

    /// The directory holding a staged name is the person's own. What it may not be is one every
    /// account on the machine may write in; a group the person shares the tree with is inside the
    /// stated boundary, because it can already rewrite the destination itself.
    #[test]
    fn a_parent_is_judged_on_who_may_write_in_it() {
        for mode in [0o755, 0o700, 0o711, 0o750, 0o775] {
            assert_eq!(
                verdict(
                    FileType::Directory,
                    Mode::from_raw_mode(mode),
                    501,
                    501,
                    PARENT
                ),
                Ok(()),
                "{mode:o} lets no account outside the person's own grant write"
            );
        }
        for mode in [0o757, 0o777, 0o702, 0o722] {
            assert_eq!(
                verdict(
                    FileType::Directory,
                    Mode::from_raw_mode(mode),
                    501,
                    501,
                    PARENT
                ),
                Err(NotShut::AdmitsOthers),
                "{mode:o} lets every account on the machine write"
            );
        }
    }

    /// A handle that does not name a directory names something this host did not stage through.
    #[test]
    fn a_handle_that_is_not_a_directory_is_never_removed_from() {
        assert_eq!(
            verdict(
                FileType::RegularFile,
                Mode::from_raw_mode(0o700),
                501,
                501,
                STAGING
            ),
            Err(NotShut::NotADirectory)
        );
    }
}
