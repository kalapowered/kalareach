//! Making and taking away the two names one apply stages a path through.
//!
//! Everything this host removes beside a destination is one of two objects it made itself: the
//! single file it writes inside its own staging directory, and that directory once it is empty.
//! This module owns the step a name alone cannot carry, which is that the removal reaches the
//! object this host proved was its own rather than whatever the name reaches at the moment of it.
//!
//! * **Windows removes the file through the handle this host verified.** The disposition is set on
//!   the open object, so the removal is conditioned on the object's identity by construction: a
//!   name re-pointed between the comparison and the removal cannot redirect it, because the name
//!   takes no part in it.
//! * **Unix has no such call**, and no platform offers one. So the removal is made as narrow as the
//!   platform allows: `unlinkat` against the open handle of the directory the name is in, never a
//!   path, so no directory moved in above it can redirect the removal; and the directory it names
//!   is one this host created exclusively, holds open, and has just proved through that same handle
//!   is the object the journal recorded, owned by this account, with a mode that admits nobody
//!   else.
//!
//! **The boundary on Unix is stated rather than implied.** Inside a directory that only this
//! account may write, the one writer that can still put another object at the name between the
//! comparison and the removal is a process running as the same account, which already holds every
//! authority this product has over that tree. That is the limit of what a removal in user space
//! can promise, and `docs/project/README.md` says so in the same terms.

#[cfg(not(any(unix, windows)))]
compile_error!(
    "an apply stages a path through a directory handle and removes through that handle; this host \
     implements that for Unix and for Windows"
);

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
    // The mode is the one this host wants rather than the one the name would inherit, and the
    // account's file-creation mask can only narrow it further. What the mask cannot do is widen it,
    // so the directory never admits another account for an instant, whatever the account's
    // settings are.
    rustix::fs::mkdirat(here, entry, rustix::fs::Mode::RWXU).map_err(Into::into)
}

/// Creates the staging directory, exclusively.
///
/// The list the directory carries is the destination's own, because this host creates it against
/// the destination's directory handle rather than by a path, and building a list of its own here
/// would mean naming a path to apply it to. Nothing about the removal rests on that list: the file
/// inside goes through the handle this host verified, which no account's rights can point
/// somewhere else.
///
/// # Errors
///
/// Returns the creation failure, which includes the name already being taken.
#[cfg(windows)]
pub(crate) fn make_exclusively(here: &Dir, entry: &str) -> Result<()> {
    here.create_dir(entry)
}

/// Holds the staging directory to this account alone, through the handle this host just opened.
///
/// The creation already asks for that mode, and this is what makes it exact rather than whatever
/// the account's file-creation mask left of it. It runs before anything is written inside.
///
/// # Errors
///
/// Returns the failure to set the mode.
#[cfg(unix)]
pub(crate) fn hold_to_this_account(directory: &Dir) -> Result<()> {
    rustix::fs::fchmod(directory, rustix::fs::Mode::RWXU).map_err(Into::into)
}

/// Holds the staging directory to this account alone.
///
/// Nothing to do: Windows removes the staged file through the handle this host verified, so no
/// right an account holds on the directory decides what that removal reaches.
///
/// # Errors
///
/// Never returns one.
#[cfg(windows)]
pub(crate) const fn hold_to_this_account(_directory: &Dir) -> Result<()> {
    Ok(())
}

/// Whether this host may take away what it holds this handle on.
///
/// The caller has already compared the directory's identity with the one the journal recorded.
/// This is the rest of the question, asked of the same handle: it is still a directory, this
/// account owns it, and its mode admits nobody else. A directory that fails any of the three is
/// left exactly as it is and reported.
#[cfg(unix)]
pub(crate) fn may_take_away(directory: &Dir) -> bool {
    let Ok(status) = rustix::fs::fstat(directory) else {
        return false;
    };
    verdict(
        rustix::fs::FileType::from_raw_mode(status.st_mode),
        rustix::fs::Mode::from_raw_mode(status.st_mode),
        status.st_uid,
        rustix::process::geteuid().as_raw(),
    )
    .is_ok()
}

/// Whether this host may take away what it holds this handle on.
///
/// Always: the removal below is conditioned on the object this host verified rather than on the
/// name or on who may reach it, so there is nothing here for an account's rights to decide.
#[cfg(windows)]
pub(crate) const fn may_take_away(_directory: &Dir) -> bool {
    true
}

/// Why a staging directory is not one this host may take away.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotOurs {
    /// The handle does not name a directory any more.
    NotADirectory,
    /// Another account owns it.
    AnotherAccount,
    /// Its mode admits an account besides its owner.
    AdmitsOthers,
}

/// Judges one staging directory from what its own handle says about it.
#[cfg(unix)]
fn verdict(
    kind: rustix::fs::FileType,
    mode: rustix::fs::Mode,
    owner: u32,
    ours: u32,
) -> std::result::Result<(), NotOurs> {
    if kind != rustix::fs::FileType::Directory {
        return Err(NotOurs::NotADirectory);
    }
    if owner != ours {
        return Err(NotOurs::AnotherAccount);
    }
    if mode.intersects(rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO) {
        return Err(NotOurs::AdmitsOthers);
    }
    Ok(())
}

/// Takes away the one file this host wrote inside its own staging directory.
///
/// The removal names the directory by the handle this host holds on it, never by a path, so a
/// directory moved in above cannot redirect it.
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

/// Takes away the staging directory itself, once it holds nothing.
///
/// An empty-directory removal, so anything another writer put inside keeps the directory rather
/// than being taken away with it. On Unix it names its parent by an open handle, as every other
/// step does.
///
/// # Errors
///
/// Returns the removal failure, which includes the directory not being empty.
#[cfg(unix)]
pub(crate) fn take_directory(here: &Dir, entry: &str) -> Result<()> {
    rustix::fs::unlinkat(here, entry, rustix::fs::AtFlags::REMOVEDIR).map_err(Into::into)
}

/// Takes away the staging directory itself, once it holds nothing.
///
/// An empty-directory removal against the parent's own handle, so anything another writer put
/// inside keeps the directory rather than being taken away with it.
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

    use super::{NotOurs, verdict};

    /// A directory of this account's own, admitting nobody else, is one this host may take away.
    #[test]
    fn a_directory_this_account_owns_alone_is_ours() {
        assert_eq!(
            verdict(FileType::Directory, Mode::from_raw_mode(0o700), 501, 501),
            Ok(())
        );
    }

    /// The owner refusal, which no test can reach through the filesystem: putting another account's
    /// name on a directory is a privileged operation, so the judgement is proved here instead.
    #[test]
    fn a_directory_another_account_owns_is_never_taken_away() {
        assert_eq!(
            verdict(FileType::Directory, Mode::from_raw_mode(0o700), 0, 501),
            Err(NotOurs::AnotherAccount)
        );
    }

    /// A mode that lets a group or anybody else in is one this host cannot promise anything about.
    #[test]
    fn a_mode_that_admits_anybody_else_is_never_taken_away() {
        for mode in [0o750, 0o705, 0o770, 0o777, 0o701, 0o710] {
            assert_eq!(
                verdict(FileType::Directory, Mode::from_raw_mode(mode), 501, 501),
                Err(NotOurs::AdmitsOthers),
                "{mode:o} admits an account besides the owner"
            );
        }
    }

    /// A handle that does not name a directory names something this host did not stage through.
    #[test]
    fn a_handle_that_is_not_a_directory_is_never_taken_away() {
        assert_eq!(
            verdict(FileType::RegularFile, Mode::from_raw_mode(0o700), 501, 501),
            Err(NotOurs::NotADirectory)
        );
    }
}
