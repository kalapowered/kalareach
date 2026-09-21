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
//! **The staging directory.** No platform offers a removal of a directory through a handle this
//! host can hold on it: the handles it resolves names through are opened so that nothing can be
//! renamed or deleted under them, which is the same property that stops a reopen for deletion. So
//! the directory's own name is removed against the open handle of the directory that holds it, and
//! only while it is empty, so anything another writer put inside keeps it rather than being taken
//! away with it. On Unix this host first establishes, of the parent's own handle, that this
//! account owns it and that it is not one every account on the machine may write in; it asks the
//! same before it creates the name, so a tree it could never clean up after itself in is one it
//! stages nothing in rather than one it leaves residue in.
//!
//! **The boundary is stated rather than implied.** Where a removal is by name, whoever may write
//! in that directory can put something else at the name in the moment between the comparison and
//! the removal: a process running as this same account, and any account the person has given write
//! access to that tree. Each of those can already rewrite the destination this apply publishes, so
//! neither is something a removal could exclude. That is the limit of what a removal in user space
//! can promise, and `docs/project/README.md` says so in the same terms.

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
/// bounds who could have replaced the file inside since this host wrote it. The mode must be
/// exactly the one this host asked the creation for: nothing for anybody else, and everything for
/// this account, because a directory it cannot itself enter is not one it can stage through.
#[cfg(unix)]
pub(crate) fn may_take_content_from(directory: &Dir) -> bool {
    shut(
        directory,
        rustix::fs::Mode::RWXU,
        rustix::fs::Mode::RWXG | rustix::fs::Mode::RWXO,
    ) && !carries_access_control(directory)
}

/// Whether this host may take away what it staged inside this directory.
///
/// Always: the removal is conditioned on the object this host verified rather than on the name or
/// on who may reach it, so there is nothing here for an account's rights to decide.
#[cfg(windows)]
pub(crate) const fn may_take_content_from(_directory: &Dir) -> bool {
    true
}

/// Whether this host may remove a name in this directory.
///
/// The directory that holds a staged name is the person's own, not one this host made, so what it
/// asks of it is only what it must: that it is a directory, that this account owns it, and that it
/// is not one every account on the machine may write in. A directory the person shares with a
/// group is **not** refused, and no list is read here, because a writer the person has admitted to
/// their own tree can already rewrite the destination this apply publishes and is inside the
/// boundary this module states rather than something a removal could exclude. Asking for more here
/// would mean refusing to clean up in ordinary trees: a private-group account scheme makes every
/// directory a person creates group-writable.
#[cfg(unix)]
pub(crate) fn may_take_a_name_from(parent: &Dir) -> bool {
    shut(parent, rustix::fs::Mode::empty(), rustix::fs::Mode::WOTH)
}

/// Whether this host may remove a name in this directory.
///
/// Always: this platform has no mode bits to ask about, and what its lists say is the same
/// question the boundary in this module's own documentation answers.
#[cfg(windows)]
pub(crate) const fn may_take_a_name_from(_parent: &Dir) -> bool {
    true
}

/// Asks one handle what the object behind it is, who owns it and what its mode says.
#[cfg(unix)]
fn shut(directory: &Dir, required: rustix::fs::Mode, forbidden: rustix::fs::Mode) -> bool {
    let Ok(status) = rustix::fs::fstat(directory) else {
        return false;
    };
    verdict(
        rustix::fs::FileType::from_raw_mode(status.st_mode),
        rustix::fs::Mode::from_raw_mode(status.st_mode),
        status.st_uid,
        rustix::process::geteuid().as_raw(),
        required,
        forbidden,
    )
    .is_ok()
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
    /// Its mode keeps this host itself out, so this host can prove nothing about what is inside.
    ShutToUs,
}

/// Judges one directory from what its own handle says about it.
#[cfg(unix)]
fn verdict(
    kind: rustix::fs::FileType,
    mode: rustix::fs::Mode,
    owner: u32,
    ours: u32,
    required: rustix::fs::Mode,
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
    if !mode.contains(required) {
        return Err(NotShut::ShutToUs);
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

/// Takes away the staging directory by its name in the directory that holds it.
///
/// An empty-directory removal, so anything another writer put inside keeps the directory rather
/// than being taken away with it. The name is removed against the parent's own open handle, and
/// only once this host has established of that handle that this account owns it and that it is not
/// one every account on the machine may write in.
///
/// The same question is asked before the name is created, so a tree this host could not clean up
/// after itself in is one it stages nothing in.
///
/// # Errors
///
/// Returns the removal failure, which includes the directory not being empty, or a refusal because
/// the parent is one this host cannot show belongs to the person.
#[cfg(unix)]
pub(crate) fn take_directory(here: &Dir, entry: &str) -> Result<()> {
    if !may_take_a_name_from(here) {
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
/// inside keeps the directory rather than being taken away with it. The same boundary holds here
/// as on Unix, and `docs/project/README.md` states it.
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

    /// What a staging directory must be for this host to take the file it wrote inside away: this
    /// account's own, entirely, and nobody else's at all.
    const STAGING_REQUIRED: Mode = Mode::RWXU;
    /// The bits a staging directory may not carry.
    const STAGING_FORBIDDEN: Mode = Mode::from_bits_retain(Mode::RWXG.bits() | Mode::RWXO.bits());

    /// The directory holding a staged name is the person's own, so nothing is required of it.
    const PARENT_REQUIRED: Mode = Mode::empty();
    /// What it may not be is one every account on the machine may write in.
    const PARENT_FORBIDDEN: Mode = Mode::WOTH;

    /// A directory of this account's own, admitting nobody else, is one this host may remove from.
    #[test]
    fn a_directory_this_account_owns_alone_is_shut() {
        assert_eq!(
            verdict(
                FileType::Directory,
                Mode::from_raw_mode(0o700),
                501,
                501,
                STAGING_REQUIRED,
                STAGING_FORBIDDEN
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
                STAGING_REQUIRED,
                STAGING_FORBIDDEN
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
                    STAGING_REQUIRED,
                    STAGING_FORBIDDEN
                ),
                Err(NotShut::AdmitsOthers),
                "{mode:o} admits an account besides the owner"
            );
        }
    }

    /// A staging directory this host cannot itself enter is one it can prove nothing about what is
    /// inside, whatever the creation asked for.
    #[test]
    fn a_staging_mode_that_keeps_this_host_out_is_never_staged_through() {
        for mode in [0o600, 0o500, 0o300, 0o000] {
            assert_eq!(
                verdict(
                    FileType::Directory,
                    Mode::from_raw_mode(mode),
                    501,
                    501,
                    STAGING_REQUIRED,
                    STAGING_FORBIDDEN
                ),
                Err(NotShut::ShutToUs),
                "{mode:o} is not the mode the creation asked for"
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
                    PARENT_REQUIRED,
                    PARENT_FORBIDDEN
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
                    PARENT_REQUIRED,
                    PARENT_FORBIDDEN
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
                STAGING_REQUIRED,
                STAGING_FORBIDDEN
            ),
            Err(NotShut::NotADirectory)
        );
    }
}
