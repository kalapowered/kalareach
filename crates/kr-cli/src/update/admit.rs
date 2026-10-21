//! Admitting the release a package manager put on this host.
//!
//! A package manager unpacks the signed release under a prefix of its own and puts that release's
//! `kr` on the search path. That `kr` is outside the store of releases, and a store keeps every
//! release a live worker runs from, so the prefix is never what the host runs from: the first
//! command of such a `kr` admits its release into the store, and then the command runs as the
//! store's own copy.
//!
//! * With no release in the store, the release is installed as `kr host install` installs one.
//! * With another release current, and this one newer and not kept yet, the release is packed as a
//!   release archive and handed to the current release's `kr` as an update
//!   (`kr host update --archive <archive>`), which checks it against the update channel's root,
//!   hands the daemons over and switches, or waits for a live worker as any update does. The
//!   current release may be one that knows nothing of package managers, so what it is offered is
//!   what every release takes of an update. A wait is not a failure: the command goes on with the
//!   release still current, and the release the update left staged is offered again at the next
//!   command.
//! * A release that is the current one, one the store already keeps, and one no newer than the
//!   current is not put in the store again, and the command goes on with the release that is
//!   current. A release kept after a rollback is not switched back to by running its `kr`.
//!
//! A release that carries no update channel root is refused, so that a package manager's release is
//! always checked against the keys it names: the first installation by hand is the one that takes a
//! release with none. A release that cannot be checked is refused, with the reason, and the command
//! does not run. Two first commands at once serialise on the store's own locks: the one that does
//! not take them goes on with the release that is current.
//!
//! The store names the package manager in a file of its own, which owns which release is current.
//!
//! A `kr` of a store, a build outside any package manager's prefix and the commands that read
//! nothing of the host (`--help`, `--version`, a mistake in the arguments) do none of this.

use std::convert::Infallible;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use kr_client::shown;
use kr_client::shown::Shown;
use kr_ipc::install::{Program, Running, Store};

use super::{install, release, said};
use crate::error::{CliError, Result};

/// How long a first command waits for another first command to finish installing.
const INSTALL_WAIT: Duration = Duration::from_secs(60);

/// The release this `kr` is part of when it is a package manager's, and which manager.
///
/// `None` for a `kr` of a store and for one outside a store that no package manager put there. A
/// `kr` in a package manager's prefix is one whether or not its release is whole: a prefix that has
/// lost its manifest is refused by [`admit`], and is never taken for a build of this checkout.
#[must_use]
pub fn unadmitted() -> Option<(PathBuf, &'static str)> {
    let Ok(Running::Loose { directory }) = kr_ipc::install::this_process() else {
        return None;
    };
    let tree = directory.parent()?;
    Some((tree.to_path_buf(), installer_of(tree)?))
}

/// The package manager whose prefix `tree` is in: the release's directory under the package's own
/// name in the directory that manager keeps releases in.
fn installer_of(tree: &Path) -> Option<&'static str> {
    let parts: Vec<_> = tree
        .components()
        .map(|part| part.as_os_str().to_str())
        .collect();
    parts.windows(2).find_map(|pair| match pair {
        [Some("Cellar" | "Caskroom"), Some("kalareach")] => Some("homebrew"),
        _ => None,
    })
}

/// Admits the release in `tree`, and then runs this command again as the store's `kr`.
///
/// # Errors
///
/// Returns the reason the release was refused or could not be made current, and the failure to
/// start the store's `kr` if that is what went wrong. It returns nothing otherwise, since the
/// command then runs as another program.
pub async fn admit(tree: &Path, installer: &str) -> Result<Infallible> {
    let root = Store::default_root().ok_or_else(|| {
        CliError::HostUnavailable(Shown::said(
            "this user's store of releases has no place on this system",
        ))
    })?;
    let store = Store::at(root);
    let document = release::manifest_document(tree)?;
    let manifest = release::read_manifest(&document)?;
    if release::ChannelRoot::read(tree)?.is_none() {
        return Err(CliError::Other(shown!(
            "the release at {} carries no update channel root, so it cannot be checked, and this \
             command did not run",
            Shown::root(tree)
        )));
    }

    let deadline = Instant::now() + INSTALL_WAIT;
    loop {
        let current = store
            .current()
            .map_err(|error| CliError::Other(said(&error)))?;
        match current {
            Some(current) if current == manifest.release => {
                // The store's own copy runs, so what the prefix holds changes nothing, but the
                // manager takes ownership only of the release it put there: the same manifest,
                // byte for byte.
                let kept = release::manifest_document(&store.release_directory(&current))?;
                if kept != document {
                    return Err(CliError::Other(shown!(
                        "the release at {} has the name of the one in this host's store and is not \
                         it, and this command did not run",
                        Shown::root(tree)
                    )));
                }
                super::write_installer(&store, installer)?;
                break;
            }
            Some(current) => {
                if let Some(why) = not_to_admit(&store, &current, &manifest) {
                    eprintln!("kr: {why}; this command runs as the release that is current");
                    break;
                }
                hand_to_current(&store, tree, &manifest.release, installer)?;
                break;
            }
            None => match install(Some(tree), None, Some(installer)).await {
                Ok(_) => break,
                // Another first command holds the store, or finished installing between the look
                // and the lock: look again.
                Err(CliError::UpdateDeferred(_) | CliError::Usage(_))
                    if Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Err(error) => return Err(error),
            },
        }
    }

    let error = std::process::Command::new(store.stable(Program::Kr))
        .args(std::env::args_os().skip(1))
        .exec();
    Err(CliError::Other(shown!(
        "the release this host keeps could not be started: {}",
        Shown::io(&error)
    )))
}

/// Why `release` is not offered to the current release as an update, when it is not: the store
/// keeps it already and no update left it staged, or it is no newer than the current release.
fn not_to_admit(
    store: &Store,
    current: &kr_protocol::update::ReleaseName,
    release: &kr_protocol::update::ReleaseManifest,
) -> Option<String> {
    if store.release_directory(&release.release).exists() {
        // An update that waited leaves its release in the store, staged for the next attempt, which
        // is this one; a release kept after a rollback is not staged.
        let staged = super::Record::read(store)
            .is_ok_and(|record| record.staged.as_ref() == Some(&release.release));
        if !staged {
            return Some(format!(
                "release {} is in this host's store already",
                release.release
            ));
        }
    }
    let newer = release::manifest_document(&store.release_directory(current))
        .and_then(|document| release::read_manifest(&document))
        .map(|held| release.sequence.get() > held.sequence.get());
    match newer {
        Ok(true) => None,
        Ok(false) => Some(format!(
            "release {} is no newer than release {current}, which this host runs",
            release.release
        )),
        // A current release whose manifest cannot be read is for the update to refuse by name.
        Err(_) => None,
    }
}

/// Offers `tree` to the current release's `kr` as an update.
///
/// The tree is packed as the release archive that update takes, in a directory of the store's
/// staging place that only this user reads, and the package manager is named once the release is
/// current. An update that waits (exit 9) leaves the current release in place and is not a failure.
/// The current `kr` says why on standard error; what it prints to standard output is its report of
/// the update, which the command that follows must not be preceded by. It reads nothing from
/// standard input, which belongs to the command that follows.
fn hand_to_current(
    store: &Store,
    tree: &Path,
    release: &kr_protocol::update::ReleaseName,
    installer: &str,
) -> Result<()> {
    let staging = store.staging().join(kr_ipc::new_uuid().to_string());
    let handed = pack_and_hand(store, tree, release, &staging);
    let _ = std::fs::remove_dir_all(&staging);
    let status = handed?;
    match status.code() {
        Some(0 | 9) => {}
        // Another command's update may have switched to this release between the look and the
        // lock, which the current release's own refusal then reads as no update to make.
        _ if store.current().ok().flatten().as_ref() == Some(release) => {}
        _ => {
            return Err(CliError::Other(shown!(
                "the release at {} was not admitted to this host's store, and this command did not \
                 run",
                Shown::root(tree)
            )));
        }
    }
    // The package manager owns which release is current from here, once this one is.
    if store.current().ok().flatten().as_ref() == Some(release) {
        super::write_installer(store, installer)?;
    }
    Ok(())
}

/// Packs `tree` into `staging` and runs the current release's `kr` on the archive.
fn pack_and_hand(
    store: &Store,
    tree: &Path,
    release: &kr_protocol::update::ReleaseName,
    staging: &Path,
) -> Result<std::process::ExitStatus> {
    kr_ipc::paths::create_private_tree(store.root(), staging)?;
    let top = format!("kalareach-{}-{release}", release::this_target());
    let archive = staging.join(format!("{top}.tar.gz"));
    release::pack_tree(tree, &top, &archive)?;
    std::process::Command::new(store.stable(Program::Kr))
        .args(["host", "update", "--archive"])
        .arg(&archive)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()
        .map_err(|error| {
            CliError::Other(shown!(
                "the current release's kr could not be started to take in the release at {}: {}",
                Shown::root(tree),
                Shown::io(&error)
            ))
        })
}
