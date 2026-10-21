//! Admitting the release a package manager put on this host.
//!
//! A package manager unpacks the signed release under a prefix of its own and puts that release's
//! `kr` on the search path. That `kr` is outside the store of releases, and a store keeps every
//! release a live worker runs from, so the prefix is never what the host runs from: the first
//! command of such a `kr` admits its release into the store, and then the command runs as the
//! store's own copy.
//!
//! * With no release in the store, the release is installed as `kr host install` installs one.
//! * With another release current, the release is handed to the current release's `kr` as an
//!   update (`kr host update --archive <tree>`), which checks it against the update channel's root,
//!   hands the daemons over and switches, or waits for a live worker as any update does. A wait is
//!   not a failure: the command goes on with the release still current.
//!
//! Either way the record of the store names the package manager, which owns which release is
//! current from then on. A release that cannot be checked is refused, with the reason, and the
//! command does not run. Two first commands at once serialise on the store's own locks: the one
//! that does not take them goes on with the release that is current.
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
/// `None` for a `kr` of a store, for one outside a store that no package manager put there, and
/// for one with no release beside it.
#[must_use]
pub fn unadmitted() -> Option<(PathBuf, &'static str)> {
    let Ok(Running::Loose { directory }) = kr_ipc::install::this_process() else {
        return None;
    };
    let tree = directory.parent()?;
    if !tree.join(kr_protocol::update::MANIFEST_FILE).is_file() {
        return None;
    }
    Some((tree.to_path_buf(), installer_of(tree)?))
}

/// The package manager whose prefix `tree` is in, from the directories each keeps releases in.
fn installer_of(tree: &Path) -> Option<&'static str> {
    tree.components()
        .find_map(|part| match part.as_os_str().to_str() {
            Some("Cellar" | "Caskroom") => Some("homebrew"),
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
    let release = release::read_manifest(&release::manifest_document(tree)?)?.release;

    let deadline = Instant::now() + INSTALL_WAIT;
    loop {
        let current = store
            .current()
            .map_err(|error| CliError::Other(said(&error)))?;
        match current {
            Some(current) if current == release => break,
            Some(_) => {
                hand_to_current(&store, tree, installer)?;
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

/// Offers `tree` to the current release's `kr` as an update.
///
/// An update that waits (exit 9) leaves the current release in place and is not a failure. The
/// current `kr` says why on standard error; what it prints to standard output is its report of the
/// update, which the command that follows must not be preceded by.
fn hand_to_current(store: &Store, tree: &Path, installer: &str) -> Result<()> {
    let status = std::process::Command::new(store.stable(Program::Kr))
        .args(["host", "update", "--installer", installer, "--archive"])
        .arg(tree)
        .stdout(Stdio::null())
        .status()
        .map_err(|error| {
            CliError::Other(shown!(
                "the current release's kr could not be started to take in the release at {}: {}",
                Shown::root(tree),
                Shown::io(&error)
            ))
        })?;
    match status.code() {
        Some(0 | 9) => Ok(()),
        _ => Err(CliError::Other(shown!(
            "the release at {} was not admitted to this host's store, and this command did not \
             run",
            Shown::root(tree)
        ))),
    }
}
