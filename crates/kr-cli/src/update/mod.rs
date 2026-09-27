//! The releases this host keeps side by side, and updating between them: `kr host install`,
//! `kr host update` and `kr host versions`.
//!
//! What a release is and how a process holds the one it runs is [`kr_ipc::install`]'s. This module
//! is the command line's side: putting a checked release into the store, handing each control
//! daemon over to the new release, switching `current`, and saying what the host keeps.
//!
//! # An update, in order
//!
//! 1. The update lock is taken, so one update runs at a time, and an update an earlier run left
//!    part way is settled first, by what `current` actually names ([`recover`]).
//! 2. The release is staged and checked ([`release`]): signed by the release keys the current
//!    release's channel root names, every file as listed, for this system, newer than the current
//!    release.
//! 3. Every worker the store's environments describe is asked what it is, and nothing is stopped
//!    yet: a worker at a level the new release does not retain holds the update, which waits
//!    (exit 9) and says why.
//! 4. Each daemon is asked to prepare, and how each was started is recorded durably before any is
//!    told to stop. A daemon that does not prepare holds the update: the others resume.
//! 5. Once every daemon has stopped, the install lock and every environment's lock are held, and
//!    every record of every registry is classed ([`inventory::classify`]). Anything that holds the
//!    update restarts the daemons it stopped, from the release still current, and the update waits.
//! 6. `current` is switched in one rename, the locks are let go, each daemon is started as it was
//!    before, from the new release, and each is waited for to answer as a daemon of it.
//! 7. Releases nothing needs are removed: not the current one, not the previous one, not one
//!    staged for a later update, and not one a running process holds.
//!
//! The record of the update under way is written before each step that changes what runs, so a
//! run that stops part way leaves what the next needs to finish it or undo it.

#[cfg(unix)]
mod handover;
#[cfg(unix)]
mod inventory;
#[cfg(unix)]
pub mod release;

use kr_client::shown;
use kr_client::shown::Shown;
use kr_ipc::install::{InstallError, Store};
use kr_protocol::ids::EnvironmentId;
use kr_protocol::update::ReleaseName;
use serde::{Deserialize, Serialize};

use crate::error::{CliError, Result};
use crate::output::Document;

/// What a failure of the store, or of a program's hold on its release, says.
///
/// Every path in one is the store's own, derived from where this program is or from a root the
/// person named, so it is said whole; what a manifest said about itself is not repeated.
#[must_use]
pub fn said(error: &InstallError) -> Shown {
    match error {
        InstallError::Image(source) => shown!(
            "where this program is could not be read from the operating system: {}",
            Shown::io(source)
        ),
        InstallError::Replaced { path, reason } => {
            shown!("{} {}", Shown::root(path), *reason)
        }
        InstallError::Manifest { path, .. } => shown!(
            "{} is not a release manifest this build reads",
            Shown::root(path)
        ),
        InstallError::Io {
            operation,
            path,
            source,
        } => shown!(
            "{} {}: {}",
            *operation,
            Shown::root(path),
            Shown::io(source)
        ),
        InstallError::Unsupported => {
            Shown::said("this host keeps no store of releases on this platform")
        }
    }
}

/// The store record's format this build writes, and the newest it reads.
const RECORD_FORMAT: u32 = 1;

/// The store's record, `install.json`: what an update needs that the store's directories do not
/// say. Which release is current is `current` itself, never this.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// The record's format.
    pub format: u32,
    /// The release that was current before the last switch, kept so the host can go back to it.
    #[serde(default)]
    pub previous: Option<ReleaseName>,
    /// A release an update put in the store and did not make current because it waited, kept for
    /// the next attempt.
    #[serde(default)]
    pub staged: Option<ReleaseName>,
    /// The update under way, from before its first stop to its settling.
    #[serde(default)]
    pub update: Option<Transaction>,
}

kr_client::debug_as_name!(Record);

/// An update under way.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// The release that was current when it began.
    pub source: ReleaseName,
    /// The release it makes current.
    pub target: ReleaseName,
    /// How far it has come.
    pub state: TransactionState,
    /// How each daemon it stopped is started again, recorded before it is told to stop.
    pub restarts: Vec<Restart>,
}

kr_client::debug_as_name!(Transaction);

/// How far an update has come.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionState {
    /// The release is staged and checked, and no daemon has been told anything.
    Prepared,
    /// Daemons are being handed over: each one's restart is recorded before it is told to stop.
    HandingOver,
    /// `current` names the target, and the daemons are being started.
    Switched,
}

kr_client::debug_as_name!(TransactionState);

/// How one daemon an update stopped is started again.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Restart {
    /// Its environment.
    pub environment: EnvironmentId,
    /// The runtime root it served.
    pub runtime_root: String,
    /// The state root it served.
    pub state_root: String,
    /// How it is started.
    pub start: Start,
}

kr_client::debug_as_name!(Restart);

/// How a daemon is started again.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Start {
    /// By this user's service manager, from the definition `kr host startup` wrote, which names the
    /// daemon through the store's `current`.
    Service,
    /// Through the store's `current`, with the arguments it was started with and in the directory
    /// it was started in.
    Arguments {
        /// Its arguments, its program's name left out.
        arguments: Vec<String>,
        /// Its working directory.
        working_directory: String,
    },
}

kr_client::debug_as_name!(Start);

impl Record {
    /// Reads a store's record.
    ///
    /// # Errors
    ///
    /// Returns a failure when there is none, it cannot be read, or it is of a format this build
    /// does not read.
    pub fn read(store: &Store) -> Result<Self> {
        let path = store.record();
        let bytes = kr_ipc::paths::read_owner_only_file(&path, 1024 * 1024)?.ok_or_else(|| {
            CliError::HostUnavailable(shown!(
                "{} holds no store of releases",
                Shown::root(store.root())
            ))
        })?;
        let record: Self = serde_json::from_slice(&bytes).map_err(|error| {
            CliError::Other(shown!(
                "the store's record {} could not be read: {}",
                Shown::root(&path),
                Shown::json(&error)
            ))
        })?;
        if record.format > RECORD_FORMAT {
            return Err(CliError::Other(shown!(
                "the store's record {} is of format {}, and this kr reads format {} at most: \
                 update this host with the current release's kr",
                Shown::root(&path),
                record.format,
                RECORD_FORMAT
            )));
        }
        Ok(record)
    }

    /// Writes the record in place of the store's, whole or not at all, and flushed.
    ///
    /// # Errors
    ///
    /// Returns the failure to write it.
    pub fn write(&self, store: &Store) -> Result<()> {
        let mut bytes = serde_json::to_vec_pretty(self).map_err(|error| {
            CliError::Other(shown!(
                "the store's record could not be written: {}",
                Shown::json(&error)
            ))
        })?;
        bytes.push(b'\n');
        kr_ipc::paths::write_owner_only_file(&store.record(), &bytes)?;
        Ok(())
    }
}

/// What a release in the store is to this host.
pub struct Kept {
    /// The release.
    pub release: ReleaseName,
    /// Its place among releases, where its manifest could be read.
    pub sequence: Option<u64>,
    /// Whether it is current.
    pub current: bool,
    /// Whether it was current before the last switch.
    pub previous: bool,
    /// Whether an update staged it for a later attempt.
    pub staged: bool,
    /// Whether a running program holds it.
    pub held: bool,
}

impl Kept {
    /// What `--json` says of it.
    #[must_use]
    pub fn document(&self) -> Document {
        Document::new()
            .with("release", crate::shown::release(&self.release))
            .with("sequence", self.sequence)
            .with("current", self.current)
            .with("previous", self.previous)
            .with("staged", self.staged)
            .with("held", self.held)
    }

    /// What a line of `kr host versions` says of it.
    #[must_use]
    pub fn said(&self) -> Shown {
        let mut said = crate::shown::release(&self.release);
        for (holds, word) in [
            (self.current, " current"),
            (self.previous, " previous"),
            (self.staged, " staged"),
            (self.held, " in use"),
        ] {
            if holds {
                said = shown!("{}{}", said, word);
            }
        }
        said
    }
}

/// What `kr host install` did.
pub struct Installed {
    /// The store.
    pub store: Store,
    /// The release, now current.
    pub release: ReleaseName,
    /// Whether the release carries an update channel root, without which no update is checked.
    pub has_root: bool,
}

impl Installed {
    /// What `--json` says.
    #[must_use]
    pub fn document(&self) -> Document {
        Document::new()
            .with("ok", true)
            .with("store", Shown::root(self.store.root()))
            .with("release", crate::shown::release(&self.release))
            .with(
                "programs",
                Shown::root(&self.store.current_link().join("bin")),
            )
            .with("update_root", self.has_root)
    }

    /// What is said to a person.
    #[must_use]
    pub fn lines(&self) -> Vec<Shown> {
        let mut lines = vec![
            shown!(
                "installed release {} in {}, and made it current",
                crate::shown::release(&self.release),
                Shown::root(self.store.root())
            ),
            shown!(
                "its programs are in {}; put that directory on your search path",
                Shown::root(&self.store.current_link().join("bin"))
            ),
        ];
        if !self.has_root {
            lines.push(Shown::said(
                "this release carries no update channel root, so kr host update refuses every \
                 release for this host until one carrying a root is installed",
            ));
        }
        lines
    }
}

/// What `kr host update` did.
pub struct Updated {
    /// The release that was current.
    pub source: ReleaseName,
    /// The release that is current now.
    pub target: ReleaseName,
    /// The environments whose daemons now run the target.
    pub restarted: Vec<EnvironmentId>,
    /// The releases removed because nothing needs them.
    pub removed: Vec<ReleaseName>,
    /// Whether this was a check only, which changed nothing.
    pub checked_only: bool,
}

impl Updated {
    /// What `--json` says.
    #[must_use]
    pub fn document(&self) -> Document {
        Document::new()
            .with("ok", true)
            .with("source", crate::shown::release(&self.source))
            .with("target", crate::shown::release(&self.target))
            .with("checked_only", self.checked_only)
            .with(
                "restarted",
                self.restarted
                    .iter()
                    .map(|environment| crate::output::said(environment))
                    .collect::<Vec<_>>(),
            )
            .with(
                "removed",
                self.removed
                    .iter()
                    .map(crate::shown::release)
                    .collect::<Vec<_>>(),
            )
    }

    /// What is said to a person.
    #[must_use]
    pub fn lines(&self) -> Vec<Shown> {
        if self.checked_only {
            return vec![shown!(
                "release {} can replace {} now: it is checked, and no live session runs at a \
                 level it does not retain",
                crate::shown::release(&self.target),
                crate::shown::release(&self.source)
            )];
        }
        if self.source == self.target {
            return vec![shown!(
                "release {} is already current",
                crate::shown::release(&self.target)
            )];
        }
        let mut lines = vec![shown!(
            "updated this host from release {} to {}",
            crate::shown::release(&self.source),
            crate::shown::release(&self.target)
        )];
        for environment in &self.restarted {
            lines.push(shown!(
                "the control daemon of environment {} now runs {}",
                *environment,
                crate::shown::release(&self.target)
            ));
        }
        lines.push(Shown::said(
            "every live session goes on running the release it started from until it closes",
        ));
        for removed in &self.removed {
            lines.push(shown!(
                "removed release {}, which nothing uses",
                crate::shown::release(removed)
            ));
        }
        lines
    }
}

/// The store the running program is a release of, and which release that is, refusing a program
/// outside a store and one of a release that is not current.
#[cfg(unix)]
fn current_release_store() -> Result<(Store, ReleaseName)> {
    let running = kr_ipc::install::this_process().map_err(|error| CliError::Other(said(error)))?;
    let (Some(store), Some(release)) = (running.store(), running.release()) else {
        return Err(CliError::HostUnavailable(Shown::said(
            "this kr is not of an installed release: kr host update updates a host installed with \
             kr host install, and runs as the current release's kr",
        )));
    };
    let current = store
        .current()
        .map_err(|error| CliError::Other(said(&error)))?;
    if current.as_ref() != Some(release) {
        return Err(CliError::HostUnavailable(match current {
            Some(current) => shown!(
                "this kr is of release {}, and this host's current release is {}: run {} instead",
                crate::shown::release(release),
                crate::shown::release(&current),
                Shown::root(&store.stable(kr_ipc::install::Program::Kr))
            ),
            None => shown!(
                "the store at {} names no current release",
                Shown::root(store.root())
            ),
        }));
    }
    Ok((store.clone(), release.clone()))
}

/// `kr host install`: puts the unpacked release `tree` into the store at `root` and makes it
/// current.
///
/// Only the first release of a store is installed this way: a store with a current release takes
/// another through `kr host update`, which hands its daemons over first. The release's own `kr`
/// runs this, from the unpacked tree, so what is installed is the program that installs it; the
/// search path and the shells' profiles are the person's, or their installer's, to change.
///
/// # Errors
///
/// Returns a refusal when the tree is not a release this host installs, or the store already has a
/// current release, and the failure to write the store otherwise.
#[cfg(unix)]
pub fn install(
    tree: Option<&std::path::Path>,
    root: Option<&std::path::Path>,
) -> Result<Installed> {
    let running = kr_ipc::install::this_process().map_err(|error| CliError::Other(said(error)))?;
    if running.store().is_some() {
        return Err(CliError::Usage(Shown::said(
            "this kr is already of an installed release; a store takes another release through \
             kr host update --archive",
        )));
    }
    let tree = match tree {
        Some(tree) => tree.to_path_buf(),
        None => kr_ipc::install::image_path()
            .ok()
            .and_then(|image| {
                image
                    .parent()
                    .and_then(std::path::Path::parent)
                    .map(std::path::Path::to_path_buf)
            })
            .ok_or_else(|| {
                CliError::Usage(Shown::said(
                    "where this kr is could not be read; name the unpacked release to install",
                ))
            })?,
    };
    let root = match root {
        Some(root) => root.to_path_buf(),
        None => Store::default_root().ok_or_else(|| {
            CliError::Usage(Shown::said(
                "this user's store has no place on this system; name one with --store",
            ))
        })?,
    };
    let store = Store::at(root);
    if store.is_store()
        && store
            .current()
            .map_err(|error| CliError::Other(said(&error)))?
            .is_some()
    {
        return Err(CliError::Usage(shown!(
            "the store at {} already has a current release; install another with kr host update \
             --archive, which hands this host's daemons over first",
            Shown::root(store.root())
        )));
    }
    store
        .create_directories()
        .map_err(|error| CliError::Other(said(&error)))?;
    let staging = store.staging().join(kr_ipc::new_uuid().to_string());
    let staged = stage_tree(&store, &tree, &staging);
    let _ = remove_staging(&staging);
    let (release, has_root) = staged?;
    // The record last: until it exists nothing takes the directory for a store.
    Record {
        format: RECORD_FORMAT,
        ..Record::default()
    }
    .write(&store)?;
    Ok(Installed {
        store,
        release,
        has_root,
    })
}

/// Copies, checks, seals and admits the release at `tree`, and makes it current.
#[cfg(unix)]
fn stage_tree(
    store: &Store,
    tree: &std::path::Path,
    staging: &std::path::Path,
) -> Result<(ReleaseName, bool)> {
    let (staged, written) = release::copy_tree(tree, staging)?;
    let document = release::manifest_document(&staged)?;
    let root = release::ChannelRoot::read(&staged)?;
    // A first installation has nothing earlier to check the release against, so it takes the
    // release's own root: its manifest has to be signed by the release keys that root names.
    let manifest = match &root {
        Some(root) => root.verify(&document)?,
        None => release::read_manifest(&document)?,
    };
    release::check_files(&manifest, &written)?;
    release::check_system(&manifest)?;
    release::seal(&staged, &manifest)?;
    release::admit(&staged, store, &manifest.release)?;
    let held = store
        .lock_install()
        .map_err(|error| CliError::Other(said(&error)))?;
    store
        .switch(&manifest.release, &held)
        .map_err(|error| CliError::Other(said(&error)))?;
    Ok((manifest.release, root.is_some()))
}

/// Removes a staging directory and whatever an interrupted run left in it.
#[cfg(unix)]
fn remove_staging(staging: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    if !staging.exists() {
        return Ok(());
    }
    // A sealed release is read-only, and its directories are opened to removal first.
    let mut pending = vec![staging.to_path_buf()];
    while let Some(directory) = pending.pop() {
        std::fs::set_permissions(
            &directory,
            std::fs::Permissions::from_mode(kr_ipc::paths::OWNER_ONLY_DIRECTORY_MODE),
        )?;
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            }
        }
    }
    std::fs::remove_dir_all(staging)
}

/// `kr host versions`: the releases the store keeps, and what each is to this host.
///
/// # Errors
///
/// Returns a failure when this kr is not of an installed release, or the store cannot be read.
#[cfg(unix)]
pub fn versions() -> Result<Vec<Kept>> {
    let running = kr_ipc::install::this_process().map_err(|error| CliError::Other(said(error)))?;
    let Some(store) = running.store() else {
        return Err(CliError::HostUnavailable(Shown::said(
            "this kr is not of an installed release, so it keeps no releases",
        )));
    };
    let record = Record::read(store)?;
    let current = store
        .current()
        .map_err(|error| CliError::Other(said(&error)))?;
    let mut kept = Vec::new();
    for release in store
        .releases()
        .map_err(|error| CliError::Other(said(&error)))?
    {
        let sequence =
            kr_ipc::paths::read_owner_only_file(&store.manifest(&release), 4 * 1024 * 1024)
                .ok()
                .flatten()
                .and_then(|bytes| kr_protocol::update::ReleaseManifest::read_document(&bytes).ok())
                .map(|manifest| manifest.sequence.get());
        kept.push(Kept {
            current: current.as_ref() == Some(&release),
            previous: record.previous.as_ref() == Some(&release),
            staged: record.staged.as_ref() == Some(&release),
            held: store.held(&release).unwrap_or(false),
            sequence,
            release,
        });
    }
    Ok(kept)
}

/// `kr host update`: updates this host to the release in `archive`, or says whether it could now
/// with `check`.
///
/// # Errors
///
/// Returns [`CliError::UpdateDeferred`] (exit 9) when something live holds the update, naming what
/// and what to do, with every daemon it stopped started again from the release still current; and
/// a refusal or a failure otherwise.
#[cfg(unix)]
pub async fn update(archive: Option<&std::path::Path>, check: bool) -> Result<Updated> {
    let (store, source) = current_release_store()?;
    let Some(archive) = archive else {
        return Err(CliError::Usage(Shown::said(
            "this host has no update channel to fetch a release from; name a release archive with \
             --archive",
        )));
    };
    let update_lock = store
        .try_lock_update()
        .map_err(|error| CliError::Other(said(&error)))?
        .ok_or_else(|| {
            CliError::UpdateDeferred(Shown::said(
                "another update of this host is running; run kr host update again once it has \
                 finished",
            ))
        })?;
    let mut record = Record::read(&store)?;
    // An update an earlier run left part way is settled first. It never switches `current`, so
    // this kr is still the current release's afterwards.
    if !check && record.update.is_some() {
        recover(&store, &mut record).await?;
    }
    let current_manifest = installed_manifest(&store, &source)?;
    let trusted =
        release::ChannelRoot::read(&store.release_directory(&source))?.ok_or_else(|| {
            CliError::Other(shown!(
                "release {} carries no update channel root, so no release can be checked for this \
             host; the update is refused",
                crate::shown::release(&source)
            ))
        })?;
    let staging = store.staging().join(kr_ipc::new_uuid().to_string());
    let staged = stage_archive(
        &store,
        &trusted,
        &current_manifest,
        archive,
        &staging,
        check,
    );
    let _ = remove_staging(&staging);
    let target = staged?;
    if target.release == source {
        return Ok(Updated {
            target: source.clone(),
            source,
            restarted: Vec::new(),
            removed: Vec::new(),
            checked_only: check,
        });
    }
    // The release is in the store now, and stays there, staged, whatever the rest of this run
    // decides: an update that waits uses it again.
    if !check {
        record.staged = Some(target.release.clone());
        record.write(&store)?;
    }
    let environments = inventory::environments(&store)?;
    // Nothing is stopped for the first look: a worker at a level the new release does not retain
    // holds the update here, before any daemon is asked anything.
    for environment in &environments {
        for stated in inventory::described(&environment.paths).await {
            let retained = stated
                .build
                .as_ref()
                .is_some_and(|build| target.retains(build.protocol_version));
            if !retained {
                return Err(deferred(
                    &target,
                    inventory::Holding::Unretained(stated).said(&target),
                ));
            }
        }
    }
    if check {
        return Ok(Updated {
            source,
            target: target.release,
            restarted: Vec::new(),
            removed: Vec::new(),
            checked_only: true,
        });
    }
    record.update = Some(Transaction {
        source: source.clone(),
        target: target.release.clone(),
        state: TransactionState::Prepared,
        restarts: Vec::new(),
    });
    record.write(&store)?;
    let restarted = hand_over(&store, &mut record, &environments, &target).await?;
    let removed = collect(&store, &record, &update_lock);
    Ok(Updated {
        source,
        target: target.release,
        restarted,
        removed,
        checked_only: false,
    })
}

/// The manifest of a release already in the store.
#[cfg(unix)]
fn installed_manifest(
    store: &Store,
    release: &ReleaseName,
) -> Result<kr_protocol::update::ReleaseManifest> {
    let document = release::manifest_document(&store.release_directory(release))?;
    release::read_manifest(&document)
}

/// Stages the release in `archive` and checks it against the current release; with `check`, the
/// staged copy goes with the staging directory and nothing is admitted.
#[cfg(unix)]
fn stage_archive(
    store: &Store,
    trusted: &release::ChannelRoot,
    current: &kr_protocol::update::ReleaseManifest,
    archive: &std::path::Path,
    staging: &std::path::Path,
    check: bool,
) -> Result<kr_protocol::update::ReleaseManifest> {
    kr_ipc::paths::create_private_tree(store.root(), staging)?;
    let (staged, written) = release::unpack(archive, staging)?;
    let document = release::manifest_document(&staged)?;
    let manifest = trusted.verify(&document)?;
    release::check_files(&manifest, &written)?;
    // The release's own root, now that its digest is known to be the listed one: it is this
    // host's root or the one that follows it, which later updates are then checked against.
    let root = release::ChannelRoot::read(&staged)?.ok_or_else(|| {
        CliError::Other(Shown::said(
            "the release carries no update channel root, so no later release could be checked \
             for this host; it is refused",
        ))
    })?;
    trusted.admits_successor(&root)?;
    release::check_system(&manifest)?;
    if manifest.release == current.release {
        return Ok(manifest);
    }
    if manifest.sequence <= current.sequence {
        return Err(CliError::Other(shown!(
            "release {} is not newer than the current release {}: kr host update installs a \
             newer release",
            crate::shown::release(&manifest.release),
            crate::shown::release(&current.release)
        )));
    }
    if check {
        return Ok(manifest);
    }
    if store.release_directory(&manifest.release).exists() {
        // Staged by an update that waited: it is used again when it is the same release, which
        // its manifest says, signatures and all.
        let kept = release::manifest_document(&store.release_directory(&manifest.release))?;
        if kept != document {
            return Err(CliError::Other(shown!(
                "the store already holds a release named {} that is not this one",
                crate::shown::release(&manifest.release)
            )));
        }
        return Ok(manifest);
    }
    release::seal(&staged, &manifest)?;
    release::admit(&staged, store, &manifest.release)?;
    Ok(manifest)
}

/// What an update that waits returns: [`CliError::UpdateDeferred`], exit 9, naming the target,
/// what held it and what to do.
#[cfg(unix)]
fn deferred(target: &kr_protocol::update::ReleaseManifest, held: Shown) -> CliError {
    CliError::UpdateDeferred(shown!(
        "the update to {} waits: {}; run kr host update again once that has changed",
        crate::shown::release(&target.release),
        held
    ))
}

/// Hands every daemon over, classes every registry, switches `current` and starts each daemon of
/// the target; or, when anything holds the update, starts again what it stopped and waits.
#[cfg(unix)]
async fn hand_over(
    store: &Store,
    record: &mut Record,
    environments: &[inventory::Environment],
    target: &kr_protocol::update::ReleaseManifest,
) -> Result<Vec<EnvironmentId>> {
    // Every daemon prepares before any stops, so a daemon that will not make way costs the others
    // only a closed gate, which reopens.
    let mut prepared = Vec::new();
    for environment in environments {
        match handover::prepare(environment, &target.release).await {
            Ok(Some(daemon)) => prepared.push((environment, daemon)),
            Ok(None) => {}
            Err(refused) => {
                for (environment, daemon) in prepared {
                    handover::resume(daemon, environment, &target.release).await;
                }
                forget_update(store, record);
                return Err(refused);
            }
        }
    }
    // How each is started again, durably, before any is told to stop. A daemon nothing could be
    // recorded for is not stopped, and neither is any other.
    let recorded = prepared
        .iter()
        .map(|(environment, daemon)| restart_of(environment, &daemon.started_as))
        .collect::<Result<Vec<_>>>()
        .and_then(|restarts| {
            if let Some(update) = record.update.as_mut() {
                update.state = TransactionState::HandingOver;
                update.restarts = restarts;
            }
            record.write(store)
        });
    if let Err(error) = recorded {
        for (environment, daemon) in prepared {
            handover::resume(daemon, environment, &target.release).await;
        }
        forget_update(store, record);
        return Err(error);
    }
    for (environment, daemon) in prepared {
        handover::stop(daemon, environment, &target.release).await;
    }
    // The install lock, then every environment's lock in the order of their identities: no daemon
    // starts in any of them until `current` has been decided.
    let install = match store.lock_install() {
        Ok(install) => install,
        Err(error) => {
            restart_all(store, record).await;
            return Err(CliError::Other(said(&error)));
        }
    };
    let mut held = Vec::new();
    let mut holding: Option<Shown> = None;
    for environment in environments {
        match handover::hold(environment).await {
            Ok(lock) => held.push(lock),
            Err(CliError::UpdateDeferred(said)) => {
                holding = Some(said);
                break;
            }
            Err(error) => {
                drop(held);
                drop(install);
                restart_all(store, record).await;
                return Err(error);
            }
        }
    }
    if holding.is_none() {
        for environment in environments {
            match inventory::classify(environment, target).await {
                Ok(found) => {
                    if let Some(first) = found.first() {
                        holding = Some(first.said(target));
                        break;
                    }
                }
                Err(error) => {
                    drop(held);
                    drop(install);
                    restart_all(store, record).await;
                    return Err(error);
                }
            }
        }
    }
    if let Some(held_by) = holding {
        drop(held);
        drop(install);
        restart_all(store, record).await;
        return Err(deferred(target, held_by));
    }
    if let Err(error) = store.switch(&target.release, &install) {
        drop(held);
        drop(install);
        restart_all(store, record).await;
        return Err(CliError::Other(said(&error)));
    }
    // From here the switch has happened. A record that cannot say so is left for the next update,
    // whose recovery reads `current` itself; the daemons are started either way.
    if let Some(update) = record.update.as_mut() {
        update.state = TransactionState::Switched;
    }
    let written = record.write(store);
    drop(held);
    drop(install);
    let restarted = start_recorded(store, record).await;
    written?;
    settle(store, record)?;
    restarted
}

/// Starts every daemon the update under way recorded, from whatever `current` names now, and waits
/// for each to answer as a daemon of it.
#[cfg(unix)]
async fn start_recorded(store: &Store, record: &Record) -> Result<Vec<EnvironmentId>> {
    let Some(update) = &record.update else {
        return Ok(Vec::new());
    };
    let current = store
        .current()
        .map_err(|error| CliError::Other(said(&error)))?
        .ok_or_else(|| {
            CliError::Other(shown!(
                "the store at {} names no current release",
                Shown::root(store.root())
            ))
        })?;
    let mut started = Vec::new();
    let mut failed = None;
    for restart in &update.restarts {
        match start_one(store, restart, &current).await {
            Ok(()) => started.push(restart.environment),
            Err(error) => failed = failed.or(Some(error)),
        }
    }
    match failed {
        Some(error) => Err(error),
        None => Ok(started),
    }
}

/// Starts one recorded daemon, unless one already runs there, and waits for it to answer as a
/// daemon of `current`.
#[cfg(unix)]
async fn start_one(store: &Store, restart: &Restart, current: &ReleaseName) -> Result<()> {
    let host = kr_ipc::paths::HostPaths::new(&restart.runtime_root, &restart.state_root)?;
    let environment = inventory::Environment {
        environment_id: restart.environment,
        paths: host.environment(restart.environment),
        host,
    };
    // A daemon already there, which a person or the service manager started meanwhile, is left
    // as it is; one that does not answer as a daemon of `current` is named, with how to stop it.
    let running = kr_controller::singleton::SingletonLock::hold(
        &environment.paths.singleton_lock(),
        environment.environment_id,
    )
    .is_err();
    if running {
        return handover::answers_as(&environment, current)
            .await
            .map_err(|_| CliError::Other(handover::still_running(&environment)));
    }
    match &restart.start {
        Start::Service => {
            let known = crate::resolve::KnownEnvironment {
                environment_id: environment.environment_id,
                paths: environment.paths.clone(),
            };
            crate::startup::open_or_start(&environment.host, &known).await?;
            handover::answers_as(&environment, current).await
        }
        Start::Arguments {
            arguments,
            working_directory,
        } => {
            let mut child = crate::startup::start_as_before(
                &environment.paths,
                &store.stable(kr_ipc::install::Program::Controller),
                arguments,
                std::path::Path::new(working_directory),
            )?;
            let answered = handover::answers_as(&environment, current).await;
            // Collected if it has already ended, as one that could not take the environment has;
            // a daemon that runs goes on without this command.
            let _ = child.try_wait();
            answered
        }
    }
}

/// Starts again every daemon the update under way stopped, from the release still current, and
/// forgets the update: what it staged stays staged.
#[cfg(unix)]
async fn restart_all(store: &Store, record: &mut Record) {
    let _ = start_recorded(store, record).await;
    forget_update(store, record);
}

/// Forgets the update under way, keeping what it staged.
#[cfg(unix)]
fn forget_update(store: &Store, record: &mut Record) {
    record.update = None;
    let _ = record.write(store);
}

/// Records an update as settled: its target current, its source the previous release.
#[cfg(unix)]
fn settle(store: &Store, record: &mut Record) -> Result<()> {
    if let Some(update) = record.update.take() {
        record.previous = Some(update.source);
        if record.staged.as_ref() == Some(&update.target) {
            record.staged = None;
        }
    }
    record.write(store)
}

/// How a daemon that answered `prepare` is started again: by the service manager where its
/// environment chooses the service start, and as it was started otherwise.
#[cfg(unix)]
fn restart_of(
    environment: &inventory::Environment,
    started_as: &kr_protocol::update::HostUpdateHandoverResult,
) -> Result<Restart> {
    let text = |path: &std::path::Path| {
        path.to_str().map(str::to_owned).ok_or_else(|| {
            CliError::UpdateDeferred(shown!(
                "environment {}'s roots are not text, so its daemon cannot be recorded to be \
                 started again",
                environment.environment_id
            ))
        })
    };
    let service = crate::startup::Chosen::read(&environment.paths).controller
        == Some(kr_protocol::hostinfo::configuration::ControllerStartup::Service);
    Ok(Restart {
        environment: environment.environment_id,
        runtime_root: text(environment.host.runtime_root())?,
        state_root: text(environment.host.state_root())?,
        start: if service {
            Start::Service
        } else {
            Start::Arguments {
                arguments: started_as.arguments.clone(),
                working_directory: started_as.working_directory.clone(),
            }
        },
    })
}

/// Settles an update an earlier run left part way, by what `current` actually names.
///
/// Naming the source, the switch never happened: every daemon the update recorded is started
/// again from the source, and the target stays staged. Naming the target, the switch happened:
/// every recorded daemon that is not running is started from the target, and one that is running
/// and does not answer as the target's is named with how to stop it. Either way the update is
/// then forgotten, and a switch back to the source is an update of its own.
#[cfg(unix)]
async fn recover(store: &Store, record: &mut Record) -> Result<()> {
    let Some(update) = record.update.clone() else {
        return Ok(());
    };
    let current = {
        let _install = store
            .lock_install()
            .map_err(|error| CliError::Other(said(&error)))?;
        store
            .current()
            .map_err(|error| CliError::Other(said(&error)))?
    };
    let started = start_recorded(store, record).await;
    if current.as_ref() == Some(&update.target) {
        settle(store, record)?;
    } else {
        forget_update(store, record);
    }
    started.map(|_| ())
}

/// Removes every release nothing needs: not the current one, not the previous one, not one staged
/// for a later update, and not one a running program holds. Returns what it removed.
#[cfg(unix)]
fn collect(
    store: &Store,
    record: &Record,
    update: &kr_ipc::install::StoreLock,
) -> Vec<ReleaseName> {
    let Ok(current) = store.current() else {
        return Vec::new();
    };
    let mut removed = Vec::new();
    for release in store.releases().unwrap_or_default() {
        let needed = current.as_ref() == Some(&release)
            || record.previous.as_ref() == Some(&release)
            || record.staged.as_ref() == Some(&release);
        if !needed && store.retire(&release, update).unwrap_or(false) {
            removed.push(release);
        }
    }
    removed
}

/// `kr host install` on a platform that keeps no store.
#[cfg(not(unix))]
pub fn install(
    _tree: Option<&std::path::Path>,
    _root: Option<&std::path::Path>,
) -> Result<Installed> {
    Err(unsupported())
}

/// `kr host versions` on a platform that keeps no store.
#[cfg(not(unix))]
pub fn versions() -> Result<Vec<Kept>> {
    Err(unsupported())
}

/// `kr host update` on a platform that keeps no store.
#[cfg(not(unix))]
pub async fn update(_archive: Option<&std::path::Path>, _check: bool) -> Result<Updated> {
    Err(unsupported())
}

/// What a platform that keeps no store says.
#[cfg(not(unix))]
fn unsupported() -> CliError {
    CliError::HostUnavailable(Shown::said(
        "this host keeps no store of releases on Windows: its installer replaces the release",
    ))
}
