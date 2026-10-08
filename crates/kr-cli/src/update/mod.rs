//! The releases this host keeps side by side, and updating between them: `kr host install`,
//! `kr host update`, `kr host rollback` and `kr host versions`.
//!
//! What a release is and how a process holds the one it runs is [`kr_ipc::install`]'s. This module
//! is the command line's side: putting a checked release into the store, handing each control
//! daemon over to the new release, switching `current`, and saying what the host keeps.
//!
//! # An update, in order
//!
//! 1. The update lock is taken, so one update runs at a time and `current` stays as it is, and
//!    this `kr` is checked to be the current release's under it. An update an earlier run left
//!    part way is settled first, by what `current` actually names (`recover`).
//! 2. The release is staged and checked (`release`): signed by the release keys the current
//!    release's channel root names, every file as listed, for this system, newer than the current
//!    release.
//! 3. Every worker the store's environments describe is asked what it is, and nothing is stopped
//!    yet: a worker at a level the new release does not retain holds the update, which waits
//!    (exit 9) and says why.
//! 4. Each daemon is asked to prepare, and how each was started is recorded durably before any is
//!    told to stop. A daemon that does not prepare holds the update: the others resume.
//! 5. The install lock is taken, waiting a bound for a control daemon that is starting. The
//!    environments are read again, so a daemon that started after the first look is found, and
//!    each environment that no prepared daemon serves is looked at: a daemon that holds one holds
//!    the update, with nothing stopped and each daemon prepared resumed. Only then is any daemon
//!    told to stop, in turn. The first that answers that it does not stop ends the telling: the
//!    daemons not yet told resume, and those told are waited for to have gone, up to thirty
//!    seconds from the last telling, before anything is started again. Every environment's lock is
//!    held, every store the new release lists is read where its manifest says it is and a version
//!    the new release does not read refuses the switch (`formats`), a registry that records an
//!    earlier schema than this release reads is brought forward
//!    (`inventory::carry_forward`: the environment's daemon did not run since the earlier schema
//!    step), and every record of every registry is classed (`inventory::classify`). A recorded
//!    environment whose identity cannot be looked at because what holds it is gone is named in the
//!    outcome and passed over. Anything that holds the update restarts the daemons it stopped, from
//!    the release still current, and the update waits.
//! 6. `current` is switched in one rename, the locks are let go, each daemon is started as it was
//!    before, from the new release, and each is waited for to answer as a daemon of it.
//! 7. Releases nothing needs are removed: not the current one, not the previous one, not one
//!    staged for a later update, and not one a running process holds.
//!
//! `rollback` is the same switch to an older release the store keeps: it differs in where the
//! release comes from, which is the store, and in what it requires of it, that it is older than the
//! current release. Everything from the survey of the environments on is shared.
//!
//! The record of the update under way is written before each step that changes what runs, so a
//! run that stops part way leaves what the next needs to finish it or undo it. It is let go of
//! only once every daemon the update stopped answers again: a daemon that does not start keeps it
//! for the next run, which starts that daemon before anything else.

#[cfg(unix)]
mod formats;
#[cfg(unix)]
mod handover;
#[cfg(unix)]
mod inventory;
#[cfg(unix)]
pub mod release;

use std::path::PathBuf;

use kr_client::shown;
#[cfg(unix)]
use kr_client::shown::Said as _;
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
///
/// Format 2 records the update channel root this host trusts, and the root an update under way
/// settles on. A record of format 1 holds neither; it reads as it is and is written as format 2
/// the next time it is written.
pub const RECORD_FORMAT: u32 = 2;

/// The oldest store record format this build reads. Raise it, and remove the step in
/// [`Record::read`] that brings an earlier record forward, once no supported upgrade starts from
/// one.
pub const OLDEST_RECORD_FORMAT: u32 = 1;

/// The longest store record this build reads: it holds the channel roots of the host and of an
/// update under way, of which a release may carry one up to 1 MiB each, written out in the
/// record's own indented form, with room to spare.
const RECORD_LIMIT: u64 = 8 * 1024 * 1024;

/// What a run that stopped part way tells a person to run: either command starts, before anything
/// else, the daemons the one that stopped had stopped, and a rollback goes back from a release whose
/// daemon does not start.
const RUN_AGAIN: &str = "kr host update or kr host rollback";

/// The store's record, `install.json`: what an update needs that the store's directories do not
/// say. Which release is current is `current` itself, never this.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
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
    /// The newest update channel root this host has switched to a release of. A release carries
    /// the root it was built with, and a host trusts the newest of this and its current release's,
    /// so that going back to an older release does not bring back a key the channel has retired.
    /// Absent until the first switch settles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_root: Option<tough::schema::Signed<tough::schema::Root>>,
}

kr_client::debug_as_name!(Record);

/// An update under way.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Transaction {
    /// The release that was current when it began.
    pub source: ReleaseName,
    /// The release it makes current.
    pub target: ReleaseName,
    /// How far it has come.
    pub state: TransactionState,
    /// How each daemon it stopped is started again, recorded before it is told to stop.
    pub restarts: Vec<Restart>,
    /// The update channel root this host trusts once the switch settles: worked out from the root
    /// the store recorded and the roots of the two releases, each checked, before any daemon is
    /// stopped. Settling takes it from here and reads no release, so a root file that is gone by
    /// then cannot lower the trust the host holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_root: Option<tough::schema::Signed<tough::schema::Root>>,
    /// The update that happened and whose daemons did not all start again, which this one went on
    /// past: a rollback to the release it began from, or an update to a release that fixes it.
    /// It is kept until this one switches, so that nothing this one does before then can lose it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abandoned: Option<Abandoned>,
}

kr_client::debug_as_name!(Transaction);

/// An update that happened, `current` having named its target, and whose recorded daemons did not
/// all start from it.
///
/// One record however many updates failed in turn: a transaction that goes on past another that
/// carried one of its own takes the daemons of both and the newer root of the two, so what is
/// owed is one list and the record is never a tree.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Abandoned {
    /// The release the failed update began from.
    pub source: ReleaseName,
    /// The release it made current.
    pub target: ReleaseName,
    /// The daemons that are owed a start, as the newest record of each says.
    pub restarts: Vec<Restart>,
    /// The update channel root the failed update was to settle on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_root: Option<tough::schema::Signed<tough::schema::Root>>,
}

kr_client::debug_as_name!(Abandoned);

/// `newer` and then each of `older` for an environment `newer` has none for: a daemon recorded
/// more recently is the one to start.
fn merged(newer: Vec<Restart>, older: Vec<Restart>) -> Vec<Restart> {
    let mut restarts = newer;
    for restart in older {
        if !restarts
            .iter()
            .any(|known| known.environment == restart.environment)
        {
            restarts.push(restart);
        }
    }
    restarts
}

/// Whichever of two roots is of the higher version, the first when they are of one.
fn newer_root(
    first: Option<tough::schema::Signed<tough::schema::Root>>,
    second: Option<tough::schema::Signed<tough::schema::Root>>,
) -> Option<tough::schema::Signed<tough::schema::Root>> {
    match (first, second) {
        (Some(first), Some(second)) => {
            if second.signed.version > first.signed.version {
                Some(second)
            } else {
                Some(first)
            }
        }
        (first, second) => first.or(second),
    }
}

impl Transaction {
    /// This update, failed, as what it owes: its daemons and its root together with those of the
    /// failed update it went on past, if it did.
    fn abandon(self) -> Abandoned {
        let (restarts, trusted_root) = match self.abandoned {
            Some(earlier) => (
                merged(self.restarts, earlier.restarts),
                newer_root(self.trusted_root, earlier.trusted_root),
            ),
            None => (self.restarts, self.trusted_root),
        };
        Abandoned {
            source: self.source,
            target: self.target,
            restarts,
            trusted_root,
        }
    }
}

impl Abandoned {
    /// The update again, in the state of one whose switch happened, owing its daemons and those in
    /// `newer`, which are the more recent record of any environment they share.
    fn into_update(self, newer: Vec<Restart>) -> Transaction {
        Transaction {
            source: self.source,
            target: self.target,
            state: TransactionState::Switched,
            restarts: merged(newer, self.restarts),
            trusted_root: self.trusted_root,
            abandoned: None,
        }
    }
}

impl Transaction {
    /// The directories the daemons it recorded, and those of a failed update it went on past, read
    /// their configuration documents in, by environment, where they said.
    fn published_directories(&self) -> Vec<(EnvironmentId, PathBuf)> {
        self.restarts
            .iter()
            .chain(
                self.abandoned
                    .iter()
                    .flat_map(|failed| failed.restarts.iter()),
            )
            .filter_map(|restart| {
                restart
                    .configuration_directory
                    .as_ref()
                    .map(|directory| (restart.environment, PathBuf::from(directory)))
            })
            .collect()
    }
}

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
    /// The directory it read its configuration document in, as the daemon said when it was asked to
    /// make way: where a switch looks at the document for as long as the daemon is to be started
    /// again. Absent for a daemon whose release did not say.
    #[serde(default)]
    pub configuration_directory: Option<String>,
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
        /// The variables that decide where it keeps something, with the values it had, null where
        /// it had none. Absent for a daemon an earlier release recorded, which is started in the
        /// environment of the command that starts it, as it always was.
        ///
        /// Remove the absent case, and the reading of it in `start_one`, once no supported updater
        /// leaves a transaction that recorded a daemon without them.
        #[serde(default)]
        environment: Option<Vec<kr_protocol::update::PathVariable>>,
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
        let bytes = kr_ipc::paths::read_owner_only_file(&path, RECORD_LIMIT)?.ok_or_else(|| {
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
        // The step from an earlier format: what a record of format 1 holds is all that format 2
        // holds before it records a root, so it reads as format 2 and the next write says so.
        Ok(Self {
            format: RECORD_FORMAT,
            ..record
        })
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
        if !u64::try_from(bytes.len()).is_ok_and(|length| length <= RECORD_LIMIT) {
            return Err(CliError::Other(Shown::said(
                "the store's record would be larger than this host reads, so it was not written",
            )));
        }
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
    /// The environments no daemon served, whose registries the update brought forward.
    pub carried: Vec<CarriedRegistry>,
    /// The environments the store records that the update could not reach.
    pub unreached: Vec<Unreached>,
    /// Whether this was a check only, which changed nothing.
    pub checked_only: bool,
    /// Whether this went back to an older release rather than forward to a newer one.
    pub rolled_back: bool,
}

/// An environment's registry an update brought forward to the schema its release reads, because no
/// daemon of the environment has run since an earlier schema step.
pub struct CarriedRegistry {
    /// Its environment.
    pub environment: EnvironmentId,
    /// The schema version the registry recorded.
    pub from: i64,
    /// The schema version the migration brought it to.
    pub to: i64,
}

impl CarriedRegistry {
    /// What `--json` says of it.
    fn document(&self) -> Document {
        Document::new()
            .with("environment", crate::output::said(&self.environment))
            .with("from", self.from)
            .with("to", self.to)
    }

    /// What is said to a person.
    fn said(&self) -> Shown {
        shown!(
            "environment {}'s registry was at schema version {} and was brought forward to {}, the \
             schema this release reads; a control daemon of the new release brings it on from \
             there when it starts",
            self.environment,
            self.from,
            self.to
        )
    }

    /// What an update that did not finish says it had already done to this registry.
    #[cfg(unix)]
    fn brought(&self) -> Shown {
        shown!(
            "the registry of environment {} from schema version {} to {}",
            self.environment,
            self.from,
            self.to
        )
    }
}

/// A pair of roots the store records a control daemon served, whose environment the update could
/// not look at, because what holds its identity is gone: a stopped distribution, a removed
/// container, a mount that is not there.
pub struct Unreached {
    /// The runtime root the daemon was started with.
    pub runtime_root: PathBuf,
    /// The state root the daemon was started with.
    pub state_root: PathBuf,
    /// Why it could not be looked at.
    pub reason: Shown,
}

impl Unreached {
    /// What `--json` says of it.
    fn document(&self) -> Document {
        Document::new()
            .with("runtime_root", Shown::root(&self.runtime_root))
            .with("state_root", Shown::root(&self.state_root))
            .with("reason", self.reason.clone())
    }

    /// What is said to a person: for a check, which hands nothing over, what an update would do.
    fn said(&self, check: bool) -> Shown {
        shown!(
            "the environment recorded with runtime root {} and state root {} could not be reached: \
             {}; a control daemon there, if one runs, {} handed over and keeps the release it runs",
            Shown::root(&self.runtime_root),
            Shown::root(&self.state_root),
            self.reason,
            if check { "would not be" } else { "was not" }
        )
    }
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
            .with("rolled_back", self.rolled_back)
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
            .with(
                "carried",
                self.carried
                    .iter()
                    .map(CarriedRegistry::document)
                    .collect::<Vec<_>>(),
            )
            .with(
                "not_reached",
                self.unreached
                    .iter()
                    .map(Unreached::document)
                    .collect::<Vec<_>>(),
            )
    }

    /// What is said to a person.
    #[must_use]
    pub fn lines(&self) -> Vec<Shown> {
        if self.checked_only {
            let mut lines = vec![shown!(
                "release {} checks as a release for this host, and no live session that answered \
                 runs at a level it does not retain; kr host update --archive installs it in \
                 place of {}",
                crate::shown::release(&self.target),
                crate::shown::release(&self.source)
            )];
            lines.extend(self.unreached.iter().map(|unreached| unreached.said(true)));
            return lines;
        }
        if self.source == self.target {
            return vec![shown!(
                "release {} is already current",
                crate::shown::release(&self.target)
            )];
        }
        let mut lines = vec![shown!(
            "{} this host from release {} to {}",
            if self.rolled_back {
                "rolled back"
            } else {
                "updated"
            },
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
        lines.extend(self.carried.iter().map(CarriedRegistry::said));
        lines.extend(self.unreached.iter().map(|unreached| unreached.said(false)));
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
/// outside a store.
#[cfg(unix)]
fn this_release_store() -> Result<(Store, ReleaseName)> {
    let running = kr_ipc::install::this_process().map_err(|error| CliError::Other(said(error)))?;
    let (Some(store), Some(release)) = (running.store(), running.release()) else {
        return Err(CliError::HostUnavailable(Shown::said(
            "this kr is not of an installed release: kr host update updates a host installed with \
             kr host install, and runs as the current release's kr",
        )));
    };
    Ok((store.clone(), release.clone()))
}

/// Refuses unless `release` is the store's current release.
///
/// Asked under the update lock: `current` changes only under it, so the answer holds until the
/// lock is let go, and an update that another finished first is refused rather than checked
/// against the release it replaced.
#[cfg(unix)]
fn ensure_current(store: &Store, release: &ReleaseName) -> Result<()> {
    let current = store
        .current()
        .map_err(|error| CliError::Other(said(&error)))?;
    if current.as_ref() == Some(release) {
        return Ok(());
    }
    Err(CliError::HostUnavailable(match current {
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
    }))
}

/// `kr host install`: puts the unpacked release `tree` into the store at `root` and makes it
/// current.
///
/// Only the first release of a store is installed this way: a store with a current release takes
/// another through `kr host update`, which hands its daemons over first. The release's own `kr`
/// runs this, from the unpacked tree, so what is installed is the program that installs it; the
/// search path and the shells' profiles are the person's, or their installer's, to change.
///
/// The store's record is written before any program of the release is in the store, so a program
/// started from there is a release of the store from its first moment and holds its release, and
/// the release is published and made current under the install lock, so a control daemon of it
/// started meanwhile waits for `current` rather than finding none.
///
/// # Errors
///
/// Returns a refusal when the tree is not a release this host installs, the store already has a
/// current release, or another install or update of the store is running, and the failure to
/// write the store otherwise.
#[cfg(unix)]
pub async fn install(
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
    store
        .create_directories()
        .map_err(|error| CliError::Other(said(&error)))?;
    // One install or update of a store at a time, and whether the store has a current release is
    // decided under the same lock, which every switch of `current` is made under.
    let update_lock = store
        .try_lock_update()
        .map_err(|error| CliError::Other(said(&error)))?
        .ok_or_else(|| {
            CliError::UpdateDeferred(shown!(
                "another install or update of the store at {} is running; run kr host install \
                 again once it has finished",
                Shown::root(store.root())
            ))
        })?;
    if store
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
    // The record first: from here the directory is a store, and a program started from its
    // `versions/` holds the release it is of.
    Record {
        format: RECORD_FORMAT,
        ..Record::default()
    }
    .write(&store)?;
    let staging = store.staging().join(kr_ipc::new_uuid().to_string());
    let staged = stage_tree(&store, &tree, &staging, &update_lock).await;
    let _ = remove_staging(&staging);
    let (release, has_root) = staged?;
    Ok(Installed {
        store,
        release,
        has_root,
    })
}

/// Copies, checks, seals and admits the release at `tree`, and makes it current.
///
/// The same release already in `versions/`, as an install stopped before its switch leaves it, is
/// replaced by the copy checked here ([`replace_kept`]).
#[cfg(unix)]
async fn stage_tree(
    store: &Store,
    tree: &std::path::Path,
    staging: &std::path::Path,
    update_lock: &kr_ipc::install::StoreLock,
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
    release::check_programs(&manifest)?;
    replace_kept(store, &manifest, &document, update_lock, "install")?;
    release::seal(&staged, &manifest)?;
    // Published and made current under the install lock: a control daemon of the release started
    // in between waits for `current` to name it.
    let install =
        handover::install_lock(store, handover::INSTALL_LOCK_WAIT, "kr host install").await?;
    release::admit(&staged, store, &manifest.release)?;
    store
        .switch(&manifest.release, update_lock, &install)
        .map_err(|error| CliError::Other(said(&error)))?;
    Ok((manifest.release, root.is_some()))
}

/// Makes room in `versions/` for the release just checked, when an earlier install or update left
/// one of the same name there. `command` says which command to run again when it cannot.
///
/// What is there is never trusted in place: an interrupted run may have left it short of a file,
/// changed in one, linked to files elsewhere or still writable, and no reading of a tree in place
/// rules out every such thing. It is the same release when its manifest is, byte for byte, the one
/// just checked, and then it is removed, and the copy written and digested by this run takes its
/// place, whole by construction. Another release under the name is refused. A name that is not a
/// directory is not a release, and is removed as a name only; a release that a running program
/// holds is not removed.
#[cfg(unix)]
fn replace_kept(
    store: &Store,
    manifest: &kr_protocol::update::ReleaseManifest,
    document: &[u8],
    update_lock: &kr_ipc::install::StoreLock,
    command: &'static str,
) -> Result<()> {
    let directory = store.release_directory(&manifest.release);
    let Ok(about) = std::fs::symlink_metadata(&directory) else {
        return Ok(());
    };
    if about.file_type().is_dir() {
        let kept = release::manifest_document(&directory).map_err(|_| {
            CliError::Other(shown!(
                "the store holds a directory for release {} whose manifest is not a file this host \
                 reads, a link or a pipe among the possible causes: make {} writable with `chmod -R \
                 u+w`, remove it, and run kr host {} again",
                crate::shown::release(&manifest.release),
                Shown::root(&directory),
                command
            ))
        })?;
        if kept != document {
            return Err(CliError::Other(shown!(
                "the store already holds a release named {} that is not this one",
                crate::shown::release(&manifest.release)
            )));
        }
    }
    let removed = store
        .retire(&manifest.release, update_lock)
        .map_err(|error| CliError::Other(said(&error)))?;
    if removed {
        return Ok(());
    }
    Err(CliError::UpdateDeferred(shown!(
        "release {} was left in the store by an earlier {} and a running program holds it, so it \
         cannot be replaced; stop that program and run kr host {} again",
        crate::shown::release(&manifest.release),
        command,
        command
    )))
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
        // A release is read-only once it is in the store, so its manifest is read as a release's,
        // not as a file of this user's own.
        let sequence = release::manifest_document(&store.release_directory(&release))
            .ok()
            .and_then(|document| {
                kr_protocol::update::ReleaseManifest::read_document(&document).ok()
            })
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
    let (store, source) = this_release_store()?;
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
    // Only now: what `current` names, the root it carries and its sequence are what this update
    // is checked against, and another update may have moved it on before this one took the lock.
    ensure_current(&store, &source)?;
    let mut record = Record::read(&store)?;
    // An update an earlier run left part way is settled first. It never switches `current`, so
    // this kr is still the current release's afterwards. One that happened and whose daemons do
    // not start stays recorded, and an update to another release goes on past it.
    let mut left = None;
    if !check && record.update.is_some() {
        match recover(&store, &mut record, Recovery::Start).await? {
            Recovered::Settled => {}
            Recovered::Failed(why) => left = Some(why),
        }
    }
    let current_manifest = installed_manifest(&store, &source)?;
    let trusted = trusted_root(&store, &record, &source)?;
    let staging = store.staging().join(kr_ipc::new_uuid().to_string());
    let staged = stage_archive(
        &store,
        &update_lock,
        &trusted,
        &current_manifest,
        archive,
        &staging,
        check,
    );
    let _ = remove_staging(&staging);
    let target = staged?;
    if target.release == source {
        // The release that is current is not an update to go on past a failed one with: the daemons
        // it left unstarted are still owed.
        if let (Some(why), Some(failed)) = (left, record.update.as_ref()) {
            return Err(left_part_way(&why, &failed.source, true));
        }
        return Ok(Updated {
            target: source.clone(),
            source,
            restarted: Vec::new(),
            removed: Vec::new(),
            carried: Vec::new(),
            unreached: Vec::new(),
            checked_only: check,
            rolled_back: false,
        });
    }
    // The release is in the store now, and stays there, staged, whatever the rest of this run
    // decides: an update that waits uses it again.
    if !check {
        record.staged = Some(target.release.clone());
        record.write(&store)?;
    }
    carry_out(
        &store,
        &update_lock,
        &mut record,
        source,
        target,
        check,
        false,
    )
    .await
}

/// `kr host rollback`: goes back to the release `to` names, or to the one this host was on before
/// its last switch.
///
/// A rollback is a switch like an update: the same inventory of live workers, the same handover
/// of each control daemon, the same record of what was done and the same recovery of a run that
/// stopped part way. It differs in where the release comes from, which is the store, where it was
/// sealed when it was taken in and has been kept since, and in what it requires of it: that it
/// is older than the release now current.
///
/// # Errors
///
/// Returns [`CliError::Usage`] when there is no release to go back to or the one named is not
/// older, and what an update returns otherwise, [`CliError::UpdateDeferred`] (exit 9) when
/// something live holds it, and a refusal naming every store the older release cannot read as it
/// is, with nothing switched.
#[cfg(unix)]
pub async fn rollback(to: Option<&str>) -> Result<Updated> {
    let (store, source) = this_release_store()?;
    let update_lock = store
        .try_lock_update()
        .map_err(|error| CliError::Other(said(&error)))?
        .ok_or_else(|| {
            CliError::UpdateDeferred(Shown::said(
                "another update of this host is running; run kr host rollback again once it has \
                 finished",
            ))
        })?;
    ensure_current(&store, &source)?;
    let mut record = Record::read(&store)?;
    // An update that happened and whose daemons do not start is what a rollback is for: it goes
    // back to the release that update began from, and starts the daemons from there. Nothing of the
    // release that failed is started on the way, which would leave a daemon of it holding the
    // environment for the rollback to find.
    let failed = match record.update {
        Some(_) => matches!(
            recover(&store, &mut record, Recovery::Ask).await?,
            Recovered::Failed(_)
        ),
        None => false,
    };
    let target = match to {
        Some(name) => ReleaseName::new(name).map_err(|_| {
            CliError::Usage(Shown::said(
                "the name given to --to is not the name of a release: a release is named by its \
                 version and the first twelve digits of its commit, and kr host versions lists \
                 this host's",
            ))
        })?,
        None => if failed {
            record.update.as_ref().map(|update| update.source.clone())
        } else {
            record.previous.clone()
        }
        .ok_or_else(|| {
            CliError::Usage(Shown::said(
                "this host records no release it was on before its last switch, so there is none \
                 to go back to by default: name one with --to; kr host versions lists the releases \
                 it keeps",
            ))
        })?,
    };
    if target == source {
        return Err(CliError::Usage(shown!(
            "release {} is already current",
            crate::shown::release(&target)
        )));
    }
    let kept = store
        .releases()
        .map_err(|error| CliError::Other(said(&error)))?;
    if !kept.contains(&target) {
        return Err(CliError::Usage(shown!(
            "release {} is not in this host's store, which keeps the releases kr host versions \
             lists",
            crate::shown::release(&target)
        )));
    }
    let current = installed_manifest(&store, &source)?;
    let manifest = installed_manifest(&store, &target).map_err(|_| {
        CliError::Other(shown!(
            "release {} is in the store, and its manifest is not one this kr reads: a release that \
             lists no store it reads is not one this host can go back to",
            crate::shown::release(&target)
        ))
    })?;
    if manifest.sequence >= current.sequence {
        return Err(CliError::Usage(shown!(
            "release {} is not older than the current release {}: kr host rollback goes back to an \
             older release, and kr host update --archive moves to a newer one",
            crate::shown::release(&target),
            crate::shown::release(&source)
        )));
    }
    carry_out(
        &store,
        &update_lock,
        &mut record,
        source,
        manifest,
        false,
        true,
    )
    .await
}

/// Everything a switch to `target` does once the release is in the store: the survey of the
/// environments, the first look at the live workers, the handover and the switch, and the
/// removal of the releases nothing needs.
#[cfg(unix)]
async fn carry_out(
    store: &Store,
    update_lock: &kr_ipc::install::StoreLock,
    record: &mut Record,
    source: ReleaseName,
    target: kr_protocol::update::ReleaseManifest,
    check: bool,
    rolled_back: bool,
) -> Result<Updated> {
    // What no state of the disk changes is refused before anything is surveyed or stopped.
    let unlookable = formats::unlookable(&target);
    if !unlookable.is_empty() {
        return Err(formats::refusal(&target, &unlookable));
    }
    // The root this host will trust once the switch settles is worked out before anything is
    // surveyed or stopped, and recorded with the transaction: a root that cannot be read, or two of
    // one version that differ, is found here, while nothing has changed.
    let trusted = trusted_after(store, record, &source, &target.release)?;
    let inventory::Surveyed {
        environments,
        unreached,
        reached,
    } = inventory::environments(store)?;
    // What the rest of the run learns that a person is told, whether it finishes or not.
    let mut report = Report {
        carried: Vec::new(),
        unreached,
        check,
        rolled_back,
    };
    let restarted = match proceed(
        store,
        update_lock,
        record,
        (&environments, &reached),
        (&source, &target, trusted.map(|root| root.to_kept())),
        &mut report,
    )
    .await
    {
        Ok(restarted) => restarted,
        Err(error) => return Err(report.annotate(error)),
    };
    let removed = if check {
        Vec::new()
    } else {
        collect(store, record, update_lock)
    };
    Ok(Updated {
        source,
        target: target.release,
        restarted,
        removed,
        carried: report.carried,
        unreached: report.unreached,
        checked_only: check,
        rolled_back,
    })
}

/// What an update that has surveyed the store's environments learns, which every outcome says: the
/// registries it brought forward and the recorded environments it could not reach.
///
/// An error that leaves an update after its survey goes through [`Report::annotate`] once, in
/// [`update`], so that no exit, a failed record write among them, can leave out what the update had
/// already done.
#[cfg(unix)]
struct Report {
    carried: Vec<CarriedRegistry>,
    unreached: Vec<Unreached>,
    check: bool,
    /// Whether the switch goes back to an older release, which the messages that say what to run
    /// again name.
    rolled_back: bool,
}

#[cfg(unix)]
impl Report {
    /// The error with what the update had done and found said after it, of the same kind and with
    /// the same exit code: a local IPC failure becomes [`CliError::HostUnavailable`], which exits
    /// with 3 and carries the same stable code. An error of any other kind, which no step of an
    /// update returns, is left as it is.
    fn annotate(&self, error: CliError) -> CliError {
        let mut notes = Vec::new();
        if let Some((first, rest)) = self.carried.split_first() {
            let mut list = first.brought();
            for next in rest {
                list = shown!("{}, {}", list, next.brought());
            }
            notes.push(shown!(
                "The update had already brought forward {}; a control daemon of a newer release \
                 brings one on when it starts there",
                list
            ));
        }
        for unreached in &self.unreached {
            notes.push(shown!(
                "The update found that {}",
                unreached.said(self.check)
            ));
        }
        let mut said = match &error {
            CliError::UpdateDeferred(said)
            | CliError::Other(said)
            | CliError::HostUnavailable(said) => said.clone(),
            CliError::Ipc(failed) => Shown::ipc(failed),
            _ => return error,
        };
        if notes.is_empty() {
            return error;
        }
        for note in notes {
            said = shown!("{}. {}", said, note);
        }
        match error {
            CliError::UpdateDeferred(_) => CliError::UpdateDeferred(said),
            CliError::Other(_) => CliError::Other(said),
            _ => CliError::HostUnavailable(said),
        }
    }
}

/// Everything an update does after it has surveyed the environments: the first look at the live
/// workers, the end of a check there, and otherwise the record of the update under way and the
/// handover. Returns the environments whose daemons it started again.
#[cfg(unix)]
async fn proceed(
    store: &Store,
    update_lock: &kr_ipc::install::StoreLock,
    record: &mut Record,
    (environments, reached): (&[inventory::Environment], &[(PathBuf, EnvironmentId)]),
    (source, target, trusted): (
        &ReleaseName,
        &kr_protocol::update::ReleaseManifest,
        Option<tough::schema::Signed<tough::schema::Root>>,
    ),
    report: &mut Report,
) -> Result<Vec<EnvironmentId>> {
    // Nothing is stopped for the first look: a worker at a level the new release does not retain
    // holds the update here, before any daemon is asked anything.
    for environment in environments {
        for stated in inventory::described(&environment.paths).await {
            let retained = stated
                .build
                .as_ref()
                .is_some_and(|build| target.retains(build.protocol_version));
            if !retained {
                return Err(deferred(
                    target,
                    inventory::Holding::Unretained(stated).said(target),
                    report.rolled_back,
                ));
            }
        }
    }
    if report.check {
        return Ok(Vec::new());
    }
    record.update = Some(Transaction {
        source: source.clone(),
        target: target.release.clone(),
        state: TransactionState::Prepared,
        restarts: Vec::new(),
        trusted_root: trusted,
        // What stands recorded now is an update that happened and left daemons unstarted, or
        // nothing: this one goes on past it.
        abandoned: record.update.take().map(Transaction::abandon),
    });
    record.write(store)?;
    hand_over(
        store,
        update_lock,
        record,
        (environments, reached),
        target,
        report,
    )
    .await
}

/// The root an update to this host is checked against: the newest of the current release's and the
/// one the store recorded when it switched to a release that carried a newer.
#[cfg(unix)]
fn trusted_root(
    store: &Store,
    record: &Record,
    source: &ReleaseName,
) -> Result<release::ChannelRoot> {
    trusted_after(store, record, source, source)?.ok_or_else(|| {
        CliError::Other(shown!(
            "release {} carries no update channel root and the store recorded none, so no release \
             can be checked for this host; the update is refused",
            crate::shown::release(source)
        ))
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
    update_lock: &kr_ipc::install::StoreLock,
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
    release::check_programs(&manifest)?;
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
    // Staged by an update that waited: it is the same release when its manifest is, signatures and
    // all, and the copy checked here takes its place.
    replace_kept(store, &manifest, &document, update_lock, "update")?;
    release::seal(&staged, &manifest)?;
    release::admit(&staged, store, &manifest.release)?;
    Ok(manifest)
}

/// What an update that waits returns: [`CliError::UpdateDeferred`], exit 9, naming the target,
/// what held it and what to do.
#[cfg(unix)]
fn deferred(
    target: &kr_protocol::update::ReleaseManifest,
    held: Shown,
    rolled_back: bool,
) -> CliError {
    let (what, command) = if rolled_back {
        ("rollback", "rollback")
    } else {
        ("update", "update")
    };
    CliError::UpdateDeferred(shown!(
        "the {} to {} waits: {}; run kr host {} again once that has changed",
        what,
        crate::shown::release(&target.release),
        held,
        command
    ))
}

/// Hands every daemon over, brings the registry of each environment no daemon has run in forward,
/// classes every registry, switches `current` and starts each daemon of the target; or, when
/// anything holds the update, starts again what it stopped and waits. What it carries and finds
/// unreachable is put in `report`, from where every outcome says it.
#[cfg(unix)]
async fn hand_over(
    store: &Store,
    update_lock: &kr_ipc::install::StoreLock,
    record: &mut Record,
    (environments, reached): (&[inventory::Environment], &[(PathBuf, EnvironmentId)]),
    target: &kr_protocol::update::ReleaseManifest,
    report: &mut Report,
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
                // The daemon that did not prepare may have closed its gate all the same, and its
                // answer been lost: whichever attempt it holds ends, this run being the only one
                // that can have begun it.
                let _ = handover::resume_holder(environment, &target.release).await;
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
    // The install lock, before anything is stopped: no daemon of this store starts until `current`
    // has been decided. A daemon that is starting holds it, shared, so it is waited for, and only
    // for a bound; a daemon that never finishes starting then costs the update no more than a wait,
    // since nothing has been stopped and each daemon prepared resumes.
    let install = match handover::install_lock(
        store,
        handover::INSTALL_LOCK_WAIT,
        if report.rolled_back {
            "kr host rollback"
        } else {
            "kr host update"
        },
    )
    .await
    {
        Ok(install) => install,
        Err(error) => {
            for (environment, daemon) in prepared {
                handover::resume(daemon, environment, &target.release).await;
            }
            forget_update(store, record);
            return Err(error);
        }
    };
    let stopped: Vec<EnvironmentId> = prepared
        .iter()
        .map(|(environment, _)| environment.environment_id)
        .collect();
    // The environments again, before anything is stopped: no daemon can start while the lock is
    // held, so a daemon holding an environment that nobody prepared started after the first look,
    // or was not listening then, and was never asked to make way. It holds the update while
    // nothing has been stopped, and each daemon prepared resumes.
    let inventory::Surveyed {
        environments: again,
        unreached: unreached_again,
        reached: reached_again,
    } = match inventory::environments(store) {
        Ok(again) => again,
        Err(error) => {
            drop(install);
            for (environment, daemon) in prepared {
                handover::resume(daemon, environment, &target.release).await;
            }
            forget_update(store, record);
            return Err(error);
        }
    };
    let every = every_environment(environments, &again);
    // From here the reading under the install lock is the one a person is told of. A pair of roots
    // through which an environment held below was found, at either reading, is not also one the
    // update could not reach.
    let held: Vec<EnvironmentId> = every
        .iter()
        .map(|environment| environment.environment_id)
        .collect();
    report.unreached = still_unreached(
        unreached_again,
        &[reached, reached_again.as_slice()].concat(),
        &held,
    );
    for environment in &every {
        if stopped.contains(&environment.environment_id) {
            continue;
        }
        let held_by = match handover::hold(environment, None).await {
            Ok(_) => continue,
            Err(CliError::UpdateDeferred(said)) => deferred(target, said, report.rolled_back),
            Err(error) => error,
        };
        drop(install);
        for (environment, daemon) in prepared {
            handover::resume(daemon, environment, &target.release).await;
        }
        forget_update(store, record);
        return Err(held_by);
    }
    // Each daemon is told in turn. The first that answers that it does not stop ends the telling:
    // the daemons not yet told resume, and the ones told are waited for to have gone, before
    // anything is started again, so that no daemon is met on its way out.
    let mut told = Vec::new();
    let mut last_told = tokio::time::Instant::now();
    let mut refused: Option<Shown> = None;
    for (environment, daemon) in prepared {
        if refused.is_some() {
            handover::resume(daemon, environment, &target.release).await;
            continue;
        }
        match handover::stop(daemon, environment, &target.release).await {
            handover::Stop::Told => {
                told.push(environment);
                last_told = tokio::time::Instant::now();
            }
            handover::Stop::Refused(said) => {
                refused = Some(shown!(
                    "the control daemon of environment {} did not stop: {}",
                    environment.environment_id,
                    said
                ));
            }
        }
    }
    // Every daemon told is given the same thirty seconds, from the last telling, to have gone: the
    // resumes of the daemons not told, which follow a refusal, do not shorten them.
    let gone_by = last_told + handover::DAEMON_STOP;
    if let Some(said) = refused {
        for environment in told {
            let _ = handover::hold(environment, Some(gone_by)).await;
        }
        drop(install);
        return Err(undo(store, record, deferred(target, said, report.rolled_back)).await);
    }
    // Each environment's lock, in the order of their identities: the daemons told to stop are
    // waited for, and any other holder was looked for above.
    let mut held = Vec::new();
    let mut holding: Option<Shown> = None;
    let mut failed: Option<CliError> = None;
    // Every daemon the update stopped is waited for, whatever holds the update or fails, so what
    // it stopped is started again once it has gone.
    for environment in &every {
        let told_to_stop = stopped.contains(&environment.environment_id);
        match handover::hold(environment, told_to_stop.then_some(gone_by)).await {
            Ok(lock) => held.push(lock),
            Err(CliError::UpdateDeferred(said)) => {
                holding.get_or_insert(said);
            }
            Err(error) => {
                failed.get_or_insert(error);
            }
        }
    }
    if let Some(error) = failed {
        drop(held);
        drop(install);
        return Err(undo(store, record, error).await);
    }
    // Every store the target lists, read where the target's manifest says it is, before anything is
    // brought forward: a switch the target cannot read the stores for is refused with nothing
    // changed, and every daemon it stopped is started again.
    if holding.is_none() {
        let published = record
            .update
            .as_ref()
            .map(Transaction::published_directories)
            .unwrap_or_default();
        let refusals = formats::check(target, store, &every, &published, !report.rolled_back);
        if !refusals.is_empty() {
            drop(held);
            drop(install);
            return Err(undo(store, record, formats::refusal(target, &refusals)).await);
        }
    }
    if holding.is_none() {
        for environment in &every {
            // Every daemon has stopped and every environment's lock and the install lock are held:
            // an environment whose daemon did not run since an earlier schema step is brought to the
            // schema this release reads, which is the schema its registry is classed by.
            // A rollback carries nothing: the release it goes to reads a registry no newer than its
            // own schema, which this release's would be beyond. Its registries are classed from a
            // private copy brought forward instead, so nothing is left unlooked at.
            if !report.rolled_back {
                match inventory::carry_forward(environment) {
                    Ok(Some(done)) => report.carried.push(CarriedRegistry {
                        environment: environment.environment_id,
                        from: done.from,
                        to: done.to,
                    }),
                    Ok(None) => {}
                    Err(error) => {
                        drop(held);
                        drop(install);
                        return Err(undo(store, record, error).await);
                    }
                }
            }
            let classed = if report.rolled_back {
                inventory::classify_apart(environment, target).await
            } else {
                inventory::classify(environment, target).await
            };
            match classed {
                Ok(found) => {
                    if let Some(first) = found.first() {
                        holding = Some(first.said(target));
                        break;
                    }
                }
                Err(error) => {
                    drop(held);
                    drop(install);
                    return Err(undo(store, record, error).await);
                }
            }
        }
    }
    if let Some(held_by) = holding {
        drop(held);
        drop(install);
        return Err(undo(store, record, deferred(target, held_by, report.rolled_back)).await);
    }
    if let Err(error) = store.switch(&target.release, update_lock, &install) {
        drop(held);
        drop(install);
        return Err(undo(store, record, CliError::Other(said(&error))).await);
    }
    // From here the switch has happened. The update is settled only once every daemon it stopped
    // answers as a daemon of the target; until then the record keeps it, and the next run starts
    // what did not start. A record that cannot say it switched is read right all the same: the
    // next run goes by what `current` names.
    if let Some(update) = record.update.as_mut() {
        update.state = TransactionState::Switched;
    }
    let written = record.write(store);
    drop(held);
    drop(install);
    let went_from = record.update.as_ref().map(|update| update.source.clone());
    let restarted = match record.update.as_ref() {
        Some(update) => start_recorded(store, update, true).await,
        None => Ok(Vec::new()),
    }
    .map_err(|failed| {
        // An update that does not start can be gone back from; a rollback goes back to a release
        // that is older than the one it left, and a daemon that does not start there is started by
        // an update, which is where a host goes from here.
        let goes_back = match (&went_from, report.rolled_back) {
            (Some(source), false) => shown!(
                ", and kr host rollback goes back to {}",
                crate::shown::release(source)
            ),
            _ => Shown::said(""),
        };
        CliError::Other(shown!(
            "this host's current release is {} now, and a control daemon the update stopped did \
             not start from it: {}; the next kr host update starts it before anything else{}",
            crate::shown::release(&target.release),
            failed.said(),
            goes_back
        ))
    })?;
    written?;
    settle(store, record)?;
    Ok(restarted)
}

/// The recorded roots the reading under the install lock could not reach, less each pair of roots
/// through which an environment the update holds was found at either reading: such an environment
/// is held and classed, and is no environment the update could not reach, whatever way one of its
/// pairs of roots is spelled.
#[cfg(unix)]
fn still_unreached(
    unreached: Vec<Unreached>,
    reached: &[(PathBuf, EnvironmentId)],
    held: &[EnvironmentId],
) -> Vec<Unreached> {
    unreached
        .into_iter()
        .filter(|unreached| {
            !reached
                .iter()
                .any(|(state_root, id)| *state_root == unreached.state_root && held.contains(id))
        })
        .collect()
}

/// Every environment an update holds and classes once no daemon can start: those read again under
/// the install lock, and any the first look found that the second reading did not, in the order of
/// their identities.
#[cfg(unix)]
fn every_environment<'a>(
    first: &'a [inventory::Environment],
    again: &'a [inventory::Environment],
) -> Vec<&'a inventory::Environment> {
    let mut every: Vec<&inventory::Environment> = again.iter().collect();
    for known in first {
        if !again
            .iter()
            .any(|found| found.environment_id == known.environment_id)
        {
            every.push(known);
        }
    }
    every.sort_by_key(|environment| environment.environment_id.to_string());
    every
}

/// Starts again every daemon the update under way stopped, from the release still current, and
/// returns what ended the update, `ended_by`.
///
/// The update is forgotten, what it staged staying staged, only once every one of those daemons
/// answers. Until then the record keeps it, the next run starts what did not start before anything
/// else, and what is returned says so.
#[cfg(unix)]
async fn undo(store: &Store, record: &mut Record, ended_by: CliError) -> CliError {
    // The daemons this update stopped, and not those of a failed update it went on past: they are
    // started by the switch this update makes, from the release it makes current.
    let started = match record.update.as_ref() {
        Some(update) => start_recorded(store, update, false).await,
        None => Ok(Vec::new()),
    };
    match started {
        Ok(_) => {
            forget_update(store, record);
            ended_by
        }
        Err(failed) => CliError::Other(shown!(
            "{}. A control daemon the update stopped did not start again, and the next {} starts \
             it before anything else: {}",
            ended_by.said(),
            RUN_AGAIN,
            failed.said()
        )),
    }
}

/// Starts every daemon `update` recorded, from whatever `current` names now, and waits for each to
/// answer as a daemon of it. With `with_abandoned`, so are those of the failed update it went on
/// past, for each environment `update` recorded no daemon of: that is when `current` names the
/// release `update` made current, which is where they are owed their start.
#[cfg(unix)]
async fn start_recorded(
    store: &Store,
    update: &Transaction,
    with_abandoned: bool,
) -> Result<Vec<EnvironmentId>> {
    let current = store
        .current()
        .map_err(|error| CliError::Other(said(&error)))?
        .ok_or_else(|| {
            CliError::Other(shown!(
                "the store at {} names no current release",
                Shown::root(store.root())
            ))
        })?;
    let owed: Vec<&Restart> = match update.abandoned.as_ref().filter(|_| with_abandoned) {
        Some(failed) => update
            .restarts
            .iter()
            .chain(failed.restarts.iter().filter(|restart| {
                !update
                    .restarts
                    .iter()
                    .any(|own| own.environment == restart.environment)
            }))
            .collect(),
        None => update.restarts.iter().collect(),
    };
    let mut started = Vec::new();
    let mut failed = None;
    for restart in owed {
        match start_one(store, restart, &current, &update.target).await {
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
/// daemon of `current`. `target` is the release the update under way makes current.
///
/// A daemon already there is asked to resume first. It may be the one the update prepared, which
/// it may have told to stop, or one a person or the service manager started meanwhile. One that
/// resumes goes on serving, and no stop of the handover can end it after, so it is left as it is
/// once it answers as a daemon of `current`; one that does not is named, with how to stop it. One
/// told to stop is going: it is waited for, and then the daemon is started as recorded.
#[cfg(unix)]
async fn start_one(
    store: &Store,
    restart: &Restart,
    current: &ReleaseName,
    target: &ReleaseName,
) -> Result<()> {
    let host = kr_ipc::paths::HostPaths::new(&restart.runtime_root, &restart.state_root)?;
    let environment = inventory::Environment {
        environment_id: restart.environment,
        paths: host.environment(restart.environment),
        host,
    };
    if handover::held(store, &environment, handover::INSTALL_LOCK_WAIT).await? {
        match handover::resume_holder(&environment, target).await? {
            handover::Resumed::Serving => {
                return match handover::answers_as(store, &environment, current, None).await {
                    Ok(()) => Ok(()),
                    Err(unanswered) => {
                        Err(unanswered_by(store, &environment, current, unanswered).await)
                    }
                };
            }
            // A daemon that does not listen is starting, or is on its way out: it is waited for
            // until it answers, which ends the matter, or has gone, when the recorded daemon is
            // started below.
            handover::Resumed::NotListening => {
                match handover::answers_as_or_gone(store, &environment, current, None, true).await {
                    Ok(handover::Answered::Serving) => return Ok(()),
                    Ok(handover::Answered::Gone) => {}
                    Err(unanswered) => {
                        return Err(unanswered_by(store, &environment, current, unanswered).await);
                    }
                }
            }
            handover::Resumed::Stopping => handover::gone(store, &environment, current).await?,
        }
    }
    match &restart.start {
        Start::Service => {
            let known = crate::resolve::KnownEnvironment {
                environment_id: environment.environment_id,
                paths: environment.paths.clone(),
            };
            crate::startup::start_by_service(&known).await?;
            handover::answers_as(store, &environment, current, None).await
        }
        Start::Arguments {
            arguments,
            working_directory,
            environment: variables,
        } => {
            let mut child = crate::startup::start_as_before(
                &environment.paths,
                &store.stable(kr_ipc::install::Program::Controller),
                arguments,
                std::path::Path::new(working_directory),
                variables.as_deref(),
            )?;
            let answered =
                handover::answers_as(store, &environment, current, Some(&mut child)).await;
            // Collected if it has already ended, as one that could not take the environment has;
            // a daemon that runs goes on without this command.
            let _ = child.try_wait();
            answered
        }
    }
}

/// What it says when a daemon that holds an environment does not answer as `expected`.
///
/// A daemon that is starting holds the install lock past its bound, and the look at the environment
/// says that: it is no daemon of this update's to stop. Otherwise what failed comes first, and then
/// what [`handover::still_running`] finds: the daemon that still holds the environment, named with
/// how to stop it unless it now answers as `expected`, or said to have gone.
#[cfg(unix)]
async fn unanswered_by(
    store: &Store,
    environment: &inventory::Environment,
    expected: &ReleaseName,
    unanswered: CliError,
) -> CliError {
    match unanswered {
        deferred @ CliError::UpdateDeferred(_) => deferred,
        failed => CliError::Other(shown!(
            "{}; {}",
            failed.said(),
            handover::still_running(store, environment, expected).await
        )),
    }
}

/// Ends the update under way without its having switched, keeping what it staged.
///
/// An update that went on past a failed one leaves that one recorded again, owing what it owed and
/// the daemons this one stopped and has started again, which are the more recent record of any it
/// shares with it; otherwise nothing is left recorded.
#[cfg(unix)]
fn forget_update(store: &Store, record: &mut Record) {
    record.update = record.update.take().and_then(|ended| {
        let restarts = ended.restarts;
        ended.abandoned.map(|failed| failed.into_update(restarts))
    });
    let _ = record.write(store);
}

/// The update channel root this host trusts after a switch from `source` to `target`: the newest
/// by version of the one recorded, the source's and the target's, each of which was trusted when it
/// was current. Going back to a release never gives a newer root up. A release that carries no root
/// adds none.
///
/// # Errors
///
/// Returns a refusal when the recorded root, or a root a release carries, cannot be read or does
/// not verify against itself, and when two of them have one version and are not the same document:
/// the trust this host holds is never settled on a root it cannot establish.
#[cfg(unix)]
fn trusted_after(
    store: &Store,
    record: &Record,
    source: &ReleaseName,
    target: &ReleaseName,
) -> Result<Option<release::ChannelRoot>> {
    let mut roots = Vec::new();
    if let Some(kept) = record.trusted_root.clone() {
        roots.push((None, release::ChannelRoot::kept(kept)?));
    }
    // The roots an update that is still recorded was to settle on, or that a failed one was: this
    // host trusts the newest of them all the same, so a switch that goes on past it cannot lower
    // what it recorded.
    let pending = record.update.iter().flat_map(|update| {
        [
            update.trusted_root.clone(),
            update
                .abandoned
                .as_ref()
                .and_then(|failed| failed.trusted_root.clone()),
        ]
        .into_iter()
        .flatten()
    });
    for kept in pending {
        roots.push((None, release::ChannelRoot::kept(kept)?));
    }
    for release in [source, target] {
        if let Some(root) = release::ChannelRoot::read(&store.release_directory(release))? {
            roots.push((Some(release), root));
        }
    }
    let called = |origin: &Option<&ReleaseName>| match origin {
        Some(release) => shown!("the root of release {}", crate::shown::release(release)),
        None => Shown::said("the root this host recorded"),
    };
    for (index, (origin, root)) in roots.iter().enumerate() {
        for (other_origin, other) in &roots[index + 1..] {
            if root.version() == other.version() && !root.is(other) {
                return Err(CliError::Other(shown!(
                    "{} and {} are update channel roots of one version that are not the same \
                     document: this host trusts neither, and nothing was switched",
                    called(origin),
                    called(other_origin)
                )));
            }
        }
    }
    Ok(roots
        .into_iter()
        .map(|(_, root)| root)
        .max_by_key(release::ChannelRoot::version))
}

/// Records an update as settled: its target current, its source the previous release, and the
/// update channel root the transaction recorded as the root this host trusts from now on, where it
/// is not older than the one recorded. It reads no release, unless the transaction holds no root
/// because an earlier build began it: the roots of its two releases that can be read are then
/// taken, and the newest of them.
#[cfg(unix)]
fn settle(store: &Store, record: &mut Record) -> Result<()> {
    if let Some(update) = record.update.take() {
        let newer = |root: &tough::schema::Signed<tough::schema::Root>| {
            record
                .trusted_root
                .as_ref()
                .is_none_or(|known| root.signed.version >= known.signed.version)
        };
        // A transaction an earlier build began holds no root: the roots of its two releases are
        // read here, each on its own, and one that cannot be read adds none. Remove this, and its
        // test, once no supported updater begins a transaction without the root.
        let trusted = update.trusted_root.or_else(|| {
            [&update.source, &update.target]
                .into_iter()
                .filter_map(|release| {
                    release::ChannelRoot::read(&store.release_directory(release))
                        .ok()
                        .flatten()
                })
                .max_by_key(release::ChannelRoot::version)
                .map(|root| root.to_kept())
        });
        if let Some(trusted) = trusted.filter(newer) {
            record.trusted_root = Some(trusted);
        }
        record.previous = Some(update.source);
        if record.staged.as_ref() == Some(&update.target) {
            record.staged = None;
        }
    }
    record.write(store)
}

/// How a daemon that answered `prepare` is started again: by the service manager where the daemon
/// was started by it, and as it was started otherwise.
///
/// Which it was is decided by the configuration document the daemon itself reads, at the directory
/// it said, and not by the one this command reads: a daemon started with variables of its own may
/// read another, and the document of this command's environment says nothing of how it was started.
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
    let published = started_as.configuration_directory.as_ref();
    let chosen = match published {
        Some(directory) => crate::startup::Chosen::read_at(
            &std::path::Path::new(directory).join(kr_protocol::hostinfo::configuration::FILE_NAME),
        ),
        None => crate::startup::Chosen::read(&environment.paths),
    };
    let service =
        chosen.controller == Some(kr_protocol::hostinfo::configuration::ControllerStartup::Service);
    Ok(Restart {
        environment: environment.environment_id,
        runtime_root: text(environment.host.runtime_root())?,
        state_root: text(environment.host.state_root())?,
        configuration_directory: published.cloned(),
        start: if service {
            Start::Service
        } else {
            Start::Arguments {
                arguments: started_as.arguments.clone(),
                working_directory: started_as.working_directory.clone(),
                environment: Some(started_as.environment.clone()),
            }
        },
    })
}

/// What an update an earlier run left part way came to.
#[cfg(unix)]
enum Recovered {
    /// It is settled, or it never switched and has been ended: nothing is left recorded.
    Settled,
    /// It switched, `current` names its target, and a daemon it stopped does not answer from it. It
    /// stays recorded, owing that daemon, for an update to another release or a rollback to go on
    /// past.
    Failed(Shown),
}

/// Whether the daemons of an update left part way are started again.
#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Recovery {
    /// They are, from whatever `current` names.
    Start,
    /// Those of an update that switched are asked whether they answer from `current`, and none is
    /// started: a rollback goes back from the release `current` names, and starts each from the
    /// release it goes back to.
    Ask,
}

/// Settles an update an earlier run left part way, by what `current` actually names. The caller
/// holds the update lock, so `current` does not change meanwhile.
///
/// A rescue that never switched, a rollback or update that went on past a failed update and was
/// left before its own switch, is that failed update again, owing its daemons and those the rescue
/// had stopped. Then, `current` naming the source, the switch never happened: every daemon the
/// update recorded is started again from the source, and the target stays staged. Naming the
/// target, the switch happened: every recorded daemon that is not running is started from the
/// target, and one that runs and does not answer as the target's is named with how to stop it.
/// Once every one answers the update is settled; while any does not, the record keeps the update
/// and [`Recovered::Failed`] says why, for a run that can go on past it to go on.
///
/// # Errors
///
/// Returns the failure to write the record, and, for an update that never switched, a daemon that
/// does not start again from the release still current: nothing can be gone back to then.
#[cfg(unix)]
async fn recover(store: &Store, record: &mut Record, how: Recovery) -> Result<Recovered> {
    let Some(mut update) = record.update.clone() else {
        return Ok(Recovered::Settled);
    };
    let current = store
        .current()
        .map_err(|error| CliError::Other(said(&error)))?;
    if update.abandoned.is_some() && current.as_ref() != Some(&update.target) {
        let restarts = std::mem::take(&mut update.restarts);
        if let Some(failed) = update.abandoned.take() {
            update = failed.into_update(restarts);
        }
        record.update = Some(update.clone());
        record.write(store)?;
    }
    let switched = current.as_ref() == Some(&update.target);
    if how == Recovery::Ask && switched && update.abandoned.is_none() {
        return match answering(store, &update).await {
            Ok(()) => settle(store, record).map(|()| Recovered::Settled),
            Err(why) => Ok(Recovered::Failed(why)),
        };
    }
    match start_recorded(store, &update, switched).await {
        Ok(_) if switched => settle(store, record).map(|()| Recovered::Settled),
        Ok(_) => {
            forget_update(store, record);
            Ok(Recovered::Settled)
        }
        Err(failed) if switched => Ok(Recovered::Failed(failed.said())),
        Err(failed) => Err(left_part_way(&failed.said(), &update.source, false)),
    }
}

/// What a run says when an update an earlier run left is not settled: the daemon that does not start,
/// what starts it, and, for an update that switched, what goes back.
#[cfg(unix)]
fn left_part_way(why: &Shown, source: &ReleaseName, switched: bool) -> CliError {
    if switched {
        CliError::Other(shown!(
            "an update an earlier run left part way is not settled yet: a control daemon it \
             stopped did not start again, and the next kr host update starts it before anything \
             else, while kr host rollback goes back to {}: {}",
            crate::shown::release(source),
            why.clone()
        ))
    } else {
        CliError::Other(shown!(
            "an update an earlier run left part way is not settled yet: a control daemon it \
             stopped did not start again, and the next {} starts it before anything else: {}",
            RUN_AGAIN,
            why.clone()
        ))
    }
}

/// Asks whether each daemon `update` recorded, and each of a failed update it went on past, answers
/// as a daemon of `current`, and says which does not.
#[cfg(unix)]
async fn answering(store: &Store, update: &Transaction) -> std::result::Result<(), Shown> {
    let current = store
        .current()
        .ok()
        .flatten()
        .ok_or_else(|| Shown::said("the store names no current release"))?;
    let expected = format!("kr-controller/{current}");
    let every = update.restarts.iter().chain(
        update
            .abandoned
            .iter()
            .flat_map(|failed| failed.restarts.iter()),
    );
    for restart in every {
        let host = kr_ipc::paths::HostPaths::new(&restart.runtime_root, &restart.state_root)
            .map_err(|error| shown!("{}", Shown::ipc(&error)))?;
        let environment = inventory::Environment {
            environment_id: restart.environment,
            paths: host.environment(restart.environment),
            host,
        };
        match handover::answers_as_now(&environment).await {
            Some(build) if build.as_str() == expected => {}
            Some(build) => {
                return Err(shown!(
                    "the control daemon of environment {} answers as {}, not as a daemon of {}",
                    restart.environment,
                    crate::shown::build_name(&build),
                    crate::shown::release(&current)
                ));
            }
            None => {
                return Err(shown!(
                    "no control daemon of {} answers for environment {}",
                    crate::shown::release(&current),
                    restart.environment
                ));
            }
        }
    }
    Ok(())
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
pub async fn install(
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

/// `kr host rollback` on a platform that keeps no store.
#[cfg(not(unix))]
pub async fn rollback(_to: Option<&str>) -> Result<Updated> {
    Err(unsupported())
}

/// What a platform that keeps no store says.
#[cfg(not(unix))]
fn unsupported() -> CliError {
    CliError::HostUnavailable(Shown::said(
        "this host keeps no store of releases on Windows: its installer replaces the release",
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn environment(environment_id: EnvironmentId, root: &str) -> inventory::Environment {
        let host =
            kr_ipc::paths::HostPaths::new(format!("/{root}/runtime"), format!("/{root}/state"))
                .expect("absolute roots");
        inventory::Environment {
            environment_id,
            paths: host.environment(environment_id),
            host,
        }
    }

    /// An environment whose daemon started after the first look is held and classed with the
    /// rest, and so is one the first look found that the second reading does not.
    #[test]
    fn every_environment_either_reading_found_is_held() {
        let [one, two, three] = [1_u8, 2, 3]
            .map(|byte| EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([byte; 16])));
        let first = [environment(one, "one"), environment(two, "two")];
        let again = [environment(two, "two"), environment(three, "three")];
        let every: Vec<EnvironmentId> = every_environment(&first, &again)
            .iter()
            .map(|environment| environment.environment_id)
            .collect();
        assert_eq!(every, vec![one, two, three]);
        // The control: with nothing new, the first look is what is held.
        let every: Vec<EnvironmentId> = every_environment(&first, &first)
            .iter()
            .map(|environment| environment.environment_id)
            .collect();
        assert_eq!(every, vec![one, two]);
    }

    /// The store's record is read up to a size, and one that would be larger than that is not
    /// written: a record this host wrote and could not read again would end every later command.
    #[test]
    fn a_record_larger_than_this_host_reads_is_not_written() {
        let temp = kr_ipc::testing::TempHost::create();
        let (store, environment) = store_and_environment(&temp);
        let mut record = Record {
            format: RECORD_FORMAT,
            ..Record::default()
        };
        record.write(&store).expect("a small record is written");
        let release = |name| ReleaseName::new(name).expect("a release name");
        record.update = Some(Transaction {
            source: release("0.1.0+aaaaaaaaaaaa"),
            target: release("0.2.0+bbbbbbbbbbbb"),
            state: TransactionState::Prepared,
            trusted_root: None,
            abandoned: None,
            restarts: vec![Restart {
                environment: environment.environment_id,
                runtime_root: "/runtime".to_owned(),
                state_root: "/state".to_owned(),
                configuration_directory: None,
                start: Start::Arguments {
                    arguments: vec!["a".repeat(usize::try_from(RECORD_LIMIT).expect("fits") + 1)],
                    working_directory: "/".to_owned(),
                    environment: Some(Vec::new()),
                },
            }],
        });
        let refused = record
            .write(&store)
            .expect_err("too large to be read again");
        assert!(
            refused.to_string().contains("larger than this host reads"),
            "{refused}"
        );
        assert!(
            Record::read(&store)
                .expect("the record on disk is the small one")
                .update
                .is_none()
        );
    }

    /// A store of this test's own, and an environment in it.
    fn store_and_environment(temp: &kr_ipc::testing::TempHost) -> (Store, inventory::Environment) {
        let store = Store::at(temp.root().join("store"));
        store.create_directories().expect("the store's directories");
        let environment = inventory::Environment {
            environment_id: temp.environment_id(),
            paths: temp.environment(),
            host: temp.paths().clone(),
        };
        (store, environment)
    }

    /// Whether a daemon holds an environment is asked only once no daemon is part way through
    /// taking one: the look waits while a daemon holds the install lock for its start, so the
    /// daemon takes its environment, and the look then finds it held.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_look_at_an_environment_refuses_no_daemon_that_is_starting() {
        let temp = kr_ipc::testing::TempHost::create();
        let (store, environment) = store_and_environment(&temp);
        // A daemon part way through its start holds the install lock, shared.
        let starting = store.lock_start().expect("the start lock");
        let looking = handover::held(&store, &environment, std::time::Duration::from_secs(30));
        let starts = async {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            let daemon = kr_controller::singleton::SingletonLock::acquire(
                &environment.paths.singleton_lock(),
                environment.environment_id,
            )
            .expect("the starting daemon takes its environment");
            drop(starting);
            daemon
        };
        let (looked, daemon) = tokio::join!(looking, starts);
        assert!(looked.expect("looks"), "the look finds the daemon");
        drop(daemon);
        // The control: with no daemon there, the environment is free.
        assert!(
            !handover::held(&store, &environment, std::time::Duration::from_secs(30))
                .await
                .expect("looks")
        );
    }

    /// A daemon found holding an environment that does not listen is either starting or on its way
    /// out, and which is known only when it answers or has gone: once its lock is let go the wait
    /// ends, and the recorded daemon is started in its place.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_holder_that_does_not_listen_is_waited_for_until_it_has_gone() {
        let temp = kr_ipc::testing::TempHost::create();
        let (store, environment) = store_and_environment(&temp);
        let daemon = kr_controller::singleton::SingletonLock::acquire(
            &environment.paths.singleton_lock(),
            environment.environment_id,
        )
        .expect("a daemon holds the environment");
        let target = ReleaseName::new("0.1.0+aaaaaaaaaaaa").expect("a release");
        let waiting = handover::answers_as_or_gone(&store, &environment, &target, None, true);
        let leaves = async {
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            drop(daemon);
        };
        let began = std::time::Instant::now();
        let (answered, ()) = tokio::join!(waiting, leaves);
        assert!(
            matches!(answered, Ok(handover::Answered::Gone)),
            "the wait ends when the daemon has gone"
        );
        assert!(
            began.elapsed() < std::time::Duration::from_secs(30),
            "long before the wait for a daemon to start would have"
        );
    }

    /// A daemon told to stop that has not gone is said not to have stopped, and nobody is told to
    /// kill a process for it: the process the lock names may not be the daemon that was told, which
    /// may have ended, or another may have started since. The update starts it again, and a daemon
    /// found still stopping then is named.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_daemon_told_to_stop_that_has_not_gone_is_not_named_as_a_process_to_kill() {
        let temp = kr_ipc::testing::TempHost::create();
        let (_store, environment) = store_and_environment(&temp);
        let daemon = kr_controller::singleton::SingletonLock::acquire(
            &environment.paths.singleton_lock(),
            environment.environment_id,
        )
        .expect("a daemon holds the environment");
        let Err(refused) = handover::hold(&environment, Some(tokio::time::Instant::now())).await
        else {
            panic!("the daemon has not gone");
        };
        assert_eq!(refused.exit_code(), 9, "{refused}");
        let said = refused.to_string();
        assert!(
            said.contains("did not stop within") && !said.contains("kill"),
            "{said}"
        );
        // The control: once it has gone, the environment is taken.
        drop(daemon);
        handover::hold(&environment, Some(tokio::time::Instant::now()))
            .await
            .expect("the environment is free");
    }

    /// A daemon still there is named with the process its lock names, and one that has gone since
    /// is said to have gone: the lock names a process only while it is held. Where a daemon that is
    /// starting holds the install lock past its bound, the environment cannot be looked at, and no
    /// process is named.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_daemon_that_has_gone_is_not_named_to_be_killed() {
        let temp = kr_ipc::testing::TempHost::create();
        let (store, environment) = store_and_environment(&temp);
        let daemon = kr_controller::singleton::SingletonLock::acquire(
            &environment.paths.singleton_lock(),
            environment.environment_id,
        )
        .expect("a daemon holds the environment");
        let expected = ReleaseName::new("0.2.0+bbbbbbbbbbbb").expect("a release");
        let said = handover::still_running(&store, &environment, &expected)
            .await
            .to_string();
        assert!(
            said.contains(&format!("process {}", std::process::id())) && said.contains("kill"),
            "the control: a daemon still there is named: {said}"
        );
        drop(daemon);
        let expected = ReleaseName::new("0.2.0+bbbbbbbbbbbb").expect("a release");
        let said = handover::still_running(&store, &environment, &expected)
            .await
            .to_string();
        assert!(
            said.contains("went away") && !said.contains("kill"),
            "{said}"
        );
    }

    /// What is said of a daemon that still holds an environment: gone, or serving as the release
    /// asked for (it is not to be stopped, whatever it did meanwhile), or named with how to stop it,
    /// and, where it answers as another release, that.
    #[test]
    fn a_daemon_that_now_answers_as_the_release_asked_for_is_not_named_to_be_killed() {
        let environment = EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([7; 16]));
        let expected = ReleaseName::new("0.2.0+bbbbbbbbbbbb").expect("a release");
        let build = |text: &str| kr_protocol::ids::BuildId::new(text).expect("a build");
        let said = |holder| handover::holder_said(environment, holder, &expected).to_string();
        assert!(said(None).contains("went away"));
        // A daemon that answers as the release asked for serves: it is not a process to stop.
        let serving = build("kr-controller/0.2.0+bbbbbbbbbbbb");
        let serving = said(Some((Some(4242), Some(&serving))));
        assert!(
            serving.contains("now answers as a daemon of 0.2.0+bbbbbbbbbbbb")
                && !serving.contains("kill"),
            "{serving}"
        );
        // The controls: one that answers as another release is named with what it answers as, and
        // one that does not answer is said not to; each with how to stop it.
        let before = build("kr-controller/0.1.0+aaaaaaaaaaaa");
        let another = said(Some((Some(4242), Some(&before))));
        assert!(
            another.contains("process 4242")
                && another.contains("answers as kr-controller/0.1.0+aaaaaaaaaaaa")
                && another.contains("not as a daemon of 0.2.0+bbbbbbbbbbbb")
                && another.contains("kill 4242"),
            "{another}"
        );
        let unnamed_another = said(Some((None, Some(&before))));
        assert!(
            unnamed_another.contains("answers as kr-controller/0.1.0+aaaaaaaaaaaa")
                && !unnamed_another.contains("kill"),
            "{unnamed_another}"
        );
        let silent = said(Some((Some(4242), None)));
        assert!(
            silent.contains("does not answer") && silent.contains("kill 4242"),
            "{silent}"
        );
        let unnamed = said(Some((None, None)));
        assert!(
            unnamed.contains("does not answer") && !unnamed.contains("kill"),
            "{unnamed}"
        );
    }

    /// A daemon that has taken its environment and does not yet listen is asked again for a moment
    /// before it is said not to answer: it may be about to. Nothing answers here, so the whole
    /// moment is taken, and none of it is taken back.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_daemon_that_does_not_listen_yet_is_asked_again_before_it_is_said_silent() {
        let temp = kr_ipc::testing::TempHost::create();
        let (_store, environment) = store_and_environment(&temp);
        let began = std::time::Instant::now();
        assert!(handover::answers_as_now(&environment).await.is_none());
        assert!(
            began.elapsed() >= std::time::Duration::from_secs(4),
            "asked again until the moment was over: {:?}",
            began.elapsed()
        );
    }

    /// A daemon that holds an environment and does not listen is waited for, and where another
    /// daemon of the store starts meanwhile and holds the install lock past its bound, the update
    /// says so and names no process to stop: the daemon that holds the environment is not one it
    /// told to stop, and it could not be looked at.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_holder_that_does_not_listen_is_not_blamed_while_another_daemon_starts() {
        let temp = kr_ipc::testing::TempHost::create();
        let (store, environment) = store_and_environment(&temp);
        let _holder = kr_controller::singleton::SingletonLock::acquire(
            &environment.paths.singleton_lock(),
            environment.environment_id,
        )
        .expect("a daemon holds the environment");
        let text = |path: &std::path::Path| path.to_str().expect("text").to_owned();
        let restart = Restart {
            environment: environment.environment_id,
            runtime_root: text(temp.paths().runtime_root()),
            state_root: text(temp.paths().state_root()),
            configuration_directory: None,
            start: Start::Service,
        };
        let current = ReleaseName::new("0.1.0+aaaaaaaaaaaa").expect("a release");
        let target = ReleaseName::new("0.2.0+bbbbbbbbbbbb").expect("a release");
        let (settled, done) = tokio::sync::oneshot::channel();
        let settling = async {
            let outcome = start_one(&store, &restart, &current, &target).await;
            let _ = settled.send(());
            outcome
        };
        // Another environment's daemon starts once the wait has begun, and holds the start lock
        // until the wait has ended.
        let starting = async {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let start = store.lock_start().expect("the start lock");
            let _ = done.await;
            drop(start);
        };
        let (outcome, ()) = tokio::join!(settling, starting);
        let refused = outcome.expect_err("the daemon that holds the environment never answers");
        assert_eq!(refused.exit_code(), 9, "{refused}");
        let said = refused.to_string();
        assert!(
            said.contains("has held its start lock") && !said.contains("kill"),
            "{said}"
        );
    }

    /// The install lock is waited for only a bound: a daemon that holds it for longer than the
    /// bound makes the look, and the wait an update or an install makes, end with a refusal that
    /// says so, and neither takes it while the daemon holds it.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_install_lock_is_never_waited_for_without_a_bound() {
        let temp = kr_ipc::testing::TempHost::create();
        let (store, environment) = store_and_environment(&temp);
        let starting = store.lock_start().expect("the start lock");
        let bound = std::time::Duration::from_millis(200);
        let began = std::time::Instant::now();
        let refused = handover::held(&store, &environment, bound)
            .await
            .expect_err("a daemon that never finishes starting holds the look up for a bound");
        assert_eq!(refused.exit_code(), 9, "the update waits: {refused}");
        assert!(
            refused
                .to_string()
                .contains("is starting and has held its start lock"),
            "{refused}"
        );
        let refused = handover::install_lock(&store, bound, "kr host install")
            .await
            .expect_err("nor is the lock taken");
        assert_eq!(refused.exit_code(), 9, "{refused}");
        assert!(
            refused.to_string().contains("run kr host install again"),
            "the message names the command that waited: {refused}"
        );
        assert!(
            began.elapsed() < std::time::Duration::from_secs(20),
            "each wait ended at its bound"
        );
        // The control: once the daemon has started, the lock is taken at once.
        drop(starting);
        handover::install_lock(&store, bound, "kr host update")
            .await
            .expect("the lock is free");
    }

    /// What an update says to a person of what it carried and could not reach: a check says what an
    /// update would do, and a finished one says what it did.
    #[test]
    fn the_lines_of_an_outcome_say_what_was_carried_and_what_was_not_reached() {
        let release = |name: &str| ReleaseName::new(name).expect("a release name");
        let environment = EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([3; 16]));
        let updated = |checked_only: bool| Updated {
            source: release("0.1.0+aaaaaaaaaaaa"),
            target: release("0.2.0+bbbbbbbbbbbb"),
            restarted: Vec::new(),
            removed: Vec::new(),
            carried: vec![CarriedRegistry {
                environment,
                from: 4,
                to: 6,
            }],
            unreached: vec![Unreached {
                runtime_root: PathBuf::from("/runtime/gone"),
                state_root: PathBuf::from("/state/gone"),
                reason: Shown::said("its environment identity could not be looked at"),
            }],
            checked_only,
            rolled_back: false,
        };
        let said = |lines: Vec<Shown>| {
            lines
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        };
        let done = said(updated(false).lines());
        assert!(
            done.contains(&format!(
                "environment {environment}'s registry was at schema version 4 and was brought \
                 forward to 6"
            )) && done.contains("could not be reached")
                && done.contains("was not handed over"),
            "{done}"
        );
        let checked = said(updated(true).lines());
        assert!(
            checked.contains("could not be reached")
                && checked.contains("would not be handed over")
                && !checked.contains("brought forward"),
            "a check carries nothing and names what an update would not reach: {checked}"
        );
    }

    /// Whatever ends an update after its survey says what it had carried and could not reach, in the
    /// kind of error it was and with its exit code: a wait stays a wait, a failure a failure, and a
    /// local IPC failure, which exits with 3 as a host that is not available does, says it too.
    #[test]
    fn an_error_that_ends_an_update_says_what_it_had_carried_and_could_not_reach() {
        let environment =
            |byte: u8| EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([byte; 16]));
        let unreached = |name: &str| Unreached {
            runtime_root: PathBuf::from(format!("/runtime/{name}")),
            state_root: PathBuf::from(format!("/state/{name}")),
            reason: Shown::said("its environment identity could not be looked at"),
        };
        let report = |check: bool| Report {
            carried: vec![
                CarriedRegistry {
                    environment: environment(1),
                    from: 4,
                    to: 6,
                },
                CarriedRegistry {
                    environment: environment(2),
                    from: 5,
                    to: 6,
                },
            ],
            unreached: vec![unreached("one"), unreached("two")],
            check,
            rolled_back: false,
        };
        let said = |error: &CliError| error.said().to_string();

        let waits = report(false).annotate(CliError::UpdateDeferred(Shown::said("it waits")));
        assert_eq!(waits.exit_code(), 9);
        let text = said(&waits);
        assert!(
            text.starts_with("it waits. The update had already brought forward the registry of "),
            "{text}"
        );
        for expected in [
            "from schema version 4 to 6, the registry of environment",
            "from schema version 5 to 6; a control daemon of a newer release brings one on",
            "/state/one",
            "/state/two",
            "was not handed over",
        ] {
            assert!(text.contains(expected), "{expected}: {text}");
        }

        let failed = report(false).annotate(CliError::Other(Shown::said("it failed")));
        assert_eq!(
            (failed.exit_code(), failed.code()),
            (1, kr_protocol::error::ErrorCode::ResourceUnavailable)
        );
        let text = said(&failed);
        for expected in [
            "it failed. The update had already brought forward the registry of environment",
            "from schema version 4 to 6",
            "from schema version 5 to 6",
            "/state/one",
            "/state/two",
        ] {
            assert!(text.contains(expected), "{expected}: {text}");
        }

        // A local IPC failure keeps its exit code and its stable code.
        let ipc = || {
            kr_ipc::IpcError::io(
                "write",
                std::path::Path::new("/store/install.json"),
                std::io::Error::from_raw_os_error(libc::ENOSPC),
            )
        };
        let was = (
            CliError::Ipc(ipc()).exit_code(),
            kr_protocol::error::ErrorCode::HostNotConfigured,
        );
        let recorded = report(false).annotate(CliError::Ipc(ipc()));
        assert_eq!((recorded.exit_code(), recorded.code()), was);
        assert!(said(&recorded).contains("The update had already brought forward"));

        // A check names what an update would not reach, and carries nothing.
        let checked = Report {
            carried: Vec::new(),
            unreached: vec![unreached("one")],
            check: true,
            rolled_back: false,
        }
        .annotate(CliError::UpdateDeferred(Shown::said("it waits")));
        let text = said(&checked);
        assert!(
            text.contains("would not be handed over") && !text.contains("brought forward"),
            "{text}"
        );

        // Nothing carried and nothing unreached: the error is as it was.
        let plain = Report {
            carried: Vec::new(),
            unreached: Vec::new(),
            check: false,
            rolled_back: false,
        }
        .annotate(CliError::Other(Shown::said("it failed")));
        assert_eq!(said(&plain), "it failed");
    }

    /// A pair of roots the second reading could not reach is not one the update could not reach when
    /// an environment it holds was found through it at either reading, in whatever spelling of the
    /// path: `/tmp` and `/private/tmp` name one directory on macOS, and both are recorded.
    #[test]
    fn a_pair_of_roots_an_environment_the_update_holds_was_found_through_is_not_unreached() {
        let environment =
            |byte: u8| EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([byte; 16]));
        let unreached = |state: &str| Unreached {
            runtime_root: PathBuf::from("/runtime"),
            state_root: PathBuf::from(state),
            reason: Shown::said("gone"),
        };
        let found = vec![
            (PathBuf::from("/tmp/state"), environment(1)),
            (PathBuf::from("/private/tmp/state"), environment(1)),
            (PathBuf::from("/state/other"), environment(2)),
        ];
        let left = still_unreached(
            vec![
                unreached("/tmp/state"),
                unreached("/private/tmp/state"),
                unreached("/state/other"),
                unreached("/state/removed"),
            ],
            &found,
            &[environment(1)],
        );
        let states: Vec<_> = left
            .iter()
            .map(|unreached| unreached.state_root.display().to_string())
            .collect();
        assert_eq!(
            states,
            vec!["/state/other", "/state/removed"],
            "an environment that is not held keeps its roots named, and so does a pair nothing was found through"
        );
    }
}
