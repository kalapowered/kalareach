//! Applying a package's native bridge recipe in an application's own directory, and removing
//! exactly what it applied.
//!
//! Section 11 lets a package install "a minimal bridge in an application's documented native
//! plugin or hook location", from a recipe that lists "exact files/configuration edits, hashes,
//! version requirements and removal operations", and asks that unrelated settings be preserved.
//! [`NativeBridges`] is the host's half. The catalogue decides what an installation wants, and this
//! module brings the application's directory to it and keeps a journal of what it did there.
//!
//! # When a recipe is in place
//!
//! A recipe is wanted while its package is installed, the installation's effective grants hold
//! `native_bridge.install` and the installed manifest carries one. [`NativeBridges::reconcile`]
//! compares that with the journal: a wanted release that is not applied is applied, a release the
//! installation moved on from is removed first, and one no longer wanted is removed. None of it
//! changes what the catalogue answered: the installation is committed before the recipe runs, and
//! the recipe's outcome is its journal's.
//!
//! # What is checked before anything is written
//!
//! - The platform: where this host cannot read access-control lists, it changes nothing.
//! - The application's directory: one this host knows, which exists.
//! - The forwarder the registration is expected to start: the `kr-hook` beside the daemon.
//! - The recipe: every step it installs has the removal that undoes it, and every file it names is
//!   the bytes it says.
//! - The version: every executable the package's match rules name on this host's search path is
//!   read, never run, and each must be one a signed qualification record of the package names, at
//!   a version inside the recipe's range. A version nothing establishes is a refusal, not a guess.
//! - The destinations, each walked from one handle on the application's directory without following
//!   a link: a file this host did not write, a key it did not set, a directory replaced by a link, a
//!   document it cannot edit exactly or whose protection a replacement would not keep.
//!
//! # What is recorded
//!
//! Each change is noted before it is made and recorded after it, so a run that stops anywhere
//! leaves a record the next run settles from what is on disk rather than from what the record
//! intended. A release is reported as applied only once every change is published, and a change
//! that cannot be shown to be this host's is neither taken nor claimed.

mod journal;
mod json;
mod tree;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::matching::MatchRule;
use kr_plugin_sdk::plugin::{BridgeRemoval, BridgeStep, NativeBridge};
use kr_plugin_sdk::version::PackageVersion;
use kr_protocol::ids::PluginId;
use kr_protocol::scalars::Digest256;
pub use kr_worker::broker::bridge::BridgeSurface;
pub use kr_worker::broker::connectors::{BridgeFacts, QualifiedExecutable};

use self::journal::{
    Change, Journal, Journals, Kept, Publication, RecordedFacts, Release, Removal, State,
};
use self::tree::{Child, Dir, Entry, Walk};
use crate::catalogue::files;
use crate::error::{ControllerError, Result};

/// The forwarder's executable name.
const FORWARDER: &str = if cfg!(windows) {
    "kr-hook.exe"
} else {
    "kr-hook"
};

/// What happens instead where this host will not change an application's directory.
const INSTEAD: &str = "the package stays installed without its bridge";

/// The most of a settings document this host reads.
const DOCUMENT_LIMIT: u64 = 1 << 20;

/// The most of an installed file this host reads to compare it with what it installed.
const FILE_LIMIT: u64 = 1 << 20;

/// The most of an application's executable this host reads to hash it.
const EXECUTABLE_LIMIT: u64 = 1 << 30;

/// How many times an edit is made again when its document changes underneath it.
const EDIT_ATTEMPTS: usize = 3;

/// Where this host applies native bridges, and what it reads to do it.
#[derive(Clone, Debug)]
pub struct BridgeHost {
    /// Where each package's journal is kept.
    pub journals: PathBuf,
    /// The directory of each application this host applies a bridge for.
    pub applications: Vec<ApplicationDirectory>,
    /// Where an application's executables are looked for.
    pub search_path: Vec<PathBuf>,
    /// The forwarder this installation's registrations are expected to start.
    pub forwarder: Option<PathBuf>,
}

impl BridgeHost {
    /// This host's own: journals in the environment's state directory, each application's
    /// directory under the account's home, the daemon's search path, and the `kr-hook` beside the
    /// daemon, where every packaged installation puts it.
    #[must_use]
    pub fn discover(state_dir: &Path) -> Self {
        Self {
            journals: state_dir.join("native-bridges"),
            applications: files::home_directory()
                .map(|home| application_directories(&home))
                .unwrap_or_default(),
            search_path: std::env::var_os("PATH")
                .map(|path| std::env::split_paths(&path).collect())
                .unwrap_or_default(),
            forwarder: std::env::current_exe()
                .ok()
                .and_then(|path| path.parent().map(|directory| directory.join(FORWARDER)))
                .filter(|path| path.is_file()),
        }
    }
}

/// One application's own directory, which a recipe's paths are under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationDirectory {
    /// The application, as a recipe names it.
    pub application: String,
    /// Its directory.
    pub directory: PathBuf,
}

/// The application directories this host knows, under an account's home.
///
/// Claude Code's is `.claude` in the home directory, where its `settings.json` lives and its
/// `skills/` sits: the directory it reads when `CLAUDE_CONFIG_DIR` is not set, and the one the
/// contact skill's installation uses. The daemon's environment is not the one Claude Code runs in,
/// so a directory that variable names elsewhere is not read from it, and does not get the bridge.
#[must_use]
pub fn application_directories(home: &Path) -> Vec<ApplicationDirectory> {
    vec![ApplicationDirectory {
        application: "Claude Code".to_owned(),
        directory: home.join(".claude"),
    }]
}

/// What an installation wants in place: one release's recipe, and what it is checked against.
#[derive(Clone, Debug)]
pub struct BridgeTarget {
    /// The package.
    pub plugin_id: PluginId,
    /// The installed package hash.
    pub package_digest: PayloadDigest,
    /// The package's extracted copy, where the recipe's files are read from.
    pub package_dir: PathBuf,
    /// The recipe.
    pub recipe: NativeBridge,
    /// The package's match rules, which name the application's executables.
    pub match_rules: Vec<MatchRule>,
    /// The executables the package's signed qualification records name.
    pub qualified: Vec<QualifiedExecutable>,
}

/// What a reconciliation left.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Settled {
    /// Nothing needed doing.
    Unchanged,
    /// The release is applied.
    Applied,
    /// Nothing this host placed is left, apart from what its report names.
    Removed,
    /// The recipe was refused, and nothing of the release is in place.
    Refused(String),
    /// Something that may be this host's could not be settled, so nothing is reported as applied.
    Unsettled(String),
}

/// One package's bridge, as a person reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeReport {
    /// The package.
    pub plugin_id: String,
    /// Where it stands: applying, applied, removing, refused or removed.
    pub state: String,
    /// The release it is about, where there is one.
    pub package_digest: Option<String>,
    /// What no longer matches, what was left in place, what could not be settled, and why the last
    /// application was refused.
    pub notes: Vec<String>,
}

/// The native bridges this host applies.
pub struct NativeBridges {
    host: BridgeHost,
    journals: Journals,
    #[cfg(feature = "testing")]
    testing: Testing,
}

impl std::fmt::Debug for NativeBridges {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeBridges")
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

/// Where this host's own tests stop a run, and what they do just before a publication.
#[cfg(feature = "testing")]
#[derive(Default)]
struct Testing {
    stop_at: std::sync::atomic::AtomicUsize,
    taken: std::sync::atomic::AtomicUsize,
    before_publishing: std::sync::Mutex<Option<PublishingHook>>,
}

#[cfg(feature = "testing")]
type PublishingHook = Box<dyn Fn(&Path) + Send + Sync>;

/// Why a run did not finish.
enum Fault {
    /// The recipe cannot be applied as things are. What the release has in place is taken out and
    /// the reason recorded.
    Refused(String),
    /// This host's own record could not be written or read, or the run was stopped. Everything is
    /// left as it is, for the next run to settle.
    Halted(ControllerError),
}

impl From<ControllerError> for Fault {
    fn from(error: ControllerError) -> Self {
        Self::Halted(error)
    }
}

type Run<T> = std::result::Result<T, Fault>;

/// What settling one change found.
enum Found {
    /// It stays in the journal, perhaps now published.
    Keep(Change),
    /// Nothing of this host's is there.
    Drop,
    /// It may be this host's and cannot be shown to be.
    Unresolved(Kept),
}

/// What one application will be.
struct Plan {
    release: Release,
    root: Dir,
    steps: Vec<Planned>,
}

/// One install step still to be carried out.
enum Planned {
    File {
        path: String,
        digest: String,
        bytes: Vec<u8>,
    },
    Key {
        file: String,
        key: String,
        value: String,
    },
}

impl NativeBridges {
    /// Applies bridges where `host` says.
    #[must_use]
    pub fn new(host: BridgeHost) -> Self {
        let journals = Journals::new(host.journals.clone());
        Self {
            host,
            journals,
            #[cfg(feature = "testing")]
            testing: Testing::default(),
        }
    }

    /// Brings one package's bridge to what its installation wants: the release in `wanted`, or
    /// nothing.
    ///
    /// A refusal is an answer, recorded in the journal, and not an error.
    ///
    /// # Errors
    ///
    /// Returns an error when this host's own record cannot be read or written. What the run had
    /// done by then is left for the next run to settle.
    pub fn reconcile(
        &self,
        plugin_id: &PluginId,
        wanted: Option<&BridgeTarget>,
    ) -> Result<Settled> {
        #[cfg(feature = "testing")]
        self.testing
            .taken
            .store(0, std::sync::atomic::Ordering::SeqCst);
        match self.run(plugin_id, wanted) {
            Ok(settled) => Ok(settled),
            Err(Fault::Halted(error)) => Err(error),
            Err(Fault::Refused(reason)) => Ok(Settled::Refused(reason)),
        }
    }

    /// Returns the packages this host has a journal for.
    ///
    /// # Errors
    ///
    /// Returns an error when a journal cannot be read.
    pub fn journaled(&self) -> Result<Vec<PluginId>> {
        self.journals
            .all()?
            .into_iter()
            .map(|journal| {
                PluginId::new(journal.plugin_id.clone()).map_err(|error| {
                    ControllerError::InvalidArgument(format!(
                        "a native bridge journal names {}: {error}",
                        journal.plugin_id
                    ))
                })
            })
            .collect()
    }

    /// Returns what one release's bridge yields: the application name the installed registration
    /// invokes the forwarder for, the registrations it makes and the forwarder it is expected to
    /// start. `None` unless that exact release is applied with every change published.
    ///
    /// # Errors
    ///
    /// Returns an error when the journal cannot be read.
    pub fn facts(
        &self,
        plugin_id: &PluginId,
        package_digest: PayloadDigest,
    ) -> Result<Option<BridgeFacts>> {
        let Some(journal) = self.journals.load(&plugin_id.to_string())? else {
            return Ok(None);
        };
        if journal.digest() != Some(package_digest.to_string().as_str()) || !journal.is_applied() {
            return Ok(None);
        }
        Ok(journal
            .release
            .and_then(|release| release.facts)
            .map(|facts| facts.facts()))
    }

    /// Reports every package's bridge: what no longer matches what was applied, what removals
    /// left, what could not be settled and why an application was refused.
    ///
    /// # Errors
    ///
    /// Returns an error when a journal cannot be read.
    pub fn reports(&self) -> Result<Vec<BridgeReport>> {
        let mut reports = Vec::new();
        for journal in self.journals.all()? {
            let mut notes = Vec::new();
            if journal.state == State::Applied {
                notes.extend(drift(&journal));
            }
            notes.extend(
                journal
                    .leftovers
                    .iter()
                    .map(|kept| format!("left in place: {}", kept.describe())),
            );
            notes.extend(
                journal
                    .unresolved
                    .iter()
                    .map(|kept| format!("not settled: {}", kept.describe())),
            );
            if let Some(reason) = &journal.refusal {
                notes.push(format!("refused: {reason}"));
            }
            reports.push(BridgeReport {
                plugin_id: journal.plugin_id.clone(),
                state: journal.state.as_str().to_owned(),
                package_digest: journal.digest().map(str::to_owned),
                notes,
            });
        }
        Ok(reports)
    }

    /// Stops each later run before its `step`th durable step, counted from one, as a host that
    /// stopped there would; zero never stops.
    #[cfg(feature = "testing")]
    pub fn stop_before(&self, step: usize) {
        self.testing
            .stop_at
            .store(step, std::sync::atomic::Ordering::SeqCst);
    }

    /// Runs `hook` with each destination's path just before it is published.
    #[cfg(feature = "testing")]
    pub fn before_publishing(&self, hook: impl Fn(&Path) + Send + Sync + 'static) {
        *self
            .testing
            .before_publishing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::new(hook));
    }

    fn run(&self, plugin_id: &PluginId, wanted: Option<&BridgeTarget>) -> Run<Settled> {
        let mut journal = match self.journals.load(&plugin_id.to_string())? {
            Some(journal) => journal,
            None if wanted.is_none() => return Ok(Settled::Unchanged),
            None => Journal::new(plugin_id),
        };
        self.settle(&mut journal)?;
        let same = wanted.is_some_and(|target| {
            journal.digest() == Some(target.package_digest.to_string().as_str())
        });
        // A removal an earlier run began is finished, and a release no longer wanted is taken out
        // before another is applied.
        if journal.state == State::Removing || (!journal.changes.is_empty() && !same) {
            self.undo(&mut journal)?;
        }
        let Some(target) = wanted else {
            return self.finish_removal(journal);
        };
        if same && journal.state == State::Applied {
            return Ok(if journal.is_applied() {
                Settled::Unchanged
            } else {
                Settled::Unsettled(unsettled(&journal))
            });
        }
        self.apply(&mut journal, target)
    }

    // -----------------------------------------------------------------------------------------
    // Applying
    // -----------------------------------------------------------------------------------------

    fn apply(&self, journal: &mut Journal, target: &BridgeTarget) -> Run<Settled> {
        let plan = match self.preflight(journal, target) {
            Ok(plan) => plan,
            Err(reason) => return self.refuse(journal, reason),
        };
        journal.release = Some(plan.release.clone());
        journal.state = State::Applying;
        journal.refusal = None;
        self.save(journal)?;
        match self.carry_out(journal, &plan) {
            Ok(()) => {}
            Err(Fault::Refused(reason)) => return self.refuse(journal, reason),
            Err(halted) => return Err(halted),
        }
        journal.state = State::Applied;
        recheck(journal);
        self.save(journal)?;
        Ok(if journal.is_applied() {
            Settled::Applied
        } else {
            Settled::Unsettled(unsettled(journal))
        })
    }

    /// Takes out whatever of the release is in place and records why it was refused, so a refusal
    /// leaves nothing of the release behind.
    fn refuse(&self, journal: &mut Journal, reason: String) -> Run<Settled> {
        self.settle(journal)?;
        if !journal.changes.is_empty() {
            self.undo(journal)?;
        }
        journal.state = State::Refused;
        journal.refusal = Some(reason.clone());
        recheck(journal);
        self.save(journal)?;
        Ok(if journal.unresolved.is_empty() {
            Settled::Refused(reason)
        } else {
            Settled::Unsettled(unsettled(journal))
        })
    }

    /// Checks everything a recipe needs before anything is written, and says what is left to do.
    fn preflight(
        &self,
        journal: &Journal,
        target: &BridgeTarget,
    ) -> std::result::Result<Plan, String> {
        files::supported_platform("apply or remove a native bridge", INSTEAD)
            .map_err(|error| error.to_string())?;
        let recipe = &target.recipe;
        let application = recipe.application.as_str();
        let directory = self
            .host
            .applications
            .iter()
            .find(|known| known.application == application)
            .map(|known| known.directory.clone())
            .ok_or_else(|| {
                format!("this host does not know where {application} keeps its plugins")
            })?;
        let root = Dir::open(&directory).map_err(|error| {
            format!(
                "{application}'s directory {} cannot be opened: {error}",
                directory.display()
            )
        })?;
        let forwarder = self
            .host
            .forwarder
            .clone()
            .filter(|path| path.is_absolute() && path.is_file())
            .ok_or_else(|| {
                format!(
                    "this installation has no {FORWARDER} beside its daemon, so the registration \
                     would start a forwarder this host cannot name"
                )
            })?;
        let removal = removal_of(recipe)?;
        let mut sources = Vec::new();
        for step in &recipe.install {
            if let BridgeStep::InstallFile {
                source,
                destination,
                digest,
            } = step
            {
                let bytes = std::fs::read(target.package_dir.join(source.as_str()))
                    .map_err(|error| format!("the package's {source} cannot be read: {error}"))?;
                if PayloadDigest::of(&bytes) != *digest {
                    return Err(format!(
                        "the package's {source} is not the bytes its recipe names"
                    ));
                }
                sources.push((destination.to_string(), bytes));
            }
        }
        let facts = registration(&sources, &forwarder)?;
        let versions = self.versions(target)?;
        let mut steps = Vec::new();
        for step in &recipe.install {
            match step {
                BridgeStep::InstallFile {
                    destination,
                    digest,
                    ..
                } => {
                    let path = destination.to_string();
                    let digest = digest.to_string();
                    if file_is_ours(journal, &root, &path, &digest)? {
                        continue;
                    }
                    let bytes = sources
                        .iter()
                        .find(|(named, _)| *named == path)
                        .map(|(_, bytes)| bytes.clone())
                        .unwrap_or_default();
                    steps.push(Planned::File {
                        path,
                        digest,
                        bytes,
                    });
                }
                BridgeStep::AddConfigurationKey { file, key, value } => {
                    let value = canonical(value)?;
                    if key_is_ours(journal, &root, file.as_str(), key, &value)? {
                        continue;
                    }
                    steps.push(Planned::Key {
                        file: file.to_string(),
                        key: key.clone(),
                        value,
                    });
                }
            }
        }
        Ok(Plan {
            release: Release {
                package_digest: target.package_digest.to_string(),
                application: application.to_owned(),
                directory,
                facts,
                removal,
                versions,
            },
            root,
            steps,
        })
    }

    /// Reads every executable the package's match rules name on the search path and holds each to
    /// the recipe's range by the version a signed record names for its digest.
    fn versions(
        &self,
        target: &BridgeTarget,
    ) -> std::result::Result<Vec<(PathBuf, String)>, String> {
        let range = &target.recipe.application_range;
        let application = target.recipe.application.as_str();
        if target.qualified.is_empty() {
            return Err(format!(
                "no signed qualification record names an executable of {application}, so the \
                 recipe's requirement {range} cannot be shown to hold"
            ));
        }
        let stems: BTreeSet<&str> = target
            .match_rules
            .iter()
            .map(|rule| rule.executable.file_stem.as_str())
            .collect();
        let mut found = BTreeSet::new();
        for directory in &self.host.search_path {
            for stem in &stems {
                let candidate = directory.join(stem);
                let recognised = candidate.to_str().is_some_and(|text| {
                    target
                        .match_rules
                        .iter()
                        .any(|rule| rule.executable.matches_path(text))
                });
                if recognised
                    && candidate.is_file()
                    && let Ok(canonical) = std::fs::canonicalize(&candidate)
                {
                    found.insert(canonical);
                }
            }
        }
        if found.is_empty() {
            return Err(format!(
                "no executable of {application} ({}) is on this host's search path, so the \
                 recipe's requirement {range} cannot be checked",
                stems.into_iter().collect::<Vec<_>>().join(", ")
            ));
        }
        let mut versions = Vec::new();
        for path in found {
            let digest = read_executable(&path)?;
            let record = target
                .qualified
                .iter()
                .find(|record| record.digest == digest)
                .ok_or_else(|| {
                    format!(
                        "{} is not an executable any signed qualification record of this package \
                         names, so its version is not known",
                        path.display()
                    )
                })?;
            let version = PackageVersion::parse(&record.version).map_err(|_| {
                format!(
                    "the signed record for {} names {}, which is not a version",
                    path.display(),
                    record.version
                )
            })?;
            if !range.admits(&version) {
                return Err(format!(
                    "{} is {application} {version}, outside the {range} this recipe is written for",
                    path.display()
                ));
            }
            versions.push((path, record.version.clone()));
        }
        Ok(versions)
    }

    fn carry_out(&self, journal: &mut Journal, plan: &Plan) -> Run<()> {
        for step in &plan.steps {
            match step {
                Planned::File {
                    path,
                    digest,
                    bytes,
                } => self.place_file(journal, &plan.root, path, digest, bytes)?,
                Planned::Key { file, key, value } => {
                    self.place_key(journal, &plan.root, file, key, value)?;
                }
            }
        }
        Ok(())
    }

    /// Makes the directories on a path's way that are not there and returns the one that holds the
    /// path. Each is made under a temporary name, recorded with its identity and renamed into place
    /// only where nothing is, so the directory this host made is the one it can show it made.
    fn make_directories(&self, journal: &mut Journal, root: &Dir, path: &str) -> Run<Option<Dir>> {
        let parts = tree::components(path);
        let directories = parts
            .split_last()
            .map_or(&[][..], |(_, directories)| directories);
        let mut current: Option<Dir> = None;
        let mut walked = String::new();
        for part in directories {
            if !walked.is_empty() {
                walked.push('/');
            }
            walked.push_str(part);
            let base = current.as_ref().unwrap_or(root);
            let next = match base
                .child(part)
                .map_err(|error| refused(root, &walked, &error))?
            {
                Child::Directory(directory) => directory,
                Child::NotADirectory => return Err(Fault::Refused(substituted(root, &walked))),
                Child::Absent => {
                    self.make_directory(journal, root, base, &walked, part)?;
                    match base
                        .child(part)
                        .map_err(|error| refused(root, &walked, &error))?
                    {
                        Child::Directory(directory) => directory,
                        _ => return Err(Fault::Refused(substituted(root, &walked))),
                    }
                }
            };
            current = Some(next);
        }
        Ok(current)
    }

    /// Makes one directory at `name` in `base`, which is `path` under the application's directory.
    fn make_directory(
        &self,
        journal: &mut Journal,
        root: &Dir,
        base: &Dir,
        path: &str,
        name: &str,
    ) -> Run<()> {
        let temporary = tree::temporary_name(name);
        journal
            .changes
            .retain(|change| !matches!(change, Change::Directory { path: recorded, .. } if recorded == path));
        journal.changes.push(Change::Directory {
            path: path.to_owned(),
            temporary: temporary.clone(),
            publication: Publication::Noted,
        });
        self.save(journal)?;
        let index = journal.changes.len() - 1;
        self.step()?;
        if !base
            .make_child(&temporary)
            .map_err(|error| refused(root, path, &error))?
        {
            return Err(Fault::Refused(format!(
                "{} was taken before this host could use it",
                tree::display(base.path(), &temporary)
            )));
        }
        let identity = match base
            .child(&temporary)
            .map_err(|error| refused(root, path, &error))?
        {
            Child::Directory(made) => made
                .identity()
                .map_err(|error| refused(root, path, &error))?,
            _ => return Err(Fault::Refused(substituted(root, path))),
        };
        set_publication(
            &mut journal.changes[index],
            Publication::Staged { identity },
        );
        self.save(journal)?;
        self.step()?;
        match base.rename_new(&temporary, name) {
            Ok(()) => {
                self.step()?;
                base.flush().map_err(|error| refused(root, path, &error))?;
                set_publication(
                    &mut journal.changes[index],
                    Publication::Published { identity },
                );
            }
            // Something else made it meanwhile. It is not this host's to claim, and the one made
            // beside it goes.
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                self.step()?;
                base.remove_directory(&temporary)
                    .map_err(|error| refused(root, path, &error))?;
                journal.changes.remove(index);
            }
            Err(error) => return Err(refused(root, path, &error)),
        }
        self.save(journal)
    }

    /// Publishes one new file: noted with its temporary name, staged and recorded with the staged
    /// file's identity, renamed into place only where nothing is, and recorded as published.
    fn place_file(
        &self,
        journal: &mut Journal,
        root: &Dir,
        path: &str,
        digest: &str,
        bytes: &[u8],
    ) -> Run<()> {
        let parent = self.make_directories(journal, root, path)?;
        let directory = parent.as_ref().unwrap_or(root);
        let name = last_component(path);
        match directory
            .entry(name)
            .map_err(|error| refused(root, path, &error))?
        {
            Entry::Absent => {}
            _ => {
                return Err(Fault::Refused(format!(
                    "{} appeared while the bridge was being applied",
                    tree::display(root.path(), path)
                )));
            }
        }
        let temporary = tree::temporary_name(name);
        journal.changes.retain(
            |change| !matches!(change, Change::File { path: recorded, .. } if recorded == path),
        );
        journal.changes.push(Change::File {
            path: path.to_owned(),
            digest: digest.to_owned(),
            temporary: temporary.clone(),
            publication: Publication::Noted,
        });
        self.save(journal)?;
        let index = journal.changes.len() - 1;
        self.step()?;
        let identity = directory
            .stage(&temporary, bytes, files::READABLE)
            .map_err(|error| refused(root, path, &error))?;
        set_publication(
            &mut journal.changes[index],
            Publication::Staged { identity },
        );
        self.save(journal)?;
        self.about_to_publish(&directory.join(name));
        self.step()?;
        directory
            .rename_new(&temporary, name)
            .map_err(|error| refused(root, path, &error))?;
        self.step()?;
        directory
            .flush()
            .map_err(|error| refused(root, path, &error))?;
        set_publication(
            &mut journal.changes[index],
            Publication::Published { identity },
        );
        self.save(journal)
    }

    /// Adds one key to a document: the edit made against the document as it is, noted, staged,
    /// checked against a document that may have changed meanwhile, renamed into place and
    /// recorded.
    fn place_key(
        &self,
        journal: &mut Journal,
        root: &Dir,
        file: &str,
        key: &str,
        value: &str,
    ) -> Run<()> {
        let parent = self.make_directories(journal, root, file)?;
        let directory = parent.as_ref().unwrap_or(root);
        let name = last_component(file);
        let members: Vec<&str> = key.split('.').collect();
        let shown = tree::display(root.path(), file);
        for _ in 0..EDIT_ATTEMPTS {
            let read = directory
                .read(name, DOCUMENT_LIMIT)
                .map_err(|error| Fault::Refused(format!("{shown}: {error}")))?;
            let (bytes, created_members, created_document, mode) = match &read {
                None => (
                    created_document_text(&members, value)?,
                    members.len() - 1,
                    true,
                    files::PRIVATE,
                ),
                Some(read) => {
                    files::guard_access_controls(&directory.join(name), INSTEAD)
                        .map_err(|error| Fault::Refused(error.to_string()))?;
                    let text = std::str::from_utf8(&read.bytes)
                        .map_err(|_| Fault::Refused(format!("{shown} is not text")))?;
                    let inserted = json::insert(text, &members, value).map_err(|reason| {
                        Fault::Refused(format!(
                            "{shown} is not a document this host can edit exactly: {reason}"
                        ))
                    })?;
                    (
                        inserted.text.into_bytes(),
                        inserted.created,
                        false,
                        read.mode,
                    )
                }
            };
            let temporary = tree::temporary_name(name);
            journal.changes.retain(|change| {
                !matches!(change, Change::Key { file: recorded, key: named, .. } if recorded == file && named == key)
            });
            journal.changes.push(Change::Key {
                file: file.to_owned(),
                key: key.to_owned(),
                value: value.to_owned(),
                created_members,
                created_document,
                temporary: temporary.clone(),
                publication: Publication::Noted,
                removing: None,
            });
            self.save(journal)?;
            let index = journal.changes.len() - 1;
            self.step()?;
            let identity = directory
                .stage(&temporary, &bytes, mode)
                .map_err(|error| refused(root, file, &error))?;
            if read.is_some() {
                let listed = files::extended_access_controls(&directory.join(&temporary))
                    .map_err(|error| Fault::Refused(error.to_string()))?;
                if listed {
                    self.discard(journal, index, directory, &temporary)?;
                    return Err(Fault::Refused(format!(
                        "a new file in {} is given an access-control list by the directory \
                         itself, so replacing {shown} here would change who can read it",
                        directory.path().display()
                    )));
                }
            }
            set_publication(
                &mut journal.changes[index],
                Publication::Staged { identity },
            );
            self.save(journal)?;
            self.about_to_publish(&directory.join(name));
            // The document must still be the one the edit was made from. One that changed is read
            // again, so what somebody wrote meanwhile is kept.
            if !still_the_same(directory, name, read.as_ref())
                .map_err(|error| refused(root, file, &error))?
            {
                self.discard(journal, index, directory, &temporary)?;
                continue;
            }
            self.step()?;
            let renamed = if read.is_none() {
                directory.rename_new(&temporary, name)
            } else {
                directory.rename_over(&temporary, name)
            };
            match renamed {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    self.discard(journal, index, directory, &temporary)?;
                    continue;
                }
                Err(error) => return Err(refused(root, file, &error)),
            }
            self.step()?;
            directory
                .flush()
                .map_err(|error| refused(root, file, &error))?;
            set_publication(
                &mut journal.changes[index],
                Publication::Published { identity },
            );
            return self.save(journal);
        }
        Err(Fault::Refused(format!(
            "{shown} kept changing while {key} was added to it"
        )))
    }

    /// Removes a staged file that will not be published, and the change that noted it.
    fn discard(
        &self,
        journal: &mut Journal,
        index: usize,
        directory: &Dir,
        temporary: &str,
    ) -> Run<()> {
        self.step()?;
        directory
            .remove_file(temporary)
            .map_err(|error| Fault::Halted(files::storage(error)))?;
        journal.changes.remove(index);
        self.save(journal)
    }

    // -----------------------------------------------------------------------------------------
    // Settling what an earlier run left in flight
    // -----------------------------------------------------------------------------------------

    /// Settles every change an earlier run noted and did not record, from what is on disk.
    fn settle(&self, journal: &mut Journal) -> Run<()> {
        let in_flight = journal.changes.iter().any(|change| match change {
            Change::Directory { publication, .. } | Change::File { publication, .. } => {
                !matches!(publication, Publication::Published { .. })
            }
            Change::Key {
                publication,
                removing,
                ..
            } => !matches!(publication, Publication::Published { .. }) || removing.is_some(),
        });
        if !in_flight {
            return Ok(());
        }
        let Some(release) = journal.release.clone() else {
            journal.changes.clear();
            return self.save(journal);
        };
        let root = match Dir::open(&release.directory) {
            Ok(root) => root,
            // The directory is gone, and everything the changes were about with it.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                journal.changes.clear();
                return self.save(journal);
            }
            Err(error) => return Err(Fault::Halted(files::storage(error))),
        };
        let mut kept = Vec::with_capacity(journal.changes.len());
        for change in journal.changes.clone() {
            match self.settle_one(&root, change)? {
                Found::Keep(change) => kept.push(change),
                Found::Drop => {}
                Found::Unresolved(unresolved) => journal.unresolved.push(unresolved),
            }
        }
        journal.changes = kept;
        self.save(journal)
    }

    fn settle_one(&self, root: &Dir, change: Change) -> Run<Found> {
        match change {
            Change::Directory {
                publication: Publication::Published { .. },
                ..
            } => Ok(Found::Keep(change)),
            Change::Directory {
                ref path,
                ref temporary,
                publication,
            } => {
                let Walk::Found { parent, name } = tree::parent_of(root, path).map_err(halted)?
                else {
                    return Ok(Found::Drop);
                };
                let directory = parent.as_ref().unwrap_or(root);
                // Still there under its temporary name: it was never put in place, and nothing
                // was put in it.
                if let Child::Directory(_) = directory.child(temporary).map_err(halted)? {
                    self.step()?;
                    directory.remove_directory(temporary).map_err(halted)?;
                    self.step()?;
                    directory.flush().map_err(halted)?;
                    return Ok(Found::Drop);
                }
                match (publication, directory.child(name).map_err(halted)?) {
                    (Publication::Staged { identity }, Child::Directory(found))
                        if found
                            .identity()
                            .is_ok_and(|found| found.same_object(&identity)) =>
                    {
                        let mut published = change.clone();
                        set_publication(&mut published, Publication::Published { identity });
                        Ok(Found::Keep(published))
                    }
                    _ => Ok(Found::Drop),
                }
            }
            Change::File {
                publication: Publication::Published { .. },
                ..
            } => Ok(Found::Keep(change)),
            Change::File {
                ref path,
                ref temporary,
                publication,
                ..
            } => {
                let Walk::Found { parent, name } = tree::parent_of(root, path).map_err(halted)?
                else {
                    return Ok(Found::Drop);
                };
                let directory = parent.as_ref().unwrap_or(root);
                // Still there under its temporary name: it was never published.
                if self.remove_temporary(directory, temporary)? {
                    return Ok(Found::Drop);
                }
                match (publication, directory.entry(name).map_err(halted)?) {
                    (Publication::Staged { identity }, Entry::File(found)) if found == identity => {
                        let mut published = change.clone();
                        set_publication(&mut published, Publication::Published { identity });
                        Ok(Found::Keep(published))
                    }
                    _ => Ok(Found::Drop),
                }
            }
            Change::Key {
                ref file,
                ref key,
                ref value,
                ref temporary,
                publication,
                ref removing,
                ..
            } => {
                let Walk::Found { parent, name } = tree::parent_of(root, file).map_err(halted)?
                else {
                    return Ok(Found::Drop);
                };
                let directory = parent.as_ref().unwrap_or(root);
                let mut settled = change.clone();
                if let Some(removing) = removing {
                    self.remove_temporary(directory, removing)?;
                    if let Change::Key { removing, .. } = &mut settled {
                        *removing = None;
                    }
                }
                match publication {
                    Publication::Published { .. } => return Ok(Found::Keep(settled)),
                    Publication::Noted => {
                        self.remove_temporary(directory, temporary)?;
                        return Ok(Found::Drop);
                    }
                    Publication::Staged { .. } => {}
                }
                if self.remove_temporary(directory, temporary)? {
                    return Ok(Found::Drop);
                }
                let Publication::Staged { identity } = publication else {
                    return Ok(Found::Drop);
                };
                match directory.entry(name).map_err(halted)? {
                    Entry::File(found) if found == identity => {
                        set_publication(&mut settled, Publication::Published { identity });
                        Ok(Found::Keep(settled))
                    }
                    Entry::File(_) => {
                        // Published, and the document has been replaced since. What it says now
                        // may be this host's key carried across, or somebody's own.
                        if key_holds(directory, name, key, value) != Some(false) {
                            return Ok(Found::Unresolved(Kept {
                                directory: root.path().to_path_buf(),
                                path: file.clone(),
                                key: Some(key.clone()),
                                reason: "the document was replaced after this host wrote the key \
                                         and before it recorded doing so, so whether the key is \
                                         still this host's cannot be shown"
                                    .to_owned(),
                            }));
                        }
                        Ok(Found::Drop)
                    }
                    _ => Ok(Found::Drop),
                }
            }
        }
    }

    /// Removes a temporary file this host staged, and returns true when there was one.
    fn remove_temporary(&self, directory: &Dir, temporary: &str) -> Run<bool> {
        match directory.entry(temporary).map_err(halted)? {
            Entry::File(_) => {
                self.step()?;
                directory.remove_file(temporary).map_err(halted)?;
                self.step()?;
                directory.flush().map_err(halted)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    // -----------------------------------------------------------------------------------------
    // Removing
    // -----------------------------------------------------------------------------------------

    /// Takes out every change of the release, in the order the recipe's removal says, then the
    /// directories this host made, deepest first. What no longer holds what was installed is kept
    /// and named.
    fn undo(&self, journal: &mut Journal) -> Run<()> {
        journal.state = State::Removing;
        self.save(journal)?;
        let Some(release) = journal.release.clone() else {
            journal.changes.clear();
            return self.save(journal);
        };
        let root = match Dir::open(&release.directory) {
            Ok(root) => root,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                journal.changes.clear();
                return self.save(journal);
            }
            Err(error) => return Err(Fault::Halted(files::storage(error))),
        };
        for removal in &release.removal {
            let Some(index) = journal
                .changes
                .iter()
                .position(|change| undoes(removal, change))
            else {
                continue;
            };
            match removal {
                Removal::File { .. } => self.remove_file(journal, &root, index)?,
                Removal::Key { .. } => self.remove_key(journal, &root, index)?,
            }
        }
        let mut made: Vec<String> = journal
            .changes
            .iter()
            .filter_map(|change| match change {
                Change::Directory {
                    path,
                    publication: Publication::Published { .. },
                    ..
                } => Some(path.clone()),
                _ => None,
            })
            .collect();
        made.sort_by_key(|path| std::cmp::Reverse(tree::components(path).len()));
        for path in made {
            self.remove_directory(journal, &root, &path)?;
        }
        // Anything still recorded is something the recipe names no removal for.
        for change in std::mem::take(&mut journal.changes) {
            if let Some(kept) = kept_without_removal(&root, &change) {
                journal.leftovers.push(kept);
            }
        }
        self.save(journal)
    }

    fn remove_file(&self, journal: &mut Journal, root: &Dir, index: usize) -> Run<()> {
        let Change::File { path, digest, .. } = journal.changes[index].clone() else {
            return Ok(());
        };
        let kept = match tree::parent_of(root, &path) {
            Err(error) => Some(format!("it could not be reached: {error}")),
            Ok(Walk::Missing) => None,
            Ok(Walk::Substituted(at)) => Some(substituted_reason(root, &at)),
            Ok(Walk::Found { parent, name }) => {
                let directory = parent.as_ref().unwrap_or(root);
                match directory.read(name, FILE_LIMIT) {
                    Ok(None) => None,
                    Ok(Some(read)) if PayloadDigest::of(&read.bytes).to_string() == digest => {
                        self.step()?;
                        match directory.remove_file(name) {
                            Ok(()) => {
                                self.step()?;
                                directory.flush().map_err(halted)?;
                                None
                            }
                            Err(error) => Some(format!("it could not be removed: {error}")),
                        }
                    }
                    Ok(Some(_)) => Some("it has changed since it was installed".to_owned()),
                    Err(error) => Some(error.to_string()),
                }
            }
        };
        journal.changes.remove(index);
        if let Some(reason) = kept {
            journal.leftovers.push(Kept {
                directory: root.path().to_path_buf(),
                path,
                key: None,
                reason,
            });
        }
        self.save(journal)
    }

    fn remove_key(&self, journal: &mut Journal, root: &Dir, index: usize) -> Run<()> {
        let Change::Key {
            file,
            key,
            value,
            created_members,
            created_document,
            ..
        } = journal.changes[index].clone()
        else {
            return Ok(());
        };
        let members: Vec<&str> = key.split('.').collect();
        let mut kept = Some(format!("it kept changing while {key} was taken out of it"));
        for _ in 0..EDIT_ATTEMPTS {
            let (parent, name) = match tree::parent_of(root, &file) {
                Err(error) => {
                    kept = Some(format!("it could not be reached: {error}"));
                    break;
                }
                Ok(Walk::Missing) => {
                    kept = None;
                    break;
                }
                Ok(Walk::Substituted(at)) => {
                    kept = Some(substituted_reason(root, &at));
                    break;
                }
                Ok(Walk::Found { parent, name }) => (parent, name),
            };
            let directory = parent.as_ref().unwrap_or(root);
            let edit = match planned_removal(directory, name, &members, &value, created_members) {
                Ok(Some(edit)) => edit,
                Ok(None) => {
                    kept = None;
                    break;
                }
                Err(reason) => {
                    kept = Some(reason);
                    break;
                }
            };
            let (read, edited) = edit;
            let delete = created_document
                && json::Document::read(&edited).is_ok_and(|document| document.is_empty());
            let temporary = tree::temporary_name(name);
            if let Change::Key { removing, .. } = &mut journal.changes[index] {
                *removing = Some(temporary.clone());
            }
            self.save(journal)?;
            if !delete {
                self.step()?;
                if let Err(error) = directory.stage(&temporary, edited.as_bytes(), read.mode) {
                    kept = Some(format!("the edit could not be written: {error}"));
                    break;
                }
                let listed = files::extended_access_controls(&directory.join(&temporary));
                if !matches!(listed, Ok(false)) {
                    self.step()?;
                    directory.remove_file(&temporary).map_err(halted)?;
                    kept = Some(match listed {
                        Err(error) => error.to_string(),
                        Ok(_) => format!(
                            "a new file in {} is given an access-control list by the directory \
                             itself, so replacing it here would change who can read it",
                            directory.path().display()
                        ),
                    });
                    break;
                }
            }
            self.about_to_publish(&directory.join(name));
            if !still_the_same(directory, name, Some(&read)).map_err(halted)? {
                if !delete {
                    self.step()?;
                    directory.remove_file(&temporary).map_err(halted)?;
                }
                continue;
            }
            self.step()?;
            let done = if delete {
                directory.remove_file(name)
            } else {
                directory.rename_over(&temporary, name)
            };
            if let Err(error) = done {
                kept = Some(format!("it could not be replaced: {error}"));
                break;
            }
            self.step()?;
            directory.flush().map_err(halted)?;
            kept = None;
            break;
        }
        journal.changes.remove(index);
        if let Some(reason) = kept {
            journal.leftovers.push(Kept {
                directory: root.path().to_path_buf(),
                path: file,
                key: Some(key),
                reason,
            });
        }
        self.save(journal)
    }

    fn remove_directory(&self, journal: &mut Journal, root: &Dir, path: &str) -> Run<()> {
        let Some((index, made)) = journal
            .changes
            .iter()
            .enumerate()
            .find_map(|(index, change)| match change {
                Change::Directory {
                    path: recorded,
                    publication: Publication::Published { identity },
                    ..
                } if recorded == path => Some((index, *identity)),
                _ => None,
            })
        else {
            return Ok(());
        };
        let kept = match tree::parent_of(root, path) {
            Err(error) => Some(format!("it could not be reached: {error}")),
            Ok(Walk::Missing) => None,
            Ok(Walk::Substituted(at)) => Some(substituted_reason(root, &at)),
            Ok(Walk::Found { parent, name }) => {
                let directory = parent.as_ref().unwrap_or(root);
                match directory.child(name) {
                    Err(error) => Some(error.to_string()),
                    Ok(Child::Absent) => None,
                    Ok(Child::NotADirectory) => {
                        Some("it is now a link, or not a directory".to_owned())
                    }
                    Ok(Child::Directory(found))
                        if !found.identity().is_ok_and(|found| found.same_object(&made)) =>
                    {
                        Some("it is not the directory this host made".to_owned())
                    }
                    Ok(Child::Directory(_)) => {
                        self.step()?;
                        match directory.remove_directory(name) {
                            Ok(()) => {
                                self.step()?;
                                directory.flush().map_err(halted)?;
                                None
                            }
                            Err(error)
                                if error.kind() == std::io::ErrorKind::DirectoryNotEmpty
                                    || error.kind() == std::io::ErrorKind::AlreadyExists =>
                            {
                                Some("it holds something this host did not put there".to_owned())
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                            Err(error) => Some(format!("it could not be removed: {error}")),
                        }
                    }
                }
            }
        };
        journal.changes.remove(index);
        if let Some(reason) = kept {
            journal.leftovers.push(Kept {
                directory: root.path().to_path_buf(),
                path: path.to_owned(),
                key: None,
                reason,
            });
        }
        self.save(journal)
    }

    /// Ends a removal: the journal goes when nothing is left to say, and otherwise stays to say it.
    fn finish_removal(&self, mut journal: Journal) -> Run<Settled> {
        recheck(&mut journal);
        if journal.changes.is_empty()
            && journal.unresolved.is_empty()
            && journal.leftovers.is_empty()
        {
            self.step()?;
            self.journals.delete(&journal.plugin_id)?;
            return Ok(Settled::Removed);
        }
        journal.state = State::Removed;
        journal.refusal = None;
        self.save(&journal)?;
        Ok(if journal.unresolved.is_empty() {
            Settled::Removed
        } else {
            Settled::Unsettled(unsettled(&journal))
        })
    }

    // -----------------------------------------------------------------------------------------
    // Steps
    // -----------------------------------------------------------------------------------------

    /// Counts one durable step, and stops the run before it where a test asked for that.
    fn step(&self) -> Run<()> {
        #[cfg(feature = "testing")]
        {
            use std::sync::atomic::Ordering;
            let taken = self.testing.taken.fetch_add(1, Ordering::SeqCst) + 1;
            let stop_at = self.testing.stop_at.load(Ordering::SeqCst);
            if stop_at != 0 && taken >= stop_at {
                return Err(Fault::Halted(ControllerError::Uncertain {
                    detail: format!("the run was stopped before step {taken}"),
                }));
            }
        }
        Ok(())
    }

    /// Writes the journal, durably, as one step.
    fn save(&self, journal: &Journal) -> Run<()> {
        self.step()?;
        self.journals.save(journal)?;
        Ok(())
    }

    fn about_to_publish(&self, destination: &Path) {
        #[cfg(feature = "testing")]
        if let Some(hook) = self
            .testing
            .before_publishing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            hook(destination);
        }
        #[cfg(not(feature = "testing"))]
        let _ = destination;
    }
}

/// The removal operations of a recipe, once every step it installs is shown to have the removal
/// that undoes it and every removal to undo a step it installs.
fn removal_of(recipe: &NativeBridge) -> std::result::Result<Vec<Removal>, String> {
    for step in &recipe.install {
        let (path, key) = step.writes();
        let undone = recipe.remove.iter().any(|removal| {
            removal.undoes() == (path, key)
                && match (step, removal) {
                    (
                        BridgeStep::InstallFile { digest, .. },
                        BridgeRemoval::RemoveFile {
                            digest: removed, ..
                        },
                    ) => digest == removed,
                    (
                        BridgeStep::AddConfigurationKey { .. },
                        BridgeRemoval::RemoveConfigurationKey { .. },
                    ) => true,
                    _ => false,
                }
        });
        if !undone {
            return Err(format!(
                "the recipe installs {path}{} and names no removal that undoes it",
                key.map(|key| format!(" {key}")).unwrap_or_default()
            ));
        }
    }
    for removal in &recipe.remove {
        let (path, key) = removal.undoes();
        if !recipe
            .install
            .iter()
            .any(|step| step.writes() == (path, key))
        {
            return Err(format!(
                "the recipe removes {path}, which it does not install"
            ));
        }
    }
    Ok(recipe
        .remove
        .iter()
        .map(|removal| match removal {
            BridgeRemoval::RemoveFile {
                destination,
                digest,
            } => Removal::File {
                path: destination.to_string(),
                digest: digest.to_string(),
            },
            BridgeRemoval::RemoveConfigurationKey { file, key } => Removal::Key {
                file: file.to_string(),
                key: key.clone(),
            },
        })
        .collect())
}

/// What the registration the recipe installs says: the application name its `kr-hook`
/// invocations carry, and the registrations they are.
fn registration(
    sources: &[(String, Vec<u8>)],
    forwarder: &Path,
) -> std::result::Result<Option<RecordedFacts>, String> {
    let mut applications = BTreeSet::new();
    let mut surfaces = BTreeSet::new();
    for (destination, bytes) in sources {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            continue;
        };
        invocations(&value, destination, &mut applications, &mut surfaces)?;
    }
    let mut named = applications.into_iter();
    let Some(application) = named.next() else {
        return Ok(None);
    };
    if let Some(other) = named.next() {
        return Err(format!(
            "the registration starts the forwarder for {application} and for {other}"
        ));
    }
    Ok(Some(RecordedFacts {
        application,
        surfaces: surfaces.into_iter().collect(),
        forwarder: forwarder.to_path_buf(),
    }))
}

fn invocations(
    value: &serde_json::Value,
    destination: &str,
    applications: &mut BTreeSet<String>,
    surfaces: &mut BTreeSet<BridgeSurface>,
) -> std::result::Result<(), String> {
    match value {
        serde_json::Value::Object(members) => {
            if members.get("command").and_then(serde_json::Value::as_str) == Some("kr-hook") {
                let arguments = members.get("args").and_then(serde_json::Value::as_array);
                let words: Vec<&str> = arguments
                    .map(|arguments| {
                        arguments
                            .iter()
                            .filter_map(serde_json::Value::as_str)
                            .collect()
                    })
                    .unwrap_or_default();
                let surface = match (words.as_slice(), arguments.map(Vec::len)) {
                    ([application, "hook"], Some(2)) => (application, BridgeSurface::Hook),
                    ([application, "channel"], Some(2)) => (application, BridgeSurface::Channel),
                    _ => {
                        return Err(format!(
                            "{destination} starts the forwarder with arguments it does not accept \
                             from a bridge"
                        ));
                    }
                };
                applications.insert((*surface.0).to_owned());
                surfaces.insert(surface.1);
            }
            for nested in members.values() {
                invocations(nested, destination, applications, surfaces)?;
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                invocations(item, destination, applications, surfaces)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// True when the file at `path` is one this host published with this digest and still holds it;
/// false when nothing is there yet.
fn file_is_ours(
    journal: &Journal,
    root: &Dir,
    path: &str,
    digest: &str,
) -> std::result::Result<bool, String> {
    let recorded = journal.changes.iter().any(|change| {
        matches!(change, Change::File { path: recorded, digest: written, publication: Publication::Published { .. }, .. }
            if recorded == path && written == digest)
    });
    let shown = tree::display(root.path(), path);
    match tree::parent_of(root, path).map_err(|error| format!("{shown}: {error}"))? {
        Walk::Missing => Ok(false),
        Walk::Substituted(at) => Err(substituted(root, &at)),
        Walk::Found { parent, name } => {
            let directory = parent.as_ref().unwrap_or(root);
            match directory
                .entry(name)
                .map_err(|error| format!("{shown}: {error}"))?
            {
                Entry::Absent => Ok(false),
                Entry::File(_) if !recorded => Err(format!(
                    "{shown} is already there and this host did not write it; move it aside, \
                     then install again"
                )),
                Entry::File(_) => {
                    let read = directory
                        .read(name, FILE_LIMIT)
                        .map_err(|error| format!("{shown}: {error}"))?;
                    match read {
                        None => Ok(false),
                        Some(read) if PayloadDigest::of(&read.bytes).to_string() == digest => {
                            Ok(true)
                        }
                        Some(_) => Err(format!("{shown} has changed since this host wrote it")),
                    }
                }
                Entry::Directory | Entry::Other => {
                    Err(format!("{shown} is a link, or not a regular file"))
                }
            }
        }
    }
}

/// True when the key is one this host set with this value and still holds it; false when it is
/// not there yet.
fn key_is_ours(
    journal: &Journal,
    root: &Dir,
    file: &str,
    key: &str,
    value: &str,
) -> std::result::Result<bool, String> {
    let recorded = journal.changes.iter().any(|change| {
        matches!(change, Change::Key { file: recorded, key: named, value: written, publication: Publication::Published { .. }, .. }
            if recorded == file && named == key && written == value)
    });
    let shown = tree::display(root.path(), file);
    let members: Vec<&str> = key.split('.').collect();
    match tree::parent_of(root, file).map_err(|error| format!("{shown}: {error}"))? {
        Walk::Missing => Ok(false),
        Walk::Substituted(at) => Err(substituted(root, &at)),
        Walk::Found { parent, name } => {
            let directory = parent.as_ref().unwrap_or(root);
            match directory
                .entry(name)
                .map_err(|error| format!("{shown}: {error}"))?
            {
                Entry::Absent => Ok(false),
                Entry::Directory | Entry::Other => {
                    Err(format!("{shown} is a link, or not a regular file"))
                }
                Entry::File(_) => {
                    files::guard_access_controls(&directory.join(name), INSTEAD)
                        .map_err(|error| error.to_string())?;
                    let Some(read) = directory
                        .read(name, DOCUMENT_LIMIT)
                        .map_err(|error| format!("{shown}: {error}"))?
                    else {
                        return Ok(false);
                    };
                    let text = std::str::from_utf8(&read.bytes)
                        .map_err(|_| format!("{shown} is not text"))?;
                    let document = json::Document::read(text).map_err(|reason| {
                        format!("{shown} is not a document this host can edit exactly: {reason}")
                    })?;
                    match document
                        .value_at(text, &members)
                        .map_err(|reason| format!("{shown}: {reason}"))?
                    {
                        None => Ok(false),
                        Some(current) if recorded && same_json(current, value) => Ok(true),
                        Some(_) if recorded => Err(format!(
                            "{key} in {shown} has changed since this host set it"
                        )),
                        Some(_) => Err(format!(
                            "{key} in {shown} is already set, and not by this host"
                        )),
                    }
                }
            }
        }
    }
}

/// What taking the key out of the document at `name` would leave, with the document it was
/// planned from; `None` when the key is not there.
fn planned_removal(
    directory: &Dir,
    name: &str,
    members: &[&str],
    value: &str,
    created_members: usize,
) -> std::result::Result<Option<(tree::Read, String)>, String> {
    let read = match directory.read(name, DOCUMENT_LIMIT) {
        Ok(Some(read)) => read,
        Ok(None) => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let text = std::str::from_utf8(&read.bytes).map_err(|_| "it is not text".to_owned())?;
    let document = json::Document::read(text).map_err(|reason| {
        format!("it is no longer a document this host can edit exactly: {reason}")
    })?;
    let Some(current) = document.value_at(text, members)? else {
        return Ok(None);
    };
    if !same_json(current, value) {
        return Err("it has changed since it was installed".to_owned());
    }
    files::guard_access_controls(&directory.join(name), INSTEAD)
        .map_err(|error| error.to_string())?;
    let edited = json::remove(text, members, created_members)?;
    Ok(Some((read, edited)))
}

/// True when the document is still the one `read` took, or still absent when `read` found none.
fn still_the_same(directory: &Dir, name: &str, read: Option<&tree::Read>) -> std::io::Result<bool> {
    match (read, directory.entry(name)?) {
        (None, Entry::Absent) => Ok(true),
        (Some(read), Entry::File(identity)) if identity == read.identity => Ok(directory
            .read(name, DOCUMENT_LIMIT)?
            .is_some_and(|now| now.identity == read.identity && now.bytes == read.bytes)),
        _ => Ok(false),
    }
}

/// `Some(true)` when the document holds `value` at `key`, `Some(false)` when it holds something
/// else or nothing, and `None` when that cannot be read.
fn key_holds(directory: &Dir, name: &str, key: &str, value: &str) -> Option<bool> {
    let read = directory.read(name, DOCUMENT_LIMIT).ok()??;
    let text = std::str::from_utf8(&read.bytes).ok()?;
    let document = json::Document::read(text).ok()?;
    let members: Vec<&str> = key.split('.').collect();
    let current = document.value_at(text, &members).ok()?;
    Some(current.is_some_and(|current| same_json(current, value)))
}

/// Reads one executable, never running it: a regular file, not a script, read within the size
/// its file reports and read again when it changed meanwhile.
fn read_executable(path: &Path) -> std::result::Result<Digest256, String> {
    use std::io::Read as _;
    for _ in 0..3 {
        let file = std::fs::File::open(path)
            .map_err(|error| format!("{} cannot be read: {error}", path.display()))?;
        let before = file
            .metadata()
            .map_err(|error| format!("{} cannot be read: {error}", path.display()))?;
        if !before.is_file() {
            return Err(format!("{} is not a regular file", path.display()));
        }
        if before.len() > EXECUTABLE_LIMIT {
            return Err(format!(
                "{} is larger than the {EXECUTABLE_LIMIT} bytes this host reads of it",
                path.display()
            ));
        }
        let mut bytes = Vec::new();
        (&file)
            .take(before.len() + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("{} cannot be read: {error}", path.display()))?;
        if bytes.starts_with(b"#!") {
            return Err(format!(
                "{} is a script, and the program it runs is its interpreter",
                path.display()
            ));
        }
        let after = file
            .metadata()
            .map_err(|error| format!("{} cannot be read: {error}", path.display()))?;
        let unchanged = u64::try_from(bytes.len()).ok() == Some(before.len())
            && after.len() == before.len()
            && after.modified().ok() == before.modified().ok();
        if unchanged {
            return Ok(Digest256::from_bytes(kr_cbor::sha256(&bytes)));
        }
    }
    Err(format!(
        "{} kept changing while it was read",
        path.display()
    ))
}

/// What no longer matches an applied release, in words a person reads.
fn drift(journal: &Journal) -> Vec<String> {
    let Some(release) = journal.release.as_ref() else {
        return Vec::new();
    };
    let Ok(root) = Dir::open(&release.directory) else {
        return vec![format!("{} cannot be opened", release.directory.display())];
    };
    let mut notes = Vec::new();
    for change in &journal.changes {
        match change {
            Change::File { path, digest, .. } => {
                let shown = tree::display(root.path(), path);
                let held = match tree::parent_of(&root, path) {
                    Ok(Walk::Found { parent, name }) => parent
                        .as_ref()
                        .unwrap_or(&root)
                        .read(name, FILE_LIMIT)
                        .map(|read| read.map(|read| PayloadDigest::of(&read.bytes).to_string())),
                    Ok(Walk::Missing) => Ok(None),
                    Ok(Walk::Substituted(at)) => {
                        notes.push(substituted(&root, &at));
                        continue;
                    }
                    Err(error) => Err(error),
                };
                match held {
                    Ok(None) => notes.push(format!("{shown} is missing")),
                    Ok(Some(found)) if found != *digest => {
                        notes.push(format!("{shown} has changed since it was installed"));
                    }
                    Ok(Some(_)) => {}
                    Err(error) => notes.push(format!("{shown}: {error}")),
                }
            }
            Change::Key {
                file, key, value, ..
            } => {
                let shown = tree::display(root.path(), file);
                let holds = match tree::parent_of(&root, file) {
                    Ok(Walk::Found { parent, name }) => {
                        key_holds(parent.as_ref().unwrap_or(&root), name, key, value)
                    }
                    Ok(Walk::Missing) => Some(false),
                    _ => None,
                };
                match holds {
                    Some(true) => {}
                    Some(false) => notes.push(format!(
                        "{key} in {shown} is missing or has changed since it was set"
                    )),
                    None => notes.push(format!("{shown} cannot be read")),
                }
            }
            Change::Directory { .. } => {}
        }
    }
    notes
}

/// Drops what removals left, and what could not be settled, once it is no longer there.
fn recheck(journal: &mut Journal) {
    journal.leftovers.retain(still_there);
    journal.unresolved.retain(still_there);
}

fn still_there(kept: &Kept) -> bool {
    let Ok(root) = Dir::open(&kept.directory) else {
        return false;
    };
    match tree::parent_of(&root, &kept.path) {
        Ok(Walk::Missing) => false,
        Ok(Walk::Found { parent, name }) => {
            let directory = parent.as_ref().unwrap_or(&root);
            match &kept.key {
                None => !matches!(directory.entry(name), Ok(Entry::Absent)),
                Some(key) => {
                    let members: Vec<&str> = key.split('.').collect();
                    match directory.read(name, DOCUMENT_LIMIT) {
                        Ok(None) => false,
                        Ok(Some(read)) => std::str::from_utf8(&read.bytes)
                            .ok()
                            .and_then(|text| {
                                json::Document::read(text)
                                    .ok()
                                    .and_then(|document| document.value_at(text, &members).ok())
                                    .map(|current| current.is_some())
                            })
                            .unwrap_or(true),
                        Err(_) => true,
                    }
                }
            }
        }
        _ => true,
    }
}

fn undoes(removal: &Removal, change: &Change) -> bool {
    match (removal, change) {
        (
            Removal::File { path, digest },
            Change::File {
                path: recorded,
                digest: written,
                publication: Publication::Published { .. },
                ..
            },
        ) => path == recorded && digest == written,
        (
            Removal::Key { file, key },
            Change::Key {
                file: recorded,
                key: named,
                publication: Publication::Published { .. },
                ..
            },
        ) => file == recorded && key == named,
        _ => false,
    }
}

fn kept_without_removal(root: &Dir, change: &Change) -> Option<Kept> {
    let (path, key) = match change {
        Change::File {
            path,
            publication: Publication::Published { .. },
            ..
        } => (path.clone(), None),
        Change::Key {
            file,
            key,
            publication: Publication::Published { .. },
            ..
        } => (file.clone(), Some(key.clone())),
        _ => return None,
    };
    Some(Kept {
        directory: root.path().to_path_buf(),
        path,
        key,
        reason: "the recipe names no removal for it".to_owned(),
    })
}

fn set_publication(change: &mut Change, stage: Publication) {
    match change {
        Change::Directory { publication, .. }
        | Change::File { publication, .. }
        | Change::Key { publication, .. } => *publication = stage,
    }
}

/// The text of a document this host creates to hold one key.
fn created_document_text(members: &[&str], value: &str) -> Run<Vec<u8>> {
    let mut document: serde_json::Value = serde_json::from_str(value)
        .map_err(|error| Fault::Refused(format!("the recipe's value is not JSON: {error}")))?;
    for member in members.iter().rev() {
        let mut object = serde_json::Map::new();
        object.insert((*member).to_owned(), document);
        document = serde_json::Value::Object(object);
    }
    let text = serde_json::to_string_pretty(&document)
        .map_err(|error| Fault::Refused(format!("the document cannot be written: {error}")))?;
    Ok(format!("{text}\n").into_bytes())
}

/// The recipe's value, as the one spelling this host writes and compares.
fn canonical(value: &str) -> std::result::Result<String, String> {
    let parsed: serde_json::Value = serde_json::from_str(value)
        .map_err(|error| format!("the recipe's value {value} is not JSON: {error}"))?;
    serde_json::to_string(&parsed).map_err(|error| error.to_string())
}

fn same_json(left: &str, right: &str) -> bool {
    match (
        serde_json::from_str::<serde_json::Value>(left),
        serde_json::from_str::<serde_json::Value>(right),
    ) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn last_component(path: &str) -> &str {
    tree::components(path).last().copied().unwrap_or(path)
}

fn unsettled(journal: &Journal) -> String {
    journal
        .unresolved
        .iter()
        .map(Kept::describe)
        .collect::<Vec<_>>()
        .join("; ")
}

fn substituted(root: &Dir, at: &str) -> String {
    format!(
        "{} is a link, or not a directory, and this host does not follow it",
        tree::display(root.path(), at)
    )
}

fn substituted_reason(root: &Dir, at: &str) -> String {
    format!(
        "{} is now a link, or not a directory, so what is there is not reached",
        tree::display(root.path(), at)
    )
}

fn refused(root: &Dir, path: &str, error: &std::io::Error) -> Fault {
    Fault::Refused(format!("{}: {error}", tree::display(root.path(), path)))
}

fn halted(error: std::io::Error) -> Fault {
    Fault::Halted(files::storage(error))
}
