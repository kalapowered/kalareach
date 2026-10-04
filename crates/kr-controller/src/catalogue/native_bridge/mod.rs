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
//! A recipe is wanted while its package is installed and enabled, its repository has not revoked the
//! release, the organisation's adapter allowlist (where there is one) names it, the installation's
//! effective grants hold `native_bridge.install` and the installed manifest carries one: a
//! registration is the package running in the application's name, so it follows the standing the
//! admissions decide. [`NativeBridges::reconcile`]
//! compares that with the journal: a wanted release that is not applied is applied, a release the
//! installation moved on from is removed first, and one no longer wanted is removed. None of it
//! changes what the catalogue answered: the installation is committed before the recipe runs, and
//! the recipe's outcome is its journal's.
//!
//! # What is checked before anything is written
//!
//! - The platform: this host changes an application's directory on macOS and Linux only, where
//!   it walks the directory as below and checks what a replacement keeps.
//! - The application's directory: one this host knows, which exists.
//! - The forwarder the registration is expected to start: the `kr-hook` beside the daemon.
//! - The recipe: every step it installs has the removal that undoes it, and every file it names is
//!   the bytes it says.
//! - The version: every executable the package's match rules name on this host's search path is
//!   read, never run, and each must be one a signed qualification record of the package names, at
//!   a version inside the recipe's range. A version nothing establishes is a refusal, not a guess.
//! - The destinations, each walked from one handle on the application's directory without
//!   following a link: a file this host did not write, a key it did not set, a directory replaced
//!   by a link, a document it cannot edit exactly or would take past the size it reads back, or
//!   one whose protection a replacement would not keep.
//!
//! # What is recorded
//!
//! Each change is noted before it is made and recorded after it, so a run that stops anywhere
//! leaves a record the next run settles from what is on disk rather than from what the record
//! intended. Something the host cannot show it made is neither taken nor claimed: it is left in
//! place and named, and while it is there the bridge is not reported as applied. A publication is
//! recorded only once its directory is flushed, by the run that made it or by the one that settles
//! it, and a record goes only once what it names is gone and that absence is flushed. The
//! application's directory is known by its identity as well as its path, so a directory put in its
//! place is never taken for it, and nothing at its path is not taken as its deletion: what was
//! placed stays recorded until the directory is back.

mod check;
mod journal;
pub(crate) mod json;
mod shapes;
mod tree;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::forwarder;
use kr_plugin_sdk::matching::MatchRule;
use kr_plugin_sdk::plugin::{BridgeRemoval, BridgeStep, NativeBridge};
use kr_plugin_sdk::version::PackageVersion;
use kr_protocol::ids::PluginId;
use kr_protocol::scalars::Digest256;
pub use kr_worker::broker::bridge::BridgeSurface;
pub use kr_worker::broker::connectors::{BridgeFacts, QualifiedExecutable};

pub use self::check::{check, unread_check};
use self::journal::{
    Change, Journal, Journals, Kept, Publication, RecordedFacts, Release, Removal, Staging, State,
};
use self::tree::{Child, Dir, Entry, Fetched, Identity, Unstaged, Walk};
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

/// The most of a settings document this host reads, and the most it writes.
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
    /// Signed qualification records this host's own tests stand in for, read beside the ones a
    /// release carries. No shipped build has the field.
    #[cfg(feature = "testing")]
    pub signed_records: Vec<QualifiedExecutable>,
}

impl BridgeHost {
    /// This host's own: journals in the environment's state directory, each application's
    /// directory under the account's home, the daemon's search path, and the `kr-hook` an update
    /// replaces: through the store's `current` for a daemon of an installed release, so a
    /// registration keeps naming the forwarder across updates, and beside the daemon otherwise,
    /// where every packaged installation puts it.
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
            forwarder: kr_ipc::install::this_process()
                .ok()
                .map(|running| running.stable(kr_ipc::install::Program::Hook))
                .filter(|path| path.is_file()),
            #[cfg(feature = "testing")]
            signed_records: Vec::new(),
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
///
/// An application this host does not name here has no directory, and a recipe for it places
/// nothing. Gemini CLI's is not named: its recipe must leave the record of where its extension is
/// installed in place for as long as anything else stays in the extension's directory, because
/// Gemini CLI refuses to start while such a directory has no record, and a recipe's removal steps
/// cannot say "last, and only when nothing else is left".
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
    /// Nothing this host placed is left, apart from what its report names as changed since.
    Removed,
    /// The recipe was refused, and nothing of the release is in place.
    Refused(String),
    /// Something may be this host's and cannot be shown to be, or could not be taken out this
    /// time, so nothing is reported as applied or as clean.
    Unsettled(String),
}

/// One file a bridge's release put in an application's directory, by the digest of its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeFile {
    /// The file, under the application's directory.
    pub path: String,
    /// The digest of the bytes this host published, in hexadecimal.
    pub digest: String,
}

/// One package's bridge, as a person reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeReport {
    /// The package.
    pub plugin_id: String,
    /// Where it stands: applying, applied, removing, refused, removed, or unsettled while
    /// something may be the host's and cannot be shown to be.
    pub state: String,
    /// The release it is about, where there is one.
    pub package_digest: Option<String>,
    /// The application the release's recipe is for, as the recipe names it, where there is a
    /// release.
    pub application: Option<String>,
    /// Each file this host has published for the release, by digest.
    pub files: Vec<BridgeFile>,
    /// What no longer matches, what was left in place, what could not be settled or taken out, and
    /// why the last application was refused.
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

/// Where this host's own tests stop a run, what they do just before a publication, and what the
/// last run did, in order.
#[cfg(feature = "testing")]
#[derive(Default)]
struct Testing {
    stop_at: std::sync::atomic::AtomicUsize,
    taken: std::sync::atomic::AtomicUsize,
    before_publishing: std::sync::Mutex<Option<PublishingHook>>,
    staging_fails: std::sync::Mutex<Option<PublishingHook>>,
    trace: std::sync::Mutex<Vec<String>>,
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

/// What opening a release's application directory found.
enum Root {
    /// The directory the release was applied in.
    Open(Dir),
    /// Nothing is at its path, or another directory is, and why. What the release placed is in
    /// the directory it was applied in, which is not reached, so nothing is taken out and nothing
    /// is forgotten.
    Unavailable(String),
}

/// What settling one change found: the change as it stays in the journal, where it stays, and
/// what may be this host's and cannot be shown to be.
struct Found {
    change: Option<Change>,
    unresolved: Vec<Kept>,
}

impl Found {
    fn keep(change: Change) -> Self {
        Self {
            change: Some(change),
            unresolved: Vec::new(),
        }
    }

    fn drop() -> Self {
        Self {
            change: None,
            unresolved: Vec::new(),
        }
    }
}

/// What an unrecorded publication came to at its destination.
enum Settlement {
    /// Nothing of it is in place: it was never renamed, and its staged copy, which this host could
    /// show it made, is gone.
    Absent,
    /// It is in place under the identity it was staged with, and its directory is flushed.
    Placed(Identity),
    /// What is at its destination is not what this host staged.
    NotOurs,
}

/// What was at a staged object's temporary name.
enum Cleared {
    /// Nothing is there now: there was nothing, or it was the object this host staged and is
    /// removed. Either way its directory is flushed, so no removal is lost.
    Gone,
    /// Something this host cannot show it staged, or a directory something was put in. It is
    /// left, and why.
    Left(String),
}

/// Whether a file object is a file or a directory, for the checks that differ between the two.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    File,
    Directory,
}

/// What is at one name, by kind.
enum Object {
    Absent,
    Found(Identity),
    Other,
}

/// How one removal step ended.
enum Outcome {
    /// It is gone, and its directory is flushed.
    Done,
    /// It is left in place for good, and why: it changed, or it is no longer reached.
    Kept(String),
    /// It could not be taken out this time, and why. The next reconciliation tries again.
    Unfinished(String),
}

/// Whether a document is still the one an edit was made from.
enum Sameness {
    Same,
    Changed,
    Refused(String),
}

/// A copy of a document this run staged beside it.
struct Staged<'a> {
    /// The document, under the application's directory.
    file: &'a str,
    /// The temporary name the copy is staged under.
    temporary: &'a str,
    /// The staged copy's identity.
    identity: Identity,
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
    /// Returns an error when this host's own record cannot be read or written, or a directory
    /// cannot be read. What the run had done by then is left for the next run to settle.
    pub fn reconcile(
        &self,
        plugin_id: &PluginId,
        wanted: Option<&BridgeTarget>,
    ) -> Result<Settled> {
        #[cfg(feature = "testing")]
        {
            self.testing
                .taken
                .store(0, std::sync::atomic::Ordering::SeqCst);
            self.testing
                .trace
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clear();
        }
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
    /// start. `None` unless that exact release is applied with every change published and nothing
    /// unsettled.
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
    /// left or could not finish, what could not be settled and why an application was refused.
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
            if journal.state == State::Removing
                && let Some(release) = journal.release.as_ref()
            {
                for change in &journal.changes {
                    let (path, key) = placed_path(change);
                    let blocked = journal
                        .blocked
                        .iter()
                        .any(|kept| kept.path == path && kept.key.as_deref() == key);
                    if !blocked {
                        notes.push(
                            kept_in(
                                &release.directory,
                                release.directory_identity,
                                change,
                                "not yet taken out",
                            )
                            .describe(),
                        );
                    }
                }
            }
            notes.extend(
                journal
                    .blocked
                    .iter()
                    .map(|kept| format!("could not be taken out: {}", kept.describe())),
            );
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
            if let Some(release) = journal.release.as_ref()
                && journal.changes.iter().any(in_flight)
            {
                let why = match Dir::open(&release.directory) {
                    Ok(root) if root.identity().same_object(&release.directory_identity) => {
                        "a run stopped while it was being made or taken out".to_owned()
                    }
                    Ok(_) => "a run stopped while it was being made or taken out, and another \
                              directory is at its directory's path now"
                        .to_owned(),
                    Err(error) => format!(
                        "a run stopped while it was being made or taken out, and its directory \
                         cannot be opened: {error}"
                    ),
                };
                for change in journal.changes.iter().filter(|change| in_flight(change)) {
                    let named =
                        kept_in(&release.directory, release.directory_identity, change, &why);
                    notes.push(format!("not settled: {}", named.describe()));
                }
            }
            if let Some(reason) = &journal.refusal {
                notes.push(format!("refused: {reason}"));
            }
            let unsettled = !journal.unresolved.is_empty()
                || journal.changes.iter().any(in_flight)
                || (journal.state == State::Refused && !journal.is_clean_refusal());
            reports.push(BridgeReport {
                plugin_id: journal.plugin_id.clone(),
                state: if unsettled {
                    "unsettled".to_owned()
                } else {
                    journal.state.as_str().to_owned()
                },
                package_digest: journal.digest().map(str::to_owned),
                application: journal
                    .release
                    .as_ref()
                    .map(|release| release.application.clone()),
                files: journal
                    .changes
                    .iter()
                    .filter_map(|change| match change {
                        Change::File {
                            path,
                            digest,
                            publication: Publication::Published { .. },
                            ..
                        } => Some(BridgeFile {
                            path: path.clone(),
                            digest: digest.clone(),
                        }),
                        _ => None,
                    })
                    .collect(),
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

    /// Makes every later staged write fail once it has made its file, after running `hook` with
    /// that file's path.
    #[cfg(feature = "testing")]
    pub fn staging_fails(&self, hook: impl Fn(&Path) + Send + Sync + 'static) {
        *self
            .testing
            .staging_fails
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::new(hook));
    }

    /// Returns the durable steps the last run took, in order: `save` for the journal, and the
    /// operation and path of each change to the application's directory.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn steps(&self) -> Vec<String> {
        self.testing
            .trace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// True unless the journal's release registered a forwarder, and this host now names another.
    fn names_the_forwarder_it_was_applied_with(&self, journal: &Journal) -> bool {
        let applied = journal
            .release
            .as_ref()
            .and_then(|release| release.facts.as_ref())
            .map(|facts| &facts.forwarder);
        match (applied, self.host.forwarder.as_ref()) {
            (Some(applied), Some(now)) => applied == now,
            _ => true,
        }
    }

    /// True when the journal's release was applied in another directory than the one this host
    /// now keeps its application's plugins in.
    fn moved(&self, journal: &Journal) -> bool {
        journal.release.as_ref().is_some_and(|release| {
            !self.host.applications.iter().any(|known| {
                known.application == release.application && known.directory == release.directory
            })
        })
    }

    fn run(&self, plugin_id: &PluginId, wanted: Option<&BridgeTarget>) -> Run<Settled> {
        let mut journal = match self.journals.load(&plugin_id.to_string())? {
            Some(journal) => journal,
            None if wanted.is_none() => return Ok(Settled::Unchanged),
            None => Journal::new(plugin_id),
        };
        self.settle(&mut journal)?;
        // What an earlier run left and named, and has gone since, no longer holds anything up.
        let rechecked = self.recheck(&mut journal);
        // A registration names the forwarder by the path it was written with, so a release applied
        // with another forwarder is not the release that is wanted: it is taken out and applied
        // again with the one this host names now.
        let same = wanted.is_some_and(|target| {
            journal.digest() == Some(target.package_digest.to_string().as_str())
        }) && self.names_the_forwarder_it_was_applied_with(&journal);
        // A removal an earlier run began is finished, and a release no longer wanted, or applied in
        // a directory this host no longer keeps its application's plugins in, is taken out before
        // another is applied.
        let removing = journal.state == State::Removing
            || (!journal.changes.is_empty() && (!same || self.moved(&journal)));
        if removing {
            self.undo(&mut journal)?;
        }
        let Some(target) = wanted else {
            return self.finish_removal(journal);
        };
        if removing && !journal.changes.is_empty() {
            // What was placed could not all be taken out. Nothing is applied over it; the next
            // reconciliation tries again.
            return Ok(Settled::Unsettled(outstanding(&journal)));
        }
        if same && journal.state == State::Applied {
            if rechecked {
                self.save(&journal)?;
            }
            return Ok(if journal.is_applied() {
                Settled::Unchanged
            } else {
                Settled::Unsettled(outstanding(&journal))
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
        journal.blocked.clear();
        self.save(journal)?;
        match self.carry_out(journal, &plan) {
            Ok(()) => {}
            Err(Fault::Refused(reason)) => return self.refuse(journal, reason),
            Err(halted) => return Err(halted),
        }
        journal.state = State::Applied;
        journal.refusal = None;
        self.recheck(journal);
        self.save(journal)?;
        Ok(if journal.is_applied() {
            Settled::Applied
        } else {
            Settled::Unsettled(outstanding(journal))
        })
    }

    /// Takes out whatever of the release is in place and records why it was refused. The refusal
    /// is reported as clean only when nothing of the release is left and nothing is unsettled.
    fn refuse(&self, journal: &mut Journal, reason: String) -> Run<Settled> {
        self.settle(journal)?;
        // The refusal is on record before anything is taken out, so a run that stops part way
        // leaves it said. Whether it is clean is read from the journal, never from what one run
        // saw: what any undo had to leave stays among the leftovers until it is gone.
        journal.refusal = Some(reason.clone());
        if !journal.changes.is_empty() {
            self.undo(journal)?;
        }
        journal.state = if journal.changes.is_empty() {
            State::Refused
        } else {
            State::Removing
        };
        self.recheck(journal);
        self.save(journal)?;
        if journal.is_clean_refusal() {
            return Ok(Settled::Refused(reason));
        }
        Ok(Settled::Unsettled(format!(
            "{reason}; and {}",
            outstanding(journal)
        )))
    }

    /// Checks everything a recipe needs before anything is written, and says what is left to do.
    fn preflight(
        &self,
        journal: &Journal,
        target: &BridgeTarget,
    ) -> std::result::Result<Plan, String> {
        supported_platform()?;
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
        let directory_identity = root.identity();
        // A release recorded here was applied in one directory, and the one at the path now is
        // another: the record says nothing about what is in it.
        if let Some(release) = journal.release.as_ref()
            && release.directory == directory
            && !journal.changes.is_empty()
            && !release.directory_identity.same_object(&directory_identity)
        {
            return Err(format!(
                "{} is now another directory than the one this host applied the bridge in",
                directory.display()
            ));
        }
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
        let mut removal = removal_of(recipe)?;
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
        // What a recipe may place is a closed set this host names for the application: the
        // registration files in one directory of the application's own, and the one key that
        // enables them. Nothing else a bridge adds can hold a command, so none is left unread.
        permitted(recipe)?;
        place_is_free(&root, journal, recipe)?;
        let facts = registration(&sources, &forwarder, recipe.application.as_str())?;
        // What is written is the template with the forwarder's path where the package names the
        // forwarder, and it is that file's bytes the journal knows the file by from here on: the
        // recipe's digests name the template, which is what the package's hash signs.
        let mut written = Vec::new();
        for (destination, template) in &sources {
            written.push((
                destination.clone(),
                expanded(destination, template, &forwarder)?,
            ));
        }
        for entry in &mut removal {
            if let Removal::File { path, digest } = entry
                && let Some((_, bytes)) = written.iter().find(|(named, _)| named == path)
            {
                *digest = PayloadDigest::of(bytes).to_string();
            }
        }
        // The forwarder a registration starts reports for the application it names, and a
        // launch of this package admits only its own: a registration for another package's
        // application would be a bridge no launch of either could use.
        if let Some(facts) = facts.as_ref() {
            let own = package_name(&target.plugin_id);
            if facts.application != own {
                return Err(format!(
                    "the registration starts the forwarder for {}, which is not the application \
                     of {} ({own})",
                    facts.application, target.plugin_id
                ));
            }
        }
        let versions = self.versions(target)?;
        let mut steps = Vec::new();
        for step in &recipe.install {
            match step {
                BridgeStep::InstallFile { destination, .. } => {
                    let path = destination.to_string();
                    let bytes = written
                        .iter()
                        .find(|(named, _)| *named == path)
                        .map(|(_, bytes)| bytes.clone())
                        .unwrap_or_default();
                    let digest = PayloadDigest::of(&bytes).to_string();
                    if file_is_ours(journal, &root, &path, &digest)? {
                        continue;
                    }
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
                directory_identity,
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
    ///
    /// The search joins each match rule's bare name to each directory and adds no executable
    /// suffix, which is how macOS and Linux name a program. It never runs on Windows, where a
    /// command is found by its suffixes: [`Self::preflight`] is its only caller and refuses there
    /// first, through [`supported_platform`], before it looks for anything.
    fn versions(
        &self,
        target: &BridgeTarget,
    ) -> std::result::Result<Vec<(PathBuf, String)>, String> {
        let range = &target.recipe.application_range;
        let application = target.recipe.application.as_str();
        #[cfg_attr(not(feature = "testing"), expect(unused_mut))]
        let mut qualified = target.qualified.clone();
        #[cfg(feature = "testing")]
        qualified.extend(self.host.signed_records.iter().cloned());
        if qualified.is_empty() {
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
            let record = qualified
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
        journal.changes.retain(
            |change| !matches!(change, Change::Directory { path: recorded, .. } if recorded == path),
        );
        journal.changes.push(Change::Directory {
            path: path.to_owned(),
            temporary: temporary.clone(),
            publication: Publication::Noted,
        });
        self.save(journal)?;
        let index = journal.changes.len() - 1;
        self.step("make", &base.join(&temporary))?;
        if !base
            .make_child(&temporary)
            .map_err(|error| refused(root, path, &error))?
        {
            return Err(Fault::Refused(format!(
                "{} was taken before this host could use it",
                base.join(&temporary).display()
            )));
        }
        let identity = match base
            .child(&temporary)
            .map_err(|error| refused(root, path, &error))?
        {
            Child::Directory(made) => made.identity(),
            _ => return Err(Fault::Refused(substituted(root, path))),
        };
        set_publication(
            &mut journal.changes[index],
            Publication::Staged { identity },
        );
        self.save(journal)?;
        self.step("rename", &base.join(name))?;
        match base.rename_new(&temporary, name) {
            Ok(()) => {
                self.flush(base)
                    .map_err(|error| refused(root, path, &error))?;
                set_publication(
                    &mut journal.changes[index],
                    Publication::Published { identity },
                );
            }
            // Something else made it meanwhile. It is not this host's to claim, and the one made
            // beside it goes.
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                journal.changes.remove(index);
                if let Cleared::Left(reason) =
                    self.clear_staged(base, &temporary, Kind::Directory, Some(identity))?
                {
                    journal
                        .unresolved
                        .push(unproven_at(root, path, &temporary, reason));
                }
            }
            Err(error) => return Err(refused(root, path, &error)),
        }
        self.save(journal)
    }

    /// Publishes one new file: noted with its temporary name, staged and recorded with the staged
    /// file's identity, renamed into place only where nothing is, flushed, and recorded as
    /// published.
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
        self.step("stage", &directory.join(&temporary))?;
        let identity = match self.stage(directory, &temporary, bytes, files::READABLE) {
            Ok(identity) => identity,
            Err(unstaged) => {
                journal.changes.remove(index);
                return Err(self.unstaged(journal, root, directory, path, &temporary, unstaged));
            }
        };
        set_publication(
            &mut journal.changes[index],
            Publication::Staged { identity },
        );
        self.save(journal)?;
        self.about_to_publish(&directory.join(name));
        self.step("rename", &directory.join(name))?;
        directory
            .rename_new(&temporary, name)
            .map_err(|error| refused(root, path, &error))?;
        self.flush(directory)
            .map_err(|error| refused(root, path, &error))?;
        set_publication(
            &mut journal.changes[index],
            Publication::Published { identity },
        );
        self.save(journal)
    }

    /// Adds one key to a document: the edit made against the document as it is, noted, staged,
    /// checked against a document that may have changed meanwhile, renamed into place, flushed and
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
            let read = match directory
                .fetch(name, DOCUMENT_LIMIT)
                .map_err(|error| Fault::Refused(format!("{shown}: {error}")))?
            {
                Fetched::Absent => None,
                Fetched::File(read) => Some(read),
                Fetched::NotRegular => {
                    return Err(Fault::Refused(format!(
                        "{shown} is a link, or not a regular file"
                    )));
                }
                Fetched::TooLarge => return Err(Fault::Refused(too_large(&shown))),
            };
            let (bytes, created_members, created_document, mode) = match &read {
                None => (
                    creation(&shown, &members, value).map_err(Fault::Refused)?,
                    members.len() - 1,
                    true,
                    files::PRIVATE,
                ),
                Some(read) => {
                    files::guard_access_controls(&directory.join(name), INSTEAD)
                        .map_err(|error| Fault::Refused(error.to_string()))?;
                    let inserted =
                        insertion(&shown, &read.bytes, &members, value).map_err(Fault::Refused)?;
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
            self.step("stage", &directory.join(&temporary))?;
            let identity = match self.stage(directory, &temporary, &bytes, mode) {
                Ok(identity) => identity,
                Err(unstaged) => {
                    journal.changes.remove(index);
                    return Err(self.unstaged(journal, root, directory, file, &temporary, unstaged));
                }
            };
            set_publication(
                &mut journal.changes[index],
                Publication::Staged { identity },
            );
            self.save(journal)?;
            let staged = Staged {
                file,
                temporary: &temporary,
                identity,
            };
            if let Some(document) = read.as_ref()
                && let Err(reason) =
                    staged_protection(directory, &temporary, &identity, document, &shown)
            {
                self.discard(journal, index, root, directory, &staged)?;
                return Err(Fault::Refused(reason));
            }
            self.about_to_publish(&directory.join(name));
            // The document must still be the one the edit was made from, with the protection it
            // had. One that changed is read again, so what somebody wrote meanwhile is kept.
            match still_the_same(directory, name, read.as_ref())
                .map_err(|error| refused(root, file, &error))?
            {
                Sameness::Same => {}
                Sameness::Changed => {
                    self.discard(journal, index, root, directory, &staged)?;
                    continue;
                }
                Sameness::Refused(reason) => {
                    self.discard(journal, index, root, directory, &staged)?;
                    return Err(Fault::Refused(reason));
                }
            }
            self.step("rename", &directory.join(name))?;
            let renamed = if read.is_none() {
                directory.rename_new(&temporary, name)
            } else {
                directory.rename_over(&temporary, name)
            };
            match renamed {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    self.discard(journal, index, root, directory, &staged)?;
                    continue;
                }
                Err(error) => return Err(refused(root, file, &error)),
            }
            self.flush(directory)
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

    /// Takes back a copy this run staged and will not publish, and forgets the change that noted
    /// it.
    fn discard(
        &self,
        journal: &mut Journal,
        index: usize,
        root: &Dir,
        directory: &Dir,
        staged: &Staged<'_>,
    ) -> Run<()> {
        journal.changes.remove(index);
        self.take_back(journal, root, directory, staged)?;
        self.save(journal)
    }

    /// Takes back the file a staged write that did not finish had made, where it is still that
    /// file, and says why the write failed. Anything else at the name is left and named. The
    /// caller has forgotten the change that noted it.
    fn unstaged(
        &self,
        journal: &mut Journal,
        root: &Dir,
        directory: &Dir,
        path: &str,
        temporary: &str,
        unstaged: Unstaged,
    ) -> Fault {
        match self.clear_staged(directory, temporary, Kind::File, unstaged.made) {
            Ok(Cleared::Left(reason)) => {
                journal
                    .unresolved
                    .push(unproven_at(root, path, temporary, reason));
            }
            Ok(Cleared::Gone) => {}
            Err(fault) => return fault,
        }
        refused(root, path, &unstaged.error)
    }

    /// Removes a copy this run staged, where it is still that copy; anything else at its name is
    /// left and recorded as not settled.
    fn take_back(
        &self,
        journal: &mut Journal,
        root: &Dir,
        directory: &Dir,
        staged: &Staged<'_>,
    ) -> Run<()> {
        if let Cleared::Left(reason) = self.clear_staged(
            directory,
            staged.temporary,
            Kind::File,
            Some(staged.identity),
        )? {
            journal
                .unresolved
                .push(unproven_at(root, staged.file, staged.temporary, reason));
        }
        Ok(())
    }

    /// Takes away the object this host staged at `temporary` and will not publish, where it is
    /// still the object staged with `staged`, and flushes its directory. Anything else there is
    /// left.
    fn clear_staged(
        &self,
        directory: &Dir,
        temporary: &str,
        kind: Kind,
        staged: Option<Identity>,
    ) -> Run<Cleared> {
        match object_at(directory, temporary, kind).map_err(halted)? {
            // An earlier run may have taken it and stopped before its directory was flushed.
            // Its record goes only once that removal is durable.
            Object::Absent => {
                self.flush(directory).map_err(halted)?;
                Ok(Cleared::Gone)
            }
            Object::Found(found) if staged.is_some_and(|staged| same(kind, &staged, &found)) => {
                match kind {
                    Kind::File => {
                        self.step("unlink", &directory.join(temporary))?;
                        directory.remove_file(temporary).map_err(halted)?;
                    }
                    Kind::Directory => {
                        self.step("unmake", &directory.join(temporary))?;
                        match directory.remove_directory(temporary) {
                            Ok(()) => {}
                            Err(error)
                                if error.kind() == std::io::ErrorKind::DirectoryNotEmpty
                                    || error.kind() == std::io::ErrorKind::AlreadyExists =>
                            {
                                return Ok(Cleared::Left(
                                    "it holds something this host did not put there".to_owned(),
                                ));
                            }
                            Err(error) => return Err(halted(error)),
                        }
                    }
                }
                self.flush(directory).map_err(halted)?;
                Ok(Cleared::Gone)
            }
            Object::Found(_) | Object::Other => Ok(Cleared::Left(unproven())),
        }
    }

    // -----------------------------------------------------------------------------------------
    // Settling what an earlier run left in flight
    // -----------------------------------------------------------------------------------------

    /// Settles every change an earlier run noted and did not record, from what is on disk.
    fn settle(&self, journal: &mut Journal) -> Run<()> {
        if !journal.changes.iter().any(in_flight) {
            return Ok(());
        }
        let Some(release) = journal.release.clone() else {
            journal.changes.clear();
            return self.save(journal);
        };
        match self.open_root(&release)? {
            // What was in flight stays recorded as it was, with the identities that settle it once
            // the directory is back.
            Root::Unavailable(_) => return Ok(()),
            Root::Open(root) => {
                let mut settled = Vec::with_capacity(journal.changes.len());
                for change in journal.changes.clone() {
                    let found = self.settle_one(&root, change)?;
                    settled.extend(found.change);
                    journal.unresolved.extend(found.unresolved);
                }
                journal.changes = settled;
            }
        }
        self.save(journal)
    }

    fn settle_one(&self, root: &Dir, change: Change) -> Run<Found> {
        if !in_flight(&change) {
            return Ok(Found::keep(change));
        }
        let (path, _) = placed_path(&change);
        let (parent, name) = match tree::parent_of(root, path).map_err(halted)? {
            Walk::Found { parent, name } => (parent, name),
            // A directory on the way is not there, so neither is anything the change made. That
            // is recorded only once the deepest directory that is there is flushed.
            Walk::Missing { reached } => {
                self.flush(reached.as_ref().unwrap_or(root))
                    .map_err(halted)?;
                return Ok(Found::drop());
            }
            // A directory on the way was replaced. What the change made, if anything, is in the one
            // it replaced, so the change stays in flight until that is back.
            Walk::Substituted(_) => return Ok(Found::keep(change)),
        };
        let directory = parent.as_ref().unwrap_or(root);
        let mut found = Found::keep(change.clone());
        // An edit that was taking a key out when the run stopped. Its staged copy goes where this
        // host can show it made it; the key itself is decided by the removal.
        if let Change::Key {
            removing: Some(staging),
            ..
        } = &change
        {
            if let Cleared::Left(reason) =
                self.clear_staged(directory, &staging.temporary, Kind::File, staging.identity)?
            {
                found
                    .unresolved
                    .push(unproven_at(root, path, &staging.temporary, reason));
            }
            if let Some(settled) = found.change.as_mut() {
                set_removing(settled, None);
            }
        }
        let (temporary, publication, kind) = match &change {
            Change::Directory {
                temporary,
                publication,
                ..
            } => (temporary, *publication, Kind::Directory),
            Change::File {
                temporary,
                publication,
                ..
            }
            | Change::Key {
                temporary,
                publication,
                ..
            } => (temporary, *publication, Kind::File),
        };
        // What is at the temporary name and what is at the destination are settled apart: an
        // object somebody put at the temporary name after the rename says nothing about the
        // destination, which may hold what this host published.
        let (settlement, beside) =
            self.settle_publication(directory, temporary, name, publication, kind)?;
        if let Some(reason) = beside {
            found
                .unresolved
                .push(unproven_at(root, path, temporary, reason));
        }
        match settlement {
            Settlement::Placed(identity) => {
                if let Some(settled) = found.change.as_mut() {
                    set_publication(settled, Publication::Published { identity });
                }
            }
            Settlement::Absent => found.change = None,
            Settlement::NotOurs => {
                found.change = None;
                // The document at the name is not the one this host renamed there. The key in it
                // may be this host's, carried across by whoever replaced the document, or
                // somebody's own.
                if let Change::Key { key, value, .. } = &change
                    && (key_holds(directory, name, key, value) != Some(false)
                        || !self.durably_absent(directory, name))
                {
                    found.unresolved.push(kept(
                        root,
                        &change,
                        "the document was replaced after this host wrote the key and before it \
                         recorded doing so, so whether the key is this host's cannot be shown",
                    ));
                }
            }
        }
        Ok(found)
    }

    /// Settles one unrecorded publication: says what came of it at its destination and, apart
    /// from that, why anything left at its temporary name is left. A publication already recorded
    /// is left as it is.
    fn settle_publication(
        &self,
        directory: &Dir,
        temporary: &str,
        name: &str,
        publication: Publication,
        kind: Kind,
    ) -> Run<(Settlement, Option<String>)> {
        let staged = match publication {
            Publication::Published { identity } => {
                return Ok((Settlement::Placed(identity), None));
            }
            Publication::Staged { identity } => Some(identity),
            Publication::Noted => None,
        };
        // What is at the temporary name is settled first, and says nothing about the destination:
        // the staged object may be there as a second link to what was renamed into place.
        let beside = match self.clear_staged(directory, temporary, kind, staged)? {
            Cleared::Left(reason) => Some(reason),
            Cleared::Gone => None,
        };
        // Only a staged object is ever renamed into place.
        let Some(staged) = staged else {
            return Ok((Settlement::Absent, beside));
        };
        match object_at(directory, name, kind).map_err(halted)? {
            // The destination is the object staged, by device and inode, so the rename happened,
            // whatever has been written to it since: what was changed is the removal's to find and
            // leave. It is recorded only once its directory is flushed.
            Object::Found(found) if staged.same_object(&found) => {
                self.flush(directory).map_err(halted)?;
                Ok((Settlement::Placed(staged), beside))
            }
            _ => Ok((Settlement::NotOurs, beside)),
        }
    }

    // -----------------------------------------------------------------------------------------
    // Removing
    // -----------------------------------------------------------------------------------------

    /// Takes out every change of the release, in the order the recipe's removal says, then the
    /// directories this host made, deepest first. What changed since it was placed is left and
    /// named; what could not be taken out this time stays recorded for the next run, and so does
    /// every directory that still holds it. While another directory, or nothing, is at the
    /// application directory's path, nothing is taken out and everything stays recorded, to be
    /// taken out if the directory the release was applied in comes back.
    fn undo(&self, journal: &mut Journal) -> Run<()> {
        journal.state = State::Removing;
        journal.blocked.clear();
        self.save(journal)?;
        let Some(release) = journal.release.clone() else {
            journal.changes.clear();
            return self.save(journal);
        };
        let root = match self.open_root(&release)? {
            Root::Open(root) => root,
            // What the release placed is in the directory it was applied in, which is not reached.
            // Nothing is taken out, and everything stays recorded for when it is back.
            Root::Unavailable(reason) => {
                let blocked: Vec<Kept> = journal
                    .changes
                    .iter()
                    .map(|change| {
                        kept_in(
                            &release.directory,
                            release.directory_identity,
                            change,
                            &reason,
                        )
                    })
                    .collect();
                journal.blocked.extend(blocked);
                return self.save(journal);
            }
        };
        for removal in &release.removal {
            let Some(index) = journal
                .changes
                .iter()
                .position(|change| undoes(removal, change))
            else {
                continue;
            };
            let outcome = match removal {
                Removal::File { .. } => self.remove_file(journal, &root, index)?,
                Removal::Key { .. } => self.remove_key(journal, &root, index)?,
            };
            self.settle_removal(journal, &root, index, outcome)?;
        }
        // A change the recipe names no removal for is left in place and named.
        let uncovered: Vec<usize> = journal
            .changes
            .iter()
            .enumerate()
            .filter(|(_, change)| {
                !matches!(change, Change::Directory { .. })
                    && !in_flight(change)
                    && !release
                        .removal
                        .iter()
                        .any(|removal| undoes(removal, change))
            })
            .map(|(index, _)| index)
            .collect();
        for index in uncovered.into_iter().rev() {
            let change = journal.changes.remove(index);
            journal
                .leftovers
                .push(kept(&root, &change, "the recipe names no removal for it"));
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
            let Some(index) = journal.changes.iter().position(
                |change| matches!(change, Change::Directory { path: recorded, .. } if *recorded == path),
            ) else {
                continue;
            };
            let outcome = self.remove_directory(journal, &root, index)?;
            self.settle_removal(journal, &root, index, outcome)?;
        }
        self.save(journal)
    }

    /// Records how one removal step ended: gone, left for good, or left for the next run.
    fn settle_removal(
        &self,
        journal: &mut Journal,
        root: &Dir,
        index: usize,
        outcome: Outcome,
    ) -> Run<()> {
        match outcome {
            Outcome::Done => {
                journal.changes.remove(index);
            }
            Outcome::Kept(reason) => {
                let change = journal.changes.remove(index);
                journal.leftovers.push(kept(root, &change, &reason));
            }
            Outcome::Unfinished(reason) => {
                let blocked = kept(root, &journal.changes[index], &reason);
                journal.blocked.push(blocked);
            }
        }
        self.save(journal)
    }

    fn remove_file(&self, journal: &Journal, root: &Dir, index: usize) -> Run<Outcome> {
        let Change::File {
            path,
            digest,
            publication: Publication::Published {
                identity: published,
            },
            ..
        } = journal.changes[index].clone()
        else {
            return Ok(Outcome::Done);
        };
        let (parent, name) = match tree::parent_of(root, &path) {
            Err(error) => return Ok(Outcome::Unfinished(error.to_string())),
            Ok(Walk::Missing { reached }) => {
                self.flush(reached.as_ref().unwrap_or(root))
                    .map_err(halted)?;
                return Ok(Outcome::Done);
            }
            Ok(Walk::Substituted(at)) => {
                return Ok(Outcome::Unfinished(substituted_reason(root, &at)));
            }
            Ok(Walk::Found { parent, name }) => (parent, name),
        };
        let directory = parent.as_ref().unwrap_or(root);
        match directory.fetch(name, FILE_LIMIT) {
            Err(error) => Ok(Outcome::Unfinished(error.to_string())),
            Ok(Fetched::Absent) => {
                self.flush(directory).map_err(halted)?;
                Ok(Outcome::Done)
            }
            Ok(Fetched::NotRegular) => Ok(Outcome::Kept(
                "it is now a link, or not a regular file".to_owned(),
            )),
            Ok(Fetched::TooLarge) => Ok(Outcome::Kept(
                "it has changed since it was installed".to_owned(),
            )),
            // The same bytes in another file are not the file this host installed: somebody put
            // them there, and they are theirs to remove.
            Ok(Fetched::File(read)) if !read.identity.same_object(&published) => Ok(Outcome::Kept(
                "it is not the file this host installed".to_owned(),
            )),
            Ok(Fetched::File(read)) if PayloadDigest::of(&read.bytes).to_string() != digest => Ok(
                Outcome::Kept("it has changed since it was installed".to_owned()),
            ),
            Ok(Fetched::File(_)) => {
                self.step("unlink", &directory.join(name))?;
                if let Err(error) = directory.remove_file(name) {
                    return Ok(Outcome::Unfinished(format!(
                        "it could not be removed: {error}"
                    )));
                }
                self.flush(directory).map_err(halted)?;
                Ok(Outcome::Done)
            }
        }
    }

    fn remove_key(&self, journal: &mut Journal, root: &Dir, index: usize) -> Run<Outcome> {
        let Change::Key {
            file,
            key,
            value,
            created_members,
            created_document,
            publication: Publication::Published {
                identity: published,
            },
            ..
        } = journal.changes[index].clone()
        else {
            return Ok(Outcome::Done);
        };
        let members: Vec<&str> = key.split('.').collect();
        for _ in 0..EDIT_ATTEMPTS {
            let (parent, name) = match tree::parent_of(root, &file) {
                Err(error) => return Ok(Outcome::Unfinished(error.to_string())),
                Ok(Walk::Missing { reached }) => {
                    self.flush(reached.as_ref().unwrap_or(root))
                        .map_err(halted)?;
                    return Ok(Outcome::Done);
                }
                Ok(Walk::Substituted(at)) => {
                    return Ok(Outcome::Unfinished(substituted_reason(root, &at)));
                }
                Ok(Walk::Found { parent, name }) => (parent, name),
            };
            let directory = parent.as_ref().unwrap_or(root);
            let (read, edited) =
                match planned_removal(directory, name, &members, &value, created_members) {
                    Ok(Some(planned)) => planned,
                    Ok(None) => {
                        // The key or its document is gone, by an earlier run of this host's that
                        // stopped before recording it, or by somebody. Either way the document as
                        // it is now, and its directory, are made durable before it is recorded as
                        // gone.
                        if !self.durably_absent(directory, name) {
                            return Ok(Outcome::Unfinished(
                                "the document without the key could not be made durable".to_owned(),
                            ));
                        }
                        return Ok(Outcome::Done);
                    }
                    Err(outcome) => return Ok(outcome),
                };
            // A document this host created, left with nothing in it, goes, while it is the document
            // this host created. Another one somebody put in its place keeps its file and loses only
            // the key.
            let delete = created_document
                && read.identity.same_object(&published)
                && json::Document::read(&edited).is_ok_and(|document| document.is_empty());
            let temporary = tree::temporary_name(name);
            let mut staged = None;
            if !delete {
                set_removing(
                    &mut journal.changes[index],
                    Some(Staging {
                        temporary: temporary.clone(),
                        identity: None,
                    }),
                );
                self.save(journal)?;
                self.step("stage", &directory.join(&temporary))?;
                let identity = match self.stage(directory, &temporary, edited.as_bytes(), read.mode)
                {
                    Ok(identity) => identity,
                    Err(unstaged) => {
                        // The file the write made is taken back where it is still that file;
                        // anything else at the name is left and named.
                        if let Cleared::Left(reason) =
                            self.clear_staged(directory, &temporary, Kind::File, unstaged.made)?
                        {
                            journal
                                .unresolved
                                .push(unproven_at(root, &file, &temporary, reason));
                        }
                        set_removing(&mut journal.changes[index], None);
                        self.save(journal)?;
                        return Ok(Outcome::Unfinished(format!(
                            "the edit could not be written: {}",
                            unstaged.error
                        )));
                    }
                };
                set_removing(
                    &mut journal.changes[index],
                    Some(Staging {
                        temporary: temporary.clone(),
                        identity: Some(identity),
                    }),
                );
                self.save(journal)?;
                staged = Some(Staged {
                    file: &file,
                    temporary: &temporary,
                    identity,
                });
                if let Err(reason) = staged_protection(
                    directory,
                    &temporary,
                    &identity,
                    &read,
                    &directory.join(name).display().to_string(),
                ) {
                    self.withdraw_removal(journal, index, root, directory, staged.as_ref())?;
                    return Ok(Outcome::Unfinished(reason));
                }
            }
            self.about_to_publish(&directory.join(name));
            let unchanged = still_the_same(directory, name, Some(&read)).map_err(halted)?;
            if !matches!(unchanged, Sameness::Same) {
                self.withdraw_removal(journal, index, root, directory, staged.as_ref())?;
                match unchanged {
                    Sameness::Refused(reason) => return Ok(Outcome::Unfinished(reason)),
                    _ => continue,
                }
            }
            let done = if delete {
                self.step("unlink", &directory.join(name))?;
                directory.remove_file(name)
            } else {
                self.step("rename", &directory.join(name))?;
                directory.rename_over(&temporary, name)
            };
            if let Err(error) = done {
                self.withdraw_removal(journal, index, root, directory, staged.as_ref())?;
                return Ok(Outcome::Unfinished(format!(
                    "the document could not be replaced: {error}"
                )));
            }
            self.flush(directory).map_err(halted)?;
            return Ok(Outcome::Done);
        }
        Ok(Outcome::Unfinished(format!(
            "the document kept changing while {key} was taken out of it"
        )))
    }

    /// Takes back the staged copy of an edit that will not take the document's place, where
    /// there is one, and forgets it.
    fn withdraw_removal(
        &self,
        journal: &mut Journal,
        index: usize,
        root: &Dir,
        directory: &Dir,
        staged: Option<&Staged<'_>>,
    ) -> Run<()> {
        let Some(staged) = staged else {
            return Ok(());
        };
        self.take_back(journal, root, directory, staged)?;
        set_removing(&mut journal.changes[index], None);
        self.save(journal)
    }

    fn remove_directory(&self, journal: &Journal, root: &Dir, index: usize) -> Run<Outcome> {
        let Change::Directory {
            path,
            publication: Publication::Published { identity },
            ..
        } = journal.changes[index].clone()
        else {
            return Ok(Outcome::Done);
        };
        let within = format!("{path}/");
        if journal
            .changes
            .iter()
            .any(|change| placed_path(change).0.starts_with(&within))
        {
            return Ok(Outcome::Unfinished(
                "it still holds something this host placed that is not yet taken out".to_owned(),
            ));
        }
        if journal
            .unresolved
            .iter()
            .any(|kept| kept.directory == root.path() && kept.path.starts_with(&within))
        {
            return Ok(Outcome::Unfinished(
                "it still holds something that may be this host's and is not settled".to_owned(),
            ));
        }
        let (parent, name) = match tree::parent_of(root, &path) {
            Err(error) => return Ok(Outcome::Unfinished(error.to_string())),
            Ok(Walk::Missing { reached }) => {
                self.flush(reached.as_ref().unwrap_or(root))
                    .map_err(halted)?;
                return Ok(Outcome::Done);
            }
            Ok(Walk::Substituted(at)) => {
                return Ok(Outcome::Unfinished(substituted_reason(root, &at)));
            }
            Ok(Walk::Found { parent, name }) => (parent, name),
        };
        let directory = parent.as_ref().unwrap_or(root);
        match directory.child(name) {
            Err(error) => Ok(Outcome::Unfinished(error.to_string())),
            Ok(Child::Absent) => {
                self.flush(directory).map_err(halted)?;
                Ok(Outcome::Done)
            }
            Ok(Child::NotADirectory) => Ok(Outcome::Kept(
                "it is now a link, or not a directory".to_owned(),
            )),
            Ok(Child::Directory(found)) if !found.identity().same_object(&identity) => Ok(
                Outcome::Kept("it is not the directory this host made".to_owned()),
            ),
            Ok(Child::Directory(_)) => {
                self.step("unmake", &directory.join(name))?;
                match directory.remove_directory(name) {
                    Ok(()) => {
                        self.flush(directory).map_err(halted)?;
                        Ok(Outcome::Done)
                    }
                    Err(error)
                        if error.kind() == std::io::ErrorKind::DirectoryNotEmpty
                            || error.kind() == std::io::ErrorKind::AlreadyExists =>
                    {
                        Ok(Outcome::Kept(
                            "it holds something this host did not put there".to_owned(),
                        ))
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        self.flush(directory).map_err(halted)?;
                        Ok(Outcome::Done)
                    }
                    Err(error) => Ok(Outcome::Unfinished(format!(
                        "it could not be removed: {error}"
                    ))),
                }
            }
        }
    }

    /// Ends a removal: the journal goes when nothing is left to say, and otherwise stays to say it.
    fn finish_removal(&self, mut journal: Journal) -> Run<Settled> {
        self.recheck(&mut journal);
        if !journal.changes.is_empty() {
            journal.state = State::Removing;
            self.save(&journal)?;
            return Ok(Settled::Unsettled(outstanding(&journal)));
        }
        journal.blocked.clear();
        if journal.unresolved.is_empty() && journal.leftovers.is_empty() {
            self.step("delete", &self.host.journals)?;
            self.journals.delete(&journal.plugin_id)?;
            return Ok(Settled::Removed);
        }
        journal.state = State::Removed;
        journal.refusal = None;
        self.save(&journal)?;
        Ok(if journal.unresolved.is_empty() {
            Settled::Removed
        } else {
            Settled::Unsettled(outstanding(&journal))
        })
    }

    /// Makes a document's absence, or its bytes as they are now, durable, and its directory's
    /// entries with them; false when either cannot be.
    fn durably_absent(&self, directory: &Dir, name: &str) -> bool {
        self.step("sync", &directory.join(name)).is_ok()
            && directory.sync_file(name).is_ok()
            && self.flush(directory).is_ok()
    }

    /// Drops what removals left, and what could not be settled, once it is shown to be gone and that
    /// is durable; returns whether anything was dropped.
    fn recheck(&self, journal: &mut Journal) -> bool {
        let before = journal.leftovers.len() + journal.unresolved.len();
        journal.leftovers.retain(|kept| !self.confirmed_gone(kept));
        journal.unresolved.retain(|kept| !self.confirmed_gone(kept));
        journal.leftovers.len() + journal.unresolved.len() != before
    }

    /// True only when what `kept` names is shown to be gone from the directory it is recorded in,
    /// and that absence is flushed. An error, another directory at the path, nothing at the path,
    /// or a document that cannot be read says nothing about it, and neither does a flush that
    /// fails.
    fn confirmed_gone(&self, kept: &Kept) -> bool {
        let Ok(root) = Dir::open(&kept.directory) else {
            return false;
        };
        if !root.identity().same_object(&kept.directory_identity) {
            return false;
        }
        match tree::parent_of(&root, &kept.path) {
            Ok(Walk::Missing { reached }) => self.flush(reached.as_ref().unwrap_or(&root)).is_ok(),
            Ok(Walk::Found { parent, name }) => {
                let directory = parent.as_ref().unwrap_or(&root);
                let gone = match &kept.key {
                    None => matches!(directory.entry(name), Ok(Entry::Absent)),
                    // The document without the key is made durable too, as it is now.
                    Some(key) => key_holds_anything(directory, name, key) == Some(false),
                };
                gone && self.durably_absent(directory, name)
            }
            _ => false,
        }
    }

    /// Opens a release's application directory, and says whether it is still the one the release
    /// was applied in.
    fn open_root(&self, release: &Release) -> Run<Root> {
        let root = match Dir::open(&release.directory) {
            Ok(root) => root,
            // Absence at a path cannot tell a deleted directory from one moved away, or a link
            // that leads nowhere now.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Root::Unavailable(format!(
                    "{} is not there, so what this host placed in the directory it applied the \
                     bridge in is not reached",
                    release.directory.display()
                )));
            }
            Err(error) => return Err(halted(error)),
        };
        if !root.identity().same_object(&release.directory_identity) {
            return Ok(Root::Unavailable(format!(
                "{} is now another directory than the one this host applied the bridge in, so \
                 nothing in it is taken as this host's",
                release.directory.display()
            )));
        }
        Ok(Root::Open(root))
    }

    // -----------------------------------------------------------------------------------------
    // Steps
    // -----------------------------------------------------------------------------------------

    /// Counts one durable step, and stops the run before it where a test asked for that.
    fn step(&self, operation: &str, path: &Path) -> Run<()> {
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
            self.testing
                .trace
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(format!("{operation} {}", path.display()));
        }
        #[cfg(not(feature = "testing"))]
        let _ = (operation, path);
        Ok(())
    }

    /// Writes the journal, durably, as one step.
    fn save(&self, journal: &Journal) -> Run<()> {
        self.step("save", &self.host.journals)?;
        self.journals.save(journal)?;
        Ok(())
    }

    /// Makes a directory's own entries durable, as one step. A test's stop comes back as an error
    /// the caller passes on, as it passes on any other failure to flush.
    fn flush(&self, directory: &Dir) -> std::io::Result<()> {
        if let Err(Fault::Halted(error)) = self.step("flush", directory.path()) {
            return Err(std::io::Error::other(error.to_string()));
        }
        directory.flush()
    }

    /// Writes a staged copy; a test can have the write fail once it has made its file.
    fn stage(
        &self,
        directory: &Dir,
        temporary: &str,
        bytes: &[u8],
        mode: u32,
    ) -> std::result::Result<Identity, Unstaged> {
        let identity = directory.stage(temporary, bytes, mode)?;
        #[cfg(feature = "testing")]
        if let Some(hook) = self
            .testing
            .staging_fails
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            hook(&directory.join(temporary));
            return Err(Unstaged {
                error: std::io::Error::other("the write was stopped by a test"),
                made: Some(identity),
            });
        }
        Ok(identity)
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

/// Refuses on the platform where this host does not change an application's directory.
///
/// Every name a recipe writes, reads or removes is reached from one handle on the application's
/// directory without following a link, a file is known by the device and inode a rename keeps (see
/// [`tree`]), and a copy about to replace a document must keep its permission bits, its owners and
/// its protection. That walk and those checks exist on macOS and Linux only.
fn supported_platform() -> std::result::Result<(), String> {
    // A compile-time value rather than a conditional body, so both answers are checked on every
    // platform this crate builds for.
    if cfg!(windows) {
        return Err(format!(
            "this host does not apply or remove a native bridge on Windows, because it reaches an \
             application's files from one handle on its directory without following a link, and \
             checks what a replacement keeps, on macOS and Linux only; {INSTEAD}"
        ));
    }
    Ok(())
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

/// Returns a package's name under its publisher, the application name its forwarder reports for.
fn package_name(plugin_id: &PluginId) -> &str {
    plugin_id
        .as_str()
        .rsplit_once('/')
        .map_or(plugin_id.as_str(), |(_, name)| name)
}

/// What the registration the recipe installs says: the application name its `kr-hook`
/// invocations carry, and the registrations they are.
fn registration(
    sources: &[(String, Vec<u8>)],
    forwarder: &Path,
    application: &str,
) -> std::result::Result<Option<RecordedFacts>, String> {
    let mut applications = BTreeSet::new();
    let mut surfaces = BTreeSet::new();
    for (destination, bytes) in sources {
        // Every file a recipe installs is JSON this host reads, whatever its name says: an
        // application may read a file more leniently than this host does, or run it as a script,
        // and what is not read is not checked.
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            return Err(format!(
                "{destination} cannot be read as JSON, so what it registers cannot be checked"
            ));
        };
        invocations(&value, destination, &mut applications, &mut surfaces)?;
        // Then the file's own shape, which is closed: what the commands are is read above, and
        // what else the file asks the application to do is only what this host names for it.
        let (directory, tail) = destination
            .split_once('/')
            .and_then(|(_, rest)| rest.split_once('/'))
            .ok_or_else(|| format!("{destination} is not in a directory of its own"))?;
        shapes::check(application, directory, tail, &value).map_err(|why| {
            format!(
                "{destination} is not a registration file this host permits a native bridge \
                 for {application} to install: {why}"
            )
        })?;
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

/// A template's bytes with the forwarder's path written where the package names the forwarder.
///
/// A template that names no forwarder is returned as it is, so a package that registers the bare
/// name installs the bytes its recipe names. Otherwise the path is written for where the
/// placeholder stands (a program started whole, or a line a shell runs); the template has been read
/// by [`registration`] already, so the commands it runs are the forwarder and nothing else.
fn expanded(
    destination: &str,
    template: &[u8],
    forwarder: &Path,
) -> std::result::Result<Vec<u8>, String> {
    let Ok(text) = std::str::from_utf8(template) else {
        return Ok(template.to_vec());
    };
    if !forwarder::mentions(text) {
        return Ok(template.to_vec());
    }
    forwarder::expand(text, forwarder)
        .map(String::into_bytes)
        .map_err(|error| format!("{destination} cannot be written with the forwarder: {error}"))
}

fn invocations(
    value: &serde_json::Value,
    destination: &str,
    applications: &mut BTreeSet<String>,
    surfaces: &mut BTreeSet<BridgeSurface>,
) -> std::result::Result<(), String> {
    match value {
        serde_json::Value::Object(members) => {
            // Every command a registration runs is the forwarder, and in a form this host reads: its
            // name alone, with the application and the surface as the two arguments in a list, or
            // one line of the name, the application it reports for and the surface, separated by
            // single spaces, each word of plain characters, for an application that runs a hook
            // through a shell. Anything else a registration would run, a quoted or escaped name,
            // an operator, another word, another command, is refused wherever it stands, so that no
            // command beside a good one is left unread.
            if let Some(command) = members.get("command") {
                let unaccepted = || {
                    format!(
                        "{destination} starts the forwarder with arguments it does not accept \
                         from a bridge, or starts something other than the forwarder"
                    )
                };
                let command = command.as_str().ok_or_else(unaccepted)?;
                // The members a forwarder registration uses, and no others: one beside the
                // command can run it in another environment or place.
                if members
                    .keys()
                    .any(|member| !COMMAND_MEMBERS.contains(&member.as_str()))
                {
                    return Err(unaccepted());
                }
                // The bare name is what the packages written before the placeholder register; it
                // is read until no catalogue holds one, and then only the placeholder is.
                let surface = if command == "kr-hook" || command == forwarder::PLACEHOLDER {
                    let arguments = members.get("args").and_then(serde_json::Value::as_array);
                    let words: Vec<&str> = arguments
                        .map(|arguments| {
                            arguments
                                .iter()
                                .filter_map(serde_json::Value::as_str)
                                .collect()
                        })
                        .unwrap_or_default();
                    match (words.as_slice(), arguments.map(Vec::len)) {
                        ([application, "hook"], Some(2)) => (*application, BridgeSurface::Hook),
                        ([application, "channel"], Some(2)) => {
                            (*application, BridgeSurface::Channel)
                        }
                        _ => return Err(unaccepted()),
                    }
                } else {
                    // A command written as one line is complete: an argument list beside it is
                    // another word the application would run.
                    if members.contains_key("args") {
                        return Err(unaccepted());
                    }
                    let words: Vec<&str> = command.split(' ').collect();
                    match words.as_slice() {
                        ["kr-hook" | forwarder::PLACEHOLDER, application, "hook"]
                            if plain_word(application) =>
                        {
                            (*application, BridgeSurface::Hook)
                        }
                        ["kr-hook" | forwarder::PLACEHOLDER, application, "channel"]
                            if plain_word(application) =>
                        {
                            (*application, BridgeSurface::Channel)
                        }
                        _ => return Err(unaccepted()),
                    }
                };
                applications.insert(surface.0.to_owned());
                surfaces.insert(surface.1);
            }
            for (name, nested) in members {
                // The placeholder stands where a command starts and nowhere else: a key or a value
                // that holds it elsewhere would have the host write the forwarder's path into
                // something the registration does not run. These are decoded already; what the
                // file spells with escapes is read in its own text, where the host writes the path.
                if name.contains(forwarder::PLACEHOLDER) {
                    return Err(format!(
                        "{destination} names the forwarder's placeholder somewhere that is not a \
                         command"
                    ));
                }
                if name != "command" {
                    invocations(nested, destination, applications, surfaces)?;
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                invocations(item, destination, applications, surfaces)?;
            }
        }
        serde_json::Value::String(text) if text.contains(forwarder::PLACEHOLDER) => {
            return Err(format!(
                "{destination} names the forwarder's placeholder somewhere that is not a command"
            ));
        }
        _ => {}
    }
    Ok(())
}

/// The members of an object that holds a command, which a forwarder registration uses: what kind
/// of entry it is, its name, the command, its arguments and its time limit.
const COMMAND_MEMBERS: [&str; 5] = ["type", "name", "command", "args", "timeout"];

/// What a native bridge for an application may place, as a closed table this host names.
///
/// A bridge installs exactly the registration files its application reads from one directory of
/// its own, `<root>/<name>/<tail>` for each tail the table lists, and may add the one configuration
/// key that enables them where the application has one, `enabledPlugins.<name>@skills-dir` set to
/// `true` in `settings.json`, for the same `<name>`. A destination or a key that is not on the
/// table is refused, so a bridge never installs a settings document of its own and adds no value
/// that can hold a command. Whether the directory and the name are free is `place_is_free`'s. A
/// name in another case is another name here: it is refused.
fn permitted(recipe: &NativeBridge) -> std::result::Result<(), String> {
    struct Layout {
        root: &'static str,
        tails: &'static [&'static str],
        enabling: Option<(&'static str, &'static str, &'static str)>,
    }
    let layout = match recipe.application.as_str() {
        "Claude Code" => Layout {
            root: "skills",
            tails: &[
                ".claude-plugin/plugin.json",
                ".mcp.json",
                "hooks/hooks.json",
            ],
            enabling: Some(("settings.json", "enabledPlugins.", "@skills-dir")),
        },
        "Gemini CLI" => Layout {
            root: "extensions",
            tails: &[
                ".gemini-extension-install.json",
                "gemini-extension.json",
                "hooks/hooks.json",
            ],
            enabling: None,
        },
        other => {
            return Err(format!(
                "this host does not name what a native bridge for {other} may place"
            ));
        }
    };
    let application = &recipe.application;
    let mut name: Option<&str> = None;
    let mut placed_tails: Vec<&str> = Vec::new();
    // The files first, whatever order the recipe lists its steps in: the key is held to the
    // directory they are in.
    for step in &recipe.install {
        if let BridgeStep::InstallFile { destination, .. } = step {
            {
                let destination = destination.as_str();
                let placed = destination
                    .strip_prefix(layout.root)
                    .and_then(|rest| rest.strip_prefix('/'))
                    .and_then(|rest| rest.split_once('/'))
                    .filter(|(directory, tail)| {
                        plain_name(directory) && layout.tails.contains(tail)
                    });
                let Some((directory, _)) = placed else {
                    return Err(format!(
                        "the recipe installs {destination}, which this host does not permit a \
                         native bridge for {application} to install: it installs {}/<name>/ with \
                         {} and nothing else",
                        layout.root,
                        layout.tails.join(", ")
                    ));
                };
                if name.is_some_and(|first| first != directory) {
                    return Err(format!(
                        "the recipe installs into more than one directory under {}/, which this \
                         host does not permit a native bridge for {application} to do",
                        layout.root
                    ));
                }
                name = Some(directory);
                placed_tails.push(destination);
            }
        }
    }
    // Every file of the registration, and each once: an application reads the files beside the
    // ones a recipe leaves out, and a directory that holds another manifest or server file is
    // not one this host has checked.
    for tail in layout.tails {
        let times = placed_tails
            .iter()
            .filter(|destination| destination.ends_with(&format!("/{tail}")))
            .count();
        match times {
            1 => {}
            0 => {
                return Err(format!(
                    "the recipe does not install {tail}, and this host does not permit a native \
                     bridge for {application} to install less than every file of its registration"
                ));
            }
            _ => {
                return Err(format!(
                    "the recipe installs {tail} {times} times, and this host does not permit a \
                     native bridge for {application} to install a file of its registration more \
                     than once"
                ));
            }
        }
    }
    for step in &recipe.install {
        if let BridgeStep::AddConfigurationKey { file, key, value } = step {
            let enabled = layout.enabling.is_some_and(|(document, prefix, suffix)| {
                file.as_str() == document
                    && value == "true"
                    && key
                        .strip_prefix(prefix)
                        .and_then(|rest| rest.strip_suffix(suffix))
                        .is_some_and(|enabled| plain_name(enabled) && Some(enabled) == name)
            });
            if !enabled {
                return Err(format!(
                    "the recipe adds the key {key} to {file}, which this host does not permit a \
                     native bridge for {application} to add: it adds only the key that enables \
                     the registration it installs, set to true"
                ));
            }
        }
    }
    Ok(())
}

/// Whether the directory a bridge installs its registration in is one it may make or already made,
/// and whether the name its manifest gives is one the application keeps once.
///
/// An application enables everything it finds in a plugin's directory with the plugin: a directory
/// that is already there and that this host did not make holds the person's own content, such as
/// a monitor's command, which the owner's confirmation of the publisher's statement did not
/// describe. A directory is the one this host made when the journal records its publication under
/// the identity the directory has now, and never because of its path: another directory may have
/// been put in its place. And an application keeps one plugin for each name, the first it reads, so
/// a manifest of the same name in another folder beside this one could be the plugin the enabling
/// key reaches. Another folder's manifest is read as the application reads it, a leading byte order
/// mark dropped, and one that is there and that this host cannot read whole or parse is a refusal,
/// never taken for one that is not there. The directory itself under another name (a link to it, a
/// spelling a volume that ignores case reads alike) is not another folder, and for Claude Code
/// neither is a hidden one, which it does not read as a plugin. Every refusal comes before anything
/// is written. The other folders are read through their paths, as an advisory check beside the
/// walk the executor makes from one handle: what appears after it is the person's own, as it is
/// after the install.
fn place_is_free(
    root: &Dir,
    journal: &Journal,
    recipe: &NativeBridge,
) -> std::result::Result<(), String> {
    let application = &recipe.application;
    let (manifest, skips_hidden) = match application.as_str() {
        "Claude Code" => (".claude-plugin/plugin.json", true),
        _ => ("gemini-extension.json", false),
    };
    let Some((area, name)) = recipe.install.iter().find_map(|step| match step {
        BridgeStep::InstallFile { destination, .. } => destination
            .as_str()
            .split_once('/')
            .and_then(|(area, rest)| rest.split_once('/').map(|(name, _)| (area, name))),
        BridgeStep::AddConfigurationKey { .. } => None,
    }) else {
        return Ok(());
    };
    let path = format!("{area}/{name}");
    let Child::Directory(areas) = root
        .child(area)
        .map_err(|error| format!("{area} cannot be read: {error}"))?
    else {
        return Ok(());
    };
    let own = match areas
        .child(name)
        .map_err(|error| format!("{path} cannot be read: {error}"))?
    {
        Child::Directory(existing) => Some(existing),
        Child::Absent | Child::NotADirectory => None,
    };
    if let Some(existing) = own.as_ref() {
        let made = journal.changes.iter().any(|change| {
            matches!(change, Change::Directory { path: made, publication: Publication::Published { identity }, .. }
                if *made == path && identity.same_object(&existing.identity()))
        });
        let registration: Vec<&str> = recipe
            .install
            .iter()
            .filter_map(|step| match step {
                BridgeStep::InstallFile { destination, .. } => destination
                    .as_str()
                    .strip_prefix(path.as_str())
                    .and_then(|rest| rest.strip_prefix('/')),
                BridgeStep::AddConfigurationKey { .. } => None,
            })
            .collect();
        if !made
            && !holds_only(existing.path(), "", &registration)
                .map_err(|error| format!("{path} cannot be read: {error}"))?
        {
            return Err(format!(
                "{path} is already there with content that is not this registration, so this host \
                 does not permit a native bridge for {application} to install into it: \
                 {application} would enable everything in it with the registration"
            ));
        }
    }
    let own = own.as_ref().map(Dir::identity);
    let listing = std::fs::read_dir(areas.path())
        .map_err(|error| format!("{area} cannot be listed: {error}"))?;
    for entry in listing {
        let entry = entry.map_err(|error| format!("{area} cannot be listed: {error}"))?;
        let folder = entry.file_name();
        let shown = folder.to_string_lossy();
        if folder == name
            || (skips_hidden && shown.starts_with('.'))
            || own.as_ref().is_some_and(|identity| {
                folder
                    .to_str()
                    .is_some_and(|folder| areas.path_leads_to(folder, identity))
            })
        {
            continue;
        }
        match claimed_name(&entry.path().join(manifest)) {
            Ok(Some(claimed)) if claimed == name => {
                return Err(format!(
                    "{area}/{shown} holds a plugin named {name} too, and {application} keeps one of \
                     two with a name, so this host does not permit a native bridge for \
                     {application} to install a plugin of that name"
                ));
            }
            Ok(_) => {}
            Err(why) => {
                return Err(format!(
                    "{area}/{shown}/{manifest} {why}, so this host cannot tell whether {application} \
                     keeps a plugin named {name} from it, and does not permit a native bridge for \
                     {application} to install one"
                ));
            }
        }
    }
    Ok(())
}

/// The name the plugin manifest at `path` gives itself, read as an application reads it: one
/// leading byte order mark is dropped before the JSON is parsed. `None` when there is no manifest
/// there, or it names nothing, which an application does not load. An error says why a manifest
/// that is there could not be read whole within the limit or parsed.
fn claimed_name(path: &Path) -> std::result::Result<Option<String>, String> {
    use std::io::Read as _;
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(format!("cannot be read: {error}")),
    };
    if !metadata.is_file() {
        return Err("is not a file this host reads".to_owned());
    }
    let too_large = || "is larger than this host reads".to_owned();
    if metadata.len() > FILE_LIMIT {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(FILE_LIMIT + 1).read_to_end(&mut bytes))
        .map_err(|error| format!("cannot be read: {error}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > FILE_LIMIT {
        return Err(too_large());
    }
    let text = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&bytes);
    let value: serde_json::Value =
        serde_json::from_slice(text).map_err(|_| "is not JSON this host reads".to_owned())?;
    Ok(value
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned))
}

/// Whether a directory holds nothing but empty directories and the files of `registration`, which
/// are named relative to it. `within` is the way from the directory the walk began in. A file of the
/// registration that is there is the executor's to refuse, as one this host did not write.
///
/// # Errors
///
/// Returns the error of a listing that fails: what it holds is then not known.
fn holds_only(directory: &Path, within: &str, registration: &[&str]) -> std::io::Result<bool> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let relative = if within.is_empty() {
            name
        } else {
            format!("{within}/{name}")
        };
        let fits = if kind.is_dir() {
            holds_only(&entry.path(), &relative, registration)?
        } else {
            kind.is_file() && registration.contains(&relative.as_str())
        };
        if !fits {
            return Ok(false);
        }
    }
    Ok(true)
}

/// True for a name of ASCII letters, digits, hyphens and underscores, which is one path component
/// and one key member as it is written.
fn plain_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// True for a word of lower-case letters, digits and hyphens, which a shell reads as itself.
fn plain_word(word: &str) -> bool {
    !word.is_empty()
        && word
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
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
        Walk::Missing { .. } => Ok(false),
        Walk::Substituted(at) => Err(substituted(root, &at)),
        Walk::Found { parent, name } => {
            let directory = parent.as_ref().unwrap_or(root);
            match directory
                .fetch(name, FILE_LIMIT)
                .map_err(|error| format!("{shown}: {error}"))?
            {
                Fetched::Absent => Ok(false),
                Fetched::NotRegular => Err(format!("{shown} is a link, or not a regular file")),
                Fetched::File(_) | Fetched::TooLarge if !recorded => Err(format!(
                    "{shown} is already there and this host did not write it; move it aside, \
                     then install again"
                )),
                Fetched::File(read) if PayloadDigest::of(&read.bytes).to_string() == digest => {
                    Ok(true)
                }
                Fetched::File(_) | Fetched::TooLarge => {
                    Err(format!("{shown} has changed since this host wrote it"))
                }
            }
        }
    }
}

/// True when the key is one this host set with this value and still holds it; false when it is
/// not there yet, and the document it would go into takes it within the size this host reads.
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
        // Not there: the document it would be written into is made now, without writing it, so
        // one this host could not read back is refused before anything is written.
        Walk::Missing { .. } => creation(&shown, &members, value).map(|_| false),
        Walk::Substituted(at) => Err(substituted(root, &at)),
        Walk::Found { parent, name } => {
            let directory = parent.as_ref().unwrap_or(root);
            let read = match directory
                .fetch(name, DOCUMENT_LIMIT)
                .map_err(|error| format!("{shown}: {error}"))?
            {
                Fetched::Absent => return creation(&shown, &members, value).map(|_| false),
                Fetched::NotRegular => {
                    return Err(format!("{shown} is a link, or not a regular file"));
                }
                Fetched::TooLarge => return Err(too_large(&shown)),
                Fetched::File(read) => read,
            };
            files::guard_access_controls(&directory.join(name), INSTEAD)
                .map_err(|error| error.to_string())?;
            if read.owners.user != tree::acting_user() {
                return Err(format!(
                    "{shown} belongs to user {}, and a replacement written by this host would \
                     belong to user {}, so replacing it would change who can read or change it",
                    read.owners.user,
                    tree::acting_user()
                ));
            }
            let text =
                std::str::from_utf8(&read.bytes).map_err(|_| format!("{shown} is not text"))?;
            let document = json::Document::read(text).map_err(|reason| {
                format!("{shown} is not a document this host can edit exactly: {reason}")
            })?;
            match document
                .value_at(text, &members)
                .map_err(|reason| format!("{shown}: {reason}"))?
            {
                // Not there: the edit it would take is made now, without writing it, so a
                // document it could not take is refused before anything is written.
                None => insertion(&shown, &read.bytes, &members, value).map(|_| false),
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

/// The document with the key added, within the size this host reads back.
fn insertion(
    shown: &str,
    bytes: &[u8],
    members: &[&str],
    value: &str,
) -> std::result::Result<json::Inserted, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| format!("{shown} is not text"))?;
    let inserted = json::insert(text, members, value).map_err(|reason| {
        format!("{shown} is not a document this host can edit exactly: {reason}")
    })?;
    if u64::try_from(inserted.text.len()).unwrap_or(u64::MAX) > DOCUMENT_LIMIT {
        return Err(format!(
            "{shown} would be larger than the {DOCUMENT_LIMIT} bytes this host reads back once \
             the key is added"
        ));
    }
    Ok(inserted)
}

/// What taking the key out of the document at `name` would leave, with the document it was
/// planned from; `None` when the key or the document is not there; an outcome when it cannot be
/// taken out.
fn planned_removal(
    directory: &Dir,
    name: &str,
    members: &[&str],
    value: &str,
    created_members: usize,
) -> std::result::Result<Option<(tree::Read, String)>, Outcome> {
    let read = match directory.fetch(name, DOCUMENT_LIMIT) {
        Err(error) => return Err(Outcome::Unfinished(error.to_string())),
        Ok(Fetched::Absent) => return Ok(None),
        Ok(Fetched::NotRegular) => {
            return Err(Outcome::Kept(
                "the document is now a link, or not a regular file".to_owned(),
            ));
        }
        Ok(Fetched::TooLarge) => {
            return Err(Outcome::Unfinished(format!(
                "the document is larger than the {DOCUMENT_LIMIT} bytes this host reads"
            )));
        }
        Ok(Fetched::File(read)) => read,
    };
    let Ok(text) = std::str::from_utf8(&read.bytes) else {
        return Err(Outcome::Unfinished("the document is not text".to_owned()));
    };
    let document = json::Document::read(text).map_err(|reason| {
        Outcome::Unfinished(format!(
            "the document is not one this host can edit exactly: {reason}"
        ))
    })?;
    let current = document.value_at(text, members).map_err(Outcome::Kept)?;
    let Some(current) = current else {
        return Ok(None);
    };
    if !same_json(current, value) {
        return Err(Outcome::Kept(
            "it has changed since it was installed".to_owned(),
        ));
    }
    files::guard_access_controls(&directory.join(name), INSTEAD)
        .map_err(|error| Outcome::Unfinished(error.to_string()))?;
    let edited = json::remove(text, members, created_members).map_err(Outcome::Kept)?;
    Ok(Some((read, edited)))
}

/// Whether the document is still the one `read` took, with the same bytes and protection, or still
/// absent when `read` found none. Its access-control lists are read again here, just before the
/// replacement: a change to them does not change the file's bytes.
fn still_the_same(
    directory: &Dir,
    name: &str,
    read: Option<&tree::Read>,
) -> std::io::Result<Sameness> {
    match (read, directory.fetch(name, DOCUMENT_LIMIT)?) {
        (None, Fetched::Absent) => Ok(Sameness::Same),
        (Some(read), Fetched::File(now))
            if now.identity == read.identity
                && now.mode == read.mode
                && now.owners == read.owners
                && now.bytes == read.bytes =>
        {
            Ok(guard_held(directory, name, &now.identity))
        }
        _ => Ok(Sameness::Changed),
    }
}

/// The access-control guard for a document about to be replaced. It can only read through paths,
/// so it runs while the directory's path leads to the held directory and the document's path to
/// the document just read through it, checked before and after: what it reads is about them, and
/// not about something put in their place.
fn guard_held(directory: &Dir, name: &str, identity: &Identity) -> Sameness {
    let reached = || directory.path_leads_here() && directory.path_leads_to(name, identity);
    let lost = || {
        Sameness::Refused(format!(
            "{} no longer leads to the document this host read, so its protection cannot be read",
            directory.join(name).display()
        ))
    };
    if !reached() {
        return lost();
    }
    let guarded = files::guard_access_controls(&directory.join(name), INSTEAD);
    if !reached() {
        return lost();
    }
    match guarded {
        Ok(()) => Sameness::Same,
        Err(error) => Sameness::Refused(error.to_string()),
    }
}

/// Why the copy staged at `temporary` would not keep the protection of the document it is to
/// replace, where it would not: its directory gave it an access-control list, or it belongs to
/// another user or group than the document does.
fn staged_protection(
    directory: &Dir,
    temporary: &str,
    identity: &Identity,
    document: &tree::Read,
    shown: &str,
) -> std::result::Result<(), String> {
    if staged_listed(directory, temporary, identity)? {
        return Err(format!(
            "a new file in {} is given an access-control list by the directory itself, so \
             replacing {shown} here would change who can read it",
            directory.path().display()
        ));
    }
    let staged = directory
        .owners(temporary)
        .map_err(|error| error.to_string())?;
    if staged != Some(document.owners) {
        return Err(format!(
            "{shown} belongs to user {} and group {}, and a replacement written here would belong \
             to {}, so replacing it would change who can read or change it",
            document.owners.user,
            document.owners.group,
            staged.map_or_else(
                || "nothing this host can read".to_owned(),
                |owners| format!("user {} and group {}", owners.user, owners.group)
            )
        ));
    }
    Ok(())
}

/// Whether the copy staged at `temporary` was given an access-control list by its directory, read
/// through its path while the paths lead to the held directory and to the copy.
fn staged_listed(
    directory: &Dir,
    temporary: &str,
    identity: &Identity,
) -> std::result::Result<bool, String> {
    let reached = || directory.path_leads_here() && directory.path_leads_to(temporary, identity);
    let lost = || {
        format!(
            "{} no longer leads to the copy this host staged, so its protection cannot be read",
            directory.join(temporary).display()
        )
    };
    if !reached() {
        return Err(lost());
    }
    let listed = files::extended_access_controls(&directory.join(temporary))
        .map_err(|error| error.to_string());
    if !reached() {
        return Err(lost());
    }
    listed
}

/// `Some(true)` when the document holds `value` at `key`, `Some(false)` when it holds something
/// else or nothing, and `None` when that cannot be read.
fn key_holds(directory: &Dir, name: &str, key: &str, value: &str) -> Option<bool> {
    let read = match directory.fetch(name, DOCUMENT_LIMIT).ok()? {
        Fetched::File(read) => read,
        Fetched::Absent => return Some(false),
        Fetched::NotRegular | Fetched::TooLarge => return None,
    };
    let text = std::str::from_utf8(&read.bytes).ok()?;
    let document = json::Document::read(text).ok()?;
    let members: Vec<&str> = key.split('.').collect();
    let current = document.value_at(text, &members).ok()?;
    Some(current.is_some_and(|current| same_json(current, value)))
}

/// What is at one name, as a file or as a directory.
fn object_at(directory: &Dir, name: &str, kind: Kind) -> std::io::Result<Object> {
    match kind {
        Kind::File => Ok(match directory.entry(name)? {
            Entry::Absent => Object::Absent,
            Entry::File(identity) => Object::Found(identity),
            Entry::Directory | Entry::Other => Object::Other,
        }),
        Kind::Directory => Ok(match directory.child(name)? {
            Child::Absent => Object::Absent,
            Child::Directory(found) => Object::Found(found.identity()),
            Child::NotADirectory => Object::Other,
        }),
    }
}

/// True when two identities name the object staged: a file by its whole identity, a directory by
/// its device and inode, since its entries move its size and time.
fn same(kind: Kind, staged: &Identity, found: &Identity) -> bool {
    match kind {
        Kind::File => staged == found,
        Kind::Directory => staged.same_object(found),
    }
}

/// Reads one executable, never running it: a regular file, not a script, read within the size
/// its file reports and read again when it changed meanwhile.
pub(crate) fn read_executable(path: &Path) -> std::result::Result<Digest256, String> {
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
    let root = match Dir::open(&release.directory) {
        Ok(root) => root,
        Err(error) => return vec![format!("{}: {error}", release.directory.display())],
    };
    if !root.identity().same_object(&release.directory_identity) {
        return vec![format!(
            "{} is now another directory than the one this host applied the bridge in",
            release.directory.display()
        )];
    }
    let mut notes = Vec::new();
    for change in &journal.changes {
        match change {
            Change::File { path, digest, .. } => {
                let shown = tree::display(root.path(), path);
                let held = match tree::parent_of(&root, path) {
                    Ok(Walk::Found { parent, name }) => parent
                        .as_ref()
                        .unwrap_or(&root)
                        .fetch(name, FILE_LIMIT)
                        .map(|fetched| match fetched {
                            Fetched::File(read) => Some(PayloadDigest::of(&read.bytes).to_string()),
                            Fetched::Absent => None,
                            Fetched::NotRegular | Fetched::TooLarge => Some(String::new()),
                        }),
                    Ok(Walk::Missing { .. }) => Ok(None),
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
                    Ok(Walk::Missing { .. }) => Some(false),
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

/// `Some(true)` when the document holds anything at `key`, `Some(false)` when it or the key is
/// not there, and `None` when that cannot be read.
fn key_holds_anything(directory: &Dir, name: &str, key: &str) -> Option<bool> {
    let read = match directory.fetch(name, DOCUMENT_LIMIT).ok()? {
        Fetched::File(read) => read,
        Fetched::Absent => return Some(false),
        Fetched::NotRegular | Fetched::TooLarge => return None,
    };
    let text = std::str::from_utf8(&read.bytes).ok()?;
    let document = json::Document::read(text).ok()?;
    let members: Vec<&str> = key.split('.').collect();
    Some(document.value_at(text, &members).ok()?.is_some())
}

fn in_flight(change: &Change) -> bool {
    match change {
        Change::Directory { publication, .. } | Change::File { publication, .. } => {
            !matches!(publication, Publication::Published { .. })
        }
        Change::Key {
            publication,
            removing,
            ..
        } => !matches!(publication, Publication::Published { .. }) || removing.is_some(),
    }
}

/// The path, and the key where there is one, a change placed or was placing.
fn placed_path(change: &Change) -> (&str, Option<&str>) {
    match change {
        Change::Directory { path, .. } | Change::File { path, .. } => (path, None),
        Change::Key { file, key, .. } => (file, Some(key)),
    }
}

/// A record of what a change placed, in the directory this run holds, and why it is named.
fn kept(root: &Dir, change: &Change, reason: &str) -> Kept {
    kept_in(root.path(), root.identity(), change, reason)
}

/// A record of what a change placed, in the directory with this path and identity, and why it is
/// named.
fn kept_in(directory: &Path, identity: Identity, change: &Change, reason: &str) -> Kept {
    let (path, key) = placed_path(change);
    Kept {
        directory: directory.to_path_buf(),
        directory_identity: identity,
        path: path.to_owned(),
        key: key.map(str::to_owned),
        reason: reason.to_owned(),
    }
}

/// A record of something at `temporary` beside `path` that may be this host's and cannot be shown
/// to be.
fn unproven_at(root: &Dir, path: &str, temporary: &str, reason: String) -> Kept {
    Kept {
        directory: root.path().to_path_buf(),
        directory_identity: root.identity(),
        path: sibling(path, temporary),
        key: None,
        reason,
    }
}

/// Why something at a temporary name is left.
fn unproven() -> String {
    "a run that stopped may have made this, and this host cannot show it did, so it is left for \
     you to remove"
        .to_owned()
}

/// The path of `temporary` beside `path`.
fn sibling(path: &str, temporary: &str) -> String {
    let parts = tree::components(path);
    match parts.split_last() {
        Some((_, [])) | None => temporary.to_owned(),
        Some((_, directories)) => format!("{}/{temporary}", directories.join("/")),
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

fn set_publication(change: &mut Change, stage: Publication) {
    match change {
        Change::Directory { publication, .. }
        | Change::File { publication, .. }
        | Change::Key { publication, .. } => *publication = stage,
    }
}

fn set_removing(change: &mut Change, staging: Option<Staging>) {
    if let Change::Key { removing, .. } = change {
        *removing = staging;
    }
}

/// The text of a document this host creates to hold one key, within the size this host reads
/// back.
fn creation(shown: &str, members: &[&str], value: &str) -> std::result::Result<Vec<u8>, String> {
    let mut document: serde_json::Value = serde_json::from_str(value)
        .map_err(|error| format!("the recipe's value is not JSON: {error}"))?;
    for member in members.iter().rev() {
        let mut object = serde_json::Map::new();
        object.insert((*member).to_owned(), document);
        document = serde_json::Value::Object(object);
    }
    let text = serde_json::to_string_pretty(&document)
        .map_err(|error| format!("the document cannot be written: {error}"))?;
    let bytes = format!("{text}\n").into_bytes();
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > DOCUMENT_LIMIT {
        return Err(format!(
            "{shown} would be larger than the {DOCUMENT_LIMIT} bytes this host reads back once \
             the key is written"
        ));
    }
    Ok(bytes)
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

/// What keeps a bridge from being applied or clean: what could not be taken out, and what may be
/// this host's and cannot be shown to be.
fn outstanding(journal: &Journal) -> String {
    let mut parts = Vec::new();
    if !journal.changes.is_empty() && journal.state == State::Removing {
        let blocked: Vec<String> = journal.blocked.iter().map(Kept::describe).collect();
        parts.push(if blocked.is_empty() {
            "what was placed could not all be taken out".to_owned()
        } else {
            format!(
                "what was placed could not all be taken out: {}",
                blocked.join("; ")
            )
        });
    }
    if !journal.unresolved.is_empty() {
        let unresolved: Vec<String> = journal.unresolved.iter().map(Kept::describe).collect();
        parts.push(format!("not settled: {}", unresolved.join("; ")));
    }
    if !journal.leftovers.is_empty() {
        let left: Vec<String> = journal.leftovers.iter().map(Kept::describe).collect();
        parts.push(format!("left in place: {}", left.join("; ")));
    }
    parts.join("; and ")
}

fn too_large(shown: &str) -> String {
    format!("{shown} is larger than the {DOCUMENT_LIMIT} bytes this host reads")
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The refusal names what is refused, why, and what happens instead, and only where it
    /// applies.
    #[test]
    fn the_platform_guard_refuses_on_windows_alone() {
        let answer = supported_platform();
        if cfg!(windows) {
            let refused = answer.expect_err("refuses");
            assert!(
                refused.contains("does not apply or remove a native bridge on Windows")
                    && refused.contains("without following a link")
                    && refused.ends_with(INSTEAD),
                "{refused}"
            );
        } else {
            answer.expect("changes are made here");
        }
    }
}
