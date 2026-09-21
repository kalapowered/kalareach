//! Reading this host's configuration, and resolving one preference from it.
//!
//! The schema, the precedence rule, the allowlist and the validation all live in
//! [`kr_protocol::hostinfo::configuration`], where a writer and a reader can agree about them.
//! What lives here is the half that needs a filesystem: where the document is, how much of it is
//! read, and what this process does with a document it cannot use.
//!
//! Every process that resolves a preference goes through [`Resolver`], and every preference goes
//! through [`kr_protocol::hostinfo::configuration::resolve`]. A call site that wanted its own
//! order would have to write its own ladder, which is exactly what section 26 asks not to happen.
//!
//! # What this reader does with a document it cannot use
//!
//! Nothing, except say so. An unreadable file, a file larger than the bound, a document at a
//! version this build does not know and a document that does not validate all resolve to the
//! product defaults, and the status travels with the resolver so `kr doctor` reports it. The file
//! is never rewritten and never partially read: a host that repaired its owner's document would
//! be deciding what the owner meant.

use std::path::{Path, PathBuf};

use kr_ipc::paths::EnvironmentPaths;
use kr_protocol::desktop::SleepInhibitionSetting;
pub use kr_protocol::hostinfo::configuration::Effective;
use kr_protocol::hostinfo::configuration::{
    self, ConfigurationCeilings, DocumentStatus, EnrolmentBudgets, Layers, Loaded, Offered,
    Preference, PreferenceSet,
};
use kr_protocol::hostinfo::{EffectiveValue, OverrideReport};
use kr_protocol::identity::WorkerProfile;
use kr_protocol::scalars::Nullable;

/// Returns where this environment's configuration document is.
#[must_use]
pub fn document_path(paths: &EnvironmentPaths) -> PathBuf {
    configuration::document_path(
        paths.state_dir(),
        paths.state_root(),
        paths.environment_id(),
    )
}

/// Reads this environment's configuration document.
///
/// The read is bounded by [`kr_protocol::hostinfo::configuration::MAX_LEN`] and refuses a link or
/// another user's file, because the document decides how this host behaves and a file this host
/// did not write is not this host's configuration.
#[must_use]
pub fn load(paths: &EnvironmentPaths) -> Loaded {
    let path = document_path(paths);
    match configuration::read_file(&path, configuration::MAX_LEN) {
        Ok(bytes) => configuration::load(bytes.as_deref()),
        Err(error) => configuration::unreadable(&error),
    }
}

/// Takes this environment's configuration lock.
///
/// One lock for the whole installation, taken by the daemon and by the command alike, so an edit
/// from a terminal and an edit from the host cannot each read one revision and each publish the
/// next.
///
/// # Errors
///
/// Returns the sentence a caller reports when another writer holds the lock.
pub fn lock(paths: &EnvironmentPaths) -> std::result::Result<configuration::EditLock, String> {
    configuration::lock(paths.state_dir())
}

/// Returns the documents beside the configuration that this build no longer reads./// Returns the documents beside the configuration that this build no longer reads.
///
/// One entry today: the separate `power.json` the sleep setting used to live in, before the
/// schema absorbed it. Nothing reads it and nothing removes it; `kr doctor` says in one line that
/// it is there and is being ignored, which is the whole of what an owner needs to know about a
/// file that has stopped having an effect.
#[must_use]
pub fn stale_documents(paths: &EnvironmentPaths) -> Vec<PathBuf> {
    let superseded = paths.state_dir().join(configuration::SUPERSEDED_FILE_NAME);
    if superseded.exists() {
        vec![superseded]
    } else {
        Vec::new()
    }
}

/// This host's configuration, ready to resolve preferences from.
#[derive(Clone, Debug)]
pub struct Resolver {
    loaded: Loaded,
    document: PathBuf,
    runtime_directory: PathBuf,
    state_directory: PathBuf,
    profile: Option<String>,
    stale: Vec<PathBuf>,
}

impl Resolver {
    /// Reads the configuration of one environment.
    #[must_use]
    pub fn open(paths: &EnvironmentPaths) -> Self {
        Self {
            loaded: load(paths),
            document: document_path(paths),
            runtime_directory: paths.runtime_dir().to_path_buf(),
            state_directory: paths.state_dir().to_path_buf(),
            profile: None,
            stale: stale_documents(paths),
        }
    }

    /// Builds a resolver from a document this caller already has.
    #[must_use]
    pub fn from_loaded(loaded: Loaded, paths: &EnvironmentPaths) -> Self {
        Self {
            loaded,
            document: document_path(paths),
            runtime_directory: paths.runtime_dir().to_path_buf(),
            state_directory: paths.state_dir().to_path_buf(),
            profile: None,
            stale: stale_documents(paths),
        }
    }

    /// Selects a session or environment profile by name.
    ///
    /// A name that no profile in the document answers to contributes nothing, and the preference
    /// falls through to the per-user host configuration. It is not an error: a profile is a
    /// convenience, and a request that names one this host does not have has still asked for
    /// nothing more than the defaults.
    #[must_use]
    pub fn with_profile(mut self, name: Option<String>) -> Self {
        self.profile = name;
        self
    }

    /// Returns what the document turned out to be.
    #[must_use]
    pub const fn status(&self) -> &DocumentStatus {
        &self.loaded.status
    }

    /// Returns the revision this host has applied.
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.loaded.revision()
    }

    /// Returns the loaded document.
    #[must_use]
    pub const fn loaded(&self) -> &Loaded {
        &self.loaded
    }

    /// Returns where the document is.
    #[must_use]
    pub fn document(&self) -> &Path {
        &self.document
    }

    /// Returns the documents beside it that this build no longer reads.
    #[must_use]
    pub fn stale_documents(&self) -> &[PathBuf] {
        &self.stale
    }

    /// Returns the ceilings this configuration asks for.
    #[must_use]
    pub fn ceilings(&self) -> ConfigurationCeilings {
        self.loaded.ceilings()
    }

    /// Returns the repository enrolment budgets section 11 calls configuration.
    ///
    /// The catalogue reads its budgets from here rather than carrying its own copy, so one
    /// document answers what a repository may cost on this host.
    #[must_use]
    pub fn enrolment_budgets(&self) -> EnrolmentBudgets {
        self.loaded.ceilings().enrolment_budgets()
    }

    /// Returns the profile that contributes to the middle rung, when one does.
    #[must_use]
    fn selected(&self) -> Option<(&str, &PreferenceSet)> {
        self.loaded
            .document
            .as_ref()
            .and_then(|document| document.profile(self.profile.as_deref()))
    }

    /// Assembles the ladder for one preference.
    ///
    /// The only place in this crate that says what each rung is made of. Every accessor below
    /// passes its own request value and its own field, and the order is
    /// [`kr_protocol::hostinfo::configuration::resolve`]'s alone.
    fn layers<T: Clone>(
        &self,
        requested: Option<T>,
        pick: impl Fn(&PreferenceSet) -> Option<T>,
        default: T,
    ) -> Layers<T> {
        Layers {
            request: requested.map(Offered::plain),
            profile: self
                .selected()
                .and_then(|(name, set)| pick(set).map(|value| Offered::from(value, name))),
            host: self
                .loaded
                .preferences()
                .and_then(&pick)
                .map(|value| Offered::from(value, self.document.display().to_string())),
            default,
        }
    }

    /// Resolves this host's sleep policy.
    #[must_use]
    pub fn sleep_inhibition(
        &self,
        requested: Option<SleepInhibitionSetting>,
    ) -> Effective<SleepInhibitionSetting> {
        configuration::resolve(
            configuration::SLEEP_INHIBITION,
            self.layers(
                requested,
                |set| set.sleep_inhibition.0,
                SleepInhibitionSetting::Off,
            ),
        )
    }

    /// Returns the execution context this configuration chooses, when it chooses one.
    ///
    /// The three rungs above the product default, without it: a caller that has to establish the
    /// platform's own answer first needs to know whether the configuration will override it
    /// before it spends anything finding out. It is the same ladder in the same order, which is
    /// why it is here and not assembled at a call site.
    #[must_use]
    pub fn chosen_worker_profile(&self) -> Option<WorkerProfile> {
        self.selected()
            .and_then(|(_, set)| set.worker_profile.0)
            .or_else(|| {
                self.loaded
                    .preferences()
                    .and_then(|set| set.worker_profile.0)
            })
    }

    /// Resolves the execution context a session is created in.
    ///
    /// The product default is what the platform establishes rather than a constant, so the caller
    /// supplies it: a desktop host and an SSH-only installation have different bottom rungs.
    #[must_use]
    pub fn worker_profile(
        &self,
        requested: Option<WorkerProfile>,
        platform_default: WorkerProfile,
    ) -> Effective<WorkerProfile> {
        configuration::resolve(
            configuration::WORKER_PROFILE,
            self.layers(requested, |set| set.worker_profile.0, platform_default),
        )
    }

    /// Resolves the runtime tree this installation uses.
    ///
    /// The allowlisted variable acts at the request rung, which is where
    /// [`kr_protocol::hostinfo::configuration::ALLOWLIST`] declares it: the document that would
    /// otherwise carry the value lives inside the tree the variable selects, so nothing in the
    /// document can name it.
    #[must_use]
    pub fn runtime_directory(&self) -> Effective<String> {
        self.directory(
            configuration::RUNTIME_DIRECTORY,
            kr_ipc::paths::RUNTIME_DIR_VARIABLE,
            &self.runtime_directory,
        )
    }

    /// Resolves the state tree this installation uses.
    #[must_use]
    pub fn state_directory(&self) -> Effective<String> {
        self.directory(
            configuration::STATE_DIRECTORY,
            kr_ipc::paths::STATE_DIR_VARIABLE,
            &self.state_directory,
        )
    }

    /// Resolves one directory through the same ladder, with its allowlisted variable at the rung
    /// the allowlist declares.
    fn directory(
        &self,
        preference: Preference,
        variable: &'static str,
        resolved: &Path,
    ) -> Effective<String> {
        let value = resolved.display().to_string();
        let supplied = configuration::allowlisted(variable)
            .filter(|_| std::env::var_os(variable).is_some())
            .map(|_| Offered::from_variable(value.clone(), variable));
        configuration::resolve(
            preference,
            Layers {
                request: supplied,
                profile: None,
                host: None,
                default: value,
            },
        )
    }

    /// Returns the documented environment overrides and whether this host has each one set.
    #[must_use]
    pub fn overrides(&self) -> Vec<OverrideReport> {
        configuration::ALLOWLIST
            .iter()
            .map(|entry| OverrideReport {
                variable: entry.variable.to_owned(),
                preference: entry.preference.to_owned(),
                position: entry.position,
                why: entry.why.to_owned(),
                set: std::env::var_os(entry.variable).is_some(),
            })
            .collect()
    }
}

/// Renders one resolved preference for the effective-value report.
///
/// One function, so a value's source and its effect are reported the same way wherever the value
/// came from. `rendered` carries what the value is made of with it: a preference this build
/// resolves to one of its own words is not the same thing as one that resolves to a directory
/// somebody named, and the two are decided together rather than declared separately.
pub fn effective_value<T>(
    effective: &Effective<T>,
    rendered: &kr_protocol::hostinfo::export::Declared,
) -> EffectiveValue {
    EffectiveValue::new(
        effective.preference.key,
        effective.preference.about,
        rendered,
        effective.source,
        Nullable(effective.origin.clone()),
        Nullable(effective.variable.map(str::to_owned)),
        effective.preference.effect,
    )
}

#[cfg(test)]
mod tests;
