//! What the catalogue keeps across a restart.
//!
//! A daemon that forgot its enrolments on restart would ask the owner to adopt every root again,
//! and a daemon that forgot its installations would report nothing installed while the packages
//! were still on disk. Both are held in one document beside the repositories, written the same way
//! the index pointer is: to a temporary file, flushed, then renamed.
//!
//! The trust roots are not in that document. Each repository's root lives in its own directory,
//! under `root.json`, which is where a generation carries one and where the client reads it from.
//! Keeping them apart means a state file that cannot be read never puts a root in question.

use std::path::Path;

use kr_plugin_sdk::capability::PluginCapability;
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::ids::{PluginId, PluginName, PublisherId};
use kr_plugin_sdk::limits::RepositoryBudgets;
use kr_plugin_sdk::version::PackageVersion;
use kr_protocol::ids::{EnvironmentId, RepositoryGeneration};
use serde::{Deserialize, Serialize};

use crate::catalogue::ceiling::InstallationGrant;
use crate::catalogue::error::{CatalogueError, CatalogueResult};
use crate::catalogue::install::{DisablePolicy, Installation};
use crate::catalogue::repository::{CapabilityCeiling, Enrolment, RepositoryId, RepositoryKind};

/// The file the catalogue's own state is held in.
pub const STATE_FILE: &str = "state.json";

/// Returns the capability one wire name spells.
///
/// # Errors
///
/// Returns [`CatalogueError::InvalidArgument`] for a name outside the closed vocabulary.
pub fn capability_from_str(name: &str) -> CatalogueResult<PluginCapability> {
    PluginCapability::ALL
        .iter()
        .copied()
        .find(|capability| capability.as_str() == name)
        .ok_or_else(|| CatalogueError::InvalidArgument {
            detail: format!("{name} is not a capability a package may request"),
        })
}

/// One enrolment, as the state file holds it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct EnrolmentRecord {
    id: String,
    kind: String,
    metadata_url: String,
    targets_url: String,
    budgets: RepositoryBudgets,
    ceiling: Vec<String>,
    pinned_generation: Option<u64>,
}

/// One installation, as the state file holds it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct InstallationRecord {
    plugin_id: String,
    publisher_id: String,
    plugin_name: String,
    version: String,
    package_digest: String,
    repository: String,
    environment_id: EnvironmentId,
    enabled: bool,
    pinned: bool,
    grant: Vec<String>,
}

/// Everything the catalogue holds across a restart.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogueState {
    #[serde(default)]
    repositories: Vec<EnrolmentRecord>,
    #[serde(default)]
    installations: Vec<InstallationRecord>,
    #[serde(default)]
    disable_policy: Option<String>,
}

impl CatalogueState {
    /// Reads the state, returning an empty one where there is none yet.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when the document exists and cannot be read.
    pub fn read(root: &Path) -> CatalogueResult<Self> {
        let path = root.join(STATE_FILE);
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|source| {
                CatalogueError::StorageUnavailable {
                    detail: format!("{}: {source}", path.display()),
                }
            }),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(CatalogueError::storage(&path, &source)),
        }
    }

    /// Builds the state from what a catalogue currently holds.
    #[must_use]
    pub fn of(
        repositories: &[&Enrolment],
        installations: &[&Installation],
        disable_policy: DisablePolicy,
    ) -> Self {
        Self {
            repositories: repositories
                .iter()
                .map(|enrolment| EnrolmentRecord {
                    id: enrolment.id.to_string(),
                    kind: enrolment.kind.as_str().to_owned(),
                    metadata_url: enrolment.metadata_url.to_string(),
                    targets_url: enrolment.targets_url.to_string(),
                    budgets: enrolment.budgets,
                    ceiling: enrolment
                        .ceiling
                        .capabilities()
                        .into_iter()
                        .map(|capability| capability.as_str().to_owned())
                        .collect(),
                    pinned_generation: enrolment.pinned_generation.map(RepositoryGeneration::get),
                })
                .collect(),
            installations: installations
                .iter()
                .map(|installation| InstallationRecord {
                    plugin_id: installation.plugin_id.to_string(),
                    publisher_id: installation.publisher_id.to_string(),
                    plugin_name: installation.plugin_name.to_string(),
                    version: installation.version.to_string(),
                    package_digest: installation.package_digest.to_string(),
                    repository: installation.repository.to_string(),
                    environment_id: installation.environment_id,
                    enabled: installation.enabled,
                    pinned: installation.pinned,
                    grant: installation
                        .grant
                        .capabilities()
                        .into_iter()
                        .map(|capability| capability.as_str().to_owned())
                        .collect(),
                })
                .collect(),
            disable_policy: Some(disable_policy.as_str().to_owned()),
        }
    }

    /// Writes the state beside the repositories.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when it cannot be written.
    pub fn write(&self, root: &Path) -> CatalogueResult<()> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|source| {
            CatalogueError::StorageUnavailable {
                detail: format!("the catalogue state could not be rendered: {source}"),
            }
        })?;
        crate::catalogue::store::write_document(root, &root.join(STATE_FILE), &bytes)
    }

    /// Returns the administrator's disable policy.
    #[must_use]
    pub fn disable_policy(&self) -> DisablePolicy {
        match self.disable_policy.as_deref() {
            Some("disable_at_next_admission") => DisablePolicy::DisableAtNextAdmission,
            Some("disable_at_once") => DisablePolicy::DisableAtOnce,
            _ => DisablePolicy::WarnOnly,
        }
    }

    /// Rebuilds the enrolments, reading each repository's root from its own directory.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::StorageUnavailable`] when a root cannot be read, and
    /// [`CatalogueError::InvalidArgument`] when a record cannot be understood by this build.
    pub fn enrolments(&self, root: &Path) -> CatalogueResult<Vec<Enrolment>> {
        let mut enrolments = Vec::with_capacity(self.repositories.len());
        for record in &self.repositories {
            let id = RepositoryId::new(record.id.clone())?;
            let store = crate::catalogue::store::Store::open(root, &id)?;
            let bytes = store.read_root()?;
            let kind = match record.kind.as_str() {
                "official" => RepositoryKind::Official,
                "vendor" => RepositoryKind::Vendor,
                "community" => RepositoryKind::Community,
                "local" => RepositoryKind::Local,
                "mirror" => RepositoryKind::Mirror,
                other => {
                    return Err(CatalogueError::InvalidArgument {
                        detail: format!("{other} is not a kind of repository this build knows"),
                    });
                }
            };
            let mut ceiling = Vec::new();
            for name in &record.ceiling {
                ceiling.push(capability_from_str(name)?);
            }
            let mut enrolment = Enrolment::new(
                id,
                kind,
                parse_url(&record.metadata_url)?,
                parse_url(&record.targets_url)?,
                bytes,
                record.budgets,
                CapabilityCeiling::with(ceiling),
            )?;
            enrolment.pinned_generation = record.pinned_generation.map(RepositoryGeneration::new);
            enrolments.push(enrolment);
        }
        Ok(enrolments)
    }

    /// Rebuilds the installations.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::InvalidArgument`] when a record cannot be understood by this
    /// build.
    pub fn installed(&self) -> CatalogueResult<Vec<Installation>> {
        let mut installations = Vec::with_capacity(self.installations.len());
        for record in &self.installations {
            let mut grant = InstallationGrant::none();
            for name in &record.grant {
                grant.add(capability_from_str(name)?);
            }
            installations.push(Installation {
                plugin_id: PluginId::new(record.plugin_id.clone()).map_err(invalid)?,
                publisher_id: PublisherId::new(record.publisher_id.clone()).map_err(invalid)?,
                plugin_name: PluginName::new(record.plugin_name.clone()).map_err(invalid)?,
                version: PackageVersion::parse(&record.version).map_err(invalid)?,
                package_digest: PayloadDigest::parse(&record.package_digest).map_err(invalid)?,
                repository: RepositoryId::new(record.repository.clone())?,
                environment_id: record.environment_id,
                enabled: record.enabled,
                pinned: record.pinned,
                grant,
            });
        }
        Ok(installations)
    }
}

fn invalid(source: impl core::fmt::Display) -> CatalogueError {
    CatalogueError::InvalidArgument {
        detail: format!("the catalogue state holds a record this build cannot read: {source}"),
    }
}

fn parse_url(text: &str) -> CatalogueResult<url::Url> {
    url::Url::parse(text).map_err(|source| CatalogueError::InvalidArgument {
        detail: format!("{text} is not a repository location: {source}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_capability_round_trips_through_its_wire_name() {
        for capability in PluginCapability::ALL {
            assert_eq!(
                capability_from_str(capability.as_str()).expect("a known capability"),
                *capability
            );
        }
        assert!(capability_from_str("filesystem.write").is_err());
    }

    #[test]
    fn an_absent_state_reads_as_an_empty_one() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let state = CatalogueState::read(directory.path()).expect("readable");
        assert_eq!(state, CatalogueState::default());
        assert_eq!(state.disable_policy(), DisablePolicy::WarnOnly);
        assert!(
            state
                .enrolments(directory.path())
                .expect("readable")
                .is_empty()
        );
        assert!(state.installed().expect("readable").is_empty());
    }
}
