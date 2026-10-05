//! What new bindings may use, and what each release a live binding holds is now.
//!
//! Admission is decided here, from the catalogue's current records and nothing a caller supplies:
//! an installation is admitted when it is enabled, its package is complete in the store, its own
//! manifest supports this host's operating system and architecture, and the current generation of
//! the enrolment it came through has not revoked its exact package hash. What it may do is its
//! effective grants, and which executables its release is qualified against is what that same
//! generation's entry names for this host.
//!
//! A live binding may hold a release no installation describes any more: the installation moved
//! to a newer release, or to another repository, or was removed. Each such release keeps its own
//! state: its revocation is read from the current generation of the enrolment it came through, so
//! a revocation published after an upgrade still reaches it, and what it may do is the grant cap
//! recorded when the installation left it, which later grant changes only ever narrow.
//!
//! The catalogue records no binding. The workers' own records are the one account of what is
//! bound; a worker reports its live releases, and those reports are what [`Admissions::releases`]
//! answers for.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use kr_plugin_sdk::capability::PluginCapability;
use kr_plugin_sdk::catalogue::{CatalogueIndex, IndexEntry, QualifiedBuild, RevocationRecord};
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::ids::{PluginId, PublisherId};
use kr_plugin_sdk::matching::PlatformSupport;
use kr_plugin_sdk::plugin::PayloadRole;
use kr_plugin_sdk::version::PackageVersion;
use kr_protocol::ids::EnvironmentId;

use crate::budget::{PackageLimits, ResourceLimit};
use crate::ceiling;
use crate::db::{Enrolled, Records, RetiredRelease};
use crate::error::CatalogueResult;
use crate::install::{DisablePolicy, Installation};
use crate::platform::{HostPlatform, Unsupported};
use crate::repository::{EnrolmentKey, RepositoryId};
use crate::store::{PackageCheck, Store};

/// The directory under the catalogue's own that holds every repository's store, which a
/// component's path is named relative to.
pub const PACKAGES_ROOT: &str = "repositories";

/// Where a release came from: the repository's name and the enrolment it came through.
///
/// A repository's name can be removed and enrolled again under another root, so the enrolment key
/// is what says whose generations speak for the release.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReleaseOrigin {
    /// The repository's name.
    pub repository_id: RepositoryId,
    /// The enrolment the release came through.
    pub enrolment_key: EnrolmentKey,
}

impl ReleaseOrigin {
    /// Returns where an installation's release came from.
    #[must_use]
    pub fn of(installation: &Installation) -> Self {
        Self {
            repository_id: installation.repository.clone(),
            enrolment_key: installation.enrolment.clone(),
        }
    }
}

/// One release a live binding holds, as a worker reports it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LiveRelease {
    /// The package.
    pub plugin_id: PluginId,
    /// Its publisher.
    pub publisher_id: PublisherId,
    /// The release's version.
    pub version: PackageVersion,
    /// The exact package hash the binding holds.
    pub package_digest: PayloadDigest,
    /// Where the release came from.
    pub origin: ReleaseOrigin,
}

impl LiveRelease {
    /// The key a release's state is found by: the package, its hash and where it came from.
    #[must_use]
    pub fn key(&self) -> (PluginId, PayloadDigest, ReleaseOrigin) {
        (
            self.plugin_id.clone(),
            self.package_digest,
            self.origin.clone(),
        )
    }
}

/// A package's component, by its path relative to [`PACKAGES_ROOT`], its digest and its size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedComponent {
    /// The component's path below the directory that holds every repository's store, with `/`
    /// between its parts.
    pub path: String,
    /// The component's digest.
    pub digest: PayloadDigest,
    /// Its exact size.
    pub bytes: u64,
}

/// One package new bindings may use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedPackage {
    /// The package.
    pub plugin_id: PluginId,
    /// Its publisher.
    pub publisher_id: PublisherId,
    /// The installed release.
    pub version: PackageVersion,
    /// The exact installed package hash.
    pub package_digest: PayloadDigest,
    /// Where it came from.
    pub origin: ReleaseOrigin,
    /// The directory its checked, extracted copy is in.
    pub package_dir: PathBuf,
    /// What the installation may use: its effective grants.
    pub grants: BTreeSet<PluginCapability>,
    /// The builds the current generation's entry names for this host's platform.
    pub builds: Vec<QualifiedBuild>,
    /// Its component, where it ships one.
    pub component: Option<AdmittedComponent>,
}

impl AdmittedPackage {
    /// Returns the release this package is.
    #[must_use]
    pub fn release(&self) -> LiveRelease {
        LiveRelease {
            plugin_id: self.plugin_id.clone(),
            publisher_id: self.publisher_id.clone(),
            version: self.version.clone(),
            package_digest: self.package_digest,
            origin: self.origin.clone(),
        }
    }
}

/// What one release a binding may hold is now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseState {
    /// The package.
    pub plugin_id: PluginId,
    /// The exact package hash.
    pub package_digest: PayloadDigest,
    /// Where it came from.
    pub origin: ReleaseOrigin,
    /// The revocation the current generation of its origin publishes for it, where one does.
    pub revocation: Option<RevocationRecord>,
    /// The most a binding on it may use now.
    pub grant_cap: BTreeSet<PluginCapability>,
    /// Whether a binding on it ends at its next admission boundary: its package is disabled or
    /// removed in this environment, or the organisation's allowlist does not name it.
    pub ends_at_next_boundary: bool,
}

/// Why an installation is not admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotAdmittedReason {
    /// It is installed and disabled.
    Disabled,
    /// The current generation of its origin revoked its exact package hash.
    Revoked(RevocationRecord),
    /// The organisation's allowlist does not name its package.
    NotAllowed,
    /// Its manifest does not support this host.
    Unsupported {
        /// What it does not support.
        what: Unsupported,
        /// This host's platform, named for a person.
        host: String,
        /// The platforms the package's own manifest lists, which are what the decision was made
        /// from, so the reason can say what the release does support.
        supported: Vec<PlatformSupport>,
    },
    /// Its package is not whole in the store.
    Incomplete(String),
    /// Its package is past one of the package limits in force, which this names.
    PastALimit(ResourceLimit),
}

/// Names the platforms a manifest lists, as the sentence that says what a release supports reads
/// them: each operating system once, with its architectures once each, in the order the manifest
/// first lists them, `linux (x86_64, aarch64); mac_os (aarch64)`.
///
/// A manifest may list an operating system twice or list one with no architecture, and the
/// sentence goes whole into an answer a host sizes, so what it names is bounded by the two closed
/// lists and not by what the manifest repeats.
fn describe(platforms: &[PlatformSupport]) -> String {
    let mut named: Vec<(&str, Vec<&str>)> = Vec::new();
    for platform in platforms {
        let os = platform.os.as_str();
        let at = named
            .iter()
            .position(|(seen, _)| *seen == os)
            .unwrap_or_else(|| {
                named.push((os, Vec::new()));
                named.len() - 1
            });
        for architecture in &platform.architectures {
            let architecture = architecture.as_str();
            if !named[at].1.contains(&architecture) {
                named[at].1.push(architecture);
            }
        }
    }
    if named.is_empty() {
        return "no platform".to_owned();
    }
    named
        .iter()
        .map(|(os, architectures)| {
            if architectures.is_empty() {
                format!("{os} (no architecture)")
            } else {
                format!("{os} ({})", architectures.join(", "))
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// One installation that is not admitted, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotAdmitted {
    /// The package.
    pub plugin_id: PluginId,
    /// The installed package hash.
    pub package_digest: PayloadDigest,
    /// Why.
    pub reason: NotAdmittedReason,
}

impl NotAdmitted {
    /// Says why, for a person.
    #[must_use]
    pub fn detail(&self) -> String {
        let subject = format!("{} at {}", self.plugin_id, self.package_digest);
        match &self.reason {
            NotAdmittedReason::Disabled => format!("{subject} is installed and disabled"),
            NotAdmittedReason::NotAllowed => {
                format!("{subject} is not among the adapters this organisation allows")
            }
            NotAdmittedReason::Revoked(record) => format!(
                "{subject} was revoked by its repository: {}",
                record.statement.as_str()
            ),
            NotAdmittedReason::Unsupported {
                what,
                host,
                supported,
            } => {
                let offered = describe(supported);
                match what {
                    Unsupported::OperatingSystem => format!(
                        "{subject} does not support this host's operating system ({host}); it \
                         supports {offered}"
                    ),
                    Unsupported::Architecture => format!(
                        "{subject} does not support this host's architecture ({host}); it \
                         supports {offered}"
                    ),
                }
            }
            NotAdmittedReason::Incomplete(detail) => {
                format!("{subject} is not whole in this host's store: {detail}")
            }
            NotAdmittedReason::PastALimit(limit) => {
                format!("{subject} is past a package limit in force: {limit}")
            }
        }
    }
}

/// The admissions of one environment at one admission revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admissions {
    /// The admission revision these were computed at.
    pub revision: u64,
    /// The administrator's disable policy, which says what a revocation does to a live binding.
    pub policy: DisablePolicy,
    /// What new bindings may use.
    pub packages: Vec<AdmittedPackage>,
    /// The state of every admitted release and of every release reported live.
    pub releases: Vec<ReleaseState>,
    /// Every installation left out of `packages`, and why.
    pub not_admitted: Vec<NotAdmitted>,
}

/// The first part of an admission computation: everything the records and the current indexes
/// say, read while the caller holds the catalogue.
///
/// What is left, each package's check, reads only a package's own copy, which its hash names and
/// nothing rewrites, so [`AdmissionPlan::complete`] runs it without the catalogue: a package whose
/// files are slow to read holds that computation and no other catalogue work.
#[derive(Clone, Debug)]
pub struct AdmissionPlan {
    root: PathBuf,
    host: HostPlatform,
    /// The package limits in force when the records were read, which every package check holds
    /// its package to.
    limits: PackageLimits,
    revision: u64,
    policy: DisablePolicy,
    pending: Vec<Pending>,
    not_admitted: Vec<NotAdmitted>,
    releases: Vec<ReleaseState>,
}

/// One installation the records admit, waiting for its package check.
#[derive(Clone, Debug)]
struct Pending {
    installation: Installation,
    origin: ReleaseOrigin,
    grants: BTreeSet<PluginCapability>,
    builds: Vec<QualifiedBuild>,
}

impl AdmissionPlan {
    /// Returns the admission revision the records were read at.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the state of every installed release and of every release reported live, which
    /// the records alone decide.
    #[must_use]
    pub fn releases(&self) -> &[ReleaseState] {
        &self.releases
    }

    /// Returns each package the records admit, waiting for its package check.
    pub fn pending(&self) -> impl Iterator<Item = (&PluginId, PayloadDigest)> {
        self.pending.iter().map(|pending| {
            (
                &pending.installation.plugin_id,
                pending.installation.package_digest,
            )
        })
    }

    /// Checks each admitted package's copy and completes the admissions.
    ///
    /// # Errors
    ///
    /// Returns [`crate::CatalogueError::StorageUnavailable`] when a package cannot be read.
    pub fn complete(self) -> CatalogueResult<Admissions> {
        let mut packages = Vec::new();
        let mut not_admitted = self.not_admitted;
        for Pending {
            installation,
            origin,
            grants,
            builds,
        } in self.pending
        {
            let refuse = |reason| NotAdmitted {
                plugin_id: installation.plugin_id.clone(),
                package_digest: installation.package_digest,
                reason,
            };
            // Platforms and the component are the package's own, read from the manifest its hash
            // names in its checked copy, never from an index entry.
            let store = Store::at(&self.root, &installation.enrolment);
            let package = match store.check_package(installation.package_digest, self.limits)? {
                PackageCheck::Complete(package) => package,
                PackageCheck::PastALimit(limit) => {
                    not_admitted.push(refuse(NotAdmittedReason::PastALimit(limit)));
                    continue;
                }
                PackageCheck::Missing { detail } | PackageCheck::Corrupt { detail } => {
                    not_admitted.push(refuse(NotAdmittedReason::Incomplete(detail)));
                    continue;
                }
            };
            let manifest = package.manifest();
            if let Err(what) = self.host.check(&manifest.platforms) {
                not_admitted.push(refuse(NotAdmittedReason::Unsupported {
                    what,
                    host: self.host.name(),
                    supported: manifest.platforms.clone(),
                }));
                continue;
            }
            let component =
                manifest
                    .payload(PayloadRole::Component)
                    .map(|payload| AdmittedComponent {
                        path: format!(
                            "{}/packages/{}/{}",
                            installation.enrolment.as_str(),
                            installation.package_digest,
                            payload.path.as_str()
                        ),
                        digest: payload.digest,
                        bytes: payload.size_bytes.get(),
                    });
            packages.push(AdmittedPackage {
                plugin_id: installation.plugin_id.clone(),
                publisher_id: installation.publisher_id.clone(),
                version: installation.version.clone(),
                package_digest: installation.package_digest,
                origin,
                package_dir: store.package_dir(installation.package_digest),
                grants,
                builds,
                component,
            });
        }
        Ok(Admissions {
            revision: self.revision,
            policy: self.policy,
            packages,
            releases: self.releases,
            not_admitted,
        })
    }
}

/// Says why an installation is left out by its standing alone, before anything about its package
/// is read: it is disabled, its release is revoked, or the organisation's allowlist does not name
/// it. `None` where it stands.
///
/// This is the one place that decides it, for the admissions and for everything else that acts on
/// an installation in an application's name (a native bridge), so no second reading of "may this
/// run" can disagree. A revocation is what a person can act on, so it is what an installation the
/// allowlist also leaves out is reported as.
pub(crate) fn left_out_by_standing(
    installation: &Installation,
    revocation: Option<RevocationRecord>,
    allowed: Option<&BTreeSet<PluginId>>,
) -> Option<NotAdmittedReason> {
    if !installation.enabled {
        return Some(NotAdmittedReason::Disabled);
    }
    if let Some(record) = revocation {
        return Some(NotAdmittedReason::Revoked(record));
    }
    if allowed.is_some_and(|allowed| !allowed.contains(&installation.plugin_id)) {
        return Some(NotAdmittedReason::NotAllowed);
    }
    None
}

/// Reads what the records and the current indexes say about one environment's admissions.
///
/// # Errors
///
/// Returns [`crate::CatalogueError::StorageUnavailable`] when a record or an index cannot be read,
/// and [`crate::CatalogueError::Integrity`] when an index is not the one its generation names.
pub(crate) fn plan(
    root: &Path,
    records: &Records<'_>,
    environment_id: EnvironmentId,
    live: &[LiveRelease],
    host: &HostPlatform,
    limits: PackageLimits,
    allowed: Option<&BTreeSet<PluginId>>,
) -> CatalogueResult<AdmissionPlan> {
    let permitted =
        |plugin_id: &PluginId| allowed.is_none_or(|allowed| allowed.contains(plugin_id));
    let revision = records.admission_revision()?;
    let policy = records.disable_policy()?;
    let installations: Vec<Installation> = records
        .installations()?
        .into_iter()
        .filter(|installation| installation.environment_id == environment_id)
        .collect();
    let retired: BTreeMap<(PluginId, PayloadDigest, ReleaseOrigin), RetiredRelease> = records
        .retired_releases(environment_id)?
        .into_iter()
        .map(|row| (row.key(), row))
        .collect();
    let mut indexes = Indexes::new(root);

    let mut pending = Vec::new();
    let mut not_admitted = Vec::new();
    let mut states: BTreeMap<(PluginId, PayloadDigest, ReleaseOrigin), ReleaseState> =
        BTreeMap::new();
    for installation in &installations {
        let origin = ReleaseOrigin::of(installation);
        let entry = indexes.entry(
            records,
            &installation.enrolment,
            &installation.plugin_id,
            installation.package_digest,
        )?;
        let revocation = entry.as_ref().and_then(|entry| entry.revocation.0.clone());
        let grants = ceiling::effective(
            &installation.requested,
            &installation.ceiling,
            &installation.grant,
        );
        states.insert(
            (
                installation.plugin_id.clone(),
                installation.package_digest,
                origin.clone(),
            ),
            ReleaseState {
                plugin_id: installation.plugin_id.clone(),
                package_digest: installation.package_digest,
                origin: origin.clone(),
                revocation: revocation.clone(),
                grant_cap: grants.clone(),
                ends_at_next_boundary: !installation.enabled || !permitted(&installation.plugin_id),
            },
        );
        let refuse = |reason| NotAdmitted {
            plugin_id: installation.plugin_id.clone(),
            package_digest: installation.package_digest,
            reason,
        };
        if let Some(reason) = left_out_by_standing(installation, revocation, allowed) {
            not_admitted.push(refuse(reason));
            continue;
        }
        let builds = match (entry.as_ref(), host.os, host.architecture) {
            (Some(entry), Some(os), Some(architecture)) => {
                entry.builds_for(os, architecture).cloned().collect()
            }
            _ => Vec::new(),
        };
        pending.push(Pending {
            installation: installation.clone(),
            origin,
            grants,
            builds,
        });
    }

    // Every release reported live that no installation describes: an upgrade, a move or a
    // removal left it, and its state comes from where it came from and from the cap recorded when
    // it was left.
    for release in live {
        let key = release.key();
        if states.contains_key(&key) {
            continue;
        }
        let installed = installations
            .iter()
            .find(|installation| installation.plugin_id == release.plugin_id);
        let revocation = indexes
            .entry(
                records,
                &release.origin.enrolment_key,
                &release.plugin_id,
                release.package_digest,
            )?
            .and_then(|entry| entry.revocation.0);
        let grant_cap = retired
            .get(&key)
            .map(|row| row.cap.clone())
            .unwrap_or_default();
        states.insert(
            key,
            ReleaseState {
                plugin_id: release.plugin_id.clone(),
                package_digest: release.package_digest,
                origin: release.origin.clone(),
                revocation,
                grant_cap,
                ends_at_next_boundary: !installed.is_some_and(|installation| installation.enabled)
                    || !permitted(&release.plugin_id),
            },
        );
    }
    Ok(AdmissionPlan {
        root: root.to_path_buf(),
        host: *host,
        limits,
        revision,
        policy,
        pending,
        not_admitted,
        releases: states.into_values().collect(),
    })
}

/// Returns the current generation's entry for one exact release of one enrolment.
///
/// A removed enrolment, or one with no generation, publishes nothing about the release; nor does a
/// generation whose index no longer carries it.
///
/// # Errors
///
/// Returns [`crate::CatalogueError::StorageUnavailable`] when the record or the index cannot be
/// read, and [`crate::CatalogueError::Integrity`] when the index is not the one its generation
/// names.
pub(crate) fn current_entry(
    root: &Path,
    records: &Records<'_>,
    key: &EnrolmentKey,
    plugin_id: &PluginId,
    package_digest: PayloadDigest,
) -> CatalogueResult<Option<IndexEntry>> {
    Indexes::new(root).entry(records, key, plugin_id, package_digest)
}

/// The current index of each enrolment one computation reads, each read once.
struct Indexes<'a> {
    root: &'a Path,
    read: BTreeMap<EnrolmentKey, Option<CatalogueIndex>>,
}

impl<'a> Indexes<'a> {
    fn new(root: &'a Path) -> Self {
        Self {
            root,
            read: BTreeMap::new(),
        }
    }

    fn entry(
        &mut self,
        records: &Records<'_>,
        key: &EnrolmentKey,
        plugin_id: &PluginId,
        package_digest: PayloadDigest,
    ) -> CatalogueResult<Option<IndexEntry>> {
        if !self.read.contains_key(key) {
            let index = match records.enrolment_by_key(key)? {
                Some(Enrolled {
                    key,
                    active: Some(active),
                    ..
                }) => Some(Store::at(self.root, &key).index(&active)?),
                _ => None,
            };
            self.read.insert(key.clone(), index);
        }
        Ok(self
            .read
            .get(key)
            .and_then(Option::as_ref)
            .and_then(|index| {
                index
                    .entries
                    .iter()
                    .find(|entry| {
                        &entry.plugin_id == plugin_id && entry.manifest_digest == package_digest
                    })
                    .cloned()
            }))
    }
}
