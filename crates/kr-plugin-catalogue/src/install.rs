//! Installed packages, and what a reclaim keeps for them.
//!
//! Downloading the whole catalogue does not install anything, and installing something does not
//! activate it. Three separate facts decide whether a package runs against an application:
//!
//! * it is **installed** in this environment, at one exact package hash;
//! * it is **enabled** there, which is a separate decision from installing it;
//! * its rules **recognise** what is running, which the worker's binder decides with the rule the
//!   SDK states.
//!
//! The catalogue admits (see [`crate::admission`]) and records no binding: a worker binds what the
//! catalogue admitted and keeps the record of it in its own ledger. A binding stays on the hash it
//! was made against, because a running process was qualified against the bytes it bound to and
//! not against the bytes that arrived afterwards.
//!
//! Revocation is the other asymmetry. A revoked release stops receiving new bindings immediately.
//! An active binding is not torn down under a request that is already running: it warns, and it
//! follows the administrator's explicit disable policy at the point that policy names.

use kr_plugin_sdk::capability::{CapabilityRequest, PluginCapability};
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::ids::{PluginId, PluginName, PublisherId};
use kr_plugin_sdk::version::PackageVersion;
use kr_protocol::ids::EnvironmentId;

use crate::ceiling::InstallationGrant;
use crate::error::{CatalogueError, CatalogueResult};
use crate::repository::{CapabilityCeiling, EnrolmentKey, RepositoryId};
use crate::store::{HeldPackage, ReadyPackage};

/// What an administrator has said should happen to a live binding whose package is revoked.
///
/// The default warns and leaves the binding alone. Nothing here changes a binding while a request
/// is being served: the policy decides what happens at the point it names, and "immediately" means
/// at the next admission rather than inside somebody's half-finished call.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DisablePolicy {
    /// Warn and keep serving. The person decides what to do.
    #[default]
    WarnOnly,
    /// Keep the live binding and refuse to admit anything new through it.
    DisableAtNextAdmission,
    /// Disable the binding at the next admission boundary.
    DisableAtOnce,
}

impl DisablePolicy {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WarnOnly => "warn_only",
            Self::DisableAtNextAdmission => "disable_at_next_admission",
            Self::DisableAtOnce => "disable_at_once",
        }
    }

    /// Reads the stable wire string back.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        [
            Self::WarnOnly,
            Self::DisableAtNextAdmission,
            Self::DisableAtOnce,
        ]
        .into_iter()
        .find(|policy| policy.as_str() == text)
    }
}

/// One installed package in one environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Installation {
    /// The package.
    pub plugin_id: PluginId,
    /// Its publisher.
    pub publisher_id: PublisherId,
    /// Its name under that publisher.
    pub plugin_name: PluginName,
    /// The installed release.
    pub version: PackageVersion,
    /// The exact package hash installed: the manifest digest, which covers every other file.
    pub package_digest: PayloadDigest,
    /// The enrolment it was installed through, which is where its files live.
    ///
    /// The repository's name can be removed and enrolled again under another root. The key names
    /// the enrolment this package actually came through, so a later enrolment under the same name
    /// never inherits it.
    pub enrolment: EnrolmentKey,
    /// The name the repository it came from had.
    pub repository: RepositoryId,
    /// The environment it is installed in.
    pub environment_id: EnvironmentId,
    /// Whether it is enabled here.
    pub enabled: bool,
    /// Whether the owner pinned this exact hash.
    pub pinned: bool,
    /// What it has been permitted beyond its repository's ceiling.
    pub grant: InstallationGrant,
    /// What the installed package asks to be permitted, as its manifest declared it.
    ///
    /// Recorded here rather than read from the index on demand. An installed package is usable
    /// offline, and a repository that moved on must not turn "what may this do?" into a question
    /// this host cannot answer.
    pub requested: Vec<CapabilityRequest>,
    /// Every payload the installed package consists of, by content hash.
    ///
    /// The package hash names the manifest. A cache that protected only that would leave the
    /// component and the assets a live binding runs on evictable.
    pub payloads: Vec<PayloadDigest>,
    /// The repository ceiling this package was installed under.
    ///
    /// Held here for the same reason `requested` is. An installed package stays usable when its
    /// repository is removed, and "what may this do?" is answered from what the package asked for
    /// and what its repository permitted at the time, neither of which a later enrolment can move.
    pub ceiling: CapabilityCeiling,
}

impl Installation {
    /// Builds an installation record from the package this host checked.
    ///
    /// What the package is and asks for is read from its own manifest, which the package hash
    /// names, and never from an index entry: a later index can say something else about the same
    /// hash, and what is installed must not move with it.
    #[must_use]
    pub fn from_package(
        package: &ReadyPackage,
        enrolment: EnrolmentKey,
        repository: RepositoryId,
        environment_id: EnvironmentId,
        grant: InstallationGrant,
        ceiling: CapabilityCeiling,
    ) -> Self {
        let manifest = package.manifest();
        Self {
            plugin_id: manifest.plugin_id(),
            publisher_id: manifest.publisher_id.clone(),
            plugin_name: manifest.plugin_name.clone(),
            version: manifest.version.clone(),
            package_digest: package.digest(),
            enrolment,
            repository,
            environment_id,
            enabled: false,
            pinned: false,
            grant,
            requested: manifest.capabilities.clone(),
            payloads: manifest
                .payloads
                .iter()
                .map(|payload| payload.digest)
                .collect(),
            ceiling,
        }
    }

    /// Returns the first capability a grant of `proposed` would add to this installation, where
    /// the capability is one whose statement an owner is shown only when the release is installed
    /// with a grant.
    ///
    /// A native bridge runs under the application's own permissions, outside the plugin sandbox,
    /// and a command integration changes how the application starts. The owner is shown the
    /// publisher's statement of the bridge, or the host's reading of the integration, and the
    /// host's notice of it when the release is installed with a grant. A grant that only changes
    /// an installation later shows neither. So for a release that asks for a bridge it only
    /// narrows, and for a release that asks for a command integration it never adds that
    /// capability: adding is the install's.
    #[must_use]
    pub fn widening_for_a_statement(
        &self,
        proposed: &InstallationGrant,
    ) -> Option<PluginCapability> {
        let asks = |capability| {
            self.requested
                .iter()
                .any(|request| request.capability == capability)
        };
        let added = self.grant.increase_over(proposed);
        if asks(PluginCapability::NativeBridgeInstall) {
            return added.first().copied();
        }
        if asks(PluginCapability::CommandIntegrationLaunch) {
            return added
                .into_iter()
                .find(|capability| *capability == PluginCapability::CommandIntegrationLaunch);
        }
        None
    }

    /// What a refused later grant says to do instead, for the capability `added`.
    #[must_use]
    pub fn install_requirement(&self, added: PluginCapability) -> String {
        format!(
            "plugin.install of the installed release: {} asks for {added}, so a grant that adds to \
             what it holds is made when the owner confirms the release, which shows the statement \
             of what it does and the host's notice of it",
            self.plugin_id
        )
    }

    /// Returns whether the installation is pinned once a pin naming `package_digest` is applied.
    ///
    /// `None` unpins. A pin names the hash that is installed; a pin naming another hash is refused
    /// rather than applied to whatever is installed now.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::InvalidArgument`] when the pin names another hash.
    pub fn pinned_to(&self, package_digest: Option<PayloadDigest>) -> CatalogueResult<bool> {
        match package_digest {
            Some(digest) if digest != self.package_digest => Err(CatalogueError::InvalidArgument {
                detail: format!(
                    "{} is installed at {} and the pin names {digest}; pinning operates on the \
                     hash that is installed",
                    self.plugin_id, self.package_digest
                ),
            }),
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }
}

/// Returns every payload a reclaim must keep.
///
/// That is every installed package, enabled or disabled, pinned or not, every package a worker
/// reports live, and every file each of them consists of: a package's hash names its manifest, and
/// protecting only that would leave the component and the assets a binding runs on evictable. What
/// a package consists of is read from the installation that holds it, or else from what the store
/// holds of it, through `held`. A live package the store holds nothing of is another store's, and
/// nothing here is its to lose. A live package the store holds and cannot expand is not protected
/// by guesswork: the answer is a refusal, and nothing is reclaimed.
///
/// # Errors
///
/// Returns [`CatalogueError::StorageUnavailable`] when a live package's files cannot be named, and
/// whatever `held` returns.
pub fn protected_payloads(
    installations: &[Installation],
    live: &[PayloadDigest],
    held: impl Fn(PayloadDigest) -> CatalogueResult<HeldPackage>,
) -> CatalogueResult<Vec<PayloadDigest>> {
    let mut packages: Vec<PayloadDigest> = live.to_vec();
    packages.extend(
        installations
            .iter()
            .map(|installation| installation.package_digest),
    );
    packages.sort_unstable();
    packages.dedup();
    let mut protected: Vec<PayloadDigest> = Vec::new();
    for package in packages {
        protected.push(package);
        let mut named = false;
        for installation in installations
            .iter()
            .filter(|installation| installation.package_digest == package)
        {
            protected.extend(installation.payloads.iter().copied());
            named = true;
        }
        if !named {
            match held(package)? {
                HeldPackage::Absent => {}
                HeldPackage::Named(payloads) => protected.extend(payloads),
                HeldPackage::Unnamed => {
                    return Err(CatalogueError::StorageUnavailable {
                        detail: format!(
                            "{package} is live and this host cannot name the files it consists \
                             of; nothing is reclaimed without knowing what a live package needs"
                        ),
                    });
                }
            }
        }
    }
    protected.sort_unstable();
    protected.dedup();
    Ok(protected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_plugin_sdk::catalogue::IndexEntry;
    use kr_plugin_sdk::example::example_manifest;
    use kr_protocol::scalars::Uuid;

    fn environment() -> EnvironmentId {
        EnvironmentId::new(Uuid::NIL)
    }

    fn entry(version: &str) -> IndexEntry {
        let mut manifest = example_manifest();
        manifest.version = PackageVersion::parse(version).expect("a valid version");
        IndexEntry::from_manifest(&manifest, PayloadDigest::of(version.as_bytes()), 4_096)
    }

    fn installation(entry: &IndexEntry, enabled: bool) -> Installation {
        let mut manifest = example_manifest();
        manifest.version = entry.version.clone();
        let mut installation = Installation::from_package(
            &crate::store::ReadyPackage::unchecked(entry.manifest_digest, manifest),
            EnrolmentKey::generate().expect("a key"),
            RepositoryId::new("official").expect("a valid identifier"),
            environment(),
            InstallationGrant::none(),
            CapabilityCeiling::default_ceiling(),
        );
        installation.enabled = enabled;
        installation
    }

    #[test]
    fn a_pin_names_the_hash_that_is_installed() {
        let first = entry("0.1.0");
        let installed = installation(&first, true);
        assert!(
            installed
                .pinned_to(Some(first.manifest_digest))
                .expect("the installed hash")
        );
        assert!(!installed.pinned_to(None).expect("an unpin"));
        let wrong = installed.pinned_to(Some(PayloadDigest::of(b"another")));
        assert!(matches!(wrong, Err(CatalogueError::InvalidArgument { .. })));
    }

    #[test]
    fn every_installed_or_live_package_is_protected_with_all_its_files() {
        let entry = entry("0.1.0");
        let installed = installation(&entry, false);
        let nothing =
            |_: PayloadDigest| -> CatalogueResult<HeldPackage> { Ok(HeldPackage::Absent) };

        // An installation is protected whether or not it is enabled, pinned or bound.
        let protected =
            protected_payloads(std::slice::from_ref(&installed), &[], nothing).expect("named");
        assert!(protected.contains(&entry.manifest_digest));
        for payload in &installed.payloads {
            assert!(
                protected.contains(payload),
                "every file of an installed package"
            );
        }

        // A package a worker reports live, which no installation holds any more, is expanded
        // from its own manifest where it is activated here.
        let upgraded_from = PayloadDigest::of(b"the release an upgrade replaced");
        let its_file = PayloadDigest::of(b"a file of that release");
        let protected = protected_payloads(
            std::slice::from_ref(&installed),
            &[upgraded_from],
            |package| {
                Ok(if package == upgraded_from {
                    HeldPackage::Named(vec![its_file])
                } else {
                    HeldPackage::Absent
                })
            },
        )
        .expect("named from its manifest");
        assert!(protected.contains(&upgraded_from) && protected.contains(&its_file));

        // One held here that nothing can name stops the reclaim instead of being guessed at.
        let refusal =
            protected_payloads(std::slice::from_ref(&installed), &[upgraded_from], |_| {
                Ok(HeldPackage::Unnamed)
            })
            .expect_err("a live package whose files nothing names");
        assert!(matches!(refusal, CatalogueError::StorageUnavailable { .. }));

        // And one held nowhere here is another store's, which nothing here can take from it.
        let protected =
            protected_payloads(std::slice::from_ref(&installed), &[upgraded_from], nothing)
                .expect("nothing of it is here");
        assert!(!protected.contains(&its_file));
    }

    #[test]
    fn every_disable_policy_reads_back() {
        for policy in [
            DisablePolicy::WarnOnly,
            DisablePolicy::DisableAtNextAdmission,
            DisablePolicy::DisableAtOnce,
        ] {
            assert_eq!(DisablePolicy::parse(policy.as_str()), Some(policy));
        }
        assert_eq!(DisablePolicy::parse("never"), None);
    }
}
