//! Installed packages and the bindings that hold them.
//!
//! Downloading the whole catalogue does not install anything, and installing something does not
//! activate it. Three separate facts decide whether a package runs against an application:
//!
//! * it is **installed** in this environment, at one exact package hash;
//! * it is **enabled** there, which is a separate decision from installing it;
//! * its rules **recognise** what is running, which [`crate::catalogue::search`] answers.
//!
//! A binding records the hash it was made against. An upgrade moves the installation and leaves
//! every live binding where it is, because a running process was qualified against the bytes it
//! bound to and not against the bytes that arrived afterwards.
//!
//! Revocation is the other asymmetry. A revoked release stops receiving new bindings immediately.
//! An active binding is not torn down under a request that is already running: it warns, and it
//! follows the administrator's explicit disable policy at the point that policy names.

use std::collections::BTreeMap;

use kr_plugin_sdk::capability::CapabilityRequest;
use kr_plugin_sdk::catalogue::{IndexEntry, RevocationRecord};
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::ids::{PluginId, PluginName, PublisherId};
use kr_plugin_sdk::version::PackageVersion;
use kr_protocol::ids::EnvironmentId;

use crate::catalogue::ceiling::InstallationGrant;
use crate::catalogue::error::{CatalogueError, CatalogueResult};
use crate::catalogue::repository::RepositoryId;

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
}

/// What a revoked package means for one live binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationNotice {
    /// The binding the notice is about.
    pub binding_id: BindingId,
    /// The package it holds.
    pub plugin_id: PluginId,
    /// The exact hash it is bound to.
    pub package_digest: PayloadDigest,
    /// What the catalogue published.
    pub record: RevocationRecord,
    /// What the administrator's policy says happens.
    pub policy: DisablePolicy,
    /// Whether the binding keeps serving the request it is in.
    pub keeps_serving: bool,
    /// What a person reads.
    pub warning: String,
}

/// One binding's identity inside this host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BindingId(u64);

impl BindingId {
    /// Wraps a binding number.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the binding number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl core::fmt::Display for BindingId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{}", self.0)
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
    /// The repository it came from.
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
}

impl Installation {
    /// Builds an installation record from the index entry it was installed from.
    #[must_use]
    pub fn from_entry(
        entry: &IndexEntry,
        repository: RepositoryId,
        environment_id: EnvironmentId,
        grant: InstallationGrant,
    ) -> Self {
        Self {
            plugin_id: entry.plugin_id.clone(),
            publisher_id: entry.publisher_id.clone(),
            plugin_name: entry.plugin_name.clone(),
            version: entry.version.clone(),
            package_digest: entry.manifest_digest,
            repository,
            environment_id,
            enabled: false,
            pinned: false,
            grant,
            requested: entry.capabilities.clone(),
            payloads: entry
                .payloads
                .iter()
                .map(|payload| payload.digest)
                .collect(),
        }
    }

    /// Returns every content hash this installation needs, including its manifest.
    #[must_use]
    pub fn all_payloads(&self) -> Vec<PayloadDigest> {
        let mut digests = vec![self.package_digest];
        digests.extend(self.payloads.iter().copied());
        digests
    }
}

/// One live binding between a package and something running.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// This host's identity for the binding.
    pub binding_id: BindingId,
    /// The package.
    pub plugin_id: PluginId,
    /// The exact hash the binding was made against, and stays on.
    pub package_digest: PayloadDigest,
    /// The environment it runs in.
    pub environment_id: EnvironmentId,
    /// What it is bound to.
    pub executable_path: String,
}

/// Every installation and binding this host holds.
#[derive(Debug, Default)]
pub struct Installations {
    installations: BTreeMap<(EnvironmentId, String), Installation>,
    bindings: Vec<Binding>,
    next_binding: u64,
    policy: DisablePolicy,
}

impl Installations {
    /// An empty set under the default disable policy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the administrator's disable policy.
    #[must_use]
    pub const fn policy(&self) -> DisablePolicy {
        self.policy
    }

    /// Sets the administrator's disable policy.
    pub const fn set_policy(&mut self, policy: DisablePolicy) {
        self.policy = policy;
    }

    fn key(environment_id: EnvironmentId, plugin_id: &PluginId) -> (EnvironmentId, String) {
        (environment_id, plugin_id.to_string())
    }

    /// Returns the installation of one package in one environment.
    #[must_use]
    pub fn get(
        &self,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
    ) -> Option<&Installation> {
        self.installations
            .get(&Self::key(environment_id, plugin_id))
    }

    /// Returns every installation, in a stable order.
    #[must_use]
    pub fn all(&self) -> Vec<&Installation> {
        self.installations.values().collect()
    }

    /// Returns every live binding, in the order they were made.
    #[must_use]
    pub fn bindings(&self) -> &[Binding] {
        &self.bindings
    }

    /// Returns a copy a caller can change before committing it.
    ///
    /// Bindings are live state rather than durable state, so a copy carries them unchanged: what
    /// is being proposed is a change to what is installed, not to what is running.
    #[must_use]
    pub fn snapshot(&self) -> Self {
        Self {
            installations: self.installations.clone(),
            bindings: self.bindings.clone(),
            next_binding: self.next_binding,
            policy: self.policy,
        }
    }

    /// Records an installation, replacing any earlier one of the same package.
    pub fn insert(&mut self, installation: Installation) {
        self.installations.insert(
            Self::key(installation.environment_id, &installation.plugin_id),
            installation,
        );
    }

    /// Enables or disables an installed package.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the package is not installed here.
    pub fn set_enabled(
        &mut self,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
        enabled: bool,
    ) -> CatalogueResult<()> {
        let installation = self
            .installations
            .get_mut(&Self::key(environment_id, plugin_id))
            .ok_or_else(|| CatalogueError::NotFound {
                detail: format!("{plugin_id} is not installed in this environment"),
            })?;
        installation.enabled = enabled;
        Ok(())
    }

    /// Pins or unpins an installation to the exact hash it holds.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the package is not installed here, and
    /// [`CatalogueError::InvalidArgument`] when the pin names another hash.
    pub fn set_pinned(
        &mut self,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
        package_digest: Option<PayloadDigest>,
    ) -> CatalogueResult<()> {
        let installation = self
            .installations
            .get_mut(&Self::key(environment_id, plugin_id))
            .ok_or_else(|| CatalogueError::NotFound {
                detail: format!("{plugin_id} is not installed in this environment"),
            })?;
        match package_digest {
            Some(digest) if digest != installation.package_digest => {
                Err(CatalogueError::InvalidArgument {
                    detail: format!(
                        "{plugin_id} is installed at {} and the pin names {digest}; pinning \
                         operates on the hash that is installed",
                        installation.package_digest
                    ),
                })
            }
            Some(_) => {
                installation.pinned = true;
                Ok(())
            }
            None => {
                installation.pinned = false;
                Ok(())
            }
        }
    }

    /// Removes an installation and every binding that held it.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the package is not installed here.
    pub fn remove(
        &mut self,
        environment_id: EnvironmentId,
        plugin_id: &PluginId,
    ) -> CatalogueResult<Installation> {
        let installation = self
            .installations
            .remove(&Self::key(environment_id, plugin_id))
            .ok_or_else(|| CatalogueError::NotFound {
                detail: format!("{plugin_id} is not installed in this environment"),
            })?;
        self.bindings.retain(|binding| {
            binding.environment_id != environment_id || binding.plugin_id != *plugin_id
        });
        Ok(installation)
    }

    /// Opens a binding against an installed, enabled, unrevoked package.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::NotFound`] when the package is not installed here,
    /// [`CatalogueError::Disabled`] when it is installed and disabled, and
    /// [`CatalogueError::Untrusted`] when the release is revoked, which stops new bindings.
    pub fn bind(
        &mut self,
        environment_id: EnvironmentId,
        entry: &IndexEntry,
        executable_path: &str,
    ) -> CatalogueResult<Binding> {
        let installation = self
            .installations
            .get(&Self::key(environment_id, &entry.plugin_id))
            .ok_or_else(|| CatalogueError::NotFound {
                detail: format!("{} is not installed in this environment", entry.plugin_id),
            })?;
        if !installation.enabled {
            return Err(CatalogueError::Disabled {
                detail: format!(
                    "{} is installed and disabled in this environment",
                    entry.plugin_id
                ),
            });
        }
        // The release this binding is for is the one installed here, at the hash it was installed
        // at. A caller that supplied another release's entry would otherwise have its revocation
        // record and its match rules decide an admission for a different set of bytes.
        if entry.manifest_digest != installation.package_digest {
            return Err(CatalogueError::InvalidArgument {
                detail: format!(
                    "{} is installed at {} and this is {}; a binding is admitted against the \
                     release that is installed",
                    entry.plugin_id, installation.package_digest, entry.manifest_digest
                ),
            });
        }
        // The rules the installed package declares have to recognise what is running. A binding
        // made without that check would be an instantiation nothing matched.
        if !entry
            .match_rules
            .iter()
            .any(|rule| rule.executable.matches_path(executable_path))
        {
            return Err(CatalogueError::InvalidArgument {
                detail: format!(
                    "{} declares no rule that recognises {executable_path}",
                    entry.plugin_id
                ),
            });
        }
        if let Some(record) = entry.revocation.0.as_ref() {
            return Err(CatalogueError::Untrusted {
                detail: format!(
                    "{} {} is revoked ({:?}): {}. A revoked release stops new bindings",
                    entry.plugin_id,
                    entry.version,
                    record.reason,
                    record.statement.as_str()
                ),
            });
        }
        self.next_binding = self.next_binding.saturating_add(1);
        let binding = Binding {
            binding_id: BindingId::new(self.next_binding),
            plugin_id: entry.plugin_id.clone(),
            // The hash the binding is made against, not the hash the installation may move to.
            package_digest: installation.package_digest,
            environment_id,
            executable_path: executable_path.to_owned(),
        };
        self.bindings.push(binding.clone());
        Ok(binding)
    }

    /// Closes one binding.
    pub fn unbind(&mut self, binding_id: BindingId) {
        self.bindings
            .retain(|binding| binding.binding_id != binding_id);
    }

    /// Returns what a revocation means for every live binding of that package.
    ///
    /// Nothing is torn down here. The notice says what the administrator's policy does and whether
    /// the binding keeps serving, so a caller applies it at an admission boundary rather than
    /// inside a request that is already running.
    #[must_use]
    pub fn revocation_notices(&self, entry: &IndexEntry) -> Vec<RevocationNotice> {
        let Some(record) = entry.revocation.0.as_ref() else {
            return Vec::new();
        };
        self.bindings
            .iter()
            // The exact release, not the package: another version being revoked says nothing
            // about the bytes this binding is on.
            .filter(|binding| {
                binding.plugin_id == entry.plugin_id
                    && binding.package_digest == entry.manifest_digest
            })
            .map(|binding| RevocationNotice {
                binding_id: binding.binding_id,
                plugin_id: binding.plugin_id.clone(),
                package_digest: binding.package_digest,
                record: record.clone(),
                policy: self.policy,
                keeps_serving: self.policy == DisablePolicy::WarnOnly,
                warning: format!(
                    "{} {} was revoked: {}. This binding stays on {} and {}",
                    entry.plugin_id,
                    entry.version,
                    record.statement.as_str(),
                    binding.package_digest,
                    match self.policy {
                        DisablePolicy::WarnOnly =>
                            "keeps serving until somebody disables it, under the administrator's \
                             policy",
                        DisablePolicy::DisableAtNextAdmission =>
                            "admits nothing new, under the administrator's policy",
                        DisablePolicy::DisableAtOnce =>
                            "is disabled at the next admission, under the administrator's policy",
                    }
                ),
            })
            .collect()
    }

    /// Returns every package hash a live binding or a pinned installation still needs.
    #[must_use]
    pub fn protected_packages(&self) -> Vec<PayloadDigest> {
        let mut protected: Vec<PayloadDigest> = self
            .bindings
            .iter()
            .map(|binding| binding.package_digest)
            .collect();
        protected.extend(
            self.installations
                .values()
                .filter(|installation| installation.pinned)
                .map(|installation| installation.package_digest),
        );
        protected.sort_unstable();
        protected.dedup();
        protected
    }

    /// Returns every content hash a live binding or a pinned installation still needs.
    ///
    /// These are the payloads a sync never evicts to finish: the manifest a binding is pinned to
    /// and every file that package consists of.
    #[must_use]
    pub fn protected_payloads(&self) -> Vec<PayloadDigest> {
        let packages = self.protected_packages();
        let mut protected = packages.clone();
        for installation in self.installations.values() {
            if packages.contains(&installation.package_digest) {
                protected.extend(installation.payloads.iter().copied());
            }
        }
        protected.sort_unstable();
        protected.dedup();
        protected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_plugin_sdk::example::example_manifest;
    use kr_plugin_sdk::text::Summary;
    use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};

    fn environment() -> EnvironmentId {
        EnvironmentId::new(Uuid::NIL)
    }

    fn entry(version: &str) -> IndexEntry {
        let mut manifest = example_manifest();
        manifest.version = PackageVersion::parse(version).expect("a valid version");
        IndexEntry::from_manifest(&manifest, PayloadDigest::of(version.as_bytes()), 4_096)
    }

    fn installed(enabled: bool) -> (Installations, IndexEntry) {
        let entry = entry("0.1.0");
        let mut installations = Installations::new();
        let mut installation = Installation::from_entry(
            &entry,
            RepositoryId::new("official").expect("a valid identifier"),
            environment(),
            InstallationGrant::none(),
        );
        installation.enabled = enabled;
        installations.insert(installation);
        (installations, entry)
    }

    #[test]
    fn only_an_installed_enabled_package_binds() {
        let (mut installations, entry) = installed(false);
        let refusal = installations
            .bind(environment(), &entry, "/usr/local/bin/example-agent")
            .expect_err("disabled");
        assert!(matches!(refusal, CatalogueError::Disabled { .. }));

        installations
            .set_enabled(environment(), &entry.plugin_id, true)
            .expect("installed");
        let binding = installations
            .bind(environment(), &entry, "/usr/local/bin/example-agent")
            .expect("enabled");
        assert_eq!(binding.package_digest, entry.manifest_digest);

        let mut empty = Installations::new();
        let refusal = empty
            .bind(environment(), &entry, "/usr/local/bin/example-agent")
            .expect_err("not installed");
        assert!(matches!(refusal, CatalogueError::NotFound { .. }));
    }

    #[test]
    fn a_binding_is_admitted_against_the_release_that_is_installed() {
        let (mut installations, first) = installed(true);
        // Another release's entry does not admit a binding, whatever it says about itself.
        let second = entry("0.2.0");
        let refusal = installations
            .bind(environment(), &second, "/usr/local/bin/example-agent")
            .expect_err("another release");
        assert!(
            refusal.to_string().contains("release that is installed"),
            "{refusal}"
        );

        // Nor does an executable the package's own rules do not recognise.
        let refusal = installations
            .bind(environment(), &first, "/usr/local/bin/unrelated")
            .expect_err("nothing recognises it");
        assert!(refusal.to_string().contains("no rule"), "{refusal}");
    }

    #[test]
    fn a_pin_names_the_hash_that_is_installed() {
        let (mut installations, first) = installed(true);
        installations
            .set_pinned(environment(), &first.plugin_id, Some(first.manifest_digest))
            .expect("installed");
        assert!(
            installations
                .get(environment(), &first.plugin_id)
                .expect("installed")
                .pinned
        );

        let wrong = installations.set_pinned(
            environment(),
            &first.plugin_id,
            Some(PayloadDigest::of(b"another")),
        );
        assert!(matches!(wrong, Err(CatalogueError::InvalidArgument { .. })));
    }

    #[test]
    fn a_revoked_release_stops_new_bindings_and_warns_the_live_one() {
        let (mut installations, entry) = installed(true);
        let binding = installations
            .bind(environment(), &entry, "/usr/local/bin/example-agent")
            .expect("enabled");

        let mut revoked = entry.clone();
        revoked.revocation = Nullable(Some(RevocationRecord {
            reason: kr_plugin_sdk::catalogue::RevocationReason::Vulnerable,
            revoked_at: TimestampMs::new(1_760_000_100_000),
            statement: Summary::new("Replaced by 0.1.1").expect("a valid statement"),
        }));

        let refusal = installations
            .bind(environment(), &revoked, "/usr/local/bin/example-agent")
            .expect_err("revoked");
        assert!(
            refusal.to_string().contains("stops new bindings"),
            "{refusal}"
        );

        let notices = installations.revocation_notices(&revoked);
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].binding_id, binding.binding_id);
        assert_eq!(notices[0].policy, DisablePolicy::WarnOnly);
        assert!(notices[0].keeps_serving, "the default policy warns");
        assert!(notices[0].warning.contains("Replaced by 0.1.1"));
        assert_eq!(
            installations.bindings().len(),
            1,
            "a revocation does not change a binding by itself"
        );

        installations.set_policy(DisablePolicy::DisableAtOnce);
        let notices = installations.revocation_notices(&revoked);
        assert!(!notices[0].keeps_serving);
        assert!(notices[0].warning.contains("administrator's policy"));
        assert_eq!(
            installations.bindings().len(),
            1,
            "the policy is applied at an admission boundary, not mid-request"
        );
    }

    #[test]
    fn a_live_bound_or_pinned_package_is_protected() {
        let (mut installations, entry) = installed(true);
        assert!(installations.protected_packages().is_empty());
        installations
            .bind(environment(), &entry, "/usr/local/bin/example-agent")
            .expect("enabled");
        assert_eq!(
            installations.protected_packages(),
            vec![entry.manifest_digest]
        );

        installations.unbind(BindingId::new(1));
        assert!(installations.protected_packages().is_empty());
        installations
            .set_pinned(environment(), &entry.plugin_id, Some(entry.manifest_digest))
            .expect("installed");
        assert_eq!(
            installations.protected_packages(),
            vec![entry.manifest_digest]
        );
    }
}
