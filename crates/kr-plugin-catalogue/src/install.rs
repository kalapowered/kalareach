//! Installed packages and the bindings that hold them.
//!
//! Downloading the whole catalogue does not install anything, and installing something does not
//! activate it. Three separate facts decide whether a package runs against an application:
//!
//! * it is **installed** in this environment, at one exact package hash;
//! * it is **enabled** there, which is a separate decision from installing it;
//! * its rules **recognise** what is running, which [`crate::search`] answers.
//!
//! A binding records the hash it was made against. An upgrade moves the installation and leaves
//! every live binding where it is, because a running process was qualified against the bytes it
//! bound to and not against the bytes that arrived afterwards.
//!
//! Revocation is the other asymmetry. A revoked release stops receiving new bindings immediately.
//! An active binding is not torn down under a request that is already running: it warns, and it
//! follows the administrator's explicit disable policy at the point that policy names.

use kr_plugin_sdk::capability::CapabilityRequest;
use kr_plugin_sdk::catalogue::{IndexEntry, RevocationRecord};
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
    /// The payloads of the package when the binding was admitted.
    pub payloads: Vec<PayloadDigest>,
}

/// The bindings live on this host, which are the one part of the catalogue that is not durable.
///
/// A binding is a running process holding a package on its exact hash. It ends when the process
/// does, so it lives in memory; what is installed, enabled and granted is durable and lives in
/// the catalogue's records, which a binding is admitted against.
#[derive(Debug, Default)]
pub struct Bindings {
    live: Vec<Binding>,
    next_binding: u64,
}

impl Bindings {
    /// No live bindings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns every live binding, in the order they were made.
    #[must_use]
    pub fn all(&self) -> &[Binding] {
        &self.live
    }

    /// Opens a binding against an installed, enabled, unrevoked package.
    ///
    /// `installation` is what the catalogue's records hold for this package in this environment,
    /// and `entry` is the index entry for the release it names.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogueError::Disabled`] when the package is installed and disabled,
    /// [`CatalogueError::InvalidArgument`] when the entry is another release or its rules do not
    /// recognise what is running, and [`CatalogueError::Untrusted`] when the release is revoked,
    /// which stops new bindings.
    pub fn bind(
        &mut self,
        installation: &Installation,
        entry: &IndexEntry,
        executable_path: &str,
    ) -> CatalogueResult<Binding> {
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
            environment_id: installation.environment_id,
            executable_path: executable_path.to_owned(),
            payloads: installation.payloads.clone(),
        };
        self.live.push(binding.clone());
        Ok(binding)
    }

    /// Closes one binding.
    pub fn unbind(&mut self, binding_id: BindingId) {
        self.live.retain(|binding| binding.binding_id != binding_id);
    }

    /// Returns how many live bindings hold one package in one environment.
    #[must_use]
    pub fn count_for(&self, environment_id: EnvironmentId, plugin_id: &PluginId) -> u64 {
        self.live
            .iter()
            .filter(|binding| {
                binding.environment_id == environment_id && &binding.plugin_id == plugin_id
            })
            .count() as u64
    }

    /// Closes every binding that holds one package in one environment, returning how many.
    pub fn close_for(&mut self, environment_id: EnvironmentId, plugin_id: &PluginId) -> u64 {
        let closed = self.count_for(environment_id, plugin_id);
        self.live.retain(|binding| {
            binding.environment_id != environment_id || &binding.plugin_id != plugin_id
        });
        closed
    }

    /// Returns what a revocation means for every live binding of that package.
    ///
    /// Nothing is torn down here. The notice says what the administrator's policy does and whether
    /// the binding keeps serving, so a caller applies it at an admission boundary rather than
    /// inside a request that is already running.
    #[must_use]
    pub fn revocation_notices(
        &self,
        entry: &IndexEntry,
        policy: DisablePolicy,
    ) -> Vec<RevocationNotice> {
        let Some(record) = entry.revocation.0.as_ref() else {
            return Vec::new();
        };
        self.live
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
                policy,
                keeps_serving: policy == DisablePolicy::WarnOnly,
                warning: format!(
                    "{} {} was revoked: {}. This binding stays on {} and {}",
                    entry.plugin_id,
                    entry.version,
                    record.statement.as_str(),
                    binding.package_digest,
                    match policy {
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
}

/// Returns every payload a reclaim must keep.
///
/// That is every installed package, enabled or disabled, pinned or not, every package a local
/// binding or the broker says is live, and every file each of them consists of: a package's hash
/// names its manifest, and protecting only that would leave the component and the assets a
/// binding runs on evictable. What a package consists of is read from the installation or the
/// binding that holds it, or else from what the store holds of it, through `held`. A live package
/// the store holds nothing of is another store's, and nothing here is its to lose. A live package
/// the store holds and cannot expand is not protected by guesswork: the answer is a refusal, and
/// nothing is reclaimed.
///
/// # Errors
///
/// Returns [`CatalogueError::StorageUnavailable`] when a live package's files cannot be named, and
/// whatever `held` returns.
pub fn protected_payloads(
    installations: &[Installation],
    bindings: &Bindings,
    live: &[PayloadDigest],
    held: impl Fn(PayloadDigest) -> CatalogueResult<HeldPackage>,
) -> CatalogueResult<Vec<PayloadDigest>> {
    let mut packages: Vec<PayloadDigest> = live.to_vec();
    packages.extend(
        installations
            .iter()
            .map(|installation| installation.package_digest),
    );
    packages.extend(bindings.all().iter().map(|binding| binding.package_digest));
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
        for binding in bindings
            .all()
            .iter()
            .filter(|binding| binding.package_digest == package)
        {
            protected.extend(binding.payloads.iter().copied());
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
    fn only_an_enabled_installation_binds() {
        let entry = entry("0.1.0");
        let mut bindings = Bindings::new();
        let refusal = bindings
            .bind(
                &installation(&entry, false),
                &entry,
                "/usr/local/bin/example-agent",
            )
            .expect_err("disabled");
        assert!(matches!(refusal, CatalogueError::Disabled { .. }));

        let binding = bindings
            .bind(
                &installation(&entry, true),
                &entry,
                "/usr/local/bin/example-agent",
            )
            .expect("enabled");
        assert_eq!(binding.package_digest, entry.manifest_digest);
        assert_eq!(bindings.count_for(environment(), &entry.plugin_id), 1);
    }

    #[test]
    fn a_binding_is_admitted_against_the_release_that_is_installed() {
        let first = entry("0.1.0");
        let installed = installation(&first, true);
        let mut bindings = Bindings::new();
        // Another release's entry does not admit a binding, whatever it says about itself.
        let second = entry("0.2.0");
        let refusal = bindings
            .bind(&installed, &second, "/usr/local/bin/example-agent")
            .expect_err("another release");
        assert!(
            refusal.to_string().contains("release that is installed"),
            "{refusal}"
        );

        // Nor does an executable the package's own rules do not recognise.
        let refusal = bindings
            .bind(&installed, &first, "/usr/local/bin/unrelated")
            .expect_err("nothing recognises it");
        assert!(refusal.to_string().contains("no rule"), "{refusal}");
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
    fn a_revoked_release_stops_new_bindings_and_warns_the_live_one() {
        let entry = entry("0.1.0");
        let installed = installation(&entry, true);
        let mut bindings = Bindings::new();
        let binding = bindings
            .bind(&installed, &entry, "/usr/local/bin/example-agent")
            .expect("enabled");

        let mut revoked = entry.clone();
        revoked.revocation = Nullable(Some(RevocationRecord {
            reason: kr_plugin_sdk::catalogue::RevocationReason::Vulnerable,
            revoked_at: TimestampMs::new(1_760_000_100_000),
            statement: Summary::new("Replaced by 0.1.1").expect("a valid statement"),
        }));

        let refusal = bindings
            .bind(&installed, &revoked, "/usr/local/bin/example-agent")
            .expect_err("revoked");
        assert!(
            refusal.to_string().contains("stops new bindings"),
            "{refusal}"
        );

        let notices = bindings.revocation_notices(&revoked, DisablePolicy::WarnOnly);
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].binding_id, binding.binding_id);
        assert_eq!(notices[0].policy, DisablePolicy::WarnOnly);
        assert!(notices[0].keeps_serving, "the default policy warns");
        assert!(notices[0].warning.contains("Replaced by 0.1.1"));
        assert_eq!(
            bindings.all().len(),
            1,
            "a revocation does not change a binding by itself"
        );

        let notices = bindings.revocation_notices(&revoked, DisablePolicy::DisableAtOnce);
        assert!(!notices[0].keeps_serving);
        assert!(notices[0].warning.contains("administrator's policy"));
        assert_eq!(
            bindings.all().len(),
            1,
            "the policy is applied at an admission boundary, not mid-request"
        );
    }

    #[test]
    fn every_installed_bound_or_live_package_is_protected_with_all_its_files() {
        let entry = entry("0.1.0");
        let installed = installation(&entry, false);
        let bindings = Bindings::new();
        let nothing =
            |_: PayloadDigest| -> CatalogueResult<HeldPackage> { Ok(HeldPackage::Absent) };

        // An installation is protected whether or not it is enabled, pinned or bound.
        let protected =
            protected_payloads(std::slice::from_ref(&installed), &bindings, &[], nothing)
                .expect("named");
        assert!(protected.contains(&entry.manifest_digest));
        for payload in &installed.payloads {
            assert!(
                protected.contains(payload),
                "every file of an installed package"
            );
        }

        // A package the broker says is live, which no installation holds any more, is expanded
        // from its own manifest where it is activated here.
        let upgraded_from = PayloadDigest::of(b"the release an upgrade replaced");
        let its_file = PayloadDigest::of(b"a file of that release");
        let protected = protected_payloads(
            std::slice::from_ref(&installed),
            &bindings,
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
        let refusal = protected_payloads(
            std::slice::from_ref(&installed),
            &bindings,
            &[upgraded_from],
            |_| Ok(HeldPackage::Unnamed),
        )
        .expect_err("a live package whose files nothing names");
        assert!(matches!(refusal, CatalogueError::StorageUnavailable { .. }));

        // And one held nowhere here is another store's, which nothing here can take from it.
        let protected = protected_payloads(
            std::slice::from_ref(&installed),
            &bindings,
            &[upgraded_from],
            nothing,
        )
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
