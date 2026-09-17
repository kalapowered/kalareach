//! What binds executable plugin semantics to a verified package.
//!
//! A plugin identifier on its own names a thing a publisher maintains. It says nothing about which
//! bytes are running. Three fields together do, and section 6 lists them as one row for that
//! reason: the plugin identifier, the package hash and the catalogue generation the package was
//! resolved against.
//!
//! # Why all three
//!
//! | Field | What it settles | What it cannot settle |
//! | --- | --- | --- |
//! | `plugin_id` | which publisher's plugin this is | which version, and which bytes |
//! | `package_hash` | exactly which bytes | which catalogue said they were current |
//! | `repository_generation` | which catalogue generation resolved them | anything about the bytes |
//!
//! A host that recorded only the identifier would let a package update turn an old live binding
//! into a different version. A host that recorded only the hash could not say which generation
//! admitted it, so a withdrawal in a later generation would have nothing to match against. So the
//! identity is the triple, and two identities are the same identity only when all three agree.
//!
//! # What an identity is not
//!
//! It is not a permission. A verified identity says which code is running, and the broker still
//! checks the actor, the grant, the binding revision and the declared effect class on every
//! action. It is also not a claim about behaviour: a signature over a package proves who published
//! it, never that what it does is what it says.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::digest::PayloadDigest;
use crate::ids::{PluginId, RepositoryGeneration};
use crate::version::PackageVersion;

/// The identity of one executable plugin package, as a host records it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PluginIdentity {
    /// The plugin, as its manifest names it.
    pub plugin_id: PluginId,
    /// The exact version.
    pub version: PackageVersion,
    /// The digest of the package payload the host verified.
    pub package_hash: PayloadDigest,
    /// The catalogue generation the package was resolved against.
    pub repository_generation: RepositoryGeneration,
}

impl PluginIdentity {
    /// Builds an identity.
    #[must_use]
    pub const fn new(
        plugin_id: PluginId,
        version: PackageVersion,
        package_hash: PayloadDigest,
        repository_generation: RepositoryGeneration,
    ) -> Self {
        Self {
            plugin_id,
            version,
            package_hash,
            repository_generation,
        }
    }

    /// Returns true when `other` is the same running code as this.
    ///
    /// Same plugin, same bytes, same generation. An upgrade is a different identity even under the
    /// same identifier, which is what keeps an installed update from silently becoming what an
    /// existing binding is running.
    #[must_use]
    pub fn is_same_binding_target(&self, other: &Self) -> bool {
        self == other
    }

    /// Returns true when `other` is a different build of the same plugin.
    #[must_use]
    pub fn is_other_build_of(&self, other: &Self) -> bool {
        self.plugin_id == other.plugin_id && self.package_hash != other.package_hash
    }

    /// Returns true when `other` is the same bytes resolved through a later catalogue generation.
    ///
    /// The same payload can be current in several generations. A host that has re-synchronised
    /// holds a newer generation for bytes it already had, and nothing about the running code has
    /// changed.
    #[must_use]
    pub fn is_same_payload_in_later_generation(&self, other: &Self) -> bool {
        self.plugin_id == other.plugin_id
            && self.package_hash == other.package_hash
            && other.repository_generation.get() > self.repository_generation.get()
    }
}

impl fmt::Display for PluginIdentity {
    /// Writes the identity as `plugin@version+hash/generation`.
    ///
    /// All four parts, because a log line that named only the plugin would not say which bytes
    /// produced the entry beside it.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}@{}+{}/{}",
            self.plugin_id,
            self.version,
            self.package_hash,
            self.repository_generation.get()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(hash: &[u8], generation: u64) -> PluginIdentity {
        PluginIdentity::new(
            PluginId::new("kalareach/example-declarative").expect("a bounded identifier"),
            PackageVersion::parse("1.2.0").expect("a semantic version"),
            PayloadDigest::of(hash),
            RepositoryGeneration::new(generation),
        )
    }

    #[test]
    fn an_identity_is_the_same_only_when_all_three_fields_agree() {
        let first = identity(b"the package", 7);
        assert!(first.is_same_binding_target(&identity(b"the package", 7)));
        assert!(!first.is_same_binding_target(&identity(b"a later package", 7)));
        assert!(!first.is_same_binding_target(&identity(b"the package", 8)));
    }

    #[test]
    fn a_version_change_under_the_same_identifier_is_a_different_identity() {
        let installed = identity(b"the package", 7);
        let mut upgraded = identity(b"a later package", 7);
        upgraded.version = PackageVersion::parse("1.3.0").expect("a semantic version");
        assert!(!installed.is_same_binding_target(&upgraded));
        assert!(installed.is_other_build_of(&upgraded));
    }

    #[test]
    fn the_same_bytes_in_a_later_generation_is_not_a_different_build() {
        let installed = identity(b"the package", 7);
        let resynchronised = identity(b"the package", 9);
        assert!(installed.is_same_payload_in_later_generation(&resynchronised));
        assert!(!installed.is_other_build_of(&resynchronised));
        // Still not the same identity: which generation admitted the bytes is part of the record.
        assert!(!installed.is_same_binding_target(&resynchronised));
    }

    #[test]
    fn an_earlier_generation_is_not_a_later_one() {
        let installed = identity(b"the package", 9);
        assert!(!installed.is_same_payload_in_later_generation(&identity(b"the package", 7)));
    }

    #[test]
    fn a_different_plugin_with_the_same_hash_is_not_the_same_plugin() {
        let first = identity(b"the package", 7);
        let mut second = identity(b"the package", 7);
        second.plugin_id = PluginId::new("vendor/other").expect("a bounded identifier");
        assert!(!first.is_same_binding_target(&second));
        assert!(!first.is_other_build_of(&second));
        assert!(!first.is_same_payload_in_later_generation(&second));
    }

    #[test]
    fn the_rendering_names_the_plugin_the_version_the_bytes_and_the_generation() {
        let text = identity(b"the package", 7).to_string();
        assert!(text.starts_with("kalareach/example-declarative@1.2.0+"));
        assert!(text.ends_with("/7"));
        assert!(text.contains(&PayloadDigest::of(b"the package").to_string()));
    }

    #[test]
    fn an_identity_round_trips_through_its_serialised_form() {
        let identity = identity(b"the package", 7);
        let document = serde_json::to_string(&identity).expect("a document");
        let decoded: PluginIdentity = serde_json::from_str(&document).expect("the same identity");
        assert_eq!(decoded, identity);
    }

    #[test]
    fn an_unknown_field_is_refused_rather_than_ignored() {
        let document = r#"{
            "plugin_id": "kalareach/example-declarative",
            "version": "1.2.0",
            "package_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "repository_generation": 7,
            "trusted": true
        }"#;
        assert!(serde_json::from_str::<PluginIdentity>(document).is_err());
    }
}
