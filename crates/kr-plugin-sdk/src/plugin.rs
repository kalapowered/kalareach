//! The `plugin.json` manifest.
//!
//! The manifest is everything a host needs to decide whether a package is relevant, what it will
//! be permitted to do and exactly which bytes it consists of, without fetching or running any of
//! them. A simple definition needs no Wasm module at all: a package that only contributes match
//! rules, a presentation document and declarative controls declares no component and imports
//! nothing.

use kr_protocol::scalars::Nullable;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::capability::CapabilityRequest;
use crate::digest::{ByteSize, PayloadDigest};
use crate::effect::{ActionDeclaration, AttachmentContribution};
use crate::ids::{PluginName, PublisherId};
use crate::matching::{MatchRule, PlatformSupport};
use crate::paths::PackagePath;
use crate::text::{CompactDescription, Label, Summary};
use crate::version::{PackageVersion, VersionRange};

/// What one payload in a package is.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PayloadRole {
    /// The declarative native-proxy table.
    Connector,
    /// The presentation document.
    Presentation,
    /// The Wasm component.
    Component,
    /// An asset the client renders, such as documentation the package ships.
    Asset,
    /// A file installed into an application's native plugin or hook location.
    NativeBridge,
    /// A skill package the host installs for an agent.
    Skill,
    /// A conformance fixture the package is tested against.
    Fixture,
}

/// One payload, named by its path, its digest and its exact length.
///
/// The declared size is checked before download and the actual size and digest during processing,
/// so a payload cannot expand past what the manifest declared.
///
/// `plugin.json` is not listed here. It is the document doing the declaring, so its own digest
/// belongs in the catalogue index entry that points at it, not inside itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PayloadRef {
    /// What the payload is.
    pub role: PayloadRole,
    /// Where it lives in the package.
    pub path: PackagePath,
    /// Its SHA-256 digest.
    pub digest: PayloadDigest,
    /// Its exact length in bytes.
    pub size_bytes: ByteSize,
}

/// One edit a native bridge installation makes.
///
/// A recipe lists exact files, configuration edits, hashes, version requirements and the
/// operations that remove them again. Unrelated settings are preserved: the recipe names what it
/// adds, so removal can name the same thing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum BridgeStep {
    /// Copy a package file into the application's plugin directory.
    InstallFile {
        /// The file inside the package.
        source: PackagePath,
        /// The path under the application's documented plugin directory.
        destination: PackagePath,
        /// The digest of the installed bytes.
        digest: PayloadDigest,
    },
    /// Add one key to a documented configuration file, leaving the rest untouched.
    AddConfigurationKey {
        /// The configuration file under the application's documented directory.
        file: PackagePath,
        /// The key path, as dotted members.
        key: String,
        /// The value written, as JSON text.
        value: String,
    },
}

/// A native bridge installation recipe.
///
/// Bridge code runs under the application's own permissions, outside Wasmtime. The installation
/// grant states that, which is why the recipe names its steps rather than running a script.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct NativeBridge {
    /// The application whose documented plugin location is used.
    pub application: Label,
    /// The application versions the recipe is written for.
    pub application_range: VersionRange,
    /// What installation does.
    pub install: Vec<BridgeStep>,
    /// What removal does, in the order it is applied.
    pub remove: Vec<BridgeStep>,
    /// What the grant tells the person before they accept it.
    pub grant_statement: Summary,
}

/// The publisher's own record of where a package came from.
///
/// A reviewed catalogue entry pins the publisher, the source revision and the released package
/// digest. Runtime hosts install that release; they never execute a vendor repository's current
/// branch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SourcePin {
    /// Where the source lives.
    pub repository: String,
    /// The exact revision the package was built from.
    pub revision: String,
}

/// The `plugin.json` manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PluginManifest {
    /// The manifest format version.
    pub manifest_version: u32,
    /// The publisher. Immutable for the package's life.
    pub publisher_id: PublisherId,
    /// The plugin name under that publisher. Immutable for the package's life.
    pub plugin_name: PluginName,
    /// This release's version.
    pub version: PackageVersion,
    /// The name a person reads.
    pub display_name: Label,
    /// The one-line catalogue description.
    pub description: CompactDescription,
    /// The SDK versions this package is written against.
    pub sdk_range: VersionRange,
    /// The WIT package versions this package's component targets.
    ///
    /// A package with no component still names the range it was authored against, because the
    /// manifest shape it uses comes from the same release.
    pub wit_range: VersionRange,
    /// Where the source came from.
    pub source: SourcePin,
    /// The applications this package recognises.
    pub match_rules: Vec<MatchRule>,
    /// The platforms it supports.
    pub platforms: Vec<PlatformSupport>,
    /// Every byte the package consists of.
    pub payloads: Vec<PayloadRef>,
    /// What the package asks to be permitted.
    pub capabilities: Vec<CapabilityRequest>,
    /// The actions a control may invoke.
    pub actions: Vec<ActionDeclaration>,
    /// How the package contributes attachments, where it does.
    pub attachments: Nullable<AttachmentContribution>,
    /// The native bridge recipe, where the package installs one.
    pub native_bridge: Nullable<NativeBridge>,
}

impl PluginManifest {
    /// The manifest format version this crate reads and writes.
    pub const CURRENT_VERSION: u32 = 1;

    /// Returns the wire plugin identifier.
    #[must_use]
    pub fn plugin_id(&self) -> crate::ids::PluginId {
        crate::ids::plugin_id(&self.publisher_id, &self.plugin_name)
    }

    /// Returns the payload with the given role, where the package has one.
    #[must_use]
    pub fn payload(&self, role: PayloadRole) -> Option<&PayloadRef> {
        self.payloads.iter().find(|payload| payload.role == role)
    }

    /// Returns true when the package ships a Wasm component.
    ///
    /// A pure declarative package returns false, and nothing in the contract requires it to ship
    /// one: match rules, a presentation document and controls are a complete package.
    #[must_use]
    pub fn has_component(&self) -> bool {
        self.payload(PayloadRole::Component).is_some()
    }

    /// Returns the sum of every declared payload size.
    #[must_use]
    pub fn declared_size_bytes(&self) -> u64 {
        self.payloads
            .iter()
            .map(|payload| payload.size_bytes.get())
            .sum()
    }

    /// Returns true when the package requests the given capability.
    #[must_use]
    pub fn requests(&self, capability: crate::capability::PluginCapability) -> bool {
        self.capabilities
            .iter()
            .any(|request| request.capability == capability)
    }
}
