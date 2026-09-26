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
use crate::integration::CommandIntegration;
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

/// One edit a native bridge removal undoes.
///
/// Removal has its own vocabulary because it is not installation run backwards. Deleting a file the
/// recipe installed is safe; deleting a file it edited is not. Each step names exactly what it
/// undoes, so unrelated settings survive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum BridgeRemoval {
    /// Delete a file the recipe installed, after checking it is still the bytes it installed.
    ///
    /// A file whose digest no longer matches was changed by somebody else, and removal leaves it
    /// alone and reports it rather than deleting somebody's work.
    RemoveFile {
        /// The path under the application's documented plugin directory.
        destination: PackagePath,
        /// The digest the recipe installed.
        digest: PayloadDigest,
    },
    /// Remove one key the recipe added, leaving the rest of the file untouched.
    RemoveConfigurationKey {
        /// The configuration file under the application's documented directory.
        file: PackagePath,
        /// The key path, as dotted members.
        key: String,
    },
}

impl BridgeRemoval {
    /// Returns the install step this removal undoes, as a path and key pair.
    #[must_use]
    pub fn undoes(&self) -> (&PackagePath, Option<&str>) {
        match self {
            Self::RemoveFile { destination, .. } => (destination, None),
            Self::RemoveConfigurationKey { file, key } => (file, Some(key)),
        }
    }
}

impl BridgeStep {
    /// Returns what this step writes, as a path and key pair.
    #[must_use]
    pub fn writes(&self) -> (&PackagePath, Option<&str>) {
        match self {
            Self::InstallFile { destination, .. } => (destination, None),
            Self::AddConfigurationKey { file, key, .. } => (file, Some(key)),
        }
    }
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
    /// What removal undoes, in the order it is applied.
    ///
    /// Every install step has a removal step. A recipe that installs something it cannot remove is
    /// a recipe that leaves the application changed after the package is gone.
    pub remove: Vec<BridgeRemoval>,
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
    /// The command integration, where the package declares one: the command it integrates, the
    /// flags it adds to an interactive invocation and the variables it sets for it.
    ///
    /// A package that declares none leaves the member out, so a manifest written before the member
    /// existed reads and hashes exactly as it did. A host applies one only from this verified
    /// manifest and only with `command_integration.launch` granted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_integration: Option<CommandIntegration>,
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

    /// Returns the sum of every declared payload size, saturating rather than wrapping.
    ///
    /// A manifest is untrusted input. Two declared sizes that add past `u64::MAX` would panic in a
    /// debug build and wrap in a release one, and a wrapped total is a total that passes a budget
    /// check it should fail.
    #[must_use]
    pub fn declared_size_bytes(&self) -> u64 {
        self.payloads.iter().fold(0u64, |total, payload| {
            total.saturating_add(payload.size_bytes.get())
        })
    }

    /// Returns true when any declared size, or their total, is past `limit`.
    #[must_use]
    pub fn declares_more_than(&self, limit: u64) -> bool {
        self.declared_size_bytes() > limit
            || self
                .payloads
                .iter()
                .any(|payload| payload.size_bytes.get() > limit)
    }

    /// Returns true when the package requests the given capability.
    #[must_use]
    pub fn requests(&self, capability: crate::capability::PluginCapability) -> bool {
        self.capabilities
            .iter()
            .any(|request| request.capability == capability)
    }
}
