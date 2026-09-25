//! Applying a package's native bridge recipe in an application's own directory, and removing
//! exactly what it applied.

use std::path::PathBuf;

use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::matching::MatchRule;
use kr_plugin_sdk::plugin::NativeBridge;
use kr_protocol::ids::PluginId;
pub use kr_worker::broker::bridge::BridgeSurface;
pub use kr_worker::broker::connectors::{BridgeFacts, QualifiedExecutable};

use crate::error::Result;

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
}

/// One application's own directory, which a recipe's paths are under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationDirectory {
    /// The application, as a recipe names it.
    pub application: String,
    /// Its directory.
    pub directory: PathBuf,
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
    /// Nothing this host placed is left, apart from what its report names.
    Removed,
    /// The recipe was refused, and nothing of the release is in place.
    Refused(String),
    /// Something that may be this host's could not be settled, so nothing is reported as applied.
    Unsettled(String),
}

/// One package's bridge, as a person reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeReport {
    /// The package.
    pub plugin_id: String,
    /// Where it stands: applying, applied, removing, refused or removed.
    pub state: String,
    /// The release it is about, where there is one.
    pub package_digest: Option<String>,
    /// What no longer matches, what was left in place, what could not be settled, and why the last
    /// application was refused.
    pub notes: Vec<String>,
}

/// The native bridges this host applies.
#[derive(Debug)]
pub struct NativeBridges {
    host: BridgeHost,
}

impl NativeBridges {
    /// Applies bridges where `host` says.
    #[must_use]
    pub fn new(host: BridgeHost) -> Self {
        Self { host }
    }

    /// Brings one package's bridge to what its installation wants.
    ///
    /// # Errors
    ///
    /// Returns an error when this host's own record cannot be read or written.
    pub fn reconcile(
        &self,
        plugin_id: &PluginId,
        wanted: Option<&BridgeTarget>,
    ) -> Result<Settled> {
        let _ = (plugin_id, wanted, &self.host);
        Ok(Settled::Unchanged)
    }

    /// Returns what one release's applied bridge yields, where it is applied.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be read.
    pub fn facts(
        &self,
        plugin_id: &PluginId,
        package_digest: PayloadDigest,
    ) -> Result<Option<BridgeFacts>> {
        let _ = (plugin_id, package_digest);
        Ok(None)
    }

    /// Reports every package's bridge.
    ///
    /// # Errors
    ///
    /// Returns an error when a record cannot be read.
    pub fn reports(&self) -> Result<Vec<BridgeReport>> {
        Ok(Vec::new())
    }

    /// Stops the next run before its `step`th durable step, as a stopped host would.
    #[cfg(feature = "testing")]
    pub fn stop_before(&self, step: usize) {
        let _ = step;
    }

    /// Runs `hook` with each destination just before it is published.
    #[cfg(feature = "testing")]
    pub fn before_publishing(&self, hook: impl Fn(&std::path::Path) + Send + Sync + 'static) {
        let _ = hook;
    }
}
