//! The on-disk package layout.
//!
//! A package is a directory. `plugin.json` names every other file in it by digest, so the manifest
//! digest covers the rest of the package by transitivity. The manifest does not name itself: its
//! own digest and length live in the catalogue index entry that points at it, which is what a host
//! pins.
//!
//! | File | Required | What it is |
//! | --- | --- | --- |
//! | `plugin.json` | yes | The manifest |
//! | `presentation.json` | yes | The document nodes and controls |
//! | `connector.json` | no | The declarative native-proxy table |
//! | `component.wasm` | no | The Wasm component |
//! | anything else | no | Assets, bridge files, skills and fixtures, each declared in the manifest |
//!
//! Nothing undeclared is permitted. A file on disk that the manifest does not name is a finding,
//! not a file the host quietly ignores, because a package whose contents differ from its manifest
//! is a package whose hash does not mean what it says.

use crate::connector::ConnectorManifest;
use crate::digest::PayloadDigest;
use crate::paths::PackagePath;
use crate::plugin::PluginManifest;
use crate::presentation::PresentationManifest;

/// The manifest file name.
pub const MANIFEST_FILE: &str = "plugin.json";

/// The presentation file name.
pub const PRESENTATION_FILE: &str = "presentation.json";

/// The connector file name.
pub const CONNECTOR_FILE: &str = "connector.json";

/// The conventional component file name.
pub const COMPONENT_FILE: &str = "component.wasm";

/// Maximum number of files in one package.
pub const MAX_PACKAGE_FILES: usize = 512;

/// Maximum total size of one package directory.
pub const MAX_PACKAGE_BYTES: u64 = 64 * crate::limits::MIB;

/// One file found in a package directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageFile {
    /// Its path relative to the package directory.
    pub path: PackagePath,
    /// Its exact length in bytes.
    pub size_bytes: u64,
    /// Its SHA-256 digest.
    pub digest: PayloadDigest,
}

/// A package whose manifests parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Package {
    /// The manifest.
    pub manifest: PluginManifest,
    /// The presentation document.
    pub presentation: PresentationManifest,
    /// The native-proxy table, where the package ships one.
    pub connector: Option<ConnectorManifest>,
    /// Every file in the directory.
    pub files: Vec<PackageFile>,
}

impl Package {
    /// Returns the file at `path`, where the package has one.
    #[must_use]
    pub fn file(&self, path: &PackagePath) -> Option<&PackageFile> {
        self.files.iter().find(|file| &file.path == path)
    }

    /// Returns the total size of every file in the directory.
    #[must_use]
    pub fn total_size_bytes(&self) -> u64 {
        self.files.iter().map(|file| file.size_bytes).sum()
    }
}
