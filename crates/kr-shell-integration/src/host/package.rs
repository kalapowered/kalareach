//! Which shell package a session launches, and what the worker records about it.
//!
//! Managed mode launches a KalaReach-qualified package: the exact binary the reader patch was built
//! into, with the flags that package declares, and the module tree it will load. Nothing is
//! substituted. A request for a shell no package qualifies is refused by name, because a session
//! that quietly ran the system shell instead would claim a contract nothing behind it implements.
//!
//! # Where packages live
//!
//! A build writes each package under `<root>/<shell>/<identity>/`, with a manifest beside the
//! binary. `<root>` is the installation's own shell directory, or whatever
//! [`PACKAGE_ROOT_VARIABLE`] names, which is how a test runs against a package that was just built.

use std::path::{Path, PathBuf};

use kr_protocol::error::{ErrorCode, ProtocolError};
use serde::{Deserialize, Serialize};

use crate::contract::qualification::ShellKind;
use crate::contract::transport::{ModuleEntry, PatchRevision, ShellIdentity};

/// The variable that names the directory the qualified packages were built into.
pub const PACKAGE_ROOT_VARIABLE: &str = "KR_SHELL_PACKAGES";

/// The manifest each package carries beside its binary.
pub const MANIFEST_BASENAME: &str = "package.json";

/// What a package's manifest says it is.
///
/// Every path in it is relative to the manifest's own directory, so a package that was copied
/// somewhere else is still the same package. The identity fields are the ones the handshake
/// carries, which is what makes a qualification claim checkable rather than asserted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageManifest {
    /// Which managed shell this package is.
    pub shell: ShellKind,
    /// The shell binary, relative to the manifest's directory.
    pub executable: String,
    /// The upstream shell version it was built from.
    pub upstream_version: String,
    /// The editor ABI revision the reader patch was built against.
    pub editor_abi: String,
    /// The package's own integration version.
    pub integration_version: String,
    /// The flags this package declares an interactive root shell is launched with.
    pub interactive_flags: Vec<String>,
    /// Every published reader patch in the package.
    pub patches: Vec<PatchRevision>,
    /// The module tree the shell will load, with each module's search path relative to the
    /// manifest's directory.
    pub modules: Vec<ModuleEntry>,
    /// The guarded startup entry this package installs, relative to the manifest's directory.
    pub startup_entry: String,
}

/// One qualified package, resolved to absolute paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShellPackage {
    /// The manifest, as it was read.
    pub manifest: PackageManifest,
    /// The directory the manifest was read from.
    pub directory: PathBuf,
}

impl ShellPackage {
    /// Returns the executable a session launches.
    #[must_use]
    pub fn executable(&self) -> PathBuf {
        self.directory.join(&self.manifest.executable)
    }

    /// Returns the guarded startup entry this package installs.
    #[must_use]
    pub fn startup_entry(&self) -> PathBuf {
        self.directory.join(&self.manifest.startup_entry)
    }

    /// Returns the flags an interactive root shell of this package is launched with.
    #[must_use]
    pub fn interactive_flags(&self) -> Vec<String> {
        self.manifest.interactive_flags.clone()
    }

    /// Returns the identity a bridge of this package declares.
    ///
    /// The worker records it whole and checks a hello against it, so a package that was rebuilt
    /// with a different reader patch is a different package rather than the same one.
    #[must_use]
    pub fn identity(&self) -> ShellIdentity {
        ShellIdentity {
            kind: self.manifest.shell,
            executable: self.executable().display().to_string(),
            upstream_version: self.manifest.upstream_version.clone(),
            editor_abi: self.manifest.editor_abi.clone(),
            integration_version: self.manifest.integration_version.clone(),
            patches: self.manifest.patches.clone(),
            modules: self
                .manifest
                .modules
                .iter()
                .map(|module| ModuleEntry {
                    name: module.name.clone(),
                    search_path: self
                        .directory
                        .join(&module.search_path)
                        .display()
                        .to_string(),
                    editor_abi: module.editor_abi.clone(),
                })
                .collect(),
        }
    }
}

/// Why a shell cannot be launched in managed mode.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PackageFault {
    /// No package directory is installed or configured.
    #[error("no qualified shell packages are installed; {PACKAGE_ROOT_VARIABLE} names none either")]
    NoPackages,
    /// The shell the request named has no qualified package.
    #[error(
        "{requested} has no qualified KalaReach package, so it cannot claim the managed contract"
    )]
    Unqualified {
        /// What was asked for.
        requested: String,
    },
    /// The package directory exists but its manifest cannot be read.
    #[error("the package at {path} cannot be read: {detail}")]
    Unreadable {
        /// Where the package is.
        path: String,
        /// What went wrong.
        detail: String,
    },
    /// The manifest names a binary that is not there.
    #[error("the package at {path} names an executable that is not installed")]
    MissingExecutable {
        /// Where the package is.
        path: String,
    },
    /// A request for a non-interactive script, which never becomes an interactive session shell.
    #[error("a script invocation is not an interactive root shell: {detail}")]
    NotInteractive {
        /// What the request asked for.
        detail: String,
    },
}

impl PackageFault {
    /// Returns the stable protocol code this refusal carries.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::NoPackages | Self::Unqualified { .. } | Self::NotInteractive { .. } => {
                ErrorCode::ShellIntegrationUnsupported
            }
            Self::Unreadable { .. } | Self::MissingExecutable { .. } => {
                ErrorCode::ResourceUnavailable
            }
        }
    }

    /// Returns this refusal as a protocol error.
    #[must_use]
    pub fn to_protocol_error(&self) -> ProtocolError {
        ProtocolError::new(self.code(), self.to_string())
    }
}

/// Returns where a build writes the qualified packages on this platform.
///
/// The same directory the package build writes to, so an installation that has built its packages
/// finds them without being configured. [`PACKAGE_ROOT_VARIABLE`] overrides it.
#[must_use]
pub fn default_package_root() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    #[cfg(target_vendor = "apple")]
    {
        home.join("Library/Caches/kalareach/shells")
    }
    #[cfg(not(target_vendor = "apple"))]
    {
        std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".cache"))
            .join("kalareach/shells")
    }
}

/// The qualified packages this installation has.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PackageSet {
    packages: Vec<ShellPackage>,
}

impl PackageSet {
    /// Reads every package under a root.
    ///
    /// A directory that holds no manifest is not a failure: an installation with only the Zsh
    /// package has only the Zsh package, and a request for one of the others is refused by name.
    ///
    /// # Errors
    ///
    /// Returns [`PackageFault::Unreadable`] when a manifest exists and cannot be parsed, because a
    /// package that cannot say what it is must not be launched as though it could.
    pub fn discover(root: &Path) -> Result<Self, PackageFault> {
        let mut packages = Vec::new();
        for kind in ShellKind::ALL {
            let directory = root.join(kind.as_str());
            for candidate in manifest_candidates(&directory) {
                let text = match std::fs::read_to_string(&candidate) {
                    Ok(text) => text,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => {
                        return Err(PackageFault::Unreadable {
                            path: candidate.display().to_string(),
                            detail: error.to_string(),
                        });
                    }
                };
                let manifest: PackageManifest =
                    serde_json::from_str(&text).map_err(|error| PackageFault::Unreadable {
                        path: candidate.display().to_string(),
                        detail: error.to_string(),
                    })?;
                if manifest.shell != *kind {
                    return Err(PackageFault::Unreadable {
                        path: candidate.display().to_string(),
                        detail: format!(
                            "the manifest says {} and it is installed as {}",
                            manifest.shell,
                            kind.as_str()
                        ),
                    });
                }
                let directory = candidate
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| directory.clone());
                packages.push(ShellPackage {
                    manifest,
                    directory,
                });
                break;
            }
        }
        Ok(Self { packages })
    }

    /// Reads the packages this installation is configured with.
    ///
    /// [`PACKAGE_ROOT_VARIABLE`] wins where it is set, so a test or a build runs against the
    /// package it just produced rather than the one that happens to be installed.
    ///
    /// # Errors
    ///
    /// Returns [`PackageFault::Unreadable`] when a manifest cannot be parsed.
    pub fn installed(default_root: &Path) -> Result<Self, PackageFault> {
        let root = std::env::var_os(PACKAGE_ROOT_VARIABLE)
            .map(PathBuf::from)
            .unwrap_or_else(|| default_root.to_path_buf());
        Self::discover(&root)
    }

    /// Returns every package, in shell order.
    #[must_use]
    pub fn packages(&self) -> &[ShellPackage] {
        &self.packages
    }

    /// Returns the package for one shell.
    #[must_use]
    pub fn get(&self, kind: ShellKind) -> Option<&ShellPackage> {
        self.packages
            .iter()
            .find(|package| package.manifest.shell == kind)
    }

    /// Resolves the package a create request selects.
    ///
    /// A request that names no shell takes the first qualified package this installation has, in
    /// the order [`ShellKind::ALL`] lists them. A request that names one takes that one or is
    /// refused; nothing else is ever launched in its place.
    ///
    /// # Errors
    ///
    /// Returns [`PackageFault::NotInteractive`] for a script invocation, [`PackageFault::NoPackages`]
    /// when the installation has none, [`PackageFault::Unqualified`] when the named shell has no
    /// package, and [`PackageFault::MissingExecutable`] when the manifest names a binary that is
    /// not installed.
    pub fn select(&self, requested: Option<&str>) -> Result<&ShellPackage, PackageFault> {
        let package = match requested {
            None => self.default_package().ok_or(PackageFault::NoPackages)?,
            Some(requested) => {
                let requested = requested.trim();
                if let Some(detail) = script_invocation(requested) {
                    return Err(PackageFault::NotInteractive { detail });
                }
                let name = executable_name(requested);
                let kind = ShellKind::ALL
                    .iter()
                    .copied()
                    .find(|kind| kind.as_str() == name || alias(*kind) == name)
                    .ok_or_else(|| PackageFault::Unqualified {
                        requested: requested.to_owned(),
                    })?;
                self.get(kind).ok_or_else(|| PackageFault::Unqualified {
                    requested: requested.to_owned(),
                })?
            }
        };
        if !package.executable().is_file() {
            return Err(PackageFault::MissingExecutable {
                path: package.directory.display().to_string(),
            });
        }
        Ok(package)
    }
}

impl PackageSet {
    /// Returns the package a request that names no shell takes.
    ///
    /// The shell this user's own login uses, when a package qualifies it: a session should start
    /// the shell the person already has. Failing that, the first package this installation holds,
    /// in the order [`ShellKind::ALL`] lists them.
    fn default_package(&self) -> Option<&ShellPackage> {
        let configured = std::env::var("SHELL")
            .ok()
            .map(|shell| executable_name(&shell));
        configured
            .and_then(|name| {
                ShellKind::ALL
                    .iter()
                    .copied()
                    .find(|kind| kind.as_str() == name || alias(*kind) == name)
            })
            .and_then(|kind| self.get(kind))
            .or_else(|| self.packages.first())
    }
}

/// Returns the manifests a package directory may hold, newest layout first.
fn manifest_candidates(directory: &Path) -> Vec<PathBuf> {
    let mut candidates = vec![directory.join(MANIFEST_BASENAME)];
    // A build writes one identity directory per build, so an installation can hold more than one.
    // They are read in name order, which is stable, and the first complete one is the package.
    if let Ok(entries) = std::fs::read_dir(directory) {
        let mut nested: Vec<PathBuf> = entries
            .flatten()
            .map(|entry| entry.path().join(MANIFEST_BASENAME))
            .collect();
        nested.sort();
        candidates.extend(nested);
    }
    candidates
}

/// Returns the alternative name a shell's binary is installed under.
const fn alias(kind: ShellKind) -> &'static str {
    match kind {
        ShellKind::Zsh => "zsh",
        ShellKind::Bash => "bash",
        ShellKind::Fish => "fish",
        ShellKind::PowerShell => "pwsh",
    }
}

/// Returns the file name of a path or command.
fn executable_name(requested: &str) -> String {
    let name = Path::new(requested)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or(requested)
        .to_ascii_lowercase();
    name.strip_suffix(".exe").unwrap_or(&name).to_owned()
}

/// Returns why a request is a script invocation rather than a shell.
///
/// A create request names an executable, not a command line. Section 7 is explicit that a
/// non-interactive script request never becomes an interactive shell, so anything carrying an
/// option, a redirection or a separator is refused rather than run.
///
/// A path with a space in it is a path. `/Applications/Some Shell/bin/zsh` names a file, and
/// treating every space as an argument boundary would refuse a perfectly ordinary installation.
fn script_invocation(requested: &str) -> Option<String> {
    if requested.is_empty() || Path::new(requested).is_file() {
        return None;
    }
    let script = |detail: &str| {
        Some(format!(
            "{requested} is {detail} rather than the path of a shell to run interactively"
        ))
    };
    if requested.contains(['<', '>', '|', ';', '&', '`', '$']) {
        return script("a command line");
    }
    if requested.split_whitespace().count() > 1 {
        // The whole string does not name a file, so the spaces separate words rather than being
        // part of one path: `bash script.sh` is somebody asking for a script to be run.
        return script("a command line");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(kind: ShellKind) -> PackageManifest {
        PackageManifest {
            shell: kind,
            executable: "bin/shell".to_owned(),
            upstream_version: "5.9".to_owned(),
            editor_abi: "zle-5.9".to_owned(),
            integration_version: "1".to_owned(),
            interactive_flags: vec!["-l".to_owned(), "-i".to_owned()],
            patches: vec![PatchRevision {
                name: "reader-mailbox".to_owned(),
                upstream_revision: "5.9".to_owned(),
                revision: "1".to_owned(),
            }],
            modules: vec![ModuleEntry {
                name: "kr-bridge".to_owned(),
                search_path: "lib".to_owned(),
                editor_abi: "zle-5.9".to_owned(),
            }],
            startup_entry: "share/entry.sh".to_owned(),
        }
    }

    fn install(root: &Path, kind: ShellKind, nested: bool) {
        let directory = if nested {
            root.join(kind.as_str()).join("identity-1")
        } else {
            root.join(kind.as_str())
        };
        std::fs::create_dir_all(directory.join("bin")).expect("creates the package");
        std::fs::write(directory.join("bin/shell"), b"#!/bin/sh\n").expect("writes the binary");
        std::fs::write(
            directory.join(MANIFEST_BASENAME),
            serde_json::to_string(&manifest(kind)).expect("encodes"),
        )
        .expect("writes the manifest");
    }

    #[test]
    fn a_request_for_an_unqualified_shell_is_refused_by_name() {
        let root = tempfile::tempdir().expect("a directory");
        install(root.path(), ShellKind::Zsh, false);
        let set = PackageSet::discover(root.path()).expect("reads the packages");
        assert_eq!(set.packages().len(), 1);
        let fault = set.select(Some("/bin/ksh")).expect_err("refused");
        assert_eq!(fault.code(), ErrorCode::ShellIntegrationUnsupported);
        assert!(matches!(fault, PackageFault::Unqualified { .. }), "{fault}");
        // A shell KalaReach does qualify, but this installation has no package for.
        let fault = set.select(Some("bash")).expect_err("refused");
        assert!(matches!(fault, PackageFault::Unqualified { .. }), "{fault}");
    }

    #[test]
    fn a_script_invocation_never_becomes_an_interactive_shell() {
        let root = tempfile::tempdir().expect("a directory");
        install(root.path(), ShellKind::Bash, true);
        let set = PackageSet::discover(root.path()).expect("reads the packages");
        for request in [
            "bash -c 'echo hello'",
            "zsh -lc make",
            "zsh > /tmp/out",
            "sh; rm -rf /",
        ] {
            let fault = set.select(Some(request)).expect_err("refused");
            assert!(
                matches!(fault, PackageFault::NotInteractive { .. }),
                "{request}: {fault}"
            );
            assert_eq!(fault.code(), ErrorCode::ShellIntegrationUnsupported);
        }
    }

    #[test]
    fn a_path_with_a_space_in_it_is_a_path() {
        let root = tempfile::tempdir().expect("a directory");
        let spaced = root.path().join("Some Shell/bin");
        std::fs::create_dir_all(&spaced).expect("creates the directory");
        let executable = spaced.join("zsh");
        std::fs::write(&executable, b"#!/bin/sh\n").expect("writes");
        install(root.path(), ShellKind::Zsh, false);
        let set = PackageSet::discover(root.path()).expect("reads the package");
        // It names a file, so it is a path rather than a command line, and the package that
        // qualifies that shell is what a session launches.
        let package = set
            .select(Some(executable.to_str().expect("utf-8")))
            .expect("qualified");
        assert_eq!(package.manifest.shell, ShellKind::Zsh);

        // A shell no package qualifies, at a path with a space in it, is refused as unqualified
        // rather than as a script.
        let other = spaced.join("ksh");
        std::fs::write(&other, b"#!/bin/sh\n").expect("writes");
        let fault = set
            .select(Some(other.to_str().expect("utf-8")))
            .expect_err("refused");
        assert!(matches!(fault, PackageFault::Unqualified { .. }), "{fault}");
    }

    #[test]
    fn a_package_is_launched_as_the_exact_binary_it_was_built_as() {
        let root = tempfile::tempdir().expect("a directory");
        install(root.path(), ShellKind::Zsh, true);
        let set = PackageSet::discover(root.path()).expect("reads the packages");
        let package = set.select(Some("zsh")).expect("qualified");
        assert_eq!(
            package.executable(),
            root.path().join("zsh/identity-1/bin/shell")
        );
        assert_eq!(package.interactive_flags(), vec!["-l", "-i"]);
        let identity = package.identity();
        assert_eq!(identity.kind, ShellKind::Zsh);
        assert_eq!(identity.editor_abi, "zle-5.9");
        assert_eq!(identity.patches.len(), 1);
        assert_eq!(
            identity.modules[0].search_path,
            root.path().join("zsh/identity-1/lib").display().to_string()
        );
        assert_eq!(
            package.startup_entry(),
            root.path().join("zsh/identity-1/share/entry.sh")
        );
    }

    #[test]
    fn an_installation_with_no_packages_says_so() {
        let root = tempfile::tempdir().expect("a directory");
        let set = PackageSet::discover(root.path()).expect("reads nothing");
        assert!(set.packages().is_empty());
        let fault = set.select(None).expect_err("refused");
        assert!(matches!(fault, PackageFault::NoPackages), "{fault}");
        assert_eq!(fault.code(), ErrorCode::ShellIntegrationUnsupported);
    }

    #[test]
    fn a_manifest_that_disagrees_with_where_it_is_installed_is_refused() {
        let root = tempfile::tempdir().expect("a directory");
        let directory = root.path().join("zsh");
        std::fs::create_dir_all(&directory).expect("creates the directory");
        std::fs::write(
            directory.join(MANIFEST_BASENAME),
            serde_json::to_string(&manifest(ShellKind::Bash)).expect("encodes"),
        )
        .expect("writes the manifest");
        let fault = PackageSet::discover(root.path()).expect_err("refused");
        assert!(matches!(fault, PackageFault::Unreadable { .. }), "{fault}");
    }
}
