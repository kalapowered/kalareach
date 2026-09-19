//! Which shell package a session launches, and what the worker records about it.
//!
//! Managed mode launches a KalaReach-qualified package: the exact binary the reader patch was built
//! into, with the flags that package declares, and the module tree it will load. Nothing is
//! substituted. A request for a shell no package qualifies is refused by name, because a session
//! that quietly ran the system shell instead would claim a contract nothing behind it implements.
//!
//! # Where packages live
//!
//! A build writes each package under `<root>/<shell>/<identity>/`, with its identity record beside
//! the binary and `<root>/<shell>/current` naming the identity the installation uses. `<root>` is
//! the installation's own shell directory, or whatever [`PACKAGE_ROOT_VARIABLE`] names, which is
//! how a test runs against a package that was just built.

use std::path::{Path, PathBuf};

use kr_protocol::error::{ErrorCode, ProtocolError};
use serde::{Deserialize, Serialize};

use crate::contract::qualification::ShellKind;
use crate::contract::transport::{ModuleEntry, PatchRevision, ShellIdentity};

/// The variable that names the directory the qualified packages were built into.
pub const PACKAGE_ROOT_VARIABLE: &str = "KR_SHELL_PACKAGES";

/// The identity record each package carries beside its binary.
pub const MANIFEST_BASENAME: &str = "kr-shell-identity.json";

/// The file beside a shell's packages that names the identity this installation uses.
pub const CURRENT_BASENAME: &str = "current";

/// What a package's identity record says it is.
///
/// This is the record `scripts/build-shells.sh` writes and the package declares in its handshake,
/// read here rather than restated: the identity fields are the ones the handshake carries, which is
/// what makes a qualification claim checkable rather than asserted. The record says more than this
/// host reads — the five declared mechanisms and the build's own inputs and compiler — and those
/// stay in the file for whoever needs them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageManifest {
    /// The identity a build computed from its own inputs, which also names the directory.
    pub identity: String,
    /// The shell this package is, and what it was built from.
    pub shell: PackageShell,
    /// The guarded startup entry this package installs.
    pub startup_entry: PackageStartupEntry,
}

/// What a package says about the shell inside it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageShell {
    /// Which managed shell this package is.
    pub kind: ShellKind,
    /// The shell binary, as the build installed it.
    pub executable: PathBuf,
    /// The upstream shell version it was built from.
    pub upstream_version: String,
    /// The editor ABI revision the reader patch was built against.
    pub editor_abi: String,
    /// The package's own integration version.
    pub integration_version: String,
    /// Every published reader patch in the package.
    ///
    /// Stated rather than defaulted, here and for the modules: a record that says nothing about
    /// its patches is a record this host cannot check, and a package with no modules says so by
    /// declaring an empty list.
    pub patches: Vec<PatchRevision>,
    /// The module tree the shell will load, with each module's own search path.
    pub modules: Vec<ModuleEntry>,
}

/// Where a package's guarded startup entry lives.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageStartupEntry {
    /// The file a startup entry sources, relative to the package's own directory.
    pub file: String,
}

/// Whether a root shell reads the user's login startup as well as its interactive startup.
///
/// Section 7 states the platform defaults: macOS runs normal login startup, including any path
/// changes it makes, and Linux does not unless a profile says so. It is a property of the session
/// being created rather than of the package, which is why a package is asked for its arguments in
/// one mode rather than asked what its arguments are.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum StartupMode {
    /// The interactive startup only.
    #[default]
    Interactive,
    /// The login startup as well.
    Login,
}

impl StartupMode {
    /// Returns what this platform does when nothing says otherwise.
    #[must_use]
    pub const fn for_host() -> Self {
        if cfg!(target_vendor = "apple") {
            Self::Login
        } else {
            Self::Interactive
        }
    }
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
    /// Reads the one package installed in a directory.
    ///
    /// The directory is an identity directory a build wrote, which is what a controller records
    /// when it resolves a create request's package: the worker then launches exactly the package
    /// its daemon qualified rather than resolving one of its own from its own environment. The
    /// same ownership rule applies as for a discovered package: a record naming paths outside the
    /// directory it sits in describes some other installation.
    ///
    /// # Errors
    ///
    /// Returns [`PackageFault::Unreadable`] when the directory holds no identity record, when the
    /// record cannot be parsed, or when it names paths outside itself, and
    /// [`PackageFault::MissingExecutable`] when the executable it names is not installed.
    pub fn read(directory: &Path) -> Result<Self, PackageFault> {
        let candidate = directory.join(MANIFEST_BASENAME);
        let package = read_manifest(&candidate, None, directory)?.ok_or_else(|| {
            PackageFault::Unreadable {
                path: candidate.display().to_string(),
                detail: "this directory holds no identity record".to_owned(),
            }
        })?;
        if !package.executable().is_file() {
            return Err(PackageFault::MissingExecutable {
                path: package.directory.display().to_string(),
            });
        }
        Ok(package)
    }

    /// Returns which managed shell this package is.
    #[must_use]
    pub const fn kind(&self) -> ShellKind {
        self.manifest.shell.kind
    }

    /// Returns the executable a session launches.
    #[must_use]
    pub fn executable(&self) -> PathBuf {
        self.own(&self.manifest.shell.executable)
    }

    /// Returns a path the record names, as this package's own copy of it.
    ///
    /// A build records the paths it installed, which are absolute and inside the directory it
    /// installed the package in. A package that was copied somewhere else carries paths that point
    /// back at the original, and launching that original would be launching a package this one
    /// only describes. So where a recorded path sits *inside its package* is the build's business
    /// and where the package sits is this installation's: the one is taken from the other.
    /// [`PackageSet::discover`] refuses a record whose paths say neither.
    fn own(&self, recorded: &Path) -> PathBuf {
        match self.inside(recorded) {
            // Nothing inside the package: the package itself, which a module search path may name.
            Some(tail) if tail.as_os_str().is_empty() => self.directory.clone(),
            Some(tail) => self.directory.join(tail),
            None => recorded.to_path_buf(),
        }
    }

    /// Returns where one recorded path sits inside the package, when it sits inside one.
    ///
    /// One root for the whole record, taken from the executable: every path a build recorded was
    /// installed under the same directory, so stripping each one against a root of its own would
    /// let two paths disagree about which installation they came from.
    fn inside(&self, recorded: &Path) -> Option<PathBuf> {
        let tail = if let Ok(tail) = recorded.strip_prefix(&self.directory) {
            tail.to_path_buf()
        } else if recorded.is_absolute() {
            let root = package_root(
                &self.manifest.shell.executable,
                self.kind(),
                &self.manifest.identity,
            )?;
            recorded.strip_prefix(&root).ok()?.to_path_buf()
        } else {
            recorded.to_path_buf()
        };
        within(&tail)
    }

    /// Returns whether every path this record names is one this package can answer for.
    ///
    /// A record that names something outside the package describes some other installation, and a
    /// path that climbs out of the package with `..` names one too. A file has to be a file inside
    /// the package; a module search path may be the package's own directory, which is a place
    /// rather than a file.
    fn owns_its_paths(&self) -> bool {
        if self.manifest.identity.is_empty() {
            return false;
        }
        let files = [
            self.manifest.shell.executable.as_path(),
            Path::new(&self.manifest.startup_entry.file),
        ];
        files.iter().all(|recorded| {
            self.inside(recorded)
                .is_some_and(|tail| !tail.as_os_str().is_empty())
        }) && self
            .manifest
            .shell
            .modules
            .iter()
            .all(|module| self.inside(Path::new(&module.search_path)).is_some())
    }

    /// Returns the guarded startup entry this package installs.
    #[must_use]
    pub fn startup_entry(&self) -> PathBuf {
        self.own(Path::new(&self.manifest.startup_entry.file))
    }

    /// Returns the arguments an interactive root shell of this package is launched with.
    ///
    /// The host's, not the package's: a package records what it was built from rather than how a
    /// session starts it. Section 7 states the defaults per platform, and they differ in one thing
    /// only, which is whether the shell reads the user's login startup as well as the interactive
    /// one. This host's own platform decides that; a profile that says otherwise is the caller's
    /// to pass to [`Self::arguments`].
    #[must_use]
    pub fn interactive_flags(&self) -> Vec<String> {
        self.arguments(StartupMode::for_host())
    }

    /// Returns the arguments this package's shell is launched with in one startup mode.
    #[must_use]
    pub fn arguments(&self, mode: StartupMode) -> Vec<String> {
        let login = mode == StartupMode::Login;
        match self.manifest.shell.kind {
            // Section 7: the packaged Zsh with `-l -i` on macOS, the packaged shell with `-i` on
            // Linux, and a Linux profile may ask for login startup.
            ShellKind::Zsh | ShellKind::Bash => {
                let mut arguments = Vec::new();
                if login {
                    arguments.push("-l".to_owned());
                }
                arguments.push("-i".to_owned());
                arguments
            }
            // Fish uses `--interactive` and adds `--login` for a login profile.
            ShellKind::Fish => {
                let mut arguments = Vec::new();
                if login {
                    arguments.push("--login".to_owned());
                }
                arguments.push("--interactive".to_owned());
                arguments
            }
            // PowerShell 7 with `-NoLogo`; its startup integration is the profile's, not an
            // argument, and it has no login-shell mode to ask for.
            ShellKind::PowerShell => vec!["-NoLogo".to_owned()],
        }
    }

    /// Returns what this package declares about itself, for the handshake to compare against.
    ///
    /// The whole record, not only the editor ABI and the integration version: two builds of one
    /// shell agree on both of those and are still two different readers.
    #[must_use]
    pub fn declaration(&self) -> crate::contract::transport::PackageDeclaration {
        let identity = self.identity();
        crate::contract::transport::PackageDeclaration {
            kind: identity.kind,
            executable: identity.executable,
            upstream_version: identity.upstream_version,
            editor_abi: identity.editor_abi,
            integration_version: identity.integration_version,
            patches: identity.patches,
            modules: identity.modules,
        }
    }

    /// Returns the identity a bridge of this package declares.
    ///
    /// The worker records it whole and checks a hello against it, so a package that was rebuilt
    /// with a different reader patch is a different package rather than the same one.
    #[must_use]
    pub fn identity(&self) -> ShellIdentity {
        ShellIdentity {
            kind: self.manifest.shell.kind,
            executable: self.executable().display().to_string(),
            upstream_version: self.manifest.shell.upstream_version.clone(),
            editor_abi: self.manifest.shell.editor_abi.clone(),
            integration_version: self.manifest.shell.integration_version.clone(),
            patches: self.manifest.shell.patches.clone(),
            modules: self
                .manifest
                .shell
                .modules
                .iter()
                .map(|module| ModuleEntry {
                    name: module.name.clone(),
                    search_path: self
                        .own(Path::new(&module.search_path))
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

/// Reads one identity record into a package.
///
/// `expected` is the shell the enclosing directory installs it as, where there is one: a record
/// that says it is a different shell describes some other package and is refused rather than
/// launched. `fallback` is the directory a record with no parent belongs to.
///
/// Returns `None` when the record is not there, which is what makes a directory holding no
/// manifest an installation without that package rather than a failure.
fn read_manifest(
    candidate: &Path,
    expected: Option<ShellKind>,
    fallback: &Path,
) -> Result<Option<ShellPackage>, PackageFault> {
    let text = match std::fs::read_to_string(candidate) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
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
    if let Some(expected) = expected
        && manifest.shell.kind != expected
    {
        return Err(PackageFault::Unreadable {
            path: candidate.display().to_string(),
            detail: format!(
                "the record says {} and it is installed as {}",
                manifest.shell.kind,
                expected.as_str()
            ),
        });
    }
    let directory = candidate
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| fallback.to_path_buf());
    let package = ShellPackage {
        manifest,
        directory,
    };
    // A record whose paths name neither this directory nor a directory of its own identity
    // describes some other installation. Launching what it names would launch that one, and this
    // host has no way to say which package it would be.
    if !package.owns_its_paths() {
        return Err(PackageFault::Unreadable {
            path: candidate.display().to_string(),
            detail: "it names paths outside the package it is in".to_owned(),
        });
    }
    Ok(Some(package))
}

/// The qualified packages this installation has.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PackageSet {
    packages: Vec<ShellPackage>,
    /// The shells whose installed record this host cannot read, with what is wrong with each.
    ///
    /// One shell's broken record says nothing about another's. It is kept here and reported when
    /// that shell is asked for, rather than refusing the whole installation: a machine whose
    /// PowerShell package names a binary outside itself still has a Zsh package that is exactly
    /// what it says it is.
    faults: std::collections::BTreeMap<ShellKind, PackageFault>,
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
        let mut faults = std::collections::BTreeMap::new();
        for kind in ShellKind::ALL {
            let directory = root.join(kind.as_str());
            let candidates = match manifest_candidates(&directory) {
                Ok(candidates) => candidates,
                Err(fault) => {
                    faults.insert(*kind, fault);
                    continue;
                }
            };
            for candidate in candidates {
                match read_manifest(&candidate, Some(*kind), &directory) {
                    Ok(Some(package)) => packages.push(package),
                    Ok(None) => continue,
                    // A record that cannot say what it is must not be launched as though it
                    // could. What it must not do either is take the other shells with it.
                    Err(fault) => {
                        faults.insert(*kind, fault);
                    }
                }
                break;
            }
        }
        Ok(Self { packages, faults })
    }

    /// Returns what is wrong with one shell's installed record, when this host cannot read it.
    #[must_use]
    pub fn fault(&self, kind: ShellKind) -> Option<&PackageFault> {
        self.faults.get(&kind)
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
            .find(|package| package.manifest.shell.kind == kind)
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
            None => self.default_package()?,
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
                // A request that names a shell whose record this host cannot read is told what is
                // wrong with that record rather than that the shell is unqualified.
                if let Some(fault) = self.faults.get(&kind) {
                    return Err(fault.clone());
                }
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
    fn default_package(&self) -> Result<&ShellPackage, PackageFault> {
        let configured = std::env::var("SHELL")
            .ok()
            .map(|shell| executable_name(&shell))
            .and_then(|name| {
                ShellKind::ALL
                    .iter()
                    .copied()
                    .find(|kind| kind.as_str() == name || alias(*kind) == name)
            });
        if let Some(kind) = configured {
            // The shell this user's own login uses, and its own record's fault where it has one: a
            // create that named no shell must not quietly start a different one because the shell
            // the person actually uses has a record this host cannot read.
            if let Some(fault) = self.faults.get(&kind) {
                return Err(fault.clone());
            }
            if let Some(package) = self.get(kind) {
                return Ok(package);
            }
        }
        self.packages.first().ok_or(PackageFault::NoPackages)
    }
}

/// Returns the manifests a package directory may hold, newest layout first.
fn manifest_candidates(directory: &Path) -> Result<Vec<PathBuf>, PackageFault> {
    // What the installation says it is using, and the only answer where it says anything. A build
    // writes one identity directory per build and keeps the ones before it, so an installation
    // holds every package it ever built; this file names the one that counts. A pointer that names
    // nothing is a broken installation rather than an invitation to pick an older build.
    let pointer = directory.join(CURRENT_BASENAME);
    match std::fs::read_to_string(&pointer) {
        Ok(current) => {
            let current = current.trim();
            if current.is_empty() {
                return Err(PackageFault::Unreadable {
                    path: pointer.display().to_string(),
                    detail: "it names no identity".to_owned(),
                });
            }
            let record = directory.join(current).join(MANIFEST_BASENAME);
            if !record.is_file() {
                return Err(PackageFault::Unreadable {
                    path: pointer.display().to_string(),
                    detail: format!("it names {current}, which has no identity record"),
                });
            }
            return Ok(vec![record]);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(PackageFault::Unreadable {
                path: pointer.display().to_string(),
                detail: error.to_string(),
            });
        }
    }
    // No pointer at all: a record beside the shell's own directory, or one identity directory and
    // no more. Two of them with nothing to choose between is not a choice this host may make.
    let direct = directory.join(MANIFEST_BASENAME);
    if direct.is_file() {
        return Ok(vec![direct]);
    }
    let mut nested: Vec<PathBuf> = match std::fs::read_dir(directory) {
        Ok(entries) => entries
            .flatten()
            .map(|entry| entry.path().join(MANIFEST_BASENAME))
            .filter(|record| record.is_file())
            .collect(),
        Err(_) => Vec::new(),
    };
    nested.sort();
    if nested.len() > 1 {
        return Err(PackageFault::Unreadable {
            path: directory.display().to_string(),
            detail: format!(
                "{} identity directories and no {CURRENT_BASENAME} naming one of them",
                nested.len()
            ),
        });
    }
    Ok(nested)
}

/// Returns the package directory an installed path belongs to.
///
/// A build installs a package at `<root>/<shell>/<identity>`, so the ancestor whose own name is
/// that identity and whose parent's name is that shell is the package's own directory. The deepest
/// such ancestor, because an installation root may hold a directory of either name and the one
/// nearest the file is the one that installed it. The path may be that directory itself.
fn package_root(recorded: &Path, kind: ShellKind, identity: &str) -> Option<PathBuf> {
    if identity.is_empty() {
        return None;
    }
    let mut ancestor = Some(recorded);
    while let Some(directory) = ancestor {
        let named = directory.file_name().is_some_and(|name| name == identity);
        let under = directory
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name == kind.as_str());
        if named && under {
            return Some(directory.to_path_buf());
        }
        ancestor = directory.parent();
    }
    None
}

/// Returns a suffix that stays inside whatever it is joined onto, with nothing redundant left in.
///
/// Nothing rooted and nothing that climbs: a path with `..` in it names a place outside the
/// package however it is joined. A leading `.` says nothing and is dropped. An empty result is the
/// directory itself, which is a place rather than a file, and the caller decides whether that is
/// an answer to the question it asked.
fn within(tail: &Path) -> Option<PathBuf> {
    let mut inside = PathBuf::new();
    for component in tail.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(part) => inside.push(part),
            _ => return None,
        }
    }
    Some(inside)
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
            identity: "identity-1".to_owned(),
            shell: PackageShell {
                kind,
                executable: PathBuf::from("bin/shell"),
                upstream_version: "5.9".to_owned(),
                editor_abi: "zle-5.9".to_owned(),
                integration_version: "1".to_owned(),
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
            },
            startup_entry: PackageStartupEntry {
                file: "share/entry.sh".to_owned(),
            },
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

    /// Writes an identity directory and names it in the shell's `current` pointer.
    fn install_identity(root: &Path, kind: ShellKind, identity: &str) {
        let directory = root.join(kind.as_str()).join(identity);
        std::fs::create_dir_all(directory.join("bin")).expect("creates the package");
        std::fs::write(directory.join("bin/shell"), b"#!/bin/sh\n").expect("writes the binary");
        let mut record = manifest(kind);
        record.identity = identity.to_owned();
        std::fs::write(
            directory.join(MANIFEST_BASENAME),
            serde_json::to_string(&record).expect("encodes"),
        )
        .expect("writes the record");
    }

    /// KR-REQ-07.19: one shell's unreadable record does not refuse the shells beside it.
    #[test]
    fn a_record_this_host_cannot_read_refuses_its_own_shell_and_no_other() {
        let root = tempfile::tempdir().expect("a directory");
        install(root.path(), ShellKind::Zsh, true);
        // A PowerShell package whose record names a binary outside itself: an installation can
        // hold one, and a session asking for Zsh is not about it.
        let powershell = root.path().join("powershell").join("identity-1");
        std::fs::create_dir_all(&powershell).expect("creates the package");
        std::fs::write(
            powershell.join(MANIFEST_BASENAME),
            r#"{"identity":"identity-1",
               "shell":{"kind":"powershell","executable":"/opt/elsewhere/bin/pwsh",
                        "upstream_version":"7.4","editor_abi":"psreadline-2.3",
                        "integration_version":"1","patches":[],"modules":[]},
               "startup_entry":{"file":"startup/entry"}}"#,
        )
        .expect("writes the record");
        std::fs::write(
            root.path().join("powershell").join(CURRENT_BASENAME),
            "identity-1",
        )
        .expect("names the identity");

        let set = PackageSet::discover(root.path()).expect("reads what it can");
        assert_eq!(
            set.packages().len(),
            1,
            "the readable package is still an installation this host has"
        );
        assert_eq!(
            set.select(Some("zsh")).expect("qualified").kind(),
            ShellKind::Zsh
        );
        // And the shell whose record is wrong is refused with what is wrong with it.
        let fault = set.select(Some("pwsh")).expect_err("refused");
        assert!(
            fault.to_string().contains("outside the package"),
            "the refusal says what is wrong with that record: {fault}"
        );
        assert!(set.fault(ShellKind::PowerShell).is_some());
        assert!(set.fault(ShellKind::Zsh).is_none());
    }

    #[test]
    fn the_installation_launches_the_identity_its_pointer_names() {
        // A build keeps every identity it ever produced, so the pointer is the only thing that says
        // which one this installation uses. Reading the newest, or the first by name, would launch
        // a package somebody replaced.
        let root = tempfile::tempdir().expect("a directory");
        install_identity(root.path(), ShellKind::Zsh, "aaaa-old");
        install_identity(root.path(), ShellKind::Zsh, "zzzz-new");
        std::fs::write(root.path().join("zsh/current"), "zzzz-new").expect("names one");

        let set = PackageSet::discover(root.path()).expect("reads the packages");
        let package = set.get(ShellKind::Zsh).expect("the one it names");
        assert_eq!(package.manifest.identity, "zzzz-new");
        assert!(
            package
                .executable()
                .starts_with(root.path().join("zsh/zzzz-new")),
            "{}",
            package.executable().display()
        );

        // A pointer that names nothing there is a broken installation, not a reason to pick
        // another build.
        std::fs::write(root.path().join("zsh/current"), "gone").expect("names a missing one");
        let refused = PackageSet::discover(root.path()).expect("reads what it can");
        let fault = refused
            .fault(ShellKind::Zsh)
            .expect("this shell's record is refused");
        assert!(matches!(fault, PackageFault::Unreadable { .. }), "{fault}");
        assert!(
            refused.select(Some("zsh")).is_err(),
            "and so is a request for it"
        );

        // And two identities with nothing naming one of them is not a choice this host may make.
        std::fs::remove_file(root.path().join("zsh/current")).expect("removes the pointer");
        let refused = PackageSet::discover(root.path()).expect("reads what it can");
        let fault = refused
            .fault(ShellKind::Zsh)
            .expect("this shell's record is refused");
        assert!(matches!(fault, PackageFault::Unreadable { .. }), "{fault}");
        assert!(
            refused.select(Some("zsh")).is_err(),
            "and so is a request for it"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_package_that_was_copied_launches_the_copy_rather_than_the_original() {
        // A record names the paths the build installed. A copy of that package carries them
        // unchanged, and launching them would launch the package this one only describes.
        let original = tempfile::tempdir().expect("a directory");
        install_identity(original.path(), ShellKind::Zsh, "identity-1");
        std::fs::write(original.path().join("zsh/current"), "identity-1").expect("names one");
        let installed = original.path().join("zsh/identity-1");
        let mut record = manifest(ShellKind::Zsh);
        record.identity = "identity-1".to_owned();
        record.shell.executable = installed.join("bin/zsh");
        // The layout a build makes, three components deep, which is what the real Zsh package has.
        record.shell.modules = vec![ModuleEntry {
            name: "zsh/zle".to_owned(),
            search_path: installed.join("lib/zsh/5.9").display().to_string(),
            editor_abi: "zle-5.9".to_owned(),
        }];
        record.startup_entry.file = "startup/kr-zshrc.zsh".to_owned();
        std::fs::create_dir_all(installed.join("lib/zsh/5.9")).expect("creates the module tree");
        std::fs::write(installed.join("bin/zsh"), b"#!/bin/sh\n").expect("writes the binary");
        std::fs::write(
            installed.join(MANIFEST_BASENAME),
            serde_json::to_string(&record).expect("encodes"),
        )
        .expect("writes the record");

        // The same package somewhere else, with the original still there.
        let copy = tempfile::tempdir().expect("a directory");
        let there = copy.path().join("zsh/identity-1");
        std::fs::create_dir_all(there.join("bin")).expect("creates the copy");
        std::fs::create_dir_all(there.join("lib/zsh/5.9")).expect("copies the module tree");
        std::fs::create_dir_all(there.join("startup")).expect("copies the entry directory");
        std::fs::copy(installed.join("bin/zsh"), there.join("bin/zsh")).expect("copies");
        std::fs::copy(
            installed.join(MANIFEST_BASENAME),
            there.join(MANIFEST_BASENAME),
        )
        .expect("copies the record");
        std::fs::write(copy.path().join("zsh/current"), "identity-1").expect("names one");

        let set = PackageSet::discover(copy.path()).expect("reads the copy");
        let package = set.get(ShellKind::Zsh).expect("the copy");
        assert_eq!(package.executable(), there.join("bin/zsh"));
        assert_eq!(
            package.startup_entry(),
            there.join("startup/kr-zshrc.zsh"),
            "the entry it sources is the copy's"
        );
        let identity = package.identity();
        assert_eq!(
            identity.modules[0].search_path,
            there.join("lib/zsh/5.9").display().to_string(),
            "the module tree is the copy's too, all the way down"
        );

        // Two records this host cannot answer for: one naming somebody else's installation, and one
        // that climbs out of the package with `..`. Each would resolve to a file this package does
        // not contain.
        for stray_path in [
            PathBuf::from("/opt/somebody-elses/bin/zsh"),
            installed.join("../another/bin/zsh"),
        ] {
            let stray = tempfile::tempdir().expect("a directory");
            let elsewhere = stray.path().join("zsh/identity-1");
            std::fs::create_dir_all(elsewhere.join("bin")).expect("creates it");
            let mut astray = record.clone();
            astray.shell.executable = stray_path.clone();
            std::fs::write(
                elsewhere.join(MANIFEST_BASENAME),
                serde_json::to_string(&astray).expect("encodes"),
            )
            .expect("writes the record");
            std::fs::write(stray.path().join("zsh/current"), "identity-1").expect("names one");
            match PackageSet::discover(stray.path())
                .expect("reads what it can")
                .select(Some("zsh"))
            {
                Err(PackageFault::Unreadable { .. }) => {}
                other => panic!("{} was admitted: {other:?}", stray_path.display()),
            }
        }

        // And one this host can: the identity appears in the installation root as well, so a search
        // that took the first component of that name would have found the wrong directory.
        assert_eq!(
            package_root(
                Path::new("/opt/identity-1/shells/zsh/identity-1/bin/zsh"),
                ShellKind::Zsh,
                "identity-1"
            ),
            Some(PathBuf::from("/opt/identity-1/shells/zsh/identity-1")),
            "the package's own directory is the one nearest the file"
        );
    }

    #[cfg(unix)]
    #[test]
    fn every_path_in_one_record_is_taken_from_the_same_installation() {
        // A package may hold a directory named as it is: `lib/zsh/<identity>` is a real layout.
        // Each path answered on its own would then find a different root, and the module tree of a
        // copied package would point at a directory that is not in it.
        let original = tempfile::tempdir().expect("a directory");
        let installed = original.path().join("zsh/identity-1");
        let mut record = manifest(ShellKind::Zsh);
        record.identity = "identity-1".to_owned();
        record.shell.executable = installed.join("bin/zsh");
        record.shell.modules = vec![
            ModuleEntry {
                name: "zsh/zle".to_owned(),
                search_path: installed
                    .join("lib/zsh/identity-1/modules")
                    .display()
                    .to_string(),
                editor_abi: "zle-5.9".to_owned(),
            },
            // A module search path may be the package's own directory, which is a place rather
            // than a file: it is not empty of meaning, only of components.
            ModuleEntry {
                name: "zsh/root".to_owned(),
                search_path: installed.display().to_string(),
                editor_abi: "zle-5.9".to_owned(),
            },
        ];
        // A leading `.` says nothing, and a build that writes one is not writing a stray path.
        record.startup_entry.file = "./startup/kr-zshrc.zsh".to_owned();

        let copy = tempfile::tempdir().expect("a directory");
        let there = copy.path().join("zsh/identity-1");
        std::fs::create_dir_all(there.join("bin")).expect("creates the copy");
        std::fs::write(there.join("bin/zsh"), b"#!/bin/sh\n").expect("writes the binary");
        std::fs::write(
            there.join(MANIFEST_BASENAME),
            serde_json::to_string(&record).expect("encodes"),
        )
        .expect("writes the record");
        std::fs::write(copy.path().join("zsh/current"), "identity-1").expect("names one");

        let set = PackageSet::discover(copy.path()).expect("reads the copy");
        let package = set.get(ShellKind::Zsh).expect("the copy");
        let identity = package.identity();
        assert_eq!(
            identity.modules[0].search_path,
            there
                .join("lib/zsh/identity-1/modules")
                .display()
                .to_string(),
            "the module tree is stripped against the root the executable named"
        );
        assert_eq!(
            identity.modules[1].search_path,
            there.display().to_string(),
            "and a module directory that is the package itself is the copy's own"
        );
        assert_eq!(
            package.startup_entry(),
            there.join("startup/kr-zshrc.zsh"),
            "a leading dot is not a place"
        );
    }

    #[test]
    fn a_record_that_says_nothing_about_its_patches_is_refused() {
        // Defaulting them would let a package that declares nothing look like one that declares an
        // empty list, and the second is a statement while the first is a silence.
        let root = tempfile::tempdir().expect("a directory");
        let directory = root.path().join("zsh/identity-1");
        std::fs::create_dir_all(directory.join("bin")).expect("creates the package");
        std::fs::write(directory.join("bin/shell"), b"#!/bin/sh\n").expect("writes the binary");
        std::fs::write(
            directory.join(MANIFEST_BASENAME),
            r#"{"identity":"identity-1","shell":{"kind":"zsh","executable":"bin/shell",
               "upstream_version":"5.9","editor_abi":"zle-5.9","integration_version":"1"},
               "startup_entry":{"file":"share/entry.sh"}}"#,
        )
        .expect("writes the record");
        std::fs::write(root.path().join("zsh/current"), "identity-1").expect("names one");
        let refused = PackageSet::discover(root.path()).expect("reads what it can");
        let fault = refused
            .fault(ShellKind::Zsh)
            .expect("this shell's record is refused");
        assert!(matches!(fault, PackageFault::Unreadable { .. }), "{fault}");
        assert!(
            refused.select(Some("zsh")).is_err(),
            "and so is a request for it"
        );
    }

    #[test]
    fn the_arguments_are_the_platforms_and_a_login_profile_adds_to_them() {
        // Section 7: the packaged Zsh with `-l -i` on macOS, the packaged shell with `-i` on
        // Linux, and a Linux profile may ask for login startup.
        let root = tempfile::tempdir().expect("a directory");
        install(root.path(), ShellKind::Zsh, false);
        let set = PackageSet::discover(root.path()).expect("reads the packages");
        let package = set.get(ShellKind::Zsh).expect("the package");
        assert_eq!(package.arguments(StartupMode::Interactive), vec!["-i"]);
        assert_eq!(package.arguments(StartupMode::Login), vec!["-l", "-i"]);
        assert_eq!(
            package.interactive_flags(),
            package.arguments(StartupMode::for_host()),
            "the default is this platform's"
        );
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
        assert_eq!(package.kind(), ShellKind::Zsh);

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
        // What this platform does when nothing says otherwise, which is not the same on all three.
        assert_eq!(
            package.interactive_flags(),
            package.arguments(StartupMode::for_host())
        );
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
        let refused = PackageSet::discover(root.path()).expect("reads what it can");
        let fault = refused
            .fault(ShellKind::Zsh)
            .expect("this shell's record is refused");
        assert!(matches!(fault, PackageFault::Unreadable { .. }), "{fault}");
        assert!(
            refused.select(Some("zsh")).is_err(),
            "and so is a request for it"
        );
    }
}
