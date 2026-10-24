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
use kr_protocol::hostinfo::configuration::{host_owns_variable, platform_variable_name};
use serde::{Deserialize, Serialize};

use crate::contract::qualification::ShellKind;
use crate::contract::transport::{ModuleEntry, PatchRevision, ShellIdentity};

/// The variable that names the directory the qualified packages were built into.
pub const PACKAGE_ROOT_VARIABLE: &str = "KR_SHELL_PACKAGES";

/// The identity record each package carries beside its binary.
pub const MANIFEST_BASENAME: &str = "kr-shell-identity.json";

/// The file beside a shell's packages that names the identity this installation uses.
pub const CURRENT_BASENAME: &str = "current";

/// The variable that lists the directories PowerShell finds a module by name in.
pub const MODULE_PATH_VARIABLE: &str = "PSModulePath";

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
    /// What a start of this package adds to the environment of its shell.
    ///
    /// A record that says nothing starts the shell in the environment the session built. The
    /// block is limited to what a shell that is not built here needs to find its runtime and the
    /// package's module; [`PackageLaunch`] says which names, and a record that goes past it is
    /// refused when it is read.
    #[serde(default)]
    pub launch: PackageLaunch,
}

/// What a start of a package adds to its shell's environment.
///
/// Two kinds of thing and no more: the location of the .NET runtime a shell needs to start at all,
/// which is the person's own and which the package records as it found it, and the directory the
/// package's module is found in by name, put first on the list of module directories.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageLaunch {
    /// Variables set to exactly these values: `DOTNET_ROOT` and its architecture forms.
    #[serde(default)]
    pub environment: std::collections::BTreeMap<String, String>,
    /// Lists of directories the package goes first in, each by the variable that holds the list:
    /// `PSModulePath` is the only one.
    #[serde(default)]
    pub search_paths: std::collections::BTreeMap<String, Vec<PathBuf>>,
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
                republish: package.kind() == ShellKind::PowerShell,
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
            let root = self.recorded_root()?;
            recorded.strip_prefix(&root).ok()?.to_path_buf()
        } else {
            recorded.to_path_buf()
        };
        within(&tail)
    }

    /// Returns the directory the build installed this package in, read from the paths the record
    /// names.
    ///
    /// The shell's own path says it where the package holds its shell. A package that builds none
    /// names the host it qualified, which is outside the package and says nothing of where the
    /// package was installed, so the paths that are the package's own are read next: the module
    /// directories, the directories the launch puts first, and the startup entry. The first that
    /// names a directory of this package's identity gives the root for them all.
    fn recorded_root(&self) -> Option<PathBuf> {
        let shell = &self.manifest.shell;
        std::iter::once(shell.executable.as_path())
            .chain(
                shell
                    .modules
                    .iter()
                    .map(|module| Path::new(&module.search_path)),
            )
            .chain(
                self.manifest
                    .launch
                    .search_paths
                    .values()
                    .flatten()
                    .map(PathBuf::as_path),
            )
            .chain(std::iter::once(Path::new(
                &self.manifest.startup_entry.file,
            )))
            .filter(|recorded| recorded.is_absolute())
            .find_map(|recorded| package_root(recorded, self.kind(), &self.manifest.identity))
    }

    /// Returns whether this record names the host it qualified instead of a shell it holds.
    ///
    /// A package that builds no shell has no executable of its own. The one such package is
    /// PowerShell's, which binds into the host the person already has and says which one it
    /// qualified: an absolute path to a `pwsh`, so that starting it never searches for a name.
    /// Everything else a record names is still the package's own and has to be inside it.
    fn names_its_host(&self) -> bool {
        let executable = self.manifest.shell.executable.as_path();
        self.kind() == ShellKind::PowerShell
            && executable.is_absolute()
            && !executable.to_string_lossy().contains('\0')
            && executable
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|name| {
                    name.eq_ignore_ascii_case("pwsh") || name.eq_ignore_ascii_case("pwsh.exe")
                })
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
        let a_file_inside = |recorded: &Path| {
            self.inside(recorded)
                .is_some_and(|tail| !tail.as_os_str().is_empty())
        };
        (a_file_inside(&self.manifest.shell.executable) || self.names_its_host())
            && a_file_inside(Path::new(&self.manifest.startup_entry.file))
            && self
                .manifest
                .shell
                .modules
                .iter()
                .all(|module| self.inside(Path::new(&module.search_path)).is_some())
    }

    /// Returns what is wrong with the launch block, when something is.
    ///
    /// The block is the one place a record reaches the environment of the shell a session starts,
    /// so it is held to what a package needs and nothing else: `DOTNET_ROOT` and its architecture
    /// forms set to a value with no NUL in it, and `PSModulePath` given directories of the
    /// package's own. A name the host owns is never accepted, whatever it is for. Only the
    /// PowerShell package has any launch at all.
    fn launch_fault(&self) -> Option<String> {
        let launch = &self.manifest.launch;
        if launch.environment.is_empty() && launch.search_paths.is_empty() {
            return None;
        }
        if self.kind() != ShellKind::PowerShell {
            return Some("only the PowerShell package has a launch block".to_owned());
        }
        for (name, value) in &launch.environment {
            if !is_runtime_location(name) || owned_by_the_host(name) {
                return Some(format!(
                    "the launch sets {name}, which a package does not set"
                ));
            }
            if value.is_empty() || value.contains('\0') {
                return Some(format!("the launch gives {name} no usable value"));
            }
        }
        for (name, directories) in &launch.search_paths {
            if platform_variable_name(name) != platform_variable_name(MODULE_PATH_VARIABLE)
                || owned_by_the_host(name)
            {
                return Some(format!(
                    "the launch puts directories first in {name}, which is not a list a package \
                     adds to"
                ));
            }
            for directory in directories {
                let text = directory.to_string_lossy();
                let separator = if cfg!(windows) { ';' } else { ':' };
                if text.contains('\0') || text.contains(separator) {
                    return Some(format!(
                        "the launch names a directory that cannot be in {name}"
                    ));
                }
                if !self
                    .inside(directory)
                    .is_some_and(|tail| !tail.as_os_str().is_empty())
                {
                    return Some(format!(
                        "the launch names {} for {name}, which is not inside the package",
                        directory.display()
                    ));
                }
            }
        }
        None
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
    ///
    /// It states the record as the build wrote it, paths included, because the bridge compiled
    /// into the shell says the same paths from the same build whatever directory the package has
    /// since been put in. The comparison of the hello with this checks the build's record: a
    /// package that was moved is the build it was, and a record re-rooted to where the package now
    /// sits would never agree with the shell inside it. The files the worker opens are another
    /// matter, and [`Self::identity`] names them where the package is.
    #[must_use]
    pub fn declaration(&self) -> crate::contract::transport::PackageDeclaration {
        let shell = &self.manifest.shell;
        crate::contract::transport::PackageDeclaration {
            kind: shell.kind,
            executable: shell.executable.display().to_string(),
            upstream_version: shell.upstream_version.clone(),
            editor_abi: shell.editor_abi.clone(),
            integration_version: shell.integration_version.clone(),
            patches: shell.patches.clone(),
            modules: shell.modules.clone(),
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

impl ShellPackage {
    /// Returns the variables a start of this package sets, given the environment it starts in.
    ///
    /// The record's runtime locations are set as written. Each list the record puts directories
    /// first in gets the package's directories at its front, once each, with every other entry
    /// after them in the order it had: a list that already held the package's directory further
    /// down has it moved to the front, so the module found by name is this package's own whatever
    /// else the person's list names. A list the environment does not have starts as the package's
    /// directories alone.
    ///
    /// Names are compared as the platform compares them, and `windows` says which platform that
    /// is: callers pass `cfg!(windows)`, and a check can run both rules on one host. A name the
    /// host owns is never returned, so the launch cannot set what a session's worker sets itself.
    /// Every process this package's shell is asked something of, a session's root shell and the
    /// ones that find a profile or place an entry in it, is started with these on top of the
    /// environment it would otherwise have.
    #[must_use]
    pub fn launch_environment(
        &self,
        base: &[(String, String)],
        windows: bool,
    ) -> Vec<(String, String)> {
        let fold = |name: &str| {
            if windows {
                name.to_ascii_uppercase()
            } else {
                name.to_owned()
            }
        };
        let launch = &self.manifest.launch;
        let mut set: Vec<(String, String)> = launch
            .environment
            .iter()
            .filter(|(name, _)| !owned_by_the_host(name))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        for (name, directories) in &launch.search_paths {
            if owned_by_the_host(name) {
                continue;
            }
            let ours: Vec<String> = directories
                .iter()
                .map(|directory| self.own(directory).display().to_string())
                .collect();
            let held = base
                .iter()
                .find(|(existing, _)| fold(existing) == fold(name))
                .map(|(_, value)| value.as_str());
            set.push((name.clone(), put_first(&ours, held, windows)));
        }
        set
    }
}

/// Returns `held`, a list of directories, with `ours` at its front and no other entry equal to one
/// of them.
fn put_first(ours: &[String], held: Option<&str>, windows: bool) -> String {
    let separator = if windows { ';' } else { ':' };
    let same = |left: &str, right: &str| {
        let plain = |text: &str| {
            let trimmed = text.trim_end_matches(['/', '\\']);
            if windows {
                trimmed.replace('/', "\\").to_ascii_lowercase()
            } else {
                trimmed.trim_end_matches('/').to_owned()
            }
        };
        plain(left) == plain(right)
    };
    let mut entries: Vec<&str> = Vec::new();
    for entry in ours {
        if !entries.iter().any(|kept| same(kept, entry)) {
            entries.push(entry);
        }
    }
    for entry in held.unwrap_or_default().split(separator) {
        if entry.is_empty() || ours.iter().any(|mine| same(mine, entry)) {
            continue;
        }
        entries.push(entry);
    }
    entries.join(&separator.to_string())
}

/// Whether `name` is one of the host's own, which no record sets.
fn owned_by_the_host(name: &str) -> bool {
    host_owns_variable(&platform_variable_name(name))
}

/// Whether `name` is the location of the .NET runtime: `DOTNET_ROOT`, or its form for one
/// architecture.
fn is_runtime_location(name: &str) -> bool {
    name == "DOTNET_ROOT"
        || name
            .strip_prefix("DOTNET_ROOT_")
            .is_some_and(|architecture| {
                !architecture.is_empty()
                    && architecture
                        .bytes()
                        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
            })
}

/// Why a shell cannot be launched in managed mode.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PackageFault {
    /// No package directory is installed or configured.
    #[error("{}", no_packages())]
    NoPackages,
    /// The shell the request named has no qualified package.
    #[error("{}", unqualified(requested))]
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
    #[error("the package at {path} names an executable that is not installed{}", republish_hint(*.republish))]
    MissingExecutable {
        /// Where the package is.
        path: String,
        /// Whether the package is one a person publishes for the host they have, so that the host
        /// having moved or gone is mended by publishing it again.
        republish: bool,
    },
    /// A request for a non-interactive script, which never becomes an interactive session shell.
    #[error("a script invocation is not an interactive root shell: {detail}")]
    NotInteractive {
        /// What the request asked for.
        detail: String,
    },
}

/// What follows "not installed" when publishing the package again mends it.
#[must_use]
pub fn republish_hint(republish: bool) -> String {
    if republish {
        format!("; run {PUBLISH_COMMAND} in PowerShell to qualify the one this account runs")
    } else {
        String::new()
    }
}

/// The words for a host with no package: the Windows host has one shell to qualify, so it is told
/// how.
fn no_packages() -> String {
    let said = format!(
        "no qualified shell packages are installed; {PACKAGE_ROOT_VARIABLE} names none either"
    );
    if cfg!(windows) {
        format!("{said}; run {PUBLISH_COMMAND} in PowerShell to qualify the one this account runs")
    } else {
        said
    }
}

/// The words for a shell with no package, which tell a person who asked for PowerShell how to get
/// one.
fn unqualified(requested: &str) -> String {
    let said = format!(
        "{requested} has no qualified KalaReach package, so it cannot claim the managed contract"
    );
    if executable_name(requested) == "pwsh" || executable_name(requested) == "powershell" {
        format!("{said}; run {PUBLISH_COMMAND} in PowerShell to qualify it")
    } else {
        said
    }
}

/// The command that qualifies the PowerShell a person has and publishes the package for it.
pub const PUBLISH_COMMAND: &str = "Publish-KalaReachQualification";

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
    // Windows keeps what a user's programs cache for themselves under the local application data
    // folder, beside the host's state: `HOME` is not set there, and a path made from it would be
    // one nothing wrote a package to.
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_default()
            .join("KalaReach")
            .join("shells")
    }
    #[cfg(not(windows))]
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    #[cfg(target_vendor = "apple")]
    {
        home.join("Library/Caches/kalareach/shells")
    }
    #[cfg(all(not(windows), not(target_vendor = "apple")))]
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
    if let Some(detail) = package.launch_fault() {
        return Err(PackageFault::Unreadable {
            path: candidate.display().to_string(),
            detail,
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
                republish: package.kind() == ShellKind::PowerShell,
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
            launch: PackageLaunch::default(),
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
        // A PowerShell package whose record names a startup entry outside itself: an installation
        // can hold one, and a session asking for Zsh is not about it.
        let powershell = root.path().join("powershell").join("identity-1");
        std::fs::create_dir_all(&powershell).expect("creates the package");
        std::fs::write(
            powershell.join(MANIFEST_BASENAME),
            r#"{"identity":"identity-1",
               "shell":{"kind":"powershell","executable":"bin/pwsh",
                        "upstream_version":"7.4","editor_abi":"psreadline-2.3",
                        "integration_version":"1","patches":[],"modules":[]},
               "startup_entry":{"file":"/opt/elsewhere/startup/entry"}}"#,
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

    /// KR-REQ-07.17, the part about what is recorded: the executable, the startup entry and the
    /// module search paths a package reports are those of the installation it was read from, not
    /// those its build wrote, so a copied package reports the copy's.
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

    /// KR-REQ-07.17, the part about what is recorded: the module search paths and the startup entry
    /// of one record are taken from the one installation, even where a module directory is named
    /// like the identity or is the package itself.
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

    /// KR-REQ-07.16: the arguments an interactive root shell is launched with, for every shell
    /// this host qualifies and both startup modes.
    ///
    /// Section 7 states them: Zsh with `-l -i` on macOS and Bash and Zsh with `-i` on Linux, a
    /// Linux profile that asks for login startup adds `-l`, Fish uses `--interactive` and adds
    /// `--login` for a login profile, and PowerShell 7 starts with `-NoLogo` and has no login
    /// mode. The host holds this table because a package records what it was built from, not how a
    /// session starts it.
    #[test]
    fn every_shell_is_launched_with_the_arguments_section_seven_states_for_its_startup_mode() {
        let root = tempfile::tempdir().expect("a directory");
        for kind in ShellKind::ALL {
            install(root.path(), *kind, false);
        }
        let set = PackageSet::discover(root.path()).expect("reads the packages");
        let expected = |kind: ShellKind, mode: StartupMode| -> Vec<&'static str> {
            match (kind, mode) {
                (ShellKind::Zsh | ShellKind::Bash, StartupMode::Interactive) => vec!["-i"],
                (ShellKind::Zsh | ShellKind::Bash, StartupMode::Login) => vec!["-l", "-i"],
                (ShellKind::Fish, StartupMode::Interactive) => vec!["--interactive"],
                (ShellKind::Fish, StartupMode::Login) => vec!["--login", "--interactive"],
                (ShellKind::PowerShell, _) => vec!["-NoLogo"],
            }
        };
        for kind in ShellKind::ALL {
            let package = set.get(*kind).expect("the package");
            for mode in [StartupMode::Interactive, StartupMode::Login] {
                assert_eq!(
                    package.arguments(mode),
                    expected(*kind, mode),
                    "{} in {mode:?} startup",
                    kind.as_str()
                );
            }
            assert_eq!(
                package.interactive_flags(),
                package.arguments(StartupMode::for_host()),
                "{}: the default is this platform's",
                kind.as_str()
            );
        }
    }

    /// KR-REQ-07.16: what a session with no profile is launched with is the platform's own default
    /// from section 7: Zsh with `-l -i` on macOS, the packaged shell with `-i` on Linux, and
    /// PowerShell 7 with `-NoLogo` everywhere it runs, which is the whole of its default on Windows.
    #[test]
    fn a_session_with_no_profile_is_launched_as_section_seven_defaults_this_platform() {
        let root = tempfile::tempdir().expect("a directory");
        install(root.path(), ShellKind::Zsh, false);
        install(root.path(), ShellKind::PowerShell, false);
        let set = PackageSet::discover(root.path()).expect("reads the packages");
        let default = |kind: ShellKind| set.get(kind).expect("the package").interactive_flags();
        if cfg!(target_os = "macos") {
            assert_eq!(default(ShellKind::Zsh), vec!["-l", "-i"]);
        } else if cfg!(target_os = "linux") {
            assert_eq!(default(ShellKind::Zsh), vec!["-i"]);
        }
        assert_eq!(default(ShellKind::PowerShell), vec!["-NoLogo"]);
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

    /// KR-REQ-07.18: a script request is refused rather than launched as an interactive shell: a
    /// command string, a login command, a redirect and a command list each name no interactive
    /// shell, and each is refused as shell integration this host does not support.
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

    /// KR-REQ-07.17, the part about what is recorded: the executable a package reports is the binary
    /// its record names in the installation, and the identity it reports carries its kind, its
    /// editor ABI, how many patches it holds and its module search paths, resolved to the
    /// installation.
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
        // The one shell a Windows host has is the one a person publishes a package for.
        assert_eq!(
            fault.to_string().contains(PUBLISH_COMMAND),
            cfg!(windows),
            "{fault}"
        );
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

    /// The directory a test host stands in: a file named as a PowerShell is, outside every package.
    fn a_host(directory: &Path) -> PathBuf {
        let host = directory.join("PowerShell/7/pwsh");
        std::fs::create_dir_all(host.parent().expect("a directory")).expect("creates the host");
        std::fs::write(&host, b"#!/bin/sh\n").expect("writes the host");
        host
    }

    /// The record the PowerShell package publishes for the host it qualified.
    fn host_record(root: &Path, host: &Path) -> serde_json::Value {
        let package = root.join("powershell/identity-1");
        serde_json::json!({
            "identity": "identity-1",
            "shell": {
                "kind": "powershell",
                "executable": host,
                "upstream_version": "7.6.6",
                "editor_abi": "psreadline-2.4",
                "integration_version": "1",
                "patches": [],
                "modules": [{
                    "name": "KalaReach.ShellBridge",
                    "search_path": package.join("modules"),
                    "editor_abi": "psreadline-2.4",
                }],
            },
            "startup_entry": { "file": "startup/kr-profile.ps1" },
            "launch": {
                "environment": { "DOTNET_ROOT": "/opt/dotnet" },
                "search_paths": { "PSModulePath": [package.join("modules")] },
            },
        })
    }

    /// Writes a record into the package directory it describes and names it as current.
    fn publish(root: &Path, record: &serde_json::Value) {
        let package = root.join("powershell/identity-1");
        std::fs::create_dir_all(package.join("modules")).expect("creates the package");
        std::fs::create_dir_all(package.join("startup")).expect("creates the entry's place");
        std::fs::write(package.join("startup/kr-profile.ps1"), b"# entry\n").expect("the entry");
        std::fs::write(package.join(MANIFEST_BASENAME), record.to_string()).expect("the record");
        std::fs::write(root.join("powershell").join(CURRENT_BASENAME), "identity-1")
            .expect("names the identity");
    }

    /// A PowerShell that was updated, moved or removed since the package was published leaves a
    /// package naming a host that is not there; the refusal says to publish it again.
    #[test]
    fn a_package_whose_host_has_gone_says_to_publish_it_again() {
        let root = tempfile::tempdir().expect("a directory");
        let elsewhere = tempfile::tempdir().expect("a directory");
        let host = a_host(elsewhere.path());
        publish(root.path(), &host_record(root.path(), &host));
        std::fs::remove_file(&host).expect("the host goes");

        let refused = ShellPackage::read(&root.path().join("powershell/identity-1"))
            .expect_err("a package with no host is refused");
        assert!(
            matches!(
                refused,
                PackageFault::MissingExecutable {
                    republish: true,
                    ..
                }
            ),
            "{refused}"
        );
        assert!(refused.to_string().contains(PUBLISH_COMMAND), "{refused}");
    }

    /// KR-REQ-07.16: a package that builds no shell names the host it qualified, and a session
    /// starts that host with the package's own launch in its environment. Its files are inside it.
    #[test]
    fn a_package_that_builds_no_shell_names_the_host_it_qualified() {
        let root = tempfile::tempdir().expect("a directory");
        let elsewhere = tempfile::tempdir().expect("a directory");
        let host = a_host(elsewhere.path());
        publish(root.path(), &host_record(root.path(), &host));

        let set = PackageSet::discover(root.path()).expect("reads the packages");
        let package = set.select(Some("pwsh")).expect("the qualified PowerShell");
        let package_directory = root.path().join("powershell/identity-1");
        assert_eq!(
            package.executable(),
            host,
            "the host is what a session starts"
        );
        assert_eq!(
            package.declaration().executable,
            host.display().to_string(),
            "and what the package states of its executable"
        );
        assert_eq!(
            package.identity().modules[0].search_path,
            package_directory.join("modules").display().to_string()
        );
        assert_eq!(
            package.startup_entry(),
            package_directory.join("startup/kr-profile.ps1")
        );
        let launch = package.launch_environment(&[], false);
        assert!(
            launch.contains(&("DOTNET_ROOT".to_owned(), "/opt/dotnet".to_owned())),
            "{launch:?}"
        );
        assert!(
            launch.contains(&(
                "PSModulePath".to_owned(),
                package_directory.join("modules").display().to_string()
            )),
            "{launch:?}"
        );

        // A record an earlier publish wrote, with the launcher script inside the package, is read
        // by the general rule and starts the script.
        let older = tempfile::tempdir().expect("a directory");
        let mut record = host_record(older.path(), &host);
        record["shell"]["executable"] = serde_json::json!("bin/pwsh");
        record["launch"] = serde_json::json!({ "environment": {} });
        publish(older.path(), &record);
        std::fs::create_dir_all(older.path().join("powershell/identity-1/bin")).expect("bin");
        std::fs::write(
            older.path().join("powershell/identity-1/bin/pwsh"),
            b"#!/bin/sh\n",
        )
        .expect("the script");
        let set = PackageSet::discover(older.path()).expect("reads the packages");
        assert_eq!(
            set.select(Some("pwsh"))
                .expect("the older package")
                .executable(),
            older.path().join("powershell/identity-1/bin/pwsh")
        );
    }

    /// Everything a record names other than the host it qualified is the package's
    /// own and has to be inside it, and the host has to be an absolute path to a PowerShell.
    #[test]
    fn a_record_names_nothing_outside_its_package_but_the_host() {
        let host_directory = tempfile::tempdir().expect("a directory");
        let host = a_host(host_directory.path());
        let refused = |what: &str, change: &dyn Fn(&mut serde_json::Value)| {
            let root = tempfile::tempdir().expect("a directory");
            let mut record = host_record(root.path(), &host);
            change(&mut record);
            publish(root.path(), &record);
            let set = PackageSet::discover(root.path()).expect("reads what it can");
            let fault = set
                .fault(ShellKind::PowerShell)
                .unwrap_or_else(|| panic!("{what}: the record was accepted"));
            assert!(
                matches!(fault, PackageFault::Unreadable { .. }),
                "{what}: {fault}"
            );
            assert!(set.select(Some("pwsh")).is_err(), "{what}");
        };
        refused("a host that is not a PowerShell", &|record| {
            record["shell"]["executable"] = serde_json::json!("/usr/bin/bash");
        });
        refused("a module directory outside the package", &|record| {
            record["shell"]["modules"][0]["search_path"] = serde_json::json!("/elsewhere/modules");
        });
        refused("a startup entry outside the package", &|record| {
            record["startup_entry"]["file"] = serde_json::json!("/elsewhere/kr-profile.ps1");
        });
        // The same host, named by a package of a shell that builds its own, is the control: only
        // the package that builds no shell may name one.
        let root = tempfile::tempdir().expect("a directory");
        let directory = root.path().join("zsh/identity-1");
        std::fs::create_dir_all(directory.join("bin")).expect("creates the package");
        let mut record = serde_json::to_value(manifest(ShellKind::Zsh)).expect("encodes");
        record["shell"]["executable"] = serde_json::json!(host);
        std::fs::write(directory.join(MANIFEST_BASENAME), record.to_string()).expect("the record");
        std::fs::write(root.path().join("zsh").join(CURRENT_BASENAME), "identity-1")
            .expect("names the identity");
        let set = PackageSet::discover(root.path()).expect("reads what it can");
        assert!(
            set.fault(ShellKind::Zsh).is_some(),
            "a Zsh record cannot name a host"
        );
    }

    /// The launch block reaches the environment of a shell, so it is held to the
    /// runtime's location and the module directory, and nothing a session's worker owns.
    #[test]
    fn a_launch_block_goes_no_further_than_the_runtime_and_the_modules() {
        let host_directory = tempfile::tempdir().expect("a directory");
        let host = a_host(host_directory.path());
        let refused = |what: &str, change: &dyn Fn(&mut serde_json::Value)| {
            let root = tempfile::tempdir().expect("a directory");
            let mut record = host_record(root.path(), &host);
            change(&mut record);
            publish(root.path(), &record);
            let set = PackageSet::discover(root.path()).expect("reads what it can");
            let fault = set
                .fault(ShellKind::PowerShell)
                .unwrap_or_else(|| panic!("{what}: the record was accepted"));
            assert!(
                fault.to_string().contains("launch"),
                "{what}: the refusal says it is the launch: {fault}"
            );
        };
        for name in [
            "KR_SHELL_BRIDGE",
            "KR_SESSION",
            "TERM",
            "PATH",
            "DOTNET_ROOT_x64",
            "DOTNET_ROOTS",
        ] {
            refused(name, &|record| {
                record["launch"]["environment"] = serde_json::json!({ name: "/opt/dotnet" });
            });
        }
        refused("a value with a NUL in it", &|record| {
            record["launch"]["environment"]["DOTNET_ROOT"] = serde_json::json!("/opt/\u{0}dotnet");
        });
        refused("an empty value", &|record| {
            record["launch"]["environment"]["DOTNET_ROOT"] = serde_json::json!("");
        });
        refused("a list that is not the module directories", &|record| {
            let ours = record["launch"]["search_paths"]["PSModulePath"].clone();
            record["launch"]["search_paths"] = serde_json::json!({ "PATH": ours });
        });
        refused("a directory outside the package", &|record| {
            record["launch"]["search_paths"]["PSModulePath"] = serde_json::json!(["/elsewhere"]);
        });
        refused("a directory with the list's separator in it", &|record| {
            let root = record["shell"]["modules"][0]["search_path"].clone();
            let separator = if cfg!(windows) { ';' } else { ':' };
            let tricky = format!("{}{separator}x", root.as_str().expect("text"));
            record["launch"]["search_paths"]["PSModulePath"] = serde_json::json!([tricky]);
        });
        // The architecture forms the module records are the other names it may set.
        let root = tempfile::tempdir().expect("a directory");
        let mut record = host_record(root.path(), &host);
        record["launch"]["environment"] = serde_json::json!({ "DOTNET_ROOT": "/a", "DOTNET_ROOT_X64": "/b", "DOTNET_ROOT_ARM64": "/c" });
        publish(root.path(), &record);
        let set = PackageSet::discover(root.path()).expect("reads the packages");
        assert!(set.fault(ShellKind::PowerShell).is_none());
    }

    /// KR-REQ-07.86: a package that is moved, with the place it was built in gone, starts its own
    /// modules and still states its record as the build wrote it.
    #[test]
    fn a_moved_package_that_builds_no_shell_finds_its_own_modules() {
        let host_directory = tempfile::tempdir().expect("a directory");
        let host = a_host(host_directory.path());
        let built = tempfile::tempdir().expect("a directory");
        publish(built.path(), &host_record(built.path(), &host));
        let built_modules = built
            .path()
            .join("powershell/identity-1/modules")
            .display()
            .to_string();

        let moved = tempfile::tempdir().expect("a directory");
        copy_tree(
            &built.path().join("powershell"),
            &moved.path().join("powershell"),
        );
        drop(built);

        let set = PackageSet::discover(moved.path()).expect("reads the moved package");
        let package = set.select(Some("pwsh")).expect("qualified");
        let modules = moved.path().join("powershell/identity-1/modules");
        assert_eq!(
            package.identity().modules[0].search_path,
            modules.display().to_string(),
            "the files this host opens are the moved package's own"
        );
        assert_eq!(
            package.declaration().modules[0].search_path,
            built_modules,
            "and the record is stated as the build wrote it"
        );
        let launch = package.launch_environment(&[], false);
        assert!(
            launch.contains(&("PSModulePath".to_owned(), modules.display().to_string())),
            "the module a session finds by name is the moved package's: {launch:?}"
        );
    }

    fn copy_tree(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).expect("creates the copy");
        for entry in std::fs::read_dir(from).expect("reads the tree").flatten() {
            let target = to.join(entry.file_name());
            if entry.path().is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), target).expect("copies the file");
            }
        }
    }

    /// The package's directory goes first on the list of module directories, once,
    /// and everything else on the list keeps its order, wherever the package's directory was.
    #[cfg(unix)]
    #[test]
    fn the_packages_module_directory_goes_first_and_the_rest_keep_their_order() {
        let host_directory = tempfile::tempdir().expect("a directory");
        let host = a_host(host_directory.path());
        let root = tempfile::tempdir().expect("a directory");
        publish(root.path(), &host_record(root.path(), &host));
        let set = PackageSet::discover(root.path()).expect("reads the packages");
        let package = set.select(Some("pwsh")).expect("qualified");
        let ours = root
            .path()
            .join("powershell/identity-1/modules")
            .display()
            .to_string();
        let listed = |held: Option<&str>, name: &str| {
            let base: Vec<(String, String)> = held
                .map(|value| vec![(name.to_owned(), value.to_owned())])
                .unwrap_or_default();
            package
                .launch_environment(&base, false)
                .into_iter()
                .find(|(set, _)| set == "PSModulePath")
                .map(|(_, value)| value)
                .expect("the list is set")
        };
        assert_eq!(
            listed(None, "PSModulePath"),
            ours,
            "no list is the package's alone"
        );
        assert_eq!(
            listed(Some("/a:/b:/c"), "PSModulePath"),
            format!("{ours}:/a:/b:/c")
        );
        assert_eq!(
            listed(Some(&format!("/a:{ours}:/c:{ours}/")), "PSModulePath"),
            format!("{ours}:/a:/c"),
            "an entry that was further down is moved up and not kept twice"
        );
        assert_eq!(
            listed(Some("/a::/c"), "PSModulePath"),
            format!("{ours}:/a:/c"),
            "an empty entry is nothing"
        );
        // A competing module directory that was first is behind the package's now.
        assert!(
            listed(Some("/competing/modules:/a"), "PSModulePath")
                .starts_with(&format!("{ours}:/competing/modules")),
        );
        // On a platform that compares names without regard to case the list is found under
        // whichever case the environment has, and the entry is the same entry however it is cased.
        let held = |name: &str| vec![(name.to_owned(), "/a".to_owned())];
        let folded = package.launch_environment(&held("psmodulepath"), true);
        assert!(
            folded
                .iter()
                .any(|(name, value)| name == "PSModulePath" && value.ends_with(";/a")),
            "{folded:?}"
        );
    }

    /// The same rule with the spellings of a Windows host, which a Unix host cannot reach through a
    /// package.
    #[test]
    fn a_list_of_module_directories_is_compared_as_windows_compares_paths() {
        let ours =
            vec![r"C:\Users\a\AppData\Local\KalaReach\shells\powershell\i\modules".to_owned()];
        assert_eq!(
            put_first(
                &ours,
                Some(r"C:\x;c:\users\A\appdata\local\kalareach\shells\powershell\i\modules\;D:\y;"),
                true
            ),
            format!(r"{};C:\x;D:\y", ours[0])
        );
        assert_eq!(
            put_first(
                &ours,
                Some(r"C:/x;C:\Users\a\AppData\Local\KalaReach\shells\powershell\i\modules/"),
                true
            ),
            format!(r"{};C:/x", ours[0])
        );
    }

    /// The words a person reads when PowerShell has no package name the command that makes one.
    #[test]
    fn a_refusal_for_want_of_a_powershell_package_names_the_command_that_publishes_it() {
        let root = tempfile::tempdir().expect("a directory");
        install(root.path(), ShellKind::Zsh, true);
        let set = PackageSet::discover(root.path()).expect("reads the packages");
        let powershell = set.select(Some("pwsh")).expect_err("no PowerShell package");
        assert!(
            powershell.to_string().contains(PUBLISH_COMMAND),
            "{powershell}"
        );
        let bash = set.select(Some("bash")).expect_err("no Bash package");
        assert!(
            !bash.to_string().contains(PUBLISH_COMMAND),
            "a shell a person does not publish is not told to: {bash}"
        );
    }
}
