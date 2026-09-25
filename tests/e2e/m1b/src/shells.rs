//! The managed shell package a session is made in.
//!
//! `scripts/build-shells.sh` installs each package under a prefix, with a pointer naming the build
//! in use and an identity record beside the binary. The host resolves managed shells from the
//! directory `KR_SHELL_PACKAGES` names, which a leg sets to the same prefix, so the session's root
//! shell is the package this tree built. With `KR_REQUIRE_SHELL_PACKAGES=1` a package that is not
//! there fails the leg with its reason; without it the leg says why and does nothing.

use std::path::PathBuf;

/// The variable that makes a missing package a failure rather than a skip.
pub const REQUIRE_VARIABLE: &str = "KR_REQUIRE_SHELL_PACKAGES";

/// One installed managed zsh package.
#[derive(Clone, Debug)]
pub struct ManagedShell {
    /// The prefix the package is installed under, which the host is told to resolve from.
    pub prefix: PathBuf,
    /// The build in use, as the prefix's pointer names it.
    pub identity: String,
    /// The shell binary.
    pub executable: PathBuf,
}

/// Whether a missing package is a failure.
#[must_use]
pub fn required() -> bool {
    std::env::var(REQUIRE_VARIABLE).is_ok_and(|value| value == "1")
}

/// The prefix packages are installed under: `KR_SHELL_PACKAGES`, then `KR_SHELL_PREFIX`, then the
/// build script's own default for this platform.
#[must_use]
pub fn prefix() -> PathBuf {
    for variable in ["KR_SHELL_PACKAGES", "KR_SHELL_PREFIX"] {
        if let Some(value) = std::env::var_os(variable).filter(|value| !value.is_empty()) {
            return PathBuf::from(value);
        }
    }
    let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    if cfg!(target_os = "macos") {
        home.join("Library/Caches/kalareach/shells")
    } else if let Some(cache) = std::env::var_os("XDG_CACHE_HOME").filter(|value| !value.is_empty())
    {
        PathBuf::from(cache).join("kalareach/shells")
    } else {
        home.join(".cache/kalareach/shells")
    }
}

/// Finds the managed zsh package.
///
/// # Errors
///
/// Returns why there is none: the pointer, the record or the binary is missing.
pub fn managed_zsh() -> Result<ManagedShell, String> {
    let prefix = prefix();
    let pointer = prefix.join("zsh").join("current");
    let identity = std::fs::read_to_string(&pointer)
        .map_err(|error| {
            format!(
                "the managed zsh package is not built here ({}: {error}); run \
                 scripts/build-shells.sh --zsh with KR_SHELL_PREFIX naming that prefix",
                pointer.display()
            )
        })?
        .trim()
        .to_owned();
    let record_path = prefix
        .join("zsh")
        .join(&identity)
        .join("kr-shell-identity.json");
    let record: serde_json::Value = std::fs::read(&record_path)
        .map_err(|error| format!("{} has no identity record: {error}", record_path.display()))
        .and_then(|bytes| {
            serde_json::from_slice(&bytes)
                .map_err(|error| format!("{} does not decode: {error}", record_path.display()))
        })?;
    let executable = PathBuf::from(
        record["shell"]["executable"]
            .as_str()
            .ok_or_else(|| format!("{} names no executable", record_path.display()))?,
    );
    if !executable.is_file() {
        return Err(format!(
            "the managed zsh package names {}, which is not installed",
            executable.display()
        ));
    }
    Ok(ManagedShell {
        prefix,
        identity,
        executable,
    })
}
