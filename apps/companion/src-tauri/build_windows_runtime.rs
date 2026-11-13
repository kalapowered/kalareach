//! What the build says to a request for the static Visual C++ runtime.
//!
//! This program links the dynamic runtime: the workspace's linker settings leave `LIBCMT` out of
//! every MSVC link (see `.cargo/config.toml`), and the static runtime asks for it. The Tauri build
//! step reads `STATIC_VCRUNTIME` before the attribute this package gives it, and the Tauri command
//! line sets the variable to `true` for a desktop build unless it is already `false`. A build
//! started that way asks for the runtime the linker's settings contradict, and it fails at the
//! link with errors that do not say why. This stops such a build at once, in words, whoever starts
//! it.
//!
//! The package's build script and the case that shows the decision both run this, so the case
//! reads the code that ships.

use std::ffi::OsStr;

/// The variable the Tauri build step reads before the attribute of the package.
const STATIC_RUNTIME_INPUT: &str = "STATIC_VCRUNTIME";

/// What a build that asks for the static runtime is told.
const REFUSAL: &str = "this program links the dynamic Visual C++ runtime, and the environment asks for the static one \
     (STATIC_VCRUNTIME is set to something other than `false`, which the Tauri command line does for a bundle build), \
     so build the bundle with `pnpm -C apps/companion desktop build`, which gives the build STATIC_VCRUNTIME=false";

/// The words that refuse a build, or none. Only a build for an MSVC target is refused, and only when
/// the variable is set to anything but `false`, which is the Tauri build step's own reading of it.
pub fn refusal(target_os: &str, target_env: &str, input: Option<&OsStr>) -> Option<&'static str> {
    let msvc = target_os == "windows" && target_env == "msvc";
    (msvc && input.is_some_and(|value| value != "false")).then_some(REFUSAL)
}

/// Stops the build when its environment asks for the static runtime of an MSVC target.
pub fn run() {
    println!("cargo:rerun-if-env-changed={STATIC_RUNTIME_INPUT}");
    let target = |key: &str| std::env::var(key).unwrap_or_default();
    let input = std::env::var_os(STATIC_RUNTIME_INPUT);
    if let Some(words) = refusal(
        &target("CARGO_CFG_TARGET_OS"),
        &target("CARGO_CFG_TARGET_ENV"),
        input.as_deref(),
    ) {
        panic!("{words}");
    }
}
