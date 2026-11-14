//! What the build says to a request for Tauri's static Visual C++ runtime.
//!
//! This program links the static C runtime through the workspace's target feature
//! (`-Ctarget-feature=+crt-static` in `.cargo/config.toml`), and `kr-crypto`'s build script refuses an
//! MSVC build that lacks it. Tauri's own request is another thing: `STATIC_VCRUNTIME` makes a hybrid
//! (the Visual C++ runtime static, the universal runtime dynamic) with link arguments that name
//! `libvcruntime.lib` and `ucrt.lib` beside the `libcmt` of the target feature, so the link would
//! hold two runtimes. The Tauri build step reads the variable before the attribute this package
//! gives it, and the Tauri command line sets it to `true` for a desktop build unless it is already
//! `false`. A build started that way is stopped at once, in words, whoever starts it.
//!
//! The package's build script and the case that shows the decision both run this, so the case
//! reads the code that ships.

use std::ffi::OsStr;

/// The variable the Tauri build step reads before the attribute of the package.
const STATIC_RUNTIME_INPUT: &str = "STATIC_VCRUNTIME";

/// What a build that asks for Tauri's static runtime is told.
const REFUSAL: &str = "this program links the static C runtime through the workspace's target feature, and the environment asks for \
     Tauri's hybrid runtime (static Visual C++ runtime, dynamic universal runtime), which would put two runtimes in the link \
     (STATIC_VCRUNTIME is set to something other than `false`, which the Tauri command line does for a bundle build), \
     so build the bundle with `pnpm -C apps/companion desktop build`, which gives the build STATIC_VCRUNTIME=false";

/// The words that refuse a build, or none. Only a build for an MSVC target is refused, when the
/// variable is set to anything but `false`, which is the Tauri build step's own reading of it.
pub fn refusal(target_os: &str, target_env: &str, input: Option<&OsStr>) -> Option<&'static str> {
    if !(target_os == "windows" && target_env == "msvc") {
        return None;
    }
    input
        .is_some_and(|value| value != "false")
        .then_some(REFUSAL)
}

/// Stops the build when its environment asks for Tauri's static runtime of an MSVC target.
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
