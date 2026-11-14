//! Refuses a Windows MSVC build that does not link the static C runtime.
//!
//! libsodium reaches the workspace as prebuilt MSVC libraries whose objects ask for the static
//! runtime, and every program of the product that links it must carry that runtime too. The
//! workspace's `.cargo/config.toml` gives the target feature; an environment's `RUSTFLAGS`
//! replaces that file's flags without a message, and the build would then link two runtimes. The
//! check is here, in the crate every program that links libsodium builds, so that no program of it
//! is built without the feature, whether the build is a bundle, a test or a local one.

use std::env;

#[path = "build/static_runtime.rs"]
mod static_runtime;

fn main() {
    // The flags that decide the target features come from the environment as well as from the
    // configuration, and a change of either is a change of what this build is.
    println!("cargo:rerun-if-env-changed=RUSTFLAGS");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
    let target = |key: &str| env::var(key).unwrap_or_default();
    if let Some(why) = static_runtime::refusal(
        &target("CARGO_CFG_TARGET_OS"),
        &target("CARGO_CFG_TARGET_ENV"),
        &target("CARGO_CFG_TARGET_FEATURE"),
    ) {
        panic!("{why}");
    }
}
