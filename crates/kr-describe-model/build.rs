//! Keeps the description process's processor baseline in one place.
//!
//! llama.cpp compiles its CPU code for the instruction sets it is told to, and the workspace's
//! build settings (`.cargo/config.toml`) tell it a fixed set that `kr-describe` checks a host's
//! processor against. A `target-cpu` flag, or a target feature wider than the set, would replace it
//! with the machine that compiles or with more than a host checks for, so the build is refused.

use std::env;

#[path = "build/guard.rs"]
mod guard;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build/guard.rs");
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let flags = env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    let features = env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
    if let Some(why) = guard::refusal(&arch, &flags, &features) {
        panic!("{why}");
    }
}
