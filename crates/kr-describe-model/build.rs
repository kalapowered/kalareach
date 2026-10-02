//! Keeps the description process's processor baseline in one place.
//!
//! llama.cpp compiles its CPU code for the x86-64 instruction sets it is told to, and the
//! workspace's build settings (`.cargo/config.toml`) tell it a fixed set that `kr-describe` checks a
//! host's processor against. A `target-cpu` flag would replace that set with the one the flag names,
//! and `target-cpu=native` with the machine that compiles, so an x86-64 build with one is refused.

use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let x86 = matches!(
        env::var("CARGO_CFG_TARGET_ARCH").as_deref(),
        Ok("x86" | "x86_64")
    );
    if !x86 {
        return;
    }
    let flags = env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    if let Some(flag) = flags
        .split('\x1f')
        .find(|flag| flag.contains("target-cpu="))
    {
        panic!(
            "the description process is built for the processor baseline `.cargo/config.toml` sets, \
             and `{flag}` would replace it: remove the `target-cpu` flag"
        );
    }
}
