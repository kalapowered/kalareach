//! Records the target this host compiles machine code for.
//!
//! A compiled component is machine code for one target. The cache key needs to say which, and the
//! only place the exact triple is available is here: Cargo hands it to a build script and to
//! nothing else.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_owned());
    println!("cargo:rustc-env=KR_PLUGIN_TARGET={target}");
}
