//! The decision the build script makes, apart from reading its environment, so a test runs it.

/// Returns why a build of the description process is refused, or `None` when it is accepted.
///
/// `arch` is the target's architecture, `rustflags` the flags cargo passes the build script
/// separated by `\x1f`, and `target_features` the target's features separated by commas.
///
/// llama.cpp's build script reads the same two inputs, after the options `.cargo/config.toml`
/// pins. A `target-cpu` flag becomes `-march` or, for `native`, the machine that compiles, and a
/// target feature it knows turns its option on. Either replaces the baseline a host checks its
/// processor against, so both are refused: a `target-cpu` flag on every architecture, and on x86 a
/// feature that is wider than the baseline. A feature inside the baseline is the pins' own, and the
/// Rust code of the daemon and the process refuses those itself.
pub fn refusal(arch: &str, rustflags: &str, target_features: &str) -> Option<String> {
    if let Some(flag) = rustflags
        .split('\x1f')
        .find(|flag| flag.contains("target-cpu="))
    {
        return Some(format!(
            "the description process is built for the processor baseline `.cargo/config.toml` \
             sets, and `{flag}` would replace it: remove the `target-cpu` flag"
        ));
    }
    if !matches!(arch, "x86" | "x86_64") {
        return None;
    }
    let wide = target_features.split(',').find(|feature| {
        feature.starts_with("avx512") || *feature == "avxvnni" || feature.starts_with("amx")
    })?;
    Some(format!(
        "the description process is built for the processor baseline `.cargo/config.toml` sets, \
         and the target feature `{wide}` would widen it: remove the `target-feature` flag that \
         enables it"
    ))
}
