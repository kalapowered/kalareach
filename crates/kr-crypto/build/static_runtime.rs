//! The decision the package's build script makes, apart from reading its environment, so a test runs it.

/// What a Windows MSVC build without the static C runtime is told.
const REFUSAL: &str = "every Windows MSVC build of this workspace links the static C runtime, and this build's target \
     features lack `crt-static`. `.cargo/config.toml` gives it with `-Ctarget-feature=+crt-static`, and the usual \
     cause of its loss is a `RUSTFLAGS` or `CARGO_ENCODED_RUSTFLAGS` in the environment, which replaces the flags \
     of that file with no message: unset it, or put the flag in it (a `-Ctarget-feature=-crt-static` anywhere has \
     the same effect). A program built without the feature imports `VCRUNTIME140.dll`, which a machine without \
     Microsoft's redistributable lacks, and its link holds two C runtimes, since libsodium's objects ask for the \
     static one";

/// The words that refuse a build, or none.
///
/// A build is refused when it is for an MSVC target and `crt-static` is not among the target's
/// features, which cargo hands a build script separated by commas. Any other target is no matter:
/// the static runtime is a rule of the MSVC link.
pub fn refusal(target_os: &str, target_env: &str, target_features: &str) -> Option<&'static str> {
    if !(target_os == "windows" && target_env == "msvc") {
        return None;
    }
    if target_features
        .split(',')
        .any(|feature| feature == "crt-static")
    {
        return None;
    }
    Some(REFUSAL)
}
