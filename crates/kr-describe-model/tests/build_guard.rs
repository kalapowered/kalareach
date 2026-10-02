//! What the build of the description process refuses: a compiler setting that would replace the
//! processor baseline `.cargo/config.toml` pins, or widen it past what a host checks its
//! processor against.
//!
//! The decision is a function of three things cargo hands a build script, so it runs here on
//! strings, with a control for each refusal. The same file is the build script's own.

#[path = "../build/guard.rs"]
mod guard;

use guard::refusal;

/// The flags cargo passes a build script, which separates them with this character.
const SEPARATOR: char = '\x1f';

fn flags(parts: &[&str]) -> String {
    parts.join(&SEPARATOR.to_string())
}

/// KR-REQ-22.01: a `target-cpu` flag replaces the pinned set, in either of the forms cargo accepts,
/// on every architecture a release is built for. The control is the same build without it.
#[test]
fn a_target_cpu_flag_is_refused_on_every_architecture() {
    for arch in ["x86_64", "x86", "aarch64", "arm"] {
        for spelled in [
            flags(&["-Ctarget-cpu=native"]),
            flags(&["-C", "target-cpu=x86-64-v3"]),
            flags(&["-Ccodegen-units=1", "--codegen=target-cpu=apple-m1"]),
        ] {
            let said = refusal(arch, &spelled, "sse,sse2").unwrap_or_else(|| {
                panic!("{arch} was built with `{spelled:?}` and the build accepted it")
            });
            assert!(said.contains("target-cpu"), "{said}");
            assert!(said.contains("remove"), "{said}");
        }
        assert_eq!(
            refusal(
                arch,
                &flags(&["-Ccodegen-units=1", "-Clink-arg=/IGNORE:4099"]),
                "sse,sse2"
            ),
            None,
            "{arch}: the control has no flag about the processor"
        );
        assert_eq!(refusal(arch, "", ""), None, "{arch}: no flags at all");
    }
}

/// KR-REQ-22.01: a target feature the llama.cpp build script turns into an option after the pins
/// (the AVX-512 sets, AVX-VNNI) widens the compiled set past the baseline, whatever flag enabled it,
/// and the refusal names the feature. The sets inside the baseline, and the sets a target has by
/// default, are not refused here. The control for each is the baseline's own set.
#[test]
fn a_target_feature_wider_than_the_baseline_is_refused_on_x86() {
    for arch in ["x86_64", "x86"] {
        for wide in [
            "avxvnni",
            "avx512f",
            "avx512bf16",
            "avx512vbmi",
            "avx512vnni",
            "amx-tile",
        ] {
            let features = format!("sse,sse2,sse4.2,avx,avx2,{wide},fma");
            let said = refusal(arch, "", &features)
                .unwrap_or_else(|| panic!("{arch} with {wide} was accepted"));
            assert!(said.contains(wide), "{said}");
        }
        for allowed in [
            "sse,sse2,fxsr",
            "sse,sse2,sse3,ssse3,sse4.1,cmpxchg16b",
            "sse,sse2,sse4.2,popcnt,avx,avx2,bmi1,bmi2,fma,f16c,lzcnt,movbe",
        ] {
            assert_eq!(refusal(arch, "", allowed), None, "{arch}: {allowed}");
        }
    }
}

/// A target feature of another architecture says nothing about the x86 baseline: the same names a
/// build for ARM carries are not refused, and neither is a feature that only looks like one.
#[test]
fn only_x86_is_held_to_the_x86_feature_names() {
    assert_eq!(refusal("aarch64", "", "neon,fp16,sve2,i8mm"), None);
    assert_eq!(refusal("x86_64", "", "sse,sse2,avx2,not-avx512"), None);
}
