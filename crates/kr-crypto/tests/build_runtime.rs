//! What the crate's build script says to a Windows MSVC build that lacks the static C runtime.
//!
//! The decision is a function of three things cargo hands a build script, so it runs here on
//! strings, with a control for each refusal. The same file is the build script's own.

#[allow(dead_code)]
#[path = "../build/static_runtime.rs"]
mod static_runtime;

use static_runtime::refusal;

/// The features a Windows MSVC target has without the static runtime, as cargo lists them.
const WITHOUT: [&str; 4] = ["", "fxsr,sse,sse2", "sse2", "fxsr,sse,sse2,x87,avx2"];

/// The same lists with it, in each place the feature can stand.
const WITH: [&str; 4] = [
    "crt-static",
    "crt-static,fxsr,sse,sse2",
    "fxsr,sse,sse2,crt-static",
    "fxsr,crt-static,sse2",
];

#[test]
fn an_msvc_build_without_the_static_runtime_is_refused_with_its_usual_cause() {
    for features in WITHOUT {
        let words = refusal("windows", "msvc", features)
            .unwrap_or_else(|| panic!("a build with {features:?} was not refused"));
        assert!(words.contains("crt-static"), "{features:?}: {words}");
        assert!(words.contains("RUSTFLAGS"), "{features:?}: {words}");
        assert!(
            words.contains(".cargo/config.toml"),
            "{features:?}: {words}"
        );
    }
}

#[test]
fn an_msvc_build_with_the_static_runtime_is_not_refused() {
    for features in WITH {
        assert_eq!(refusal("windows", "msvc", features), None, "{features:?}");
    }
}

#[test]
fn a_feature_that_only_looks_like_it_is_not_the_static_runtime() {
    for features in ["crt-static-x", "xcrt-static", "crt_static", "CRT-STATIC"] {
        assert!(
            refusal("windows", "msvc", features).is_some(),
            "{features:?} was not refused"
        );
    }
}

#[test]
fn a_build_for_another_target_is_not_refused_whatever_its_features_say() {
    for (os, env) in [
        ("windows", "gnu"),
        ("macos", ""),
        ("linux", "gnu"),
        ("linux", "musl"),
        ("ios", ""),
        ("android", ""),
    ] {
        for features in WITHOUT {
            assert_eq!(refusal(os, env, features), None, "{os} {env} {features:?}");
        }
    }
}
