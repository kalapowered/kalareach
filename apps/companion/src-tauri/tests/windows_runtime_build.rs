//! The build's refusal of the static Visual C++ runtime, shown by the code the build runs.
//!
//! The package's build script stops a build for an MSVC target whose environment asks for the
//! static runtime, because the workspace's linker settings leave out the start-up that it needs.
//! These cases run the decision the build script runs.

use std::ffi::OsStr;

#[allow(dead_code)]
#[path = "../build_windows_runtime.rs"]
mod build_windows_runtime;

fn refused(target_os: &str, target_env: &str, input: Option<&str>) -> Option<&'static str> {
    build_windows_runtime::refusal(target_os, target_env, input.map(OsStr::new))
}

#[test]
fn an_msvc_build_that_asks_for_the_static_runtime_is_refused_with_the_way_to_start_it() {
    // The Tauri command line sets `true`; the build step takes any value but `false` as a request.
    for value in ["true", "1", ""] {
        let words = refused("windows", "msvc", Some(value))
            .unwrap_or_else(|| panic!("a build with {value:?} was not refused"));
        assert!(
            words.contains("STATIC_VCRUNTIME=false"),
            "{value:?}: {words}"
        );
    }
}

#[test]
fn an_msvc_build_that_does_not_ask_for_it_is_not_refused() {
    assert_eq!(refused("windows", "msvc", None), None);
    assert_eq!(refused("windows", "msvc", Some("false")), None);
}

#[test]
fn a_build_for_another_target_is_not_refused_whatever_the_variable_says() {
    for (os, env) in [
        ("windows", "gnu"),
        ("macos", ""),
        ("linux", "gnu"),
        ("ios", ""),
        ("android", ""),
    ] {
        assert_eq!(refused(os, env, Some("true")), None, "{os} {env}");
    }
}
