//! The test-only later major never reaches a program a person installs (KR-REQ-26.07).
//!
//! A build with debug assertions can be made to state another public major on its local links
//! (`KR_TEST_LOCAL_MAJOR`); a build without them has no such variable and states the build's own.
//! So the programs a release ships are held to a build without debug assertions: no profile or
//! workflow switches them on, and the workflows that build the host's executables for a release
//! build them in release.

use std::path::{Path, PathBuf};

/// The repository's root.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The text of every file that decides how a program is built: the workspace's manifest, cargo's
/// configuration, and each workflow and action.
fn build_files() -> Vec<(PathBuf, String)> {
    let mut files = vec![root().join("Cargo.toml"), root().join(".cargo/config.toml")];
    // The workflows, and the actions they run, which can set a build's environment as well.
    let github = root().join(".github");
    let mut pending = vec![github.join("workflows"), github.join("actions")];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).expect("a directory of workflows or actions") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path
                .extension()
                .is_some_and(|extension| extension == "yml" || extension == "yaml")
            {
                files.push(path);
            }
        }
    }
    files
        .into_iter()
        .map(|path| {
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            (path, text)
        })
        .collect()
}

/// KR-REQ-26.07: nothing sets debug assertions on, in a profile, in cargo's configuration or in a
/// workflow's environment.
#[test]
fn nothing_switches_debug_assertions_on_for_a_shipped_program() {
    for (path, text) in build_files() {
        for spelling in ["debug-assertions", "DEBUG_ASSERTIONS", "debug_assertions"] {
            assert!(
                !text.contains(spelling),
                "{} sets {spelling}, which would put the test-only later major in a program",
                path.display()
            );
        }
    }
}

/// KR-REQ-26.07: the workflows that build the host's executables for a release build each of them in
/// release. The other workflows' builds are the tests', and are not read here.
#[test]
fn the_release_workflows_build_the_host_in_release() {
    for workflow in ["release-baselines.yml", "release-windows.yml"] {
        let path = root().join(".github/workflows").join(workflow);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        let builds: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("cargo build"))
            .collect();
        assert!(!builds.is_empty(), "{workflow} builds nothing with cargo");
        for build in builds {
            assert!(
                build.contains("--release"),
                "{workflow} builds in debug: {}",
                build.trim()
            );
        }
    }
}
