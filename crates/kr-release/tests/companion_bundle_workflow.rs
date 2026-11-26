//! The `companion-bundle` workflow builds the companion's Windows bundle on a push to main, and only
//! when a file that the bundle is built from changes. Its `paths` list has to name every crate of
//! this workspace that the companion's program links, or a change to such a crate lands without the
//! bundle being built and read on Windows. The list is held here to what `cargo tree` says the
//! program is built from, so a crate that the companion comes to link stops the run of this program
//! until the workflow lists it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The target that the workflow's runner builds for.
const TARGET: &str = "x86_64-pc-windows-msvc";

fn checkout() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The `paths` of the workflow's push trigger, as written.
fn workflow_paths(workflow: &str) -> Vec<String> {
    let mut lines = workflow.lines().skip_while(|line| *line != "    paths:");
    assert!(
        lines.next().is_some(),
        "the workflow's push trigger lists its paths"
    );
    lines
        .map_while(|line| line.strip_prefix("      "))
        .filter_map(|line| line.strip_prefix("- "))
        .map(|path| path.trim().to_string())
        .collect()
}

/// The directories, relative to the checkout, of the workspace crates that the companion's program
/// and its build scripts are made of on the target: its normal and build dependencies, followed
/// through every crate, and not its development dependencies. The tree is the one `tauri build`
/// builds, the package's own features and no other workspace member's: `cargo metadata` unifies the
/// features of every member and so adds crates that the program does not link.
fn linked_directories() -> BTreeSet<String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .args(["tree", "--locked", "--offline", "-p", "companion-tauri"])
        .args(["--edges", "normal,build", "--features", "custom-protocol"])
        .args(["--target", TARGET, "--prefix", "none", "--format", "{p}"])
        .current_dir(checkout())
        .output()
        .expect("cargo runs");
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let root = checkout().canonicalize().expect("the checkout");
    let root = root.to_string_lossy().replace('\\', "/");
    String::from_utf8(output.stdout)
        .expect("the tree is text")
        .lines()
        // A package that lives in a folder is printed as `name v0.1.0 (/the/folder)`, and a line
        // that repeats an earlier one ends with ` (*)`.
        .filter_map(|line| {
            line.trim_end_matches(" (*)")
                .strip_suffix(')')?
                .split_once(" (")
        })
        .filter_map(|(_, folder)| {
            folder
                .replace('\\', "/")
                .strip_prefix(&format!("{root}/"))
                .map(str::to_string)
        })
        .collect()
}

/// The directories that no entry of `paths` covers. An entry covers a directory when it is that
/// directory or one above it, followed by `/**`.
fn uncovered(paths: &[String], directories: &BTreeSet<String>) -> Vec<String> {
    directories
        .iter()
        .filter(|directory| {
            !paths.iter().any(|path| {
                path.strip_suffix("/**").is_some_and(|prefix| {
                    directory.as_str() == prefix
                        || directory
                            .strip_prefix(prefix)
                            .is_some_and(|rest| rest.starts_with('/'))
                })
            })
        })
        .cloned()
        .collect()
}

#[test]
fn the_workflow_lists_every_workspace_crate_that_the_companion_links() {
    let workflow =
        std::fs::read_to_string(checkout().join(".github/workflows/companion-bundle.yml"))
            .expect("the workflow");
    let paths = workflow_paths(&workflow);
    assert!(
        paths.contains(&"Cargo.lock".to_string()),
        "the list was read: {paths:?}"
    );

    let linked = linked_directories();
    // The walk reaches the companion's own folders and a crate that it links only through another,
    // and none that the program does not link.
    for expected in [
        "apps/companion/src-tauri",
        "apps/companion/native/platform",
        "crates/kr-width",
    ] {
        assert!(
            linked.contains(expected),
            "the walk finds {expected}: {linked:?}"
        );
    }
    assert!(
        !linked.contains("crates/kr-term"),
        "the walk follows only what is linked: {linked:?}"
    );
    assert_eq!(
        uncovered(&paths, &linked),
        Vec::<String>::new(),
        "a crate that the companion links is missing from the workflow's paths"
    );
}

#[test]
fn a_crate_that_the_list_does_not_cover_is_reported() {
    let listed = |entries: &[&str]| {
        entries
            .iter()
            .map(|entry| entry.to_string())
            .collect::<Vec<_>>()
    };
    let linked: BTreeSet<String> = [
        "apps/companion/native/platform",
        "crates/kr-ipc",
        "crates/kr-cbor",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();

    let paths = listed(&["apps/companion/native/**", "crates/kr-cbor/**"]);
    assert_eq!(uncovered(&paths, &linked), ["crates/kr-ipc"]);

    // A name that only starts like a listed folder, a file of the folder alone and a bare folder
    // name cover nothing.
    let paths = listed(&[
        "crates/kr-ip/**",
        "crates/kr-ipc/build.rs",
        "crates/kr-cbor",
        "apps/**",
    ]);
    assert_eq!(
        uncovered(&paths, &linked),
        ["crates/kr-cbor", "crates/kr-ipc"]
    );

    let paths = listed(&["crates/**", "apps/companion/native/platform/**"]);
    assert_eq!(uncovered(&paths, &linked), Vec::<String>::new());
}
