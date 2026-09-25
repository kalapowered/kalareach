//! The workspace's packages and targets, as Cargo describes them.
//!
//! The report reads targets from `cargo metadata` rather than from the directory layout, so a
//! target Cargo discovers on its own, one a manifest declares with its own path and one that sets
//! `test = false` are all what Cargo says they are.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;
use serde_json::Value;

/// What kind of target a target is, in the words `cargo test` selects them by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    /// The library, whatever crate types it builds.
    Lib,
    /// A binary.
    Bin,
    /// An integration test.
    Test,
    /// A benchmark.
    Bench,
    /// An example.
    Example,
}

impl TargetKind {
    /// The `cargo test` flag that selects a target of this kind by name, or `--lib`.
    #[must_use]
    pub fn selector(self, name: &str) -> String {
        match self {
            Self::Lib => "--lib".to_owned(),
            Self::Bin => format!("--bin {name}"),
            Self::Test => format!("--test {name}"),
            Self::Bench => format!("--bench {name}"),
            Self::Example => format!("--example {name}"),
        }
    }
}

/// One target of one package.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct TargetId {
    /// The package.
    pub package: String,
    /// The kind.
    pub kind: TargetKind,
    /// The target's name.
    pub name: String,
}

impl std::fmt::Display for TargetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.package, self.kind.selector(&self.name))
    }
}

/// A target and where its crate root is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// Which target it is.
    pub id: TargetId,
    /// Its crate root.
    pub src_path: PathBuf,
    /// Whether `cargo test` builds and runs it without being asked by name.
    pub tested_by_default: bool,
}

/// One package of the workspace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Package {
    /// Its name.
    pub name: String,
    /// Its version.
    pub version: String,
    /// Its targets.
    pub targets: Vec<Target>,
}

/// Reads the workspace whose manifest is at `root`, through `cargo metadata`.
///
/// # Errors
///
/// Returns what Cargo said when it could not describe the workspace.
pub fn read(root: &Path) -> Result<Vec<Package>, String> {
    let output = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--manifest-path",
        ])
        .arg(root.join("Cargo.toml"))
        .output()
        .map_err(|error| format!("cargo metadata could not start: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("cargo metadata wrote something that is not JSON: {error}"))?;
    parse(&value)
}

/// Reads packages out of `cargo metadata`'s output.
///
/// # Errors
///
/// Returns the field that is missing or has the wrong shape.
pub fn parse(value: &Value) -> Result<Vec<Package>, String> {
    let members: Vec<&str> = value["workspace_members"]
        .as_array()
        .ok_or("cargo metadata named no workspace members")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let mut packages = Vec::new();
    for package in value["packages"]
        .as_array()
        .ok_or("cargo metadata listed no packages")?
    {
        let id = package["id"].as_str().unwrap_or_default();
        if !members.contains(&id) {
            continue;
        }
        let name = package["name"]
            .as_str()
            .ok_or("a package without a name")?
            .to_owned();
        let version = package["version"].as_str().unwrap_or_default().to_owned();
        let mut targets = Vec::new();
        for target in package["targets"]
            .as_array()
            .ok_or("a package without targets")?
        {
            let kinds: Vec<&str> = target["kind"]
                .as_array()
                .map(|kinds| kinds.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let kind = if kinds.contains(&"bin") {
                TargetKind::Bin
            } else if kinds.contains(&"test") {
                TargetKind::Test
            } else if kinds.contains(&"bench") {
                TargetKind::Bench
            } else if kinds.contains(&"example") {
                TargetKind::Example
            } else if kinds.iter().any(|kind| {
                matches!(
                    *kind,
                    "lib" | "rlib" | "dylib" | "cdylib" | "staticlib" | "proc-macro"
                )
            }) {
                TargetKind::Lib
            } else {
                continue;
            };
            let target_name = target["name"].as_str().ok_or("a target without a name")?;
            let src_path = PathBuf::from(
                target["src_path"]
                    .as_str()
                    .ok_or("a target without a path")?,
            );
            // Cargo omits `test` in older formats; a benchmark and an example are only tested when
            // asked for by name, whatever the manifest says.
            let tested = target["test"].as_bool().unwrap_or(true)
                && matches!(kind, TargetKind::Lib | TargetKind::Bin | TargetKind::Test);
            targets.push(Target {
                id: TargetId {
                    package: name.clone(),
                    kind,
                    name: target_name.to_owned(),
                },
                src_path,
                tested_by_default: tested,
            });
        }
        packages.push(Package {
            name,
            version,
            targets,
        });
    }
    packages.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn members_and_their_targets_are_read_and_a_build_script_is_not_a_target() {
        let value = serde_json::json!({
            "workspace_members": ["path+file:///w/a#0.1.0"],
            "packages": [
                {
                    "id": "path+file:///w/a#0.1.0",
                    "name": "a",
                    "version": "0.1.0",
                    "targets": [
                        { "kind": ["lib"], "name": "a", "src_path": "/w/a/src/lib.rs", "test": true },
                        { "kind": ["test"], "name": "flow", "src_path": "/w/a/tests/flow.rs", "test": true },
                        { "kind": ["bench"], "name": "speed", "src_path": "/w/a/benches/speed.rs", "test": false },
                        { "kind": ["custom-build"], "name": "build-script-build", "src_path": "/w/a/build.rs" }
                    ]
                },
                { "id": "registry+x#1.0.0", "name": "dependency", "version": "1.0.0", "targets": [] }
            ]
        });
        let packages = parse(&value).expect("parses");
        assert_eq!(packages.len(), 1);
        let kinds: Vec<(TargetKind, bool)> = packages[0]
            .targets
            .iter()
            .map(|t| (t.id.kind, t.tested_by_default))
            .collect();
        assert_eq!(
            kinds,
            [
                (TargetKind::Lib, true),
                (TargetKind::Test, true),
                (TargetKind::Bench, false)
            ]
        );
        assert_eq!(packages[0].targets[1].id.to_string(), "a --test flow");
    }

    #[test]
    fn the_selector_is_the_flag_cargo_test_takes() {
        assert_eq!(TargetKind::Lib.selector("x"), "--lib");
        assert_eq!(
            TargetKind::Bench.selector("input_latency"),
            "--bench input_latency"
        );
    }
}
