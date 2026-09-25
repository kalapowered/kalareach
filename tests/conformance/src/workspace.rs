//! The workspace's packages and targets, as Cargo describes them.
//!
//! The report reads targets from `cargo metadata` rather than from the directory layout, so a
//! target Cargo discovers on its own, one a manifest declares with its own path and one that sets
//! `test = false` are all what Cargo says they are.

use std::collections::BTreeSet;
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
    /// Whether it runs under the standard test harness. A target whose manifest entry says
    /// `harness = false` is a program of its own: it prints no list and no verdicts the report can
    /// read, and only its exit status says anything.
    pub harness: bool,
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
    /// Its manifest.
    pub manifest: PathBuf,
    /// The crates it depends on from crates.io under their own names, with no other dependency
    /// renamed to any of them and the workspace's lockfile resolving each to crates.io: a path
    /// such as `tokio::test` names the crate it says only then.
    pub registry_crates: BTreeSet<String>,
    /// The names its dependencies are known by in its source: a rename where the manifest gives
    /// one, the package's name otherwise.
    pub dependency_names: BTreeSet<String>,
}

/// The sources Cargo names crates.io by.
const CRATES_IO: &[&str] = &[
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
];

/// Whether the lockfile `lock` resolves the package `name` to crates.io, every time it lists it.
fn locked_from_crates_io(lock: &str, name: &str) -> bool {
    let mut found = false;
    for block in lock.split("[[package]]").skip(1) {
        let field = |key: &str| {
            block.lines().find_map(|line| {
                line.trim()
                    .strip_prefix(key)?
                    .trim()
                    .strip_prefix('=')?
                    .trim()
                    .strip_prefix('"')?
                    .strip_suffix('"')
            })
        };
        if field("name") != Some(name) {
            continue;
        }
        if !field("source").is_some_and(|source| CRATES_IO.contains(&source)) {
            return false;
        }
        found = true;
    }
    found
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
    let mut packages = parse(&value)?;
    // What a manifest asks for is not always what the build gets: a `[patch]` can replace it.
    let lock = std::fs::read_to_string(root.join("Cargo.lock")).unwrap_or_default();
    for package in &mut packages {
        package
            .registry_crates
            .retain(|name| locked_from_crates_io(&lock, name));
    }
    // Cargo's description leaves the harness out, so each manifest says it.
    for package in &mut packages {
        let manifest = std::fs::read_to_string(&package.manifest).map_err(|error| {
            format!("{} could not be read: {error}", package.manifest.display())
        })?;
        let own = own_harnesses(&manifest, &package.name);
        for target in &mut package.targets {
            target.harness = !own.contains(&(target.id.kind, target.id.name.clone()));
        }
    }
    Ok(packages)
}

/// The targets a manifest gives a harness of their own (`harness = false`), each by the kind of
/// table it is declared in and its name. A `[lib]` table without a name is the package's library.
fn own_harnesses(manifest: &str, package: &str) -> Vec<(TargetKind, String)> {
    let mut found = Vec::new();
    let mut table: Option<TargetKind> = None;
    let mut name: Option<String> = None;
    let mut own = false;
    let mut close = |table: Option<TargetKind>, name: Option<String>, own: bool| {
        if let (Some(kind), true) = (table, own) {
            found.push((kind, name.unwrap_or_else(|| package.replace('-', "_"))));
        }
    };
    for line in manifest.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.starts_with('[') {
            close(table, name.take(), own);
            table = match line {
                "[lib]" => Some(TargetKind::Lib),
                "[[bin]]" => Some(TargetKind::Bin),
                "[[test]]" => Some(TargetKind::Test),
                "[[bench]]" => Some(TargetKind::Bench),
                "[[example]]" => Some(TargetKind::Example),
                _ => None,
            };
            own = false;
            continue;
        }
        if table.is_none() {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            match (key.trim(), value.trim()) {
                ("name", value) => name = Some(value.trim_matches('"').to_owned()),
                ("harness", "false") => own = true,
                _ => {}
            }
        }
    }
    close(table, name, own);
    found
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
        let manifest = PathBuf::from(package["manifest_path"].as_str().unwrap_or_default());
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
                harness: true,
            });
        }
        let dependencies = package["dependencies"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let renamed: BTreeSet<&str> = dependencies
            .iter()
            .filter_map(|dependency| dependency["rename"].as_str())
            .collect();
        let registry_crates = dependencies
            .iter()
            .filter(|dependency| {
                dependency["rename"].is_null()
                    && dependency["source"]
                        .as_str()
                        .is_some_and(|source| CRATES_IO.contains(&source))
            })
            .filter_map(|dependency| dependency["name"].as_str())
            .filter(|name| !renamed.contains(name))
            .map(str::to_owned)
            .collect();
        let dependency_names = dependencies
            .iter()
            .filter_map(|dependency| {
                dependency["rename"]
                    .as_str()
                    .or_else(|| dependency["name"].as_str())
            })
            .map(str::to_owned)
            .collect();
        packages.push(Package {
            name,
            version,
            targets,
            manifest,
            registry_crates,
            dependency_names,
        });
    }
    packages.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_crate_is_the_registrys_only_under_its_own_name() {
        let value = serde_json::json!({
            "workspace_members": ["path+file:///w/a#0.1.0"],
            "packages": [{
                "id": "path+file:///w/a#0.1.0",
                "name": "a",
                "version": "0.1.0",
                "manifest_path": "/w/a/Cargo.toml",
                "targets": [],
                "dependencies": [
                    { "name": "tokio", "rename": null, "source": "registry+https://github.com/rust-lang/crates.io-index" },
                    { "name": "serde", "rename": null, "source": "registry+https://github.com/rust-lang/crates.io-index" },
                    { "name": "other-serde", "rename": "serde", "source": "registry+https://github.com/rust-lang/crates.io-index" },
                    { "name": "local", "rename": null, "source": null }
                ]
            }]
        });
        let packages = parse(&value).expect("parses");
        assert_eq!(
            packages[0].registry_crates,
            BTreeSet::from(["tokio".to_owned()])
        );
        assert_eq!(
            packages[0].dependency_names,
            ["local", "serde", "tokio"]
                .into_iter()
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn a_crate_the_lockfile_takes_from_elsewhere_is_not_the_registrys() {
        let lock = "version = 4\n\n[[package]]\nname = \"tokio\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"patched\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"mirrored\"\nversion = \"1.0.0\"\nsource = \"registry+https://example.test/index\"\n";
        assert!(locked_from_crates_io(lock, "tokio"));
        assert!(!locked_from_crates_io(lock, "patched"), "a path package");
        assert!(!locked_from_crates_io(lock, "mirrored"), "another registry");
        assert!(
            !locked_from_crates_io(lock, "absent"),
            "not in the lockfile"
        );
    }

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
    fn a_target_the_manifest_gives_its_own_harness_is_found_by_its_table_and_name() {
        let manifest = "\
[package]
name = \"companion-tauri\"

[[bin]]
name = \"kalareach-companion\"
path = \"src/main.rs\"

# Opens real windows, so it has its own main thread.
[[test]]
name = \"navigation\"
harness = false # its own main

[[test]]
name = \"ordinary\"

[build-dependencies]
harness = false
";
        assert_eq!(
            own_harnesses(manifest, "companion-tauri"),
            [(TargetKind::Test, "navigation".to_owned())]
        );
        assert_eq!(
            own_harnesses("[lib]\nharness = false\n", "a-crate"),
            [(TargetKind::Lib, "a_crate".to_owned())]
        );
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
