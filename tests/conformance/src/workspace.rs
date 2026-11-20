//! The workspace's packages and targets, as Cargo describes them.
//!
//! The report reads targets from `cargo metadata` rather than from the directory layout, so a
//! target Cargo discovers on its own, one a manifest declares with its own path and one that sets
//! `test = false` are all what Cargo says they are.

use std::collections::{BTreeMap, BTreeSet};
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
    /// The kind of a target whose `kind` Cargo gives as `kinds`, in its metadata and in its build
    /// messages alike, or `None` for a build script and any other crate that no test selects.
    #[must_use]
    pub fn from_cargo(kinds: &[&str]) -> Option<Self> {
        if kinds.contains(&"bin") {
            Some(Self::Bin)
        } else if kinds.contains(&"test") {
            Some(Self::Test)
        } else if kinds.contains(&"bench") {
            Some(Self::Bench)
        } else if kinds.contains(&"example") {
            Some(Self::Example)
        } else if kinds.iter().any(|kind| {
            matches!(
                *kind,
                "lib" | "rlib" | "dylib" | "cdylib" | "staticlib" | "proc-macro"
            )
        }) {
            Some(Self::Lib)
        } else {
            None
        }
    }

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
    /// Whether `cargo test --benches` builds it: its manifest's `bench` key, else Cargo's default for
    /// its kind, which is true for a library, a binary and a benchmark and false for the rest.
    pub benchmarked: bool,
    /// The features that its manifest asks to be on before Cargo builds it.
    pub required_features: Vec<String>,
    /// Whether it runs under the standard test harness. A target whose manifest entry says
    /// `harness = false` is a program of its own: it prints no list and no verdicts the report can
    /// read, and only its exit status says anything.
    pub harness: bool,
    /// Its edition, as Cargo gives it: `2015` where the manifest names none.
    pub edition: String,
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
    /// Its features, each with the features and dependencies that turning it on turns on.
    pub features: BTreeMap<String, Vec<String>>,
    /// The features that its dev-dependency on itself turns on, `default` among them unless that
    /// dependency leaves the default features off.
    pub self_dev_features: BTreeSet<String>,
    /// Its manifest.
    pub manifest: PathBuf,
    /// The crates it depends on from crates.io under their own names, with no other dependency
    /// renamed to any of them and the workspace's lockfile resolving each to crates.io: a path
    /// such as `tokio::test` names the crate it says only then.
    pub registry_crates: BTreeSet<String>,
    /// The names its dependencies are known by in its source: a rename where the manifest gives
    /// one, the package's name otherwise.
    pub dependency_names: BTreeSet<String>,
    /// The directory of its workspace's root, relative to the tested root, as Cargo's path for it
    /// resolves: `.` for the root.
    pub workspace: String,
    /// The names of the workspace's members.
    pub workspace_members: Vec<String>,
    /// The names of the members that Cargo runs when no package is named.
    pub workspace_default_members: Vec<String>,
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

/// What reading the plan's workspaces found.
#[derive(Debug, Default)]
pub struct Workspaces {
    /// Every package of every workspace, by name.
    pub packages: Vec<Package>,
    /// What stops the map being trusted: a workspace Cargo could not describe, a lock that is
    /// absent, a package name that two workspaces hold.
    pub problems: Vec<String>,
}

/// Reads the workspace of each of `manifests` (relative to `root`), through one `cargo metadata`
/// each. A package name that two workspaces hold is a problem naming both manifests: a target's
/// identifier is its package, its kind and its name, so two such packages cannot be told apart.
#[must_use]
pub fn read(root: &Path, manifests: &[String]) -> Workspaces {
    let mut found = Workspaces::default();
    // The manifest of the plan that each package name was first read from.
    let mut from: BTreeMap<String, String> = BTreeMap::new();
    for manifest in manifests {
        match read_one(root, manifest) {
            Ok(packages) => {
                for package in packages {
                    match from.get(&package.name) {
                        Some(first) => found.problems.push(format!(
                            "the package `{}` is in two workspaces, `{first}` and `{manifest}`",
                            package.name
                        )),
                        None => {
                            from.insert(package.name.clone(), manifest.clone());
                            found.packages.push(package);
                        }
                    }
                }
            }
            Err(problem) => found.problems.push(problem),
        }
    }
    found.packages.sort_by(|a, b| a.name.cmp(&b.name));
    found
}

/// `path` relative to `root`, with forward slashes, or as it is when it lies elsewhere.
fn shown(root: &Path, path: &Path) -> String {
    let relative = path
        .strip_prefix(root)
        .map(Path::to_path_buf)
        .ok()
        .or_else(|| {
            let canonical = root.canonicalize().ok()?;
            let place = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
            place.strip_prefix(canonical).map(Path::to_path_buf).ok()
        });
    relative
        .as_deref()
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn read_one(root: &Path, manifest: &str) -> Result<Vec<Package>, String> {
    let output = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--manifest-path",
        ])
        .arg(root.join(manifest))
        .output()
        .map_err(|error| format!("cargo metadata could not start for `{manifest}`: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed for `{manifest}`: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let value: Value = serde_json::from_slice(&output.stdout).map_err(|error| {
        format!("cargo metadata wrote something that is not JSON for `{manifest}`: {error}")
    })?;
    describe(root, manifest, &value)
}

/// The packages of the workspace that `cargo metadata` described for `manifest` in `value`, each
/// with the workspace it belongs to and what its manifests say about its harnesses.
fn describe(root: &Path, manifest: &str, value: &Value) -> Result<Vec<Package>, String> {
    let mut packages = parse(value).map_err(|why| format!("{why} for `{manifest}`"))?;
    // The workspace is where Cargo says its root is, relative to the tested root.
    let workspace_root = value["workspace_root"]
        .as_str()
        .ok_or_else(|| format!("cargo metadata gave no `workspace_root` for `{manifest}`"))?;
    let workspace = match shown(root, Path::new(workspace_root)).as_str() {
        "" => ".".to_owned(),
        outside if Path::new(outside).is_absolute() => {
            return Err(format!(
                "the workspace of `{manifest}` is at `{outside}`, which is not inside the tested root"
            ));
        }
        inside => inside.to_owned(),
    };
    // The plan names each workspace by its root manifest: a member's manifest describes the same
    // workspace, and naming it would list the workspace under a name that is not its own. The two
    // manifests are compared as the file system resolves them, so a link on the way of the plan's
    // path does not make a workspace's own manifest a member's; the name shown above is derived
    // apart from that comparison.
    let own = Path::new(workspace_root).join("Cargo.toml");
    let named = root.join(manifest);
    let same = match (named.canonicalize(), own.canonicalize()) {
        (Ok(named), Ok(own)) => named == own,
        _ => named == own,
    };
    if !same {
        let root_manifest = if workspace == "." {
            "Cargo.toml".to_owned()
        } else {
            format!("{workspace}/Cargo.toml")
        };
        return Err(format!(
            "`{manifest}` is a manifest inside the workspace at `{workspace}`: name the workspace's own manifest `{root_manifest}` in `[rust] manifests`"
        ));
    }
    for package in &mut packages {
        package.workspace.clone_from(&workspace);
    }
    // What a manifest asks for is not always what the build gets: a `[patch]` can replace it. The
    // lock is the one Cargo keeps in the workspace's root.
    let lock_path = Path::new(workspace_root).join("Cargo.lock");
    let lock = std::fs::read_to_string(&lock_path).map_err(|error| {
        let lock = shown(root, &lock_path);
        if error.kind() == std::io::ErrorKind::NotFound {
            format!("the lock `{lock}` of the workspace `{manifest}` is absent")
        } else {
            format!("the lock `{lock}` could not be read: {error}")
        }
    })?;
    for package in &mut packages {
        package
            .registry_crates
            .retain(|name| locked_from_crates_io(&lock, name));
    }
    // Cargo's description leaves the harness and the `bench` key out, so each manifest says them.
    for package in &mut packages {
        let manifest = std::fs::read_to_string(&package.manifest).map_err(|error| {
            format!("{} could not be read: {error}", package.manifest.display())
        })?;
        let tables = table_keys(&manifest, &package.name);
        for target in &mut package.targets {
            let table = tables
                .iter()
                .find(|table| table.kind == target.id.kind && table.name == target.id.name);
            target.harness = !table.is_some_and(|table| table.own_harness);
            if let Some(bench) = table.and_then(|table| table.bench) {
                target.benchmarked = bench;
            }
        }
    }
    Ok(packages)
}

/// What a manifest's table for one target says about its harness and its benchmark.
#[derive(Debug, PartialEq, Eq)]
struct TableKeys {
    kind: TargetKind,
    name: String,
    /// The table says `harness = false`: the target is a program of its own.
    own_harness: bool,
    /// The table's `bench` key, if it has one.
    bench: Option<bool>,
}

/// The tables of a manifest that declare a target, each with the keys above, by the kind of table
/// and its name. A `[lib]` table without a name is the package's library.
fn table_keys(manifest: &str, package: &str) -> Vec<TableKeys> {
    let mut found = Vec::new();
    let mut open: Option<TableKeys> = None;
    for line in manifest.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.starts_with('[') {
            found.extend(open.take());
            open = match line {
                "[lib]" => Some(TargetKind::Lib),
                "[[bin]]" => Some(TargetKind::Bin),
                "[[test]]" => Some(TargetKind::Test),
                "[[bench]]" => Some(TargetKind::Bench),
                "[[example]]" => Some(TargetKind::Example),
                _ => None,
            }
            .map(|kind| TableKeys {
                kind,
                name: String::new(),
                own_harness: false,
                bench: None,
            });
            continue;
        }
        let Some(table) = open.as_mut() else {
            continue;
        };
        if let Some((key, value)) = line.split_once('=') {
            match (key.trim(), value.trim()) {
                ("name", value) => table.name = value.trim_matches('"').to_owned(),
                ("harness", "false") => table.own_harness = true,
                ("bench", "true") => table.bench = Some(true),
                ("bench", "false") => table.bench = Some(false),
                _ => {}
            }
        }
    }
    found.extend(open);
    for table in &mut found {
        if table.name.is_empty() {
            table.name = package.replace('-', "_");
        }
    }
    found
}

/// The strings of a JSON array; none for anything else.
fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
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
    let mut ids: Vec<&str> = Vec::new();
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
            let Some(kind) = TargetKind::from_cargo(&kinds) else {
                continue;
            };
            let target_name = target["name"].as_str().ok_or("a target without a name")?;
            let src_path = PathBuf::from(
                target["src_path"]
                    .as_str()
                    .ok_or("a target without a path")?,
            );
            // What Cargo says is tested when no flag names targets: a library, a binary and an
            // integration test unless their manifest says otherwise, and an example or a
            // benchmark only when its manifest says `test = true`. Older formats omit `test`.
            let tested = target["test"].as_bool().unwrap_or(matches!(
                kind,
                TargetKind::Lib | TargetKind::Bin | TargetKind::Test
            ));
            targets.push(Target {
                id: TargetId {
                    package: name.clone(),
                    kind,
                    name: target_name.to_owned(),
                },
                src_path,
                tested_by_default: tested,
                benchmarked: matches!(kind, TargetKind::Lib | TargetKind::Bin | TargetKind::Bench),
                required_features: strings(&target["required-features"]),
                harness: true,
                edition: target["edition"].as_str().unwrap_or("2015").to_owned(),
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
        let features = package["features"]
            .as_object()
            .map(|features| {
                features
                    .iter()
                    .map(|(feature, enables)| (feature.clone(), strings(enables)))
                    .collect()
            })
            .unwrap_or_default();
        let mut self_dev_features = BTreeSet::new();
        for dependency in dependencies.iter().filter(|dependency| {
            dependency["name"].as_str() == Some(name.as_str())
                && dependency["kind"].as_str() == Some("dev")
        }) {
            self_dev_features.extend(strings(&dependency["features"]));
            if dependency["uses_default_features"]
                .as_bool()
                .unwrap_or(true)
            {
                self_dev_features.insert("default".to_owned());
            }
        }
        packages.push(Package {
            name,
            version,
            targets,
            features,
            self_dev_features,
            manifest,
            registry_crates,
            dependency_names,
            workspace: String::new(),
            workspace_members: Vec::new(),
            workspace_default_members: Vec::new(),
        });
        ids.push(id);
    }
    // Cargo names members by their ids; the packages above are the members.
    let names_of = |wanted: &[&str]| -> Vec<String> {
        let mut names: Vec<String> = ids
            .iter()
            .zip(&packages)
            .filter(|(id, _)| wanted.contains(id))
            .map(|(_, package)| package.name.clone())
            .collect();
        names.sort();
        names
    };
    let members_named = names_of(&members);
    let defaults_named = names_of(
        &value["workspace_default_members"]
            .as_array()
            .ok_or("cargo metadata gave no `workspace_default_members`")?
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
    );
    for package in &mut packages {
        package.workspace_members.clone_from(&members_named);
        package
            .workspace_default_members
            .clone_from(&defaults_named);
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
            "workspace_default_members": ["path+file:///w/a#0.1.0"],
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
            "workspace_default_members": ["path+file:///w/a#0.1.0"],
            "packages": [
                {
                    "id": "path+file:///w/a#0.1.0",
                    "name": "a",
                    "version": "0.1.0",
                    "targets": [
                        { "kind": ["lib"], "name": "a", "src_path": "/w/a/src/lib.rs", "test": true },
                        { "kind": ["test"], "name": "flow", "src_path": "/w/a/tests/flow.rs", "test": true },
                        { "kind": ["bench"], "name": "speed", "src_path": "/w/a/benches/speed.rs", "test": false },
                        { "kind": ["example"], "name": "plain", "src_path": "/w/a/examples/plain.rs", "test": false },
                        { "kind": ["example"], "name": "checked", "src_path": "/w/a/examples/checked.rs", "test": true },
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
                (TargetKind::Bench, false),
                (TargetKind::Example, false),
                (TargetKind::Example, true)
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
        let own = |manifest: &str, package: &str| -> Vec<(TargetKind, String)> {
            table_keys(manifest, package)
                .into_iter()
                .filter(|table| table.own_harness)
                .map(|table| (table.kind, table.name))
                .collect()
        };
        assert_eq!(
            own(manifest, "companion-tauri"),
            [(TargetKind::Test, "navigation".to_owned())]
        );
        assert_eq!(
            own("[lib]\nharness = false\n", "a-crate"),
            [(TargetKind::Lib, "a_crate".to_owned())]
        );
    }

    #[test]
    fn a_target_the_manifest_benchmarks_or_not_is_found_by_its_table_and_name() {
        let manifest = "\
[package]
name = \"a-crate\"
bench = true

[lib]
bench = false

[[bin]]
name = \"tool\" # benchmarked by default
path = \"src/main.rs\"

[[test]]
name = \"flow\"
bench = true

[[example]]
bench=true
name = \"demo\"

[[bench]]
name = \"speed\"
bench = false
";
        let keys: Vec<(TargetKind, String, Option<bool>)> = table_keys(manifest, "a-crate")
            .into_iter()
            .map(|table| (table.kind, table.name, table.bench))
            .collect();
        assert_eq!(
            keys,
            [
                (TargetKind::Lib, "a_crate".to_owned(), Some(false)),
                (TargetKind::Bin, "tool".to_owned(), None),
                (TargetKind::Test, "flow".to_owned(), Some(true)),
                (TargetKind::Example, "demo".to_owned(), Some(true)),
                (TargetKind::Bench, "speed".to_owned(), Some(false)),
            ]
        );
    }

    /// A package `a` with one target of each kind, as `cargo metadata` lists them, in the folder
    /// `root` that holds its manifest.
    fn a_target_of_each_kind(root: &Path) -> Value {
        let manifest = root.join("Cargo.toml");
        let target = |kind: &str, name: &str, test: bool| {
            let src = root.join(format!("{kind}-{name}.rs"));
            serde_json::json!({ "kind": [kind], "name": name, "src_path": src, "test": test })
        };
        serde_json::json!({
            "workspace_root": root,
            "workspace_members": ["path+file:///w/a#0.1.0"],
            "workspace_default_members": ["path+file:///w/a#0.1.0"],
            "packages": [{
                "id": "path+file:///w/a#0.1.0",
                "name": "a",
                "version": "0.1.0",
                "manifest_path": manifest,
                "targets": [
                    target("lib", "a", true),
                    target("bin", "a", true),
                    target("test", "flow", true),
                    target("bench", "speed", false),
                    target("example", "plain", false)
                ]
            }]
        })
    }

    #[test]
    fn a_target_is_benchmarked_by_its_kind_where_its_manifest_says_nothing() {
        let packages = parse(&a_target_of_each_kind(Path::new("/w/a"))).expect("parses");
        let benchmarked: Vec<(TargetKind, bool)> = packages[0]
            .targets
            .iter()
            .map(|target| (target.id.kind, target.benchmarked))
            .collect();
        assert_eq!(
            benchmarked,
            [
                (TargetKind::Lib, true),
                (TargetKind::Bin, true),
                (TargetKind::Test, false),
                (TargetKind::Bench, true),
                (TargetKind::Example, false)
            ]
        );
    }

    #[test]
    fn a_manifests_bench_key_decides_whether_its_target_is_benchmarked_over_the_kind() {
        let root = tempfile::tempdir().expect("a directory");
        std::fs::write(
            root.path().join("Cargo.toml"),
            "[package]\nname = \"a\"\n\n[lib]\nbench = false\n\n[[bin]]\nname = \"a\"\n\n[[test]]\nname = \"flow\"\nbench = true\n\n[[bench]]\nname = \"speed\"\nbench = false\n",
        )
        .expect("writes");
        std::fs::write(root.path().join("Cargo.lock"), "version = 4\n").expect("writes");
        let value = a_target_of_each_kind(root.path());
        let packages = describe(root.path(), "Cargo.toml", &value).expect("described");
        let benchmarked: Vec<(TargetKind, bool)> = packages[0]
            .targets
            .iter()
            .map(|target| (target.id.kind, target.benchmarked))
            .collect();
        // The library and the benchmark say `bench = false` against their kinds' default, the test
        // says `bench = true` against its own, and the binary and the example say nothing.
        assert_eq!(
            benchmarked,
            [
                (TargetKind::Lib, false),
                (TargetKind::Bin, true),
                (TargetKind::Test, true),
                (TargetKind::Bench, false),
                (TargetKind::Example, false)
            ]
        );
    }

    #[test]
    fn a_target_carries_its_required_features_and_a_package_its_features_and_its_dev_dependency_on_itself()
     {
        let value = serde_json::json!({
            "workspace_members": ["path+file:///w/a#0.1.0"],
            "workspace_default_members": ["path+file:///w/a#0.1.0"],
            "packages": [{
                "id": "path+file:///w/a#0.1.0",
                "name": "a",
                "version": "0.1.0",
                "features": { "default": ["d"], "d": [], "g": ["f"], "f": [] },
                "dependencies": [
                    { "name": "a", "kind": "dev", "features": ["s"], "uses_default_features": false },
                    { "name": "a", "kind": null, "features": ["n"], "uses_default_features": true },
                    { "name": "b", "kind": "dev", "features": ["t"], "uses_default_features": true }
                ],
                "targets": [
                    { "kind": ["test"], "name": "needs", "src_path": "/w/a/tests/needs.rs", "test": true, "required-features": ["f", "s"] },
                    { "kind": ["test"], "name": "free", "src_path": "/w/a/tests/free.rs", "test": true }
                ]
            }]
        });
        let packages = parse(&value).expect("parses");
        assert_eq!(packages[0].targets[0].required_features, ["f", "s"]);
        assert!(packages[0].targets[1].required_features.is_empty());
        assert_eq!(packages[0].features["g"], ["f"]);
        assert_eq!(packages[0].features["default"], ["d"]);
        assert_eq!(
            packages[0].self_dev_features,
            BTreeSet::from(["s".to_owned()])
        );
        let with_default = serde_json::json!({
            "workspace_members": ["path+file:///w/a#0.1.0"],
            "workspace_default_members": ["path+file:///w/a#0.1.0"],
            "packages": [{
                "id": "path+file:///w/a#0.1.0", "name": "a", "version": "0.1.0", "targets": [],
                "dependencies": [{ "name": "a", "kind": "dev", "features": [] }]
            }]
        });
        assert_eq!(
            parse(&with_default).expect("parses")[0].self_dev_features,
            BTreeSet::from(["default".to_owned()])
        );
    }

    #[test]
    fn the_members_and_the_default_members_of_a_workspace_are_named_by_their_packages() {
        let package = |id: &str, name: &str| serde_json::json!({ "id": id, "name": name, "version": "0.1.0", "targets": [] });
        let mut value = serde_json::json!({
            "workspace_members": ["path+file:///w/a#0.1.0", "path+file:///w/b#0.1.0"],
            "workspace_default_members": ["path+file:///w/b#0.1.0"],
            "packages": [package("path+file:///w/b#0.1.0", "b"), package("path+file:///w/a#0.1.0", "a")]
        });
        let packages = parse(&value).expect("parses");
        for package in &packages {
            assert_eq!(package.workspace_members, ["a", "b"]);
            assert_eq!(package.workspace_default_members, ["b"]);
        }
        // A description that names no default members is refused: nothing stands in for the field.
        value
            .as_object_mut()
            .expect("an object")
            .remove("workspace_default_members");
        assert_eq!(
            parse(&value).expect_err("refused"),
            "cargo metadata gave no `workspace_default_members`"
        );
        assert_eq!(
            describe(Path::new("/r"), "w/Cargo.toml", &value).expect_err("refused"),
            "cargo metadata gave no `workspace_default_members` for `w/Cargo.toml`"
        );
    }

    #[test]
    fn a_workspace_outside_the_tested_root_is_refused_naming_where_it_is() {
        let outer = std::env::temp_dir().join("kr-conformance-outer-workspace");
        let root = outer.join("inner");
        let value = serde_json::json!({
            "workspace_members": [],
            "workspace_default_members": [],
            "packages": [],
            "workspace_root": outer.to_string_lossy(),
        });
        let problem = describe(&root, "Cargo.toml", &value).expect_err("refused");
        // The product shows a path that lies outside the root as `shown` writes it, with forward
        // slashes; the expectation calls the same helper.
        assert!(
            problem.contains(&format!("is at `{}`", shown(&root, &outer)))
                && problem.ends_with("which is not inside the tested root"),
            "{problem}"
        );
    }

    #[test]
    fn a_description_with_no_workspace_root_is_refused_naming_the_field_and_the_manifest() {
        let value = serde_json::json!({
            "workspace_members": [],
            "workspace_default_members": [],
            "packages": []
        });
        assert_eq!(
            describe(Path::new("/r"), "w/Cargo.toml", &value).expect_err("refused"),
            "cargo metadata gave no `workspace_root` for `w/Cargo.toml`"
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
