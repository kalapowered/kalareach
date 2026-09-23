//! What can run inside the processes that serve a session, read from the build that makes them.
//!
//! Section 2 keeps the worker's trusted core small: the terminal, the canonical state, the input
//! lease, the receipts and the minimal declarative gateway. Application-specific parsers, Wasm and
//! model inference run somewhere else. Whether they *can* run in a process is a fact about what
//! that process links, so these tests walk the dependency graph the build resolves - this
//! workspace's own manifests for its crates, and the lock file for everything else - and say what
//! is not in it. Development dependencies are not followed: they build tests, not the process.
//!
//! The same walk is run over the crates that do link these things, so an absence reported here is
//! the absence of the thing rather than a walk that found nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Engines that instantiate Wasm components.
const WASM_ENGINES: &[&str] = &["wasmtime", "wasmer", "wasmi", "cranelift"];

/// Runtimes that load and run a model.
const MODEL_RUNTIMES: &[&str] = &[
    "llama-cpp",
    "candle",
    "ort",
    "tract",
    "whisper",
    "onnxruntime",
    "tokenizers",
];

/// This workspace's crates that host plugins or run inference.
const PLUGIN_AND_INFERENCE_CRATES: &[&str] =
    &["kr-plugin-runtime", "kr-plugin-host", "kr-describe"];

fn workspace() -> PathBuf {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

/// Whether `name` is `family` or one of its parts, such as `wasmtime-environ` or `llama-cpp-2`.
fn of_family(name: &str, family: &str) -> bool {
    name == family
        || name
            .strip_prefix(family)
            .is_some_and(|rest| rest.starts_with('-') || rest.starts_with('_'))
}

/// This workspace's crates, by package name, with the manifest that declares each.
fn members() -> BTreeMap<String, PathBuf> {
    let root = workspace();
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("reads the workspace");
    let list = manifest
        .split("members = [")
        .nth(1)
        .and_then(|rest| rest.split(']').next())
        .expect("the workspace lists its members");
    let mut members = BTreeMap::new();
    for member in list
        .split(',')
        .map(|entry| entry.trim().trim_matches('"'))
        .filter(|entry| !entry.is_empty())
    {
        let path = root.join(member).join("Cargo.toml");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("reads {}: {error}", path.display()));
        let name = text
            .lines()
            .find_map(|line| line.strip_prefix("name = "))
            .map(|name| name.trim().trim_matches('"').to_owned())
            .unwrap_or_else(|| panic!("{} names its package", path.display()));
        members.insert(name, path);
    }
    members
}

/// What each package in the lock file depends on, every version of it together.
fn locked() -> BTreeMap<String, BTreeSet<String>> {
    let text =
        std::fs::read_to_string(workspace().join("Cargo.lock")).expect("reads the lock file");
    let mut packages: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for block in text.split("[[package]]").skip(1) {
        let mut name = None;
        let mut dependencies = BTreeSet::new();
        let mut listing = false;
        for line in block.lines().map(str::trim) {
            if let Some(value) = line.strip_prefix("name = ") {
                name = Some(value.trim_matches('"').to_owned());
            } else if line == "dependencies = [" {
                listing = true;
            } else if listing && line == "]" {
                listing = false;
            } else if listing {
                // `"name"`, or `"name version"` where two versions of one package are locked.
                let entry = line.trim_end_matches(',').trim_matches('"');
                let dependency = entry.split(' ').next().unwrap_or(entry);
                dependencies.insert(dependency.to_owned());
            }
        }
        let name = name.expect("every locked package has a name");
        packages.entry(name).or_default().extend(dependencies);
    }
    packages
}

/// What one of this workspace's crates declares for the process it builds.
///
/// Every section whose name ends in `dependencies` is read, including the per-platform ones,
/// because a dependency added for one operating system is still in that system's process.
/// Development and build dependencies are not: they build tests and build scripts.
fn declared(manifest: &Path) -> BTreeSet<String> {
    let text = std::fs::read_to_string(manifest)
        .unwrap_or_else(|error| panic!("reads {}: {error}", manifest.display()));
    let mut dependencies = BTreeSet::new();
    let mut reading = false;
    for line in text.lines() {
        if let Some(section) = line
            .trim_end()
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            reading = section.ends_with("dependencies")
                && !section.ends_with("dev-dependencies")
                && !section.ends_with("build-dependencies");
            continue;
        }
        // A dependency is a key at the start of a line; anything indented continues the one
        // before it.
        if !reading || !line.starts_with(|c: char| c.is_ascii_alphanumeric()) {
            continue;
        }
        let Some((key, _)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        dependencies.insert(key.strip_suffix(".workspace").unwrap_or(key).to_owned());
    }
    dependencies
}

/// Every package the process built from `package` links.
fn linked(package: &str) -> BTreeSet<String> {
    let members = members();
    let locked = locked();
    let mut seen = BTreeSet::new();
    let mut waiting = vec![package.to_owned()];
    while let Some(name) = waiting.pop() {
        if !seen.insert(name.clone()) {
            continue;
        }
        let next = match members.get(&name) {
            Some(manifest) => declared(manifest),
            None => locked
                .get(&name)
                .cloned()
                .unwrap_or_else(|| panic!("{name} is neither in this workspace nor locked")),
        };
        waiting.extend(next);
    }
    seen.remove(package);
    seen
}

/// The plugin hosts, Wasm engines and model runtimes among `linked`.
fn hosts_or_engines(linked: &BTreeSet<String>) -> Vec<String> {
    linked
        .iter()
        .filter(|name| {
            PLUGIN_AND_INFERENCE_CRATES.contains(&name.as_str())
                || WASM_ENGINES
                    .iter()
                    .chain(MODEL_RUNTIMES)
                    .any(|family| of_family(name, family))
        })
        .cloned()
        .collect()
}

/// KR-REQ-02.02: the worker process links no plugin runtime or host, no Wasm engine and no model
/// runtime, so no application-specific parser, Wasm component or model inference runs inside it.
#[test]
fn the_worker_links_no_plugin_runtime_wasm_engine_or_model() {
    let worker = linked("kr-worker");
    // The walk reaches the trusted core, which is what makes the next assertion mean something.
    for core in [
        "kr-term",
        "kr-protocol",
        "kr-shell-integration",
        "portable-pty",
        "rusqlite",
    ] {
        assert!(worker.contains(core), "the worker links {core}");
    }
    let found = hosts_or_engines(&worker);
    assert!(
        found.is_empty(),
        "the worker process links {found:?}, which run plugins, Wasm or models"
    );

    // The same walk finds each of them where it is linked.
    assert!(
        linked("kr-plugin-runtime")
            .iter()
            .any(|name| of_family(name, "wasmtime")),
        "the plugin runtime links its Wasm engine"
    );
    assert!(
        linked("kr-describe")
            .iter()
            .any(|name| of_family(name, "llama-cpp")),
        "the description service links its model runtime"
    );
}

/// KR-REQ-05.08: neither process that serves a shell - its worker, and the control daemon that
/// created it - links a Wasm engine or a model runtime, so neither can create a Wasm instance or a
/// model for a shell, idle or not. The plugin runtime and the description service are separate
/// programs that nothing here starts.
#[test]
fn neither_process_serving_a_shell_links_a_wasm_engine_or_a_model_runtime() {
    for process in ["kr-worker", "kr-controller"] {
        let linked = linked(process);
        assert!(
            linked.contains("kr-protocol"),
            "the walk reached {process}'s own dependencies"
        );
        let found = hosts_or_engines(&linked);
        assert!(
            found.is_empty(),
            "{process} links {found:?}, which create Wasm instances or load models"
        );
    }
}
