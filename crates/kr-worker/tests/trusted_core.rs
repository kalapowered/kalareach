//! What can run inside the processes that serve a session, read from the build that makes them.
//!
//! Section 2 keeps the worker's trusted core small: the terminal, the canonical state, the input
//! lease, the receipts and the minimal declarative gateway. Application-specific parsers, Wasm and
//! model inference run somewhere else. Whether a process can host them is a fact about what that
//! process links, so these tests walk the dependency graph Cargo resolves for the build and say
//! what is not in it. Development and build dependencies are not followed: they build tests and
//! build scripts, not the process.
//!
//! The same walk is run over the crates that do link these things, so an absence reported here is
//! the absence of the thing rather than a walk that found nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

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

/// The dependency graph Cargo resolves for this workspace, every platform at once.
///
/// Read from Cargo itself rather than from the manifests, so every way a manifest can declare a
/// dependency, and every package the lock file resolves it to, is counted the way the build counts
/// it.
fn resolved() -> serde_json::Value {
    let output = std::process::Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1", "--locked", "--offline"])
        .current_dir(workspace())
        .output()
        .expect("runs cargo metadata");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("cargo metadata writes JSON")
}

/// Every package the process built from `package` links: the normal dependencies of the graph,
/// followed from `package`, on every platform. Development and build dependencies are not
/// followed, because they build tests and build scripts rather than the process.
fn linked(graph: &serde_json::Value, package: &str) -> BTreeSet<String> {
    let names: BTreeMap<&str, &str> = graph["packages"]
        .as_array()
        .expect("the graph lists its packages")
        .iter()
        .map(|entry| {
            (
                entry["id"].as_str().expect("a package id"),
                entry["name"].as_str().expect("a package name"),
            )
        })
        .collect();
    let nodes: BTreeMap<&str, &serde_json::Value> = graph["resolve"]["nodes"]
        .as_array()
        .expect("the graph is resolved")
        .iter()
        .map(|node| (node["id"].as_str().expect("a node id"), node))
        .collect();
    let start = names
        .iter()
        .find_map(|(id, name)| (*name == package).then_some(*id))
        .unwrap_or_else(|| panic!("{package} is in the graph"));
    let mut seen = BTreeSet::new();
    let mut waiting = vec![start];
    while let Some(id) = waiting.pop() {
        if !seen.insert(id) {
            continue;
        }
        let node = nodes.get(id).unwrap_or_else(|| panic!("{id} is resolved"));
        for dependency in node["deps"]
            .as_array()
            .expect("a node lists its dependencies")
        {
            let normal = dependency["dep_kinds"]
                .as_array()
                .expect("a dependency says how it is used")
                .iter()
                .any(|kind| kind["kind"].is_null());
            if normal {
                waiting.push(dependency["pkg"].as_str().expect("a dependency's package"));
            }
        }
    }
    seen.remove(start);
    seen.iter()
        .map(|id| names.get(id).copied().unwrap_or(*id).to_owned())
        .collect()
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

/// KR-REQ-02.02: the worker process links no plugin runtime and no plugin host, which are where
/// application-specific parsers run as components, no Wasm engine and no model runtime, so none of
/// them can run inside it.
#[test]
fn the_worker_links_no_plugin_runtime_wasm_engine_or_model() {
    let graph = resolved();
    let worker = linked(&graph, "kr-worker");
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
        linked(&graph, "kr-plugin-runtime")
            .iter()
            .any(|name| of_family(name, "wasmtime")),
        "the plugin runtime links its Wasm engine"
    );
    assert!(
        linked(&graph, "kr-describe")
            .iter()
            .any(|name| of_family(name, "llama-cpp")),
        "the description service links its model runtime"
    );
}

/// KR-REQ-05.08: neither process that serves a shell - its worker, and the control daemon that
/// created it - links a Wasm engine or a model runtime, so neither can create a Wasm instance or a
/// model for a shell, idle or not. The plugin runtime and the description service, which do link
/// them, are programs of their own.
#[test]
fn neither_process_serving_a_shell_links_a_wasm_engine_or_a_model_runtime() {
    let graph = resolved();
    for process in ["kr-worker", "kr-controller"] {
        let linked = linked(&graph, process);
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
