//! What can run inside the processes that serve a session, read from the graph Cargo resolved.
//!
//! Section 2 keeps the worker's trusted core small: the terminal, the canonical state, the input
//! lease, the receipts and the minimal declarative gateway. Application-specific parsers, Wasm and
//! model inference run somewhere else. Whether a process can host them is a fact about what that
//! process links, so these tests walk the lock file, which is the dependency graph Cargo resolved
//! for the whole workspace: every package, on every platform, through every kind of dependency.
//! Walking it from one package gives more than that package's process links, never less, so an
//! absence found here is an absence in the process.
//!
//! The same walk is run from the crates that do link these things, so an absence reported here is
//! the absence of the thing rather than a walk that found nothing.

use std::collections::BTreeSet;
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

/// Whether `name` is `family` or one of its parts, such as `wasmtime-environ` or `llama-cpp-2`.
fn of_family(name: &str, family: &str) -> bool {
    name == family
        || name
            .strip_prefix(family)
            .is_some_and(|rest| rest.starts_with('-') || rest.starts_with('_'))
}

/// One package of the lock file: its name, version and source, and the dependencies Cargo resolved
/// for it, each written the way the lock file writes it.
#[derive(Debug, Default)]
struct Locked {
    name: String,
    version: String,
    source: Option<String>,
    dependencies: Vec<String>,
}

/// Every package the workspace's lock file holds.
fn locked() -> Vec<Locked> {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    let text = std::fs::read_to_string(root.join("Cargo.lock")).expect("reads the lock file");
    let mut packages: Vec<Locked> = Vec::new();
    let mut in_dependencies = false;
    let quoted = |line: &str| {
        line.trim()
            .trim_end_matches(',')
            .trim_matches('"')
            .to_owned()
    };
    for line in text.lines() {
        if line == "[[package]]" {
            packages.push(Locked::default());
            in_dependencies = false;
            continue;
        }
        let Some(package) = packages.last_mut() else {
            continue;
        };
        if in_dependencies {
            if line.trim() == "]" {
                in_dependencies = false;
            } else {
                package.dependencies.push(quoted(line));
            }
        } else if let Some(value) = line.strip_prefix("name = ") {
            package.name = quoted(value);
        } else if let Some(value) = line.strip_prefix("version = ") {
            package.version = quoted(value);
        } else if let Some(value) = line.strip_prefix("source = ") {
            package.source = Some(quoted(value));
        } else if line.starts_with("dependencies = [") {
            in_dependencies = !line.ends_with(']');
        }
    }
    assert!(
        packages.len() > 100 && packages.iter().all(|package| !package.name.is_empty()),
        "the lock file was read: {} packages",
        packages.len()
    );
    packages
}

/// The package a dependency entry names: `name`, `name version` or `name version (source)`.
fn resolve(packages: &[Locked], entry: &str) -> usize {
    let mut words = entry.splitn(3, ' ');
    let name = words.next().unwrap_or_default();
    let version = words.next();
    let source = words
        .next()
        .map(|source| source.trim_start_matches('(').trim_end_matches(')'));
    let found: Vec<usize> = packages
        .iter()
        .enumerate()
        .filter(|(_, package)| {
            package.name == name
                && version.is_none_or(|version| package.version == version)
                // A git source is written with its commit after a `#`, and a dependency entry
                // names it without one.
                && source.is_none_or(|source| {
                    package
                        .source
                        .as_deref()
                        .is_some_and(|own| own.split('#').next() == Some(source))
                })
        })
        .map(|(index, _)| index)
        .collect();
    assert_eq!(found.len(), 1, "{entry} names exactly one package");
    found[0]
}

/// Every package the lock file reaches from the workspace member `package`, itself excluded.
fn linked(packages: &[Locked], package: &str) -> BTreeSet<String> {
    let start = packages
        .iter()
        .position(|locked| locked.name == package && locked.source.is_none())
        .unwrap_or_else(|| panic!("{package} is a member of this workspace"));
    let mut seen = BTreeSet::new();
    let mut waiting = vec![start];
    while let Some(index) = waiting.pop() {
        if !seen.insert(index) {
            continue;
        }
        for entry in &packages[index].dependencies {
            waiting.push(resolve(packages, entry));
        }
    }
    seen.remove(&start);
    seen.iter()
        .map(|index| packages[*index].name.clone())
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
    let packages = locked();
    let worker = linked(&packages, "kr-worker");
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
        linked(&packages, "kr-plugin-runtime")
            .iter()
            .any(|name| of_family(name, "wasmtime")),
        "the plugin runtime links its Wasm engine"
    );
    assert!(
        linked(&packages, "kr-describe")
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
    let packages = locked();
    for process in ["kr-worker", "kr-controller"] {
        let linked = linked(&packages, process);
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
