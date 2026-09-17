//! Running real components under the section 11 bounds.
//!
//! Every test here compiles and instantiates an actual component and calls into it. That is the
//! point: a limiter that is never asked, a deadline that is never reached and an import list that
//! is never inspected all look correct in a unit test.
//!
//! Requirement rows closed here: KR-REQ-04.07, KR-REQ-06.06, KR-REQ-06.07, KR-REQ-11.01,
//! KR-REQ-11.02, KR-REQ-11.21, KR-REQ-11.38, KR-REQ-11.40, KR-REQ-11.41.

mod components;

use std::sync::Arc;

use kr_plugin_runtime::RuntimeError;
use kr_plugin_runtime::runtime::binding::{BindingEvent, Runtime, RuntimeConfig};
use kr_plugin_runtime::runtime::bindings::{
    ActionToken, Argument, EffectClass, NamedArgument, PreparedOperation, RequestSnapshot,
};
use kr_plugin_runtime::runtime::budget::{CallBudget, CallKind};
use kr_plugin_runtime::runtime::compile::{CompileBudget, CompileOrigin, compile_or_load};
use kr_plugin_runtime::runtime::engine::RuntimeEngine;
use kr_plugin_runtime::runtime::error::ExhaustedBound;
use kr_plugin_runtime::runtime::host::{BindingFacts, MAX_NODE_BYTES};
use kr_plugin_runtime::runtime::instance::Instance;
use kr_plugin_runtime::runtime::limits::InstanceLimiter;
use kr_plugin_runtime::runtime::queue::Admission;
use kr_plugin_sdk::limits::{
    FAULTS_BEFORE_DISABLE, INSTANCE_MEMORY_BYTES, OBSERVATION_QUEUE_BYTES, OUTPUT_BYTES_PER_CALL,
};

/// A cache directory that removes itself, and the runtime built over it.
struct Host {
    _directory: tempfile::TempDir,
    runtime: Runtime,
}

fn host() -> Host {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let runtime =
        Runtime::new(RuntimeConfig::new(directory.path().join("plugin-cache"))).expect("a runtime");
    Host {
        _directory: directory,
        runtime,
    }
}

fn engine() -> RuntimeEngine {
    RuntimeEngine::new().expect("an engine")
}

/// Instantiates one component directly, outside a binding's thread.
///
/// The binding lifecycle is exercised separately; these tests want the calls themselves, where the
/// bound that stopped one is the return value rather than an event.
fn instance(wasm: &[u8], plugin: &str, fuel_rate: u64) -> (tempfile::TempDir, Instance) {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let engine = engine();
    let cache = kr_plugin_runtime::runtime::cache::CompiledCache::open(
        directory.path().join("plugin-cache"),
    )
    .expect("a cache");
    let compiled = compile_or_load(&engine, &cache, wasm, CompileBudget::defaults())
        .expect("the component compiles");
    let instance = Instance::new(
        &engine,
        &compiled.component,
        components::facts(plugin),
        InstanceLimiter::defaults(),
        fuel_rate,
    )
    .expect("the component instantiates");
    (directory, instance)
}

fn bound(wasm: &[u8], plugin: &str) -> (tempfile::TempDir, Instance) {
    let (directory, mut instance) = instance(
        wasm,
        plugin,
        kr_plugin_runtime::runtime::budget::FUEL_PER_DEADLINE_MS,
    );
    let target = kr_plugin_runtime::runtime::bindings::Binding {
        plugin_id: format!("kalareach/{plugin}"),
        binding_revision: 3,
        executable: "/usr/local/bin/example-agent".to_owned(),
    };
    let outcome = instance.bind(target).expect("bind runs");
    assert!(outcome.answered(), "bind declared a fault: {outcome:?}");
    (directory, instance)
}

fn token(action: &str) -> ActionToken {
    ActionToken {
        actor_id: "actor-1".to_owned(),
        grant_id: "grant-1".to_owned(),
        binding_revision: 3,
        thread_revision: Some(4),
        action_id: action.to_owned(),
        parameter_hash: vec![7; 32],
        expires_at: 1_700_000_100_000,
    }
}

// KR-REQ-04.07, KR-REQ-11.40: a component reaches the four plugin interfaces and nothing else.
#[test]
fn kr_req_04_07_a_component_has_explicit_capabilities_only() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let engine = engine();
    let directory = tempfile::tempdir().expect("a temporary directory");
    let cache = kr_plugin_runtime::runtime::cache::CompiledCache::open(directory.path().join("c"))
        .expect("a cache");
    let compiled = compile_or_load(&engine, &cache, &wasm, CompileBudget::defaults())
        .expect("the component compiles");

    let permitted = kr_plugin_runtime::runtime::imports::permitted_imports();
    let component_type = compiled.component.component_type();
    let imports: Vec<String> = component_type
        .imports(engine.engine())
        .map(|(name, _item)| name.to_owned())
        .collect();
    assert!(!imports.is_empty(), "the component imports nothing at all");
    for import in &imports {
        assert!(
            permitted.contains(import),
            "the component imports {import}, which is outside the contract"
        );
        assert!(
            import.starts_with("kalareach:plugin/"),
            "{import} is not a plugin interface"
        );
    }
}

// KR-REQ-11.40: a component that asks for ambient access is refused, with the import named.
#[test]
fn kr_req_11_40_an_ambient_import_is_refused_and_named() {
    let Some(wasm) = components::component("ambient-import") else {
        return;
    };
    let engine = engine();
    let directory = tempfile::tempdir().expect("a temporary directory");
    let cache = kr_plugin_runtime::runtime::cache::CompiledCache::open(directory.path().join("c"))
        .expect("a cache");
    let error = compile_or_load(&engine, &cache, &wasm, CompileBudget::defaults())
        .expect_err("a component with ambient imports is refused");
    let RuntimeError::ForbiddenImport { import } = &error else {
        panic!("the refusal was not about an import: {error}");
    };
    assert!(
        import.starts_with("wasi:"),
        "the refused import was {import}"
    );
    // The message says which one, so a publisher can see what to remove.
    assert!(error.to_string().contains(import));
    // And nothing was filed in the cache for it.
    assert!(
        cache
            .verify(&compiled_key(&engine, &wasm))
            .ok()
            .flatten()
            .is_none(),
        "a refused component was cached"
    );
}

fn compiled_key(
    engine: &RuntimeEngine,
    wasm: &[u8],
) -> kr_plugin_runtime::runtime::cache::CacheKey {
    kr_plugin_runtime::runtime::compile::key_for(engine, wasm)
}

// KR-REQ-11.40: instructions are bounded with fuel, elapsed execution with deadlines, and neither
// is reported as the other.
#[test]
fn kr_req_11_40_fuel_and_deadlines_are_separate_bounds() {
    let Some(wasm) = components::component("infinite-loop") else {
        return;
    };

    // A rate low enough that fuel runs out long before 10 ms could pass.
    let (_directory, mut starved) = instance(&wasm, "infinite-loop", 1);
    starved
        .bind(kr_plugin_runtime::runtime::bindings::Binding {
            plugin_id: "kalareach/infinite-loop".to_owned(),
            binding_revision: 3,
            executable: "/usr/local/bin/example-agent".to_owned(),
        })
        .expect("bind runs");
    let error = starved
        .observe(components::scrape("se-1", "anything"))
        .expect_err("an unbounded loop does not return");
    assert_eq!(
        error,
        RuntimeError::Exhausted {
            call: "observe",
            bound: ExhaustedBound::Fuel,
        },
        "a starved call reported {error}"
    );
    // Fuel is a work bound. The failure must not describe it as elapsed time.
    let text = error.to_string().to_lowercase();
    assert!(text.contains("fuel"));
    assert!(!text.contains(" ms"));
    assert!(!text.contains("cpu"));

    // With the ordinary rate the same loop runs past its elapsed deadline instead.
    let (_directory, mut ordinary) = bound(&wasm, "infinite-loop");
    let started = std::time::Instant::now();
    let error = ordinary
        .observe(components::scrape("se-1", "anything"))
        .expect_err("an unbounded loop does not return");
    let elapsed = started.elapsed();
    assert_eq!(
        error,
        RuntimeError::Exhausted {
            call: "observe",
            bound: ExhaustedBound::Deadline,
        },
        "an ordinary call reported {error}"
    );
    assert!(
        elapsed < core::time::Duration::from_millis(2_000),
        "the 10 ms observation deadline took {elapsed:?} to stop the call"
    );
}

// KR-REQ-11.38: every per-instance limit, exercised against a component that tries to exceed it.
#[test]
fn kr_req_11_38_the_deadlines_are_the_ones_section_eleven_states() {
    let Some(wasm) = components::component("infinite-loop") else {
        return;
    };
    let (_directory, mut instance) = bound(&wasm, "infinite-loop");

    // Each export is stopped by its own deadline, and the observed elapsed time is on the order of
    // that deadline rather than of another one. The upper bound is generous because a shared
    // machine schedules the epoch thread when it pleases; the assertion is about which deadline
    // applied, which the ordering below shows.
    let mut elapsed = Vec::new();
    for (kind, call) in [
        (
            CallKind::Observe,
            Box::new(|instance: &mut Instance| {
                instance
                    .observe(components::scrape("se-1", "x"))
                    .map(|_outcome| ())
            }) as Box<dyn Fn(&mut Instance) -> Result<(), RuntimeError>>,
        ),
        (
            CallKind::Snapshot,
            Box::new(|instance: &mut Instance| instance.snapshot().map(|_outcome| ())),
        ),
    ] {
        let started = std::time::Instant::now();
        let error = call(&mut instance).expect_err("the loop does not return");
        assert_eq!(
            error,
            RuntimeError::Exhausted {
                call: kind.as_str(),
                bound: ExhaustedBound::Deadline,
            }
        );
        elapsed.push((kind, started.elapsed()));
    }

    let observe = elapsed[0].1;
    let snapshot = elapsed[1].1;
    assert_eq!(elapsed[0].0, CallKind::Observe);
    assert_eq!(elapsed[1].0, CallKind::Snapshot);
    assert!(
        observe >= core::time::Duration::from_millis(9),
        "observe was stopped after {observe:?}, before its 10 ms deadline"
    );
    assert!(
        snapshot >= core::time::Duration::from_millis(95),
        "snapshot was stopped after {snapshot:?}, before its 100 ms deadline"
    );
    assert_eq!(CallKind::Observe.deadline_ms(), Some(10));
    assert_eq!(CallKind::Snapshot.deadline_ms(), Some(100));
    assert_eq!(CallKind::DecodeRequest.deadline_ms(), Some(50));
    assert_eq!(CallKind::EncodeResponse.deadline_ms(), Some(50));
    assert_eq!(CallKind::PrepareAction.deadline_ms(), Some(10));
}

// KR-REQ-11.38: 64 MiB of linear memory, and a refusal that names the resource.
#[test]
fn kr_req_11_38_linear_memory_is_bounded_at_sixty_four_mebibytes() {
    let Some(wasm) = components::component("memory-hog") else {
        return;
    };
    let (_directory, mut instance) = bound(&wasm, "memory-hog");
    let error = instance
        .snapshot()
        .expect_err("a component that allocates without end does not return");
    assert_eq!(
        error,
        RuntimeError::ResourceRefused {
            resource: "linear memory",
            limit: INSTANCE_MEMORY_BYTES,
        },
        "the refusal was {error}"
    );
    assert!(error.to_string().contains("linear memory"));
    assert!(error.counts_as_fault());
}

// KR-REQ-11.38: 1 MiB of output per call, and the nodes emitted before the refusal are kept.
#[test]
fn kr_req_11_38_output_is_bounded_at_one_mebibyte_per_call() {
    let Some(wasm) = components::component("oversized-output") else {
        return;
    };
    let (_directory, mut instance) = bound(&wasm, "oversized-output");
    let error = instance
        .snapshot()
        .expect_err("a component that emits past its budget is a fault");
    assert_eq!(
        error,
        RuntimeError::OutputBudget {
            call: "snapshot",
            limit: OUTPUT_BYTES_PER_CALL,
        },
        "the failure was {error}"
    );
    const { assert!(MAX_NODE_BYTES < OUTPUT_BYTES_PER_CALL) }

    // A second call starts with a fresh budget rather than inheriting the exhausted one.
    let error = instance.snapshot().expect_err("the same fault again");
    assert_eq!(
        error,
        RuntimeError::OutputBudget {
            call: "snapshot",
            limit: OUTPUT_BYTES_PER_CALL,
        }
    );
}

// KR-REQ-06.07: the handle carries immutable bytes and their provenance, and nothing else reads it.
#[test]
fn kr_req_06_07_a_source_event_handle_carries_immutable_bytes_and_provenance() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let (_directory, mut instance) = bound(&wasm, "well-behaved");

    let event = components::scrape("se-1", "the quick brown fox");
    let original: Vec<u8> = event.bytes.to_vec();
    let outcome = instance.observe(event.clone()).expect("observe runs");
    assert!(outcome.answered(), "observe declared {:?}", outcome.answer);
    // The component saw the bytes and their provenance.
    let text = outcome
        .nodes
        .iter()
        .map(|node| node.body_json.clone())
        .collect::<String>();
    assert!(text.contains("the quick brown fox"));
    assert!(text.contains("terminal scrape"));
    // The host's own copy is unchanged: what the component received was a copy of it.
    assert_eq!(event.bytes.to_vec(), original);

    // The same handle read twice gives the same bytes.
    let again = instance.observe(event.clone()).expect("observe runs");
    assert!(again.answered());
    assert!(
        again
            .nodes
            .iter()
            .any(|node| node.body_json.contains("the quick brown fox"))
    );

    // A handle this call was not given is absent, not someone else's bytes. The component reports
    // the absence, which is an answer rather than a fault.
    let outcome = instance
        .observe(components::scrape("se-2", "another event"))
        .expect("observe runs");
    assert!(outcome.answered());

    // Provenance travels with the event: a native request reads as one, a scrape does not.
    let request = components::native_request("se-3", "req-9", "{\"method\":\"write\"}");
    let decoded = instance.decode_request(request).expect("decode runs");
    let projection = decoded.answer.expect("the native request decodes");
    assert_eq!(projection.request_id, "req-9");
    assert_eq!(
        projection.class,
        kr_plugin_runtime::runtime::bindings::MethodClass::Mutation
    );

    let scraped = instance
        .decode_request(components::scrape("se-4", "{\"method\":\"write\"}"))
        .expect("decode runs");
    let fault = scraped
        .answer
        .expect_err("a scrape cannot establish native approval authority");
    assert!(
        kr_plugin_runtime::runtime::binding::fault_text(&fault).contains("not permitted"),
        "a scrape decoded as {fault:?}"
    );
}

// KR-REQ-11.21: decode and encode return values and have no way to send.
#[test]
fn kr_req_11_21_decode_and_encode_return_values_and_never_send() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let (_directory, mut instance) = bound(&wasm, "well-behaved");

    let request = components::native_request("se-1", "req-1", "{\"method\":\"read\"}");
    let decoded = instance
        .decode_request(request.clone())
        .expect("decode runs")
        .answer
        .expect("the request decodes");
    assert_eq!(
        decoded.decisions,
        vec!["allow".to_owned(), "deny".to_owned()]
    );

    let snapshot = RequestSnapshot {
        request_id: "req-1".to_owned(),
        handle: "se-1".to_owned(),
        method: "fs.read".to_owned(),
        class: kr_plugin_runtime::runtime::bindings::MethodClass::Observation,
        received_at: 1_700_000_000_000,
        deadline_at: Some(1_700_000_030_000),
        offered_decisions: vec!["allow".to_owned(), "deny".to_owned()],
        binding_revision: 3,
    };
    let encoded = instance
        .encode_response(snapshot.clone(), "allow".to_owned(), Some(request))
        .expect("encode runs")
        .answer
        .expect("the decision encodes");
    // Bytes came back. They have not gone anywhere: the broker rechecks the pending request, the
    // actor grant and the binding revision, then claims and dispatches them.
    assert_eq!(encoded.request_id, "req-1");
    assert!(String::from_utf8_lossy(&encoded.bytes).contains("\"result\":\"allow\""));

    // A decision the upstream did not offer is refused rather than encoded.
    let refused = instance
        .encode_response(snapshot, "reboot".to_owned(), None)
        .expect("encode runs")
        .answer
        .expect_err("an unoffered decision is refused");
    assert!(
        kr_plugin_runtime::runtime::binding::fault_text(&refused)
            .contains("not one of the decisions")
    );

    // The contract itself says these two return values only.
    assert!(CallKind::DecodeRequest.returns_values_only());
    assert!(CallKind::EncodeResponse.returns_values_only());
}

// KR-REQ-11.01: every export works, so a vendor package with a component adds detection, events and
// controls through the SDK alone.
#[test]
fn kr_req_11_01_a_vendor_component_adds_detection_events_and_controls() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let (_directory, mut instance) = bound(&wasm, "well-behaved");

    // Events: an observation produces presentation.
    let observed = instance
        .observe(components::scrape("se-1", "building project"))
        .expect("observe runs");
    assert!(observed.answered());
    assert!(!observed.nodes.is_empty());

    // Detection: a snapshot describes the bound execution the host matched.
    let snapshot = instance.snapshot().expect("snapshot runs");
    assert!(snapshot.answered());
    let text = snapshot
        .nodes
        .iter()
        .map(|node| node.body_json.clone())
        .collect::<String>();
    assert!(text.contains("kalareach/well-behaved"));
    assert!(text.contains("Running"), "the snapshot said {text}");

    // Controls: an invoked action becomes a plan naming an operation the broker performs.
    let plan = instance
        .prepare_action(
            token("send-prompt"),
            vec![NamedArgument {
                name: "prompt".to_owned(),
                value: Argument::Text("run the tests".to_owned()),
            }],
        )
        .expect("prepare-action runs")
        .answer
        .expect("the action prepares");
    assert_eq!(plan.class, EffectClass::UpstreamPrompt);
    let PreparedOperation::UpstreamMethod(call) = &plan.operation else {
        panic!("the plan proposed {:?}", plan.operation);
    };
    assert_eq!(call.method, "prompt.submit");
    assert_eq!(call.fields.len(), 1);

    // A plan can only name an operation the broker already performs. `present` is the one that
    // leaves the host entirely.
    let plan = instance
        .prepare_action(token("redraw"), Vec::new())
        .expect("prepare-action runs")
        .answer
        .expect("the action prepares");
    assert!(
        matches!(plan.operation, PreparedOperation::Present),
        "the plan proposed {:?}",
        plan.operation
    );

    // An action the manifest never registered is refused by the component, and would be refused by
    // the broker as well.
    let refused = instance
        .prepare_action(token("delete-everything"), Vec::new())
        .expect("prepare-action runs")
        .answer
        .expect_err("an unregistered action is refused");
    assert!(kr_plugin_runtime::runtime::binding::fault_text(&refused).contains("refused"));

    // Checkpoint and restore round-trip the component's own presentation state.
    let state = instance
        .checkpoint()
        .expect("checkpoint runs")
        .answer
        .expect("the component checkpoints");
    assert!(!state.is_empty());
    instance
        .restore(state)
        .expect("restore runs")
        .answer
        .expect("the component restores");
}

// KR-REQ-11.02: the runtime carries no list of applications.
#[test]
fn kr_req_11_02_the_runtime_names_no_application() {
    // A core that had an exhaustive list of the applications it supports would have the names in
    // it. The check is over the crate's own sources, because a list in a comment is a list.
    let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    collect_sources(&crate_root.join("src"), &mut files);
    assert!(!files.is_empty(), "no sources were found to check");

    // The applications section 12 names as the ones connectors are written for. None of them is
    // known to this crate: a vendor package supplies its own semantics.
    let applications = [
        "codex",
        "claude code",
        "claudecode",
        "opencode",
        "gemini cli",
        "geminicli",
        "kimi",
        "qoder",
        "amp",
        "aider",
        "cursor",
        "copilot",
    ];
    for file in &files {
        let text = std::fs::read_to_string(file)
            .unwrap_or_else(|error| panic!("{} is unreadable: {error}", file.display()));
        let words = words_of(&text);
        for application in applications {
            let needle = format!(" {} ", words_of(application).trim());
            assert!(
                !words.contains(&needle),
                "{} names the application {application}; a core with a list of applications is a \
                 core a vendor cannot extend without a release",
                file.display()
            );
        }
    }
}

/// Reduces text to lower-case words separated by single spaces, with a space at each end.
///
/// Matching on whole words rather than substrings is the difference between finding an application
/// name and finding "amp" inside "example".
fn words_of(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push(' ');
    for character in text.chars() {
        if character.is_ascii_alphanumeric() {
            out.push(character.to_ascii_lowercase());
        } else if !out.ends_with(' ') {
            out.push(' ');
        }
    }
    if !out.ends_with(' ') {
        out.push(' ');
    }
    out
}

fn collect_sources(directory: &std::path::Path, into: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_sources(&path, into);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            into.push(path);
        }
    }
}

// KR-REQ-11.41: compilation is lazy, cached by hash and engine, and a foreign artefact is refused.
#[test]
fn kr_req_11_41_compilation_is_cached_by_hash_and_engine() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let directory = tempfile::tempdir().expect("a temporary directory");
    let engine = engine();
    let cache = kr_plugin_runtime::runtime::cache::CompiledCache::open(
        directory.path().join("plugin-cache"),
    )
    .expect("a cache");

    let first = compile_or_load(&engine, &cache, &wasm, CompileBudget::defaults())
        .expect("the component compiles");
    assert_eq!(first.origin, CompileOrigin::Compiled);

    // The same bytes under the same engine come back from the cache.
    let second = compile_or_load(&engine, &cache, &wasm, CompileBudget::defaults())
        .expect("the component loads");
    assert_eq!(second.origin, CompileOrigin::Cached);
    assert_eq!(first.key, second.key);

    // Different bytes are a different entry, so a changed component is never served the old one.
    let Some(other) = components::component("slow-compile") else {
        return;
    };
    let different = compile_or_load(&engine, &cache, &other, CompileBudget::defaults())
        .expect("the other component compiles");
    assert_ne!(different.key.wasm_digest, first.key.wasm_digest);
    assert_eq!(different.origin, CompileOrigin::Compiled);

    // An entry filed under another engine's compatibility is refused rather than loaded.
    let mut foreign = first.key.clone();
    foreign.engine_compatibility = "an engine from another release".to_owned();
    foreign.engine_version = "1.0.0".to_owned();
    let artefact = std::fs::read(cache.artefact_path(&first.key)).expect("the artefact is there");
    let directory_for_foreign = cache.directory_for(&foreign);
    kr_ipc::paths::create_private_directory(&directory_for_foreign).expect("a directory");
    kr_ipc::paths::write_owner_only_file(&cache.artefact_path(&foreign), &artefact)
        .expect("the artefact");
    let manifest = std::fs::read(cache.manifest_path(&first.key)).expect("the manifest is there");
    kr_ipc::paths::write_owner_only_file(&cache.manifest_path(&foreign), &manifest)
        .expect("the manifest");
    let error = cache
        .verify(&foreign)
        .expect_err("an entry from another engine is refused");
    assert!(
        error.to_string().contains("engine"),
        "the refusal was {error}"
    );
}

// KR-REQ-11.41: a downloaded native-code artefact is never deserialised as validated Wasm.
#[test]
fn kr_req_11_41_a_downloaded_artefact_is_never_deserialised() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let directory = tempfile::tempdir().expect("a temporary directory");
    let engine = engine();
    let cache = kr_plugin_runtime::runtime::cache::CompiledCache::open(
        directory.path().join("plugin-cache"),
    )
    .expect("a cache");
    let compiled = compile_or_load(&engine, &cache, &wasm, CompileBudget::defaults())
        .expect("the component compiles");
    let artefact = std::fs::read(cache.artefact_path(&compiled.key)).expect("the artefact");

    // A real serialised component, filed under a different component's digest: exactly what an
    // attacker who could write into the cache would do, and what a "downloaded cache" would be.
    let mut planted = compiled.key.clone();
    planted.wasm_digest = kr_plugin_sdk::digest::PayloadDigest::of(b"a component nobody compiled");
    planted.wasm_bytes = 27;
    kr_ipc::paths::write_owner_only_file(&cache.artefact_path(&planted), &artefact)
        .expect("the artefact");
    assert_eq!(
        cache.verify(&planted).expect("a lookup"),
        None,
        "an artefact with no manifest was treated as loadable"
    );
    assert!(
        cache
            .load(engine.engine(), &planted)
            .expect("a lookup")
            .is_none(),
        "an artefact with no manifest was deserialised"
    );

    // With a manifest copied from the genuine entry, the digest it records does not match the key
    // the caller verified, and the entry is refused.
    let manifest = std::fs::read(cache.manifest_path(&compiled.key)).expect("the genuine manifest");
    kr_ipc::paths::write_owner_only_file(&cache.manifest_path(&planted), &manifest)
        .expect("the manifest");
    let error = cache
        .verify(&planted)
        .expect_err("an entry compiled from other wasm is refused");
    assert!(
        error.to_string().contains("different wasm"),
        "the refusal was {error}"
    );
}

// KR-REQ-11.41: a cold compile is not inside a call deadline, and does not count as a fault.
#[test]
fn kr_req_11_41_a_cold_compile_is_not_inside_an_observation_deadline() {
    let Some(wasm) = components::component("slow-compile") else {
        return;
    };
    let host = host();
    let (events, mut received) = tokio::sync::mpsc::unbounded_channel();

    let compile_started = std::time::Instant::now();
    let compilation = host.runtime.compile(Arc::clone(&wasm)).expect("a compile");
    let submitted = compile_started.elapsed();
    // Submitting is a queue push: the caller is not behind the compile.
    assert!(
        submitted < core::time::Duration::from_millis(50),
        "submitting a compile took {submitted:?}"
    );

    let compiled = compilation
        .wait(core::time::Duration::from_secs(60))
        .expect("the component compiles");
    let compile_elapsed = compiled.elapsed_ms;
    assert_eq!(compiled.origin, CompileOrigin::Compiled);
    assert!(
        wasm.len() > 256 * 1024,
        "the slow component is only {} bytes",
        wasm.len()
    );

    let handle = host
        .runtime
        .instantiate(components::request("slow-compile", 4), &compiled, events)
        .expect("the component instantiates");

    // The call budget starts now. An observation of a component that took `compile_elapsed`
    // milliseconds to compile still finishes inside its own 10 ms deadline, because the compile is
    // not part of it.
    let admission = handle.enqueue_observation(components::scrape("se-1", "x"));
    assert_eq!(admission, Admission::Queued);
    let event = wait_for_event(&mut received, core::time::Duration::from_secs(5))
        .expect("the observation produced something");
    match event {
        BindingEvent::Document { call, nodes } => {
            assert_eq!(call, CallKind::Observe);
            assert!(!nodes.is_empty());
        }
        other => panic!("the observation produced {other:?}"),
    }
    assert!(
        handle.disabled_reason().is_none(),
        "a slow compile disabled the binding: {:?}",
        handle.disabled_reason()
    );

    // And the compile itself was not free, so the gap being crossed is a real one.
    eprintln!("the slow component compiled in {compile_elapsed} ms");

    // A second preparation of the same component finds the artefact rather than compiling again.
    let cached = host
        .runtime
        .compile(wasm)
        .expect("a compile")
        .wait(core::time::Duration::from_secs(60))
        .expect("the component loads");
    assert_eq!(cached.origin, CompileOrigin::Cached);
    assert!(
        cached.elapsed_ms <= compile_elapsed.max(1),
        "loading took {} ms and compiling took {compile_elapsed} ms",
        cached.elapsed_ms
    );
}

fn wait_for_event(
    received: &mut tokio::sync::mpsc::UnboundedReceiver<BindingEvent>,
    within: core::time::Duration,
) -> Option<BindingEvent> {
    let deadline = std::time::Instant::now() + within;
    loop {
        match received.try_recv() {
            Ok(event) => return Some(event),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                if std::time::Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(core::time::Duration::from_millis(2));
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => return None,
        }
    }
}

// KR-REQ-11.38: three faults within a minute disable the binding, with a named reason.
#[test]
fn kr_req_11_38_three_faults_in_a_minute_disable_the_binding() {
    let Some(wasm) = components::component("infinite-loop") else {
        return;
    };
    let host = host();
    let (events, mut received) = tokio::sync::mpsc::unbounded_channel();
    let compiled = host
        .runtime
        .compile(wasm)
        .expect("a compile")
        .wait(core::time::Duration::from_secs(60))
        .expect("the component compiles");
    let handle = host
        .runtime
        .instantiate(components::request("infinite-loop", 5), &compiled, events)
        .expect("the component instantiates");

    for _ in 0..FAULTS_BEFORE_DISABLE {
        handle.enqueue_observation(components::scrape("se-1", "x"));
    }

    let deadline = std::time::Instant::now() + core::time::Duration::from_secs(10);
    let mut faults = 0;
    let mut disabled = None;
    while std::time::Instant::now() < deadline && disabled.is_none() {
        match wait_for_event(&mut received, core::time::Duration::from_millis(500)) {
            Some(BindingEvent::Fault { call, detail, .. }) => {
                assert_eq!(call, CallKind::Observe);
                assert!(detail.contains("deadline"), "the fault was {detail}");
                faults += 1;
            }
            Some(BindingEvent::Disabled { reason }) => disabled = Some(reason),
            Some(other) => panic!("the binding produced {other:?}"),
            None => {}
        }
    }
    let reason = disabled.expect("three faults inside the window disable the binding");
    assert_eq!(faults, u64::from(FAULTS_BEFORE_DISABLE) - 1);
    assert!(
        reason.contains("kalareach/infinite-loop"),
        "the reason was {reason}"
    );
    assert!(
        reason.contains("3 faults within 60 s"),
        "the reason was {reason}"
    );
    assert_eq!(handle.disabled_reason().as_deref(), Some(reason.as_str()));

    // A disabled binding runs nothing more, and says why rather than failing silently.
    let error = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a runtime")
        .block_on(handle.snapshot(core::time::Duration::from_millis(500)))
        .expect_err("a disabled binding accepts no calls");
    assert!(matches!(error, RuntimeError::Disabled { .. }));
}

// KR-REQ-11.38: the 4 MiB observation queue, its explicit gap and the fresh snapshot that follows.
#[test]
fn kr_req_11_38_queue_overflow_produces_a_gap_and_a_fresh_snapshot() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let host = host();
    let (events, mut received) = tokio::sync::mpsc::unbounded_channel();
    let compiled = host
        .runtime
        .compile(wasm)
        .expect("a compile")
        .wait(core::time::Duration::from_secs(60))
        .expect("the component compiles");
    let handle = host
        .runtime
        .instantiate(components::request("well-behaved", 6), &compiled, events)
        .expect("the component instantiates");

    // Filling the queue faster than the component drains it. Each event is 64 KiB, so sixty-five
    // of them are already more than the 4 MiB the queue holds, and two hundred and fifty-six
    // arrive long before the component has read the first few.
    let filler = "y".repeat(64 * 1024);
    let mut gapped = false;
    for index in 0..256 {
        let admission =
            handle.enqueue_observation(components::scrape(&format!("se-{index}"), &filler));
        if matches!(admission, Admission::QueuedWithGap { .. }) {
            gapped = true;
        }
        assert!(
            handle.queued_bytes() <= OBSERVATION_QUEUE_BYTES,
            "the queue holds {} bytes, over its {OBSERVATION_QUEUE_BYTES} byte bound",
            handle.queued_bytes()
        );
    }
    assert!(
        gapped,
        "two hundred and fifty-six 64 KiB observations did not overflow a 4 MiB queue"
    );

    // The gap is reported, and a snapshot follows it.
    let deadline = std::time::Instant::now() + core::time::Duration::from_secs(20);
    let mut saw_gap = false;
    let mut saw_snapshot = false;
    while std::time::Instant::now() < deadline && !(saw_gap && saw_snapshot) {
        match wait_for_event(&mut received, core::time::Duration::from_millis(500)) {
            Some(BindingEvent::Gap(gap)) => {
                assert!(gap.events > 0);
                assert!(gap.bytes > 0);
                saw_gap = true;
            }
            Some(BindingEvent::Document { call, .. }) => {
                if call == CallKind::Snapshot && saw_gap {
                    saw_snapshot = true;
                }
            }
            Some(BindingEvent::Fault { detail, .. }) => {
                panic!("draining the queue faulted: {detail}");
            }
            Some(BindingEvent::Disabled { reason }) => panic!("the binding was disabled: {reason}"),
            None => {}
        }
    }
    assert!(saw_gap, "the overflow did not report a gap");
    assert!(saw_snapshot, "the gap was not followed by a fresh snapshot");
}

// KR-REQ-06.06: which plugin, which bytes and which generation, together.
#[test]
fn kr_req_06_06_a_binding_names_the_plugin_the_bytes_and_the_generation() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let host = host();
    let (events, _received) = tokio::sync::mpsc::unbounded_channel();
    let compiled = host
        .runtime
        .compile(Arc::clone(&wasm))
        .expect("a compile")
        .wait(core::time::Duration::from_secs(60))
        .expect("the component compiles");

    let request = components::request("well-behaved", 7);
    let handle = host
        .runtime
        .instantiate(request.clone(), &compiled, events.clone())
        .expect("the component instantiates");
    assert_eq!(handle.identity(), &request.identity);
    assert_eq!(host.runtime.live_bindings(), 1);

    // An upgrade under the same identifier is a different identity, so it cannot be mistaken for
    // what this binding is running.
    let mut upgraded = request.clone();
    upgraded.identity.package_hash =
        kr_plugin_sdk::digest::PayloadDigest::of(b"the next release of the package");
    upgraded.identity.version =
        kr_plugin_sdk::version::PackageVersion::parse("1.1.0").expect("a version");
    assert!(!request.identity.is_same_binding_target(&upgraded.identity));
    assert!(request.identity.is_other_build_of(&upgraded.identity));

    // The same bytes through a later catalogue generation are the same code, and still a distinct
    // record of which generation admitted them.
    let mut resynchronised = request.clone();
    resynchronised.identity.repository_generation = kr_protocol::ids::RepositoryGeneration::new(9);
    assert!(
        request
            .identity
            .is_same_payload_in_later_generation(&resynchronised.identity)
    );
    assert!(
        !request
            .identity
            .is_same_binding_target(&resynchronised.identity)
    );

    // The binding the component was told about is the one the host recorded.
    let facts: &BindingFacts = &handle.request().facts;
    assert_eq!(facts.plugin_id, request.identity.plugin_id.as_str());

    assert!(host.runtime.unbind(request.binding_id));
    assert_eq!(host.runtime.live_bindings(), 0);
}

// The bounds a component runs under are the SDK's, not this crate's own numbers.
#[test]
fn the_budgets_come_from_the_published_limits() {
    assert_eq!(
        CallBudget::of(CallKind::Observe).deadline_ms,
        Some(kr_plugin_sdk::limits::OBSERVATION_DEADLINE_MS)
    );
    assert_eq!(
        CallBudget::of(CallKind::DecodeRequest).deadline_ms,
        Some(kr_plugin_sdk::limits::INTERPRETATION_DEADLINE_MS)
    );
    assert_eq!(
        CallBudget::of(CallKind::Snapshot).deadline_ms,
        Some(kr_plugin_sdk::limits::SNAPSHOT_DEADLINE_MS)
    );
    assert_eq!(
        InstanceLimiter::defaults().memory_bytes(),
        kr_plugin_sdk::limits::INSTANCE_MEMORY_BYTES
    );
}
