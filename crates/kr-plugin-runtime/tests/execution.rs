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
use kr_plugin_runtime::runtime::binding::{
    BindingEvent, BindingOwner, DEFAULT_EVENT_QUEUE, Runtime, RuntimeConfig,
};
use kr_plugin_runtime::runtime::bindings::{
    ActionToken, Argument, EffectClass, Fault, NamedArgument, PreparedOperation, RequestSnapshot,
};
use kr_plugin_runtime::runtime::budget::{CallBudget, CallKind};
use kr_plugin_runtime::runtime::compile::{CompileBudget, CompileOrigin, compile_or_load};
use kr_plugin_runtime::runtime::engine::RuntimeEngine;
use kr_plugin_runtime::runtime::error::ExhaustedBound;
use kr_plugin_runtime::runtime::host::{BindingFacts, MAX_NODE_BYTES};
use kr_plugin_runtime::runtime::instance::{CallOutcome, Instance};
use kr_plugin_runtime::runtime::limits::InstanceLimiter;
use kr_plugin_runtime::runtime::queue::Admission;
use kr_plugin_sdk::limits::{
    FAULTS_BEFORE_DISABLE, INSTANCE_MEMORY_BYTES, OBSERVATION_QUEUE_BYTES, OUTPUT_BYTES_PER_CALL,
};

/// How long a test waits for a compile. Generous: a machine under load is not the case under test.
const COMPILE_WAIT: core::time::Duration = core::time::Duration::from_secs(60);

/// A cache directory that removes itself, the runtime built over it, and who its bindings belong to.
struct Host {
    _directory: tempfile::TempDir,
    runtime: Arc<Runtime>,
    owner: BindingOwner,
}

fn host() -> Host {
    host_with(|_config| {})
}

/// A runtime built with the defaults, and whatever this test needs changed about them.
fn host_with(adjust: impl FnOnce(&mut RuntimeConfig)) -> Host {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let mut config = RuntimeConfig::new(directory.path().join("plugin-cache"));
    adjust(&mut config);
    let runtime = Runtime::new(config).expect("a runtime");
    Host {
        _directory: directory,
        runtime: Arc::new(runtime),
        owner: BindingOwner::next(),
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
    let outcome = instance.bind(target);
    assert!(outcome.answered(), "bind did not answer: {outcome:?}");
    (directory, instance)
}

/// Returns the failure a call reported, or fails with what it produced instead.
fn failed<T: core::fmt::Debug>(outcome: CallOutcome<T>, whatever: &str) -> RuntimeError {
    match outcome.result {
        Err(error) => error,
        Ok(answer) => panic!("{whatever}: the call produced {answer:?}"),
    }
}

/// Returns the value a call produced, or fails with what it produced instead.
fn value<T: core::fmt::Debug>(outcome: CallOutcome<T>, whatever: &str) -> T {
    match outcome.result {
        Ok(Ok(value)) => value,
        other => panic!("{whatever}: the call produced {other:?}"),
    }
}

/// Returns the fault a component declared, or fails with what it produced instead.
fn declared<T: core::fmt::Debug>(outcome: CallOutcome<T>, whatever: &str) -> Fault {
    match outcome.result {
        Ok(Err(fault)) => fault,
        other => panic!("{whatever}: the call produced {other:?}"),
    }
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

fn snapshot_of(request_id: &str) -> RequestSnapshot {
    RequestSnapshot {
        request_id: request_id.to_owned(),
        handle: "se-1".to_owned(),
        method: "fs.read".to_owned(),
        class: kr_plugin_runtime::runtime::bindings::MethodClass::Observation,
        received_at: 1_700_000_000_000,
        deadline_at: Some(1_700_000_030_000),
        offered_decisions: vec!["allow".to_owned(), "deny".to_owned()],
        binding_revision: 3,
    }
}

fn events() -> (
    tokio::sync::mpsc::Sender<BindingEvent>,
    tokio::sync::mpsc::Receiver<BindingEvent>,
) {
    tokio::sync::mpsc::channel(DEFAULT_EVENT_QUEUE)
}

async fn next_event(
    received: &mut tokio::sync::mpsc::Receiver<BindingEvent>,
    within: core::time::Duration,
) -> Option<BindingEvent> {
    tokio::time::timeout(within, received.recv())
        .await
        .ok()
        .flatten()
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
    // And nothing was filed for it, on disk or in this process's memory.
    let key = kr_plugin_runtime::runtime::compile::key_for(&engine, &wasm);
    assert!(
        cache.verify(&key).ok().flatten().is_none(),
        "a refused component was cached"
    );
    assert!(cache.resident_component(&key).is_none());
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
    let target = kr_plugin_runtime::runtime::bindings::Binding {
        plugin_id: "kalareach/infinite-loop".to_owned(),
        binding_revision: 3,
        executable: "/usr/local/bin/example-agent".to_owned(),
    };
    assert!(starved.bind(target).answered(), "bind did not answer");
    let error = failed(
        starved.observe(components::scrape("se-1", "anything")),
        "an unbounded loop returned",
    );
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

    // With the ordinary rate the same loop runs past its elapsed deadline instead, and it is
    // stopped within a small multiple of the 10 ms the deadline allows rather than eventually.
    let (_directory, mut ordinary) = bound(&wasm, "infinite-loop");
    let started = std::time::Instant::now();
    let error = failed(
        ordinary.observe(components::scrape("se-1", "anything")),
        "an unbounded loop returned",
    );
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
        elapsed >= core::time::Duration::from_millis(9),
        "the 10 ms deadline stopped the call after only {elapsed:?}"
    );
    assert!(
        elapsed < core::time::Duration::from_millis(500),
        "the 10 ms deadline took {elapsed:?} to stop the call"
    );
}

// KR-REQ-11.38: every deadline section 11 states, on the export it belongs to.
#[test]
fn kr_req_11_38_every_export_is_stopped_by_its_own_deadline() {
    let Some(wasm) = components::component("infinite-loop") else {
        return;
    };
    let (_directory, mut instance) = bound(&wasm, "infinite-loop");

    // Every export that has a deadline, each stopped by its own. The lower bound is what shows the
    // deadline applied rather than a shorter one; the upper bound is generous because a shared
    // machine schedules the epoch thread when it pleases.
    type Call = Box<dyn Fn(&mut Instance) -> RuntimeError>;
    let cases: Vec<(CallKind, u64, Call)> = vec![
        (
            CallKind::Observe,
            10,
            Box::new(|instance: &mut Instance| {
                failed(
                    instance.observe(components::scrape("se-1", "x")),
                    "observe returned",
                )
            }),
        ),
        (
            CallKind::PrepareAction,
            10,
            Box::new(|instance: &mut Instance| {
                failed(
                    instance.prepare_action(token("anything"), Vec::new()),
                    "prepare-action returned",
                )
            }),
        ),
        (
            CallKind::DecodeRequest,
            50,
            Box::new(|instance: &mut Instance| {
                failed(
                    instance.decode_request(components::native_request("se-1", "req-1", "{}")),
                    "decode-request returned",
                )
            }),
        ),
        (
            CallKind::EncodeResponse,
            50,
            Box::new(|instance: &mut Instance| {
                failed(
                    instance.encode_response(snapshot_of("req-1"), "allow".to_owned(), None),
                    "encode-response returned",
                )
            }),
        ),
        (
            CallKind::Snapshot,
            100,
            Box::new(|instance: &mut Instance| failed(instance.snapshot(), "snapshot returned")),
        ),
        (
            CallKind::Checkpoint,
            100,
            Box::new(|instance: &mut Instance| {
                failed(instance.checkpoint(), "checkpoint returned")
            }),
        ),
        (
            CallKind::Restore,
            100,
            Box::new(|instance: &mut Instance| {
                failed(instance.restore(Vec::new()), "restore returned")
            }),
        ),
    ];

    for (kind, deadline_ms, call) in cases {
        assert_eq!(
            kind.deadline_ms(),
            Some(deadline_ms),
            "{kind:?} does not carry the deadline section 11 gives it"
        );
        // A trapped instance cannot be entered again, so the previous case's is replaced first.
        // The binding lifecycle does this on the caller's behalf; a caller using an instance
        // directly does it itself, which is what `Instance::faulted` is for.
        if instance.faulted() {
            instance.replace().expect("the replacement binds");
        }
        let started = std::time::Instant::now();
        let error = call(&mut instance);
        let elapsed = started.elapsed();
        assert_eq!(
            error,
            RuntimeError::Exhausted {
                call: kind.as_str(),
                bound: ExhaustedBound::Deadline,
            },
            "{kind:?} reported {error}"
        );
        assert!(
            elapsed >= core::time::Duration::from_millis(deadline_ms - 1),
            "{kind:?} was stopped after {elapsed:?}, before its {deadline_ms} ms deadline"
        );
        assert!(
            elapsed < core::time::Duration::from_millis(deadline_ms * 5 + 500),
            "{kind:?} took {elapsed:?} against a {deadline_ms} ms deadline"
        );
    }
}

// KR-REQ-11.38: 64 MiB of linear memory, and a refusal that names the resource.
#[test]
fn kr_req_11_38_linear_memory_is_bounded_at_sixty_four_mebibytes() {
    let Some(wasm) = components::component("memory-hog") else {
        return;
    };
    let (_directory, mut instance) = bound(&wasm, "memory-hog");
    let error = failed(
        instance.snapshot(),
        "a component that allocates without end returned",
    );
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

// KR-REQ-11.38: 1 MiB of output per call, whether the component emits it or returns it.
#[test]
fn kr_req_11_38_output_is_bounded_at_one_mebibyte_per_call() {
    let Some(wasm) = components::component("oversized-output") else {
        return;
    };
    let (_directory, mut instance) = bound(&wasm, "oversized-output");

    // Emitted. The refusal is a fault, and the nodes the call did emit travel with it.
    let outcome = instance.snapshot();
    let emitted = outcome.nodes.len();
    let error = failed(outcome, "a component that emits past its budget answered");
    assert_eq!(
        error,
        RuntimeError::OutputBudget {
            call: "snapshot",
            limit: OUTPUT_BYTES_PER_CALL,
        },
        "the failure was {error}"
    );
    assert!(
        emitted > 0,
        "the nodes the call emitted before the refusal were discarded"
    );
    const { assert!(MAX_NODE_BYTES < OUTPUT_BYTES_PER_CALL) }

    // A second call starts with a fresh budget rather than inheriting the exhausted one.
    let error = failed(instance.snapshot(), "the same fault again");
    assert_eq!(
        error,
        RuntimeError::OutputBudget {
            call: "snapshot",
            limit: OUTPUT_BYTES_PER_CALL,
        }
    );

    // Returned. This component's checkpoint returns two mebibytes of state, which a host that
    // bounded only the document would have carried.
    let error = failed(
        instance.checkpoint(),
        "a component that returns past its budget answered",
    );
    assert_eq!(
        error,
        RuntimeError::OutputBudget {
            call: "checkpoint",
            limit: OUTPUT_BYTES_PER_CALL,
        },
        "the failure was {error}"
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
    let outcome = instance.observe(event.clone());
    let nodes = outcome.nodes.clone();
    assert!(outcome.answered(), "observe did not answer: {outcome:?}");
    // The component saw the bytes and their provenance.
    let text = nodes
        .iter()
        .map(|node| node.body_json.clone())
        .collect::<String>();
    assert!(text.contains("the quick brown fox"));
    assert!(text.contains("terminal scrape"));
    // The host's own copy is unchanged: what the component received was a copy of it.
    assert_eq!(event.bytes.to_vec(), original);

    // The same handle read twice gives the same bytes.
    let again = instance.observe(event.clone());
    assert!(again.answered());
    assert!(
        again
            .nodes
            .iter()
            .any(|node| node.body_json.contains("the quick brown fox"))
    );

    // A handle this call was not given reads as absent. The component asks for one it invented on
    // every observation and reports what it got, so this is the component's own account of what it
    // can reach rather than the host's account of what it offered.
    let outcome = instance.observe(components::scrape("se-2", "another event"));
    assert!(outcome.answered(), "observe did not answer: {outcome:?}");
    let text = outcome
        .nodes
        .iter()
        .map(|node| node.body_json.clone())
        .collect::<String>();
    assert!(
        text.contains("invented handle: absent"),
        "the component reported {text}"
    );

    // Provenance travels with the event: a native request reads as one, a scrape does not.
    let request = components::native_request("se-3", "req-9", "{\"method\":\"write\"}");
    let projection = value(
        instance.decode_request(request),
        "the native request decodes",
    );
    assert_eq!(projection.request_id, "req-9");
    assert_eq!(
        projection.class,
        kr_plugin_runtime::runtime::bindings::MethodClass::Mutation
    );

    let fault = declared(
        instance.decode_request(components::scrape("se-4", "{\"method\":\"write\"}")),
        "a scrape established native approval authority",
    );
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
    let decoded = value(
        instance.decode_request(request.clone()),
        "the request decodes",
    );
    assert_eq!(
        decoded.decisions,
        vec!["allow".to_owned(), "deny".to_owned()]
    );

    let snapshot = snapshot_of("req-1");
    let encoded = value(
        instance.encode_response(snapshot.clone(), "allow".to_owned(), Some(request)),
        "the decision encodes",
    );
    // Bytes came back. They have not gone anywhere: the broker rechecks the pending request, the
    // actor grant and the binding revision, then claims and dispatches them.
    assert_eq!(encoded.request_id, "req-1");
    assert!(String::from_utf8_lossy(&encoded.bytes).contains("\"result\":\"allow\""));

    // A decision the upstream did not offer is refused rather than encoded.
    let refused = declared(
        instance.encode_response(snapshot, "reboot".to_owned(), None),
        "an unoffered decision was encoded",
    );
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
    let plugin = "well-behaved";
    let (_directory, mut instance) = bound(&wasm, plugin);

    // Events: an observation produces presentation.
    let observed = instance.observe(components::scrape("se-1", "building project"));
    assert!(observed.answered());
    assert!(!observed.nodes.is_empty());

    // Detection: the component describes the execution the host matched, reading the binding
    // through its own import rather than being handed a conclusion. What it reports is the plugin
    // identifier and the activity the host passed to `bind` and `upstream::state`.
    let snapshot = instance.snapshot();
    assert!(snapshot.answered());
    let text = snapshot
        .nodes
        .iter()
        .map(|node| node.body_json.clone())
        .collect::<String>();
    assert!(text.contains(&format!("kalareach/{plugin}")));
    assert!(text.contains("Running"), "the snapshot said {text}");

    // Controls: an invoked action becomes a plan naming an operation the broker performs.
    let plan = value(
        instance.prepare_action(
            token("send-prompt"),
            vec![NamedArgument {
                name: "prompt".to_owned(),
                value: Argument::Text("run the tests".to_owned()),
            }],
        ),
        "the action prepares",
    );
    assert_eq!(plan.class, EffectClass::UpstreamPrompt);
    let PreparedOperation::UpstreamMethod(call) = &plan.operation else {
        panic!("the plan proposed {:?}", plan.operation);
    };
    assert_eq!(call.method, "prompt.submit");
    assert_eq!(call.fields.len(), 1);

    // A plan can only name an operation the broker already performs. `present` is the one that
    // leaves the host entirely.
    let plan = value(
        instance.prepare_action(token("redraw"), Vec::new()),
        "the action prepares",
    );
    assert!(
        matches!(plan.operation, PreparedOperation::Present),
        "the plan proposed {:?}",
        plan.operation
    );

    // An action the manifest never registered is refused by the component, and would be refused by
    // the broker as well.
    let refused = declared(
        instance.prepare_action(token("delete-everything"), Vec::new()),
        "an unregistered action prepared",
    );
    assert!(kr_plugin_runtime::runtime::binding::fault_text(&refused).contains("refused"));

    // Checkpoint and restore round-trip the component's own presentation state.
    let state = value(instance.checkpoint(), "the component checkpoints");
    assert!(!state.is_empty());
    assert!(
        instance.restore(state).answered(),
        "the component did not restore"
    );
}

// KR-REQ-11.02: the runtime carries no list of applications.
#[test]
fn kr_req_11_02_the_runtime_names_no_application() {
    // A core that had an exhaustive list of the applications it supports would have the names in
    // it. The check is over this crate's own sources, because a list in a comment is a list. It
    // says nothing about the rest of core, which is each crate's own to keep.
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

    // The same bytes under the same engine come back rather than being compiled again.
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

    // A real serialised component, filed under a different component's digest: which is what a
    // downloaded native-code cache is, and what anything dropped into the directory is.
    let mut planted = compiled.key.clone();
    planted.wasm_digest = kr_plugin_sdk::digest::PayloadDigest::of(b"a component nobody compiled");
    planted.wasm_bytes = 27;
    kr_ipc::paths::write_owner_only_file(&cache.artefact_path(&planted), &artefact)
        .expect("the artefact");
    assert!(
        cache.verify(&planted).expect("a lookup").is_none(),
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
    // the caller verified, and the entry is refused by name.
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

    // And with the manifest rewritten to claim the planted key: every field made consistent, the
    // artefact digest recomputed, the marker copied. That passes, and the module says so: every
    // field of a manifest is one a writer of the directory can produce, so the manifest answers
    // "which artefact is this" and not "who put it here".
    let mut claimed: kr_plugin_runtime::runtime::cache::CacheManifest =
        serde_json::from_slice(&manifest).expect("the manifest decodes");
    claimed.wasm_digest = planted.wasm_digest;
    claimed.wasm_bytes = planted.wasm_bytes;
    kr_ipc::paths::write_owner_only_file(
        &cache.manifest_path(&planted),
        &serde_json::to_vec(&claimed).expect("a manifest"),
    )
    .expect("the manifest");
    assert!(
        cache.verify(&planted).expect("a lookup").is_some(),
        "the rewritten manifest was refused for a reason that is not documented"
    );

    // What answers the second question is the directory. It is the owner's own, and a process that
    // can write here runs as this user and can replace this host's executable, so the cache is not
    // where that boundary is drawn.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let metadata = std::fs::metadata(cache.root()).expect("the cache directory");
        assert_eq!(
            metadata.permissions().mode() & 0o777,
            0o700,
            "the cache directory is not the owner's own"
        );
    }
}

// KR-REQ-11.41: a cold compile is not inside a call deadline, and does not count as a fault.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_41_a_cold_compile_is_not_inside_an_observation_deadline() {
    let Some(wasm) = components::component("slow-compile") else {
        return;
    };
    // The compilation budget is the host's own bound on how long a compile may take, and this
    // machine's speed is not the case under test: what is under test is that a cold compile is not
    // inside an observation's deadline. So this runtime is given a budget that a build machine
    // under load cannot make it miss, and the deadline the test measures is the observation's.
    let host = host_with(|config| {
        config.compile.deadline_ms = COMPILE_WAIT.as_millis() as u64;
    });
    let (events, mut received) = events();

    let compile_started = std::time::Instant::now();
    let compilation = host.runtime.compile(Arc::clone(&wasm)).expect("a compile");
    let submitted = compile_started.elapsed();
    // Submitting is a queue push: the caller is not behind the compile.
    assert!(
        submitted < core::time::Duration::from_millis(50),
        "submitting a compile took {submitted:?}"
    );

    let compiled = compilation
        .wait(COMPILE_WAIT)
        .await
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
        .instantiate(
            host.owner,
            components::request("slow-compile", 4),
            &compiled,
            events,
            COMPILE_WAIT,
        )
        .await
        .expect("the component instantiates");

    // The call budget starts now. An observation of a component that took `compile_elapsed`
    // milliseconds to compile still finishes inside its own 10 ms deadline, because the compile is
    // not part of it.
    let admission = handle.enqueue_observation(components::scrape("se-1", "x"));
    assert_eq!(admission, Admission::Queued);
    let event = next_event(&mut received, core::time::Duration::from_secs(5))
        .await
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

    // A second preparation of the same component finds it rather than compiling again.
    let cached = host
        .runtime
        .compile(wasm)
        .expect("a compile")
        .wait(COMPILE_WAIT)
        .await
        .expect("the component loads");
    assert_eq!(cached.origin, CompileOrigin::Cached);
    assert!(
        cached.elapsed_ms <= compile_elapsed.max(1),
        "loading took {} ms and compiling took {compile_elapsed} ms",
        cached.elapsed_ms
    );
}

// KR-REQ-11.38: three faults within a minute disable the binding, with a named reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_38_three_faults_in_a_minute_disable_the_binding() {
    let Some(wasm) = components::component("infinite-loop") else {
        return;
    };
    let host = host();
    let (events, mut received) = events();
    let compiled = host
        .runtime
        .compile(wasm)
        .expect("a compile")
        .wait(COMPILE_WAIT)
        .await
        .expect("the component compiles");
    let handle = host
        .runtime
        .instantiate(
            host.owner,
            components::request("infinite-loop", 5),
            &compiled,
            events,
            COMPILE_WAIT,
        )
        .await
        .expect("the component instantiates");

    for index in 0..FAULTS_BEFORE_DISABLE {
        handle.enqueue_observation(components::scrape(&format!("se-{index}"), "x"));
    }

    let deadline = std::time::Instant::now() + core::time::Duration::from_secs(30);
    let mut faults = 0;
    let mut disabled = None;
    while std::time::Instant::now() < deadline && disabled.is_none() {
        match next_event(&mut received, core::time::Duration::from_millis(500)).await {
            Some(BindingEvent::Fault { call, detail, .. }) => {
                // Every call this component makes runs out of something, including the snapshot it
                // owes after the first fault. Which bound stops it is the machine's business: a
                // loaded one delivers the epoch late and the fuel ceiling catches the call
                // instead, and both are correct. What must be true is that the bound is named.
                assert!(
                    matches!(call, CallKind::Observe | CallKind::Snapshot),
                    "the fault was in {call:?}"
                );
                assert!(
                    detail.contains("deadline") || detail.contains("fuel"),
                    "the fault was {detail}"
                );
                faults += 1;
            }
            Some(BindingEvent::Disabled { reason }) => disabled = Some(reason),
            Some(BindingEvent::Gap(_) | BindingEvent::PresentationDropped { .. }) => {}
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
    let error = handle
        .snapshot(core::time::Duration::from_millis(500))
        .await
        .expect_err("a disabled binding accepts no calls");
    assert!(matches!(error, RuntimeError::Disabled { .. }));
}

// KR-REQ-11.38: the 4 MiB observation queue, its explicit gap and the fresh snapshot that follows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_38_queue_overflow_produces_a_gap_and_a_fresh_snapshot() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let host = host();
    let (events, mut received) = events();
    let compiled = host
        .runtime
        .compile(wasm)
        .expect("a compile")
        .wait(COMPILE_WAIT)
        .await
        .expect("the component compiles");
    let handle = host
        .runtime
        .instantiate(
            host.owner,
            components::request("well-behaved", 6),
            &compiled,
            events,
            COMPILE_WAIT,
        )
        .await
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
    let deadline = std::time::Instant::now() + core::time::Duration::from_secs(30);
    let mut saw_gap = false;
    let mut saw_snapshot = false;
    while std::time::Instant::now() < deadline && !(saw_gap && saw_snapshot) {
        match next_event(&mut received, core::time::Duration::from_millis(500)).await {
            Some(BindingEvent::Gap(gap)) => {
                assert!(gap.events > 0);
                assert!(gap.bytes > 0);
                saw_gap = true;
            }
            Some(BindingEvent::PresentationDropped { .. }) => {}
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
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_06_06_a_binding_names_the_plugin_the_bytes_and_the_generation() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let host = host();
    let (first_events, _first_received) = events();
    let compiled = host
        .runtime
        .compile(Arc::clone(&wasm))
        .expect("a compile")
        .wait(COMPILE_WAIT)
        .await
        .expect("the component compiles");

    let request = components::request("well-behaved", 7);
    let handle = host
        .runtime
        .instantiate(
            host.owner,
            request.clone(),
            &compiled,
            first_events,
            COMPILE_WAIT,
        )
        .await
        .expect("the component instantiates");
    assert_eq!(handle.identity(), &request.identity);
    assert_eq!(host.runtime.live_bindings(), 1);

    // One binding, one instance. A second registration under the same identifier is refused rather
    // than silently replacing an instance nothing could then reach or stop.
    let (other_events, _other_received) = events();
    let error = host
        .runtime
        .instantiate(
            host.owner,
            request.clone(),
            &compiled,
            other_events,
            COMPILE_WAIT,
        )
        .await
        .expect_err("a binding that is already live is refused");
    assert!(
        error.to_string().contains("already live"),
        "the refusal was {error}"
    );
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

    // And it binds under its own identifier, beside the first: an upgrade is a new binding rather
    // than a mutation of a live one.
    let mut second = upgraded.clone();
    second.binding_id = kr_plugin_runtime::service::client::new_binding_id();
    let (second_events, _second_received) = events();
    let upgraded_handle = host
        .runtime
        .instantiate(
            host.owner,
            second.clone(),
            &compiled,
            second_events,
            COMPILE_WAIT,
        )
        .await
        .expect("the upgraded package binds under its own identifier");
    assert_eq!(upgraded_handle.identity(), &second.identity);
    assert_ne!(upgraded_handle.identity(), handle.identity());
    assert_eq!(host.runtime.live_bindings(), 2);

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

    assert!(
        host.runtime
            .unbind(host.owner, request.binding_id)
            .existed()
    );
    assert!(host.runtime.unbind(host.owner, second.binding_id).existed());
    assert_eq!(host.runtime.live_bindings(), 0);
}

// KR-REQ-11.41: a component this process compiled is served from memory, with no file involved.
#[test]
fn a_component_this_process_compiled_is_served_from_memory() {
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
    assert_eq!(cache.resident(), 1);
    assert!(cache.resident_component(&first.key).is_some());

    // Removing the files leaves the one in memory, which is the one this process produced: no
    // question of provenance arises for it, because no file is read.
    std::fs::remove_file(cache.artefact_path(&first.key)).expect("the artefact is removed");
    std::fs::remove_file(cache.manifest_path(&first.key)).expect("the manifest is removed");
    let second = compile_or_load(&engine, &cache, &wasm, CompileBudget::defaults())
        .expect("the component loads");
    assert_eq!(second.origin, CompileOrigin::Cached);

    // Removing the entry removes the one in memory too, so a later load is a real miss.
    cache.remove(&first.key).expect("the entry is removed");
    assert_eq!(cache.resident(), 0);
    let third = compile_or_load(&engine, &cache, &wasm, CompileBudget::defaults())
        .expect("the component compiles again");
    assert_eq!(third.origin, CompileOrigin::Compiled);
}

// A replaced instance is told what the host holds now, not what it held when the binding was made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replacement_after_a_fault_is_bound_to_the_current_revision() {
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
    let mut instance = Instance::new(
        &engine,
        &compiled.component,
        components::facts("well-behaved"),
        InstanceLimiter::defaults(),
        kr_plugin_runtime::runtime::budget::FUEL_PER_DEADLINE_MS,
    )
    .expect("the component instantiates");
    let target = kr_plugin_runtime::runtime::bindings::Binding {
        plugin_id: "kalareach/well-behaved".to_owned(),
        binding_revision: 3,
        executable: "/usr/local/bin/example-agent".to_owned(),
    };
    assert!(instance.bind(target).answered());

    // The binding moves on, and an attachment arrives.
    let mut facts = components::facts("well-behaved");
    facts.binding_revision = 11;
    facts.activity = kr_plugin_runtime::runtime::host::BindingActivity::AwaitingPerson;
    instance.set_binding_facts(facts);
    instance.set_attachments(vec![kr_plugin_runtime::runtime::host::AttachmentFact {
        attachment_id: "a-1".to_owned(),
        name: "diagram.png".to_owned(),
        media_type: "image/png".to_owned(),
        size_bytes: 4096,
        completed_at_ms: 9,
    }]);

    // A replacement is bound to the revision the host holds now, and keeps the attachment. A
    // replacement given the original facts would present one execution's state against another's.
    let nodes = instance.replace().expect("the replacement binds");
    assert_eq!(instance.replacements(), 1);
    assert_eq!(instance.facts().binding_revision, 11);
    assert_eq!(instance.attachments().len(), 1);
    let text = nodes
        .iter()
        .map(|node| node.body_json.clone())
        .collect::<String>();
    assert!(
        text.contains("revision 11"),
        "the replacement was bound to {text}"
    );

    // And it still sees the attachment and the new activity.
    let snapshot = instance.snapshot();
    assert!(snapshot.answered());
    let text = snapshot
        .nodes
        .iter()
        .map(|node| node.body_json.clone())
        .collect::<String>();
    assert!(text.contains("1 attachments"), "the snapshot said {text}");
    assert!(text.contains("AwaitingPerson"), "the snapshot said {text}");
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

// A component that spends most of a call and still answers: the shape a test about what happens
// *while* a component is running needs, because a component that faults is one that is soon
// disabled and no longer running at all.
#[test]
fn a_slow_component_spends_its_call_and_still_answers() {
    let Some(wasm) = components::component("slow-observe") else {
        return;
    };
    let (_directory, mut instance) = bound(&wasm, "slow-observe");

    let mut spent = Vec::new();
    for _ in 0..(FAULTS_BEFORE_DISABLE + 5) {
        let started = std::time::Instant::now();
        let outcome = instance.observe(components::scrape("se-1", "output"));
        spent.push(started.elapsed());
        outcome
            .result
            .expect("the call did not fault")
            .expect("the component did not decline");
        assert!(
            !outcome.nodes.is_empty(),
            "the call drew nothing, so nothing can see that it happened"
        );
    }

    // Long enough to be worth queueing against, and short enough that it is not the deadline
    // stopping it: a call the deadline stopped would be a fault, and there were none.
    let longest = spent.iter().max().copied().unwrap_or_default();
    assert!(
        longest < core::time::Duration::from_millis(10),
        "the slowest call took {longest:?}, which is the observe deadline rather than the work"
    );
    // And it is work rather than nothing: a component that returned at once would not keep a
    // binding's thread occupied, which is the whole reason this fixture exists.
    let total: core::time::Duration = spent.iter().sum();
    assert!(
        total > core::time::Duration::from_millis(1),
        "eight calls took {total:?} between them"
    );
}

// A document the caller never received leaves a stale view, and the answer is the one a lost
// observation gets: the component draws again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_document_nobody_received_asks_the_component_to_draw_again() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let host = host();
    let (events, mut received) = events();
    let handle = host
        .runtime
        .prepare(
            host.owner,
            components::request("well-behaved", 11),
            Arc::clone(&wasm),
            COMPILE_WAIT,
            events,
        )
        .await
        .expect("the component binds");

    // Nothing is owed yet: the component has just drawn what `bind` produced.
    assert!(!handle.snapshot_required());

    // Whoever was to read that document did not. Saying so is what puts the obligation back, and
    // the pump discharges it with a fresh snapshot without anybody asking for one.
    handle.require_snapshot();
    assert!(handle.snapshot_required());

    let deadline = std::time::Instant::now() + core::time::Duration::from_secs(5);
    let mut drew = false;
    while !drew && std::time::Instant::now() < deadline {
        match next_event(&mut received, core::time::Duration::from_millis(200)).await {
            Some(BindingEvent::Document { call, nodes }) => {
                if call == CallKind::Snapshot {
                    assert!(!nodes.is_empty());
                    drew = true;
                }
            }
            Some(BindingEvent::Fault { detail, .. }) => panic!("the component faulted: {detail}"),
            Some(_) | None => {}
        }
    }
    assert!(drew, "the component was never asked to draw again");
    assert!(
        !handle.snapshot_required(),
        "the obligation was not cleared"
    );
}
