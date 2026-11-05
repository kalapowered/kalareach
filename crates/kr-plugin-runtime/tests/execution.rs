//! Running real components under the section 11 bounds.
//!
//! Every test here compiles and instantiates an actual component and calls into it. That is the
//! point: a limiter that is never asked, a deadline that is never reached and an import list that
//! is never inspected all look correct in a unit test.

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
use kr_plugin_runtime::runtime::compile::{
    CompileBudget, CompileOrigin, CompilePool, Payload, compile_or_load, key_for,
};
use kr_plugin_runtime::runtime::engine::{ENGINE_VERSION, RuntimeEngine};
use kr_plugin_runtime::runtime::error::ExhaustedBound;
use kr_plugin_runtime::runtime::instance::{CallOutcome, Instance};
use kr_plugin_runtime::runtime::limits::InstanceLimiter;
use kr_plugin_runtime::runtime::thread_time::with_scripted_thread_cpu_time;
use kr_plugin_sdk::limits::{
    FAULTS_BEFORE_DISABLE, INSTANCE_MEMORY_BYTES, OBSERVATION_QUEUE_BYTES, OUTPUT_BYTES_PER_CALL,
};
use kr_plugin_service::vocabulary::{Admission, BindingFacts, MAX_NODE_BYTES};

/// How long a test waits for a compile, or for the instantiation after one. A compile runs at
/// background priority, so a machine that other work keeps busy leaves it a hundredth of a processor
/// or less and it takes tens of minutes; a case decides by what the compile comes to, never by this,
/// which ends only a compile that never does.
const COMPILE_WAIT: core::time::Duration = core::time::Duration::from_secs(60 * 60);

/// How long a case waits for what a binding's thread does before it calls that a failure. Nothing
/// is decided by it: the waits are on conditions, and this ends only a binding that never gets
/// there.
const LIVENESS: core::time::Duration = core::time::Duration::from_secs(60);

/// The compile budget of a case that is not about how much work a compile may do: the host's own
/// size bound and no bound on processor time.
///
/// What a compile costs is the processor time its thread uses, which a busy machine does not raise,
/// but a platform that does not say what a thread used holds the budget to the clock, and a machine
/// kept off the CPU for half a minute reaches the host's bound there. No case that shows what a
/// compile makes, files or refuses is about it.
fn no_compile_work_bound() -> CompileBudget {
    CompileBudget {
        processor_ms: u64::MAX,
        ..CompileBudget::defaults()
    }
}

/// A cache directory that removes itself, the runtime built over it, and who its bindings belong to.
struct Host {
    _directory: tempfile::TempDir,
    runtime: Arc<Runtime>,
    owner: BindingOwner,
}

/// A runtime built with the defaults, and no time bound on its compiles.
fn host() -> Host {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let mut config = RuntimeConfig::new(directory.path().join("plugin-cache"));
    config.compile = no_compile_work_bound();
    let runtime = Runtime::new(config).expect("a runtime");
    Host {
        _directory: directory,
        runtime: Arc::new(runtime),
        owner: BindingOwner::next(),
    }
}

/// A runtime whose epoch no time advances, for the tests of what a binding does with the events it
/// is given: a call is stopped by its deadline only when a test advances the epoch, so a machine
/// that stalls a call for as long as it likes cannot reach one.
fn held_host() -> Host {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let mut config = RuntimeConfig::new(directory.path().join("plugin-cache"));
    config.compile = no_compile_work_bound();
    let runtime = Runtime::with_epoch_held(config).expect("a runtime");
    Host {
        _directory: directory,
        runtime: Arc::new(runtime),
        owner: BindingOwner::next(),
    }
}

fn engine() -> RuntimeEngine {
    RuntimeEngine::new().expect("an engine")
}

/// Instantiates one component directly, outside a binding's thread, on an engine the test holds so
/// that it can read what the engine's epoch did.
///
/// The binding lifecycle is exercised separately; these tests want the calls themselves, where the
/// bound that stopped one is the return value rather than an event.
fn instance_on(
    engine: &RuntimeEngine,
    wasm: &[u8],
    plugin: &str,
    fuel_rate: u64,
) -> (tempfile::TempDir, Instance) {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let cache = kr_plugin_runtime::runtime::cache::CompiledCache::open(
        directory.path().join("plugin-cache"),
    )
    .expect("a cache");
    let compiled = compile_or_load(engine, &cache, wasm, no_compile_work_bound())
        .expect("the component compiles");
    let instance = Instance::new(
        engine,
        &compiled.component,
        components::facts(plugin),
        InstanceLimiter::defaults(),
        fuel_rate,
    )
    .expect("the component instantiates");
    (directory, instance)
}

/// One component bound on an engine whose epoch is held, for the cases that read what a call
/// returns: a call is stopped by its deadline only when a test advances the epoch, so a machine
/// that takes longer over a call than its deadline cannot change what the case reads.
fn bound(wasm: &[u8], plugin: &str) -> (tempfile::TempDir, Instance) {
    bound_on(&held_engine(), wasm, plugin)
}

/// As [`bound`], on an engine the test holds.
fn bound_on(engine: &RuntimeEngine, wasm: &[u8], plugin: &str) -> (tempfile::TempDir, Instance) {
    bound_at(
        engine,
        wasm,
        plugin,
        kr_plugin_runtime::runtime::budget::FUEL_PER_DEADLINE_MS,
    )
}

/// As [`bound_on`], with a fuel rate the test chooses.
fn bound_at(
    engine: &RuntimeEngine,
    wasm: &[u8],
    plugin: &str,
    fuel_rate: u64,
) -> (tempfile::TempDir, Instance) {
    let (directory, mut instance) = instance_on(engine, wasm, plugin, fuel_rate);
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
    let compiled = compile_or_load(&engine, &cache, &wasm, no_compile_work_bound())
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
    let error = compile_or_load(&engine, &cache, &wasm, no_compile_work_bound())
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
    assert!(cache.resident_component(engine.engine(), &key).is_none());
}

// KR-REQ-11.40: instructions are bounded with fuel, elapsed execution with deadlines, and neither
// is reported as the other.
#[test]
fn kr_req_11_40_fuel_and_deadlines_are_separate_bounds() {
    let Some(wasm) = components::component("infinite-loop") else {
        return;
    };

    // A rate low enough that fuel runs out long before 10 ms could pass. The engine's epoch is held,
    // so that no time the machine takes can reach the deadline first.
    let (_directory, mut starved) = instance_on(&held_engine(), &wasm, "infinite-loop", 1);
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

    // With a rate no loop reaches the end of, the same loop runs into its elapsed deadline
    // instead, and the deadline is what stops it.
    let engine = held_engine();
    let (_directory, mut ordinary) = bound_at(&engine, &wasm, "infinite-loop", FUEL_NEVER_ENDS);
    let (error, ticks) = ticks_until_stopped(&engine, || {
        failed(
            ordinary.observe(components::scrape("se-1", "anything")),
            "an unbounded loop returned",
        )
    });
    assert_eq!(
        error,
        RuntimeError::Exhausted {
            call: "observe",
            bound: ExhaustedBound::Deadline,
        },
        "an ordinary call reported {error}"
    );
    assert_stopped_after_its_ticks(CallKind::Observe, ticks);
}

/// A fuel rate no call reaches the end of, so that a call that does not return can be stopped only
/// by its deadline.
const FUEL_NEVER_ENDS: u64 = 1 << 52;

/// An engine whose epoch time does not advance: the only thing that moves it is what a test asks
/// of it, so a deadline is reached when the test says and never because the machine was slow.
fn held_engine() -> RuntimeEngine {
    RuntimeEngine::with_epoch_held().expect("an engine")
}

/// Runs `call` on a thread of its own and advances the engine's epoch one tick at a time until it
/// has returned, and says what it returned and how many ticks the epoch advanced meanwhile.
///
/// The epoch is the engine's, not the clock's: this is what a deadline is a count of. A call that
/// nothing stops is a test that never ends, because the call runs on a thread this test cannot
/// end and so cannot fail it with a bound of its own: the run's own limit is what ends it.
fn ticks_until_stopped<T: Send>(
    engine: &RuntimeEngine,
    call: impl FnOnce() -> T + Send,
) -> (T, u64) {
    let before = engine.ticks();
    std::thread::scope(|scope| {
        let running = scope.spawn(call);
        while !running.is_finished() {
            engine.advance_epoch();
            std::thread::sleep(core::time::Duration::from_millis(1));
        }
        let outcome = running.join().expect("the call returned");
        (outcome, engine.ticks().saturating_sub(before))
    })
}

/// Checks that a call stopped by its deadline was given the ticks section 11's deadline is worth.
///
/// A deadline of *n* milliseconds is *n* ticks and one more: a call that starts part way through a
/// tick would otherwise be cut short by up to a whole one. `ticks` is what the epoch advanced from
/// before the call was started until it had returned, which is the ticks the call was stopped
/// after, any that came before it began to run and any that came while it was returning. It is at
/// least the first, so a call that was stopped after fewer ticks than it is owed passes only if
/// those others made up the rest: on a slow machine this can let a call stopped a little early
/// pass, and on no machine can it fail a call that was stopped on time.
fn assert_stopped_after_its_ticks(kind: CallKind, ticks: u64) {
    let deadline_ms = kind.deadline_ms().expect("the call has a deadline");
    let owed = CallBudget::of(kind).epoch_ticks(kr_plugin_runtime::runtime::engine::EPOCH_TICK_MS);
    assert_eq!(
        owed,
        Some(deadline_ms / kr_plugin_runtime::runtime::engine::EPOCH_TICK_MS + 1),
        "{kind:?} is not given the ticks its deadline is worth"
    );
    assert!(
        Some(ticks) >= owed,
        "{kind:?} was stopped after {ticks} epoch ticks, before the {owed:?} its deadline is worth"
    );
}

// KR-REQ-11.38: every deadline section 11 states, on the export it belongs to.
#[test]
fn kr_req_11_38_every_export_is_stopped_by_its_own_deadline() {
    let Some(wasm) = components::component("infinite-loop") else {
        return;
    };
    let engine = held_engine();
    let (_directory, mut instance) = bound_at(&engine, &wasm, "infinite-loop", FUEL_NEVER_ENDS);

    // Every export that has a deadline, each stopped by its own. What shows the deadline applied
    // rather than a shorter one is the ticks the engine's epoch advanced before the call was
    // stopped, which a test advances one at a time and so counts, as the check below says, to
    // within the ticks that came before the call began to run and while it returned.
    type Call = Box<dyn Fn(&mut Instance) -> RuntimeError + Send + Sync>;
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
        let (error, ticks) = ticks_until_stopped(&engine, || call(&mut instance));
        assert_eq!(
            error,
            RuntimeError::Exhausted {
                call: kind.as_str(),
                bound: ExhaustedBound::Deadline,
            },
            "{kind:?} reported {error}"
        );
        assert_stopped_after_its_ticks(kind, ticks);
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
//
// The engine's epoch is held: this case is about what each export does, and a call that a slow
// machine kept from running for ten milliseconds would be stopped by its deadline and say nothing
// about that. The deadlines are shown where a test advances the epoch itself.
#[test]
fn kr_req_11_01_a_vendor_component_adds_detection_events_and_controls() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let plugin = "well-behaved";
    let engine = held_engine();
    let (_directory, mut instance) = bound_on(&engine, &wasm, plugin);

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

    let first = compile_or_load(&engine, &cache, &wasm, no_compile_work_bound())
        .expect("the component compiles");
    assert_eq!(first.origin, CompileOrigin::Compiled);

    // The same bytes under the same engine come back rather than being compiled again.
    let second = compile_or_load(&engine, &cache, &wasm, no_compile_work_bound())
        .expect("the component loads");
    assert_eq!(second.origin, CompileOrigin::Cached);
    assert_eq!(first.key, second.key);

    // Different bytes are a different entry, so a changed component is never served the old one.
    let Some(other) = components::component("slow-compile") else {
        return;
    };
    let different = compile_or_load(&engine, &cache, &other, no_compile_work_bound())
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

/// The compatibility hash an engine computes under a module version strategy, with nothing else
/// about it changed.
///
/// The hash is what a cache entry's manifest records, and it is what tells two patch releases of
/// one major version apart: the stamp wasmtime writes into a serialised artefact holds the major
/// version alone, so an artefact one patch release made passes the next one's own checks on load.
fn compatibility_under(strategy: wasmtime::ModuleVersionStrategy) -> u64 {
    use std::hash::{Hash as _, Hasher as _};

    let mut config = wasmtime::Config::new();
    config.wasm_component_model(true);
    config.module_version(strategy).expect("a module version");
    let engine = wasmtime::Engine::new(&config).expect("an engine");
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    engine.precompile_compatibility_hash().hash(&mut hasher);
    hasher.finish()
}

/// Compiles a component as this host does, so that what comes of it is an artefact this host's
/// engine accepts on load.
fn compiled_by_this_host(engine: &RuntimeEngine, wasm: &[u8]) -> wasmtime::component::Component {
    wasmtime::component::Component::new(engine.engine(), wasm).expect("a component")
}

// KR-REQ-11.41: the compatibility hash a cache entry is filed under covers the engine's release.
#[test]
fn kr_req_11_41_the_compatibility_hash_covers_the_engine_release() {
    let this_release = compatibility_under(wasmtime::ModuleVersionStrategy::WasmtimeVersion);
    // What the engine hashes for itself is the full release this host names as its own, and not
    // the major version its artefacts are stamped with.
    assert_eq!(
        this_release,
        compatibility_under(wasmtime::ModuleVersionStrategy::Custom(
            ENGINE_VERSION.to_owned()
        )),
        "the engine's compatibility hash is not the one of the release this host names"
    );
    for earlier in ["48.0.3", "48.0.6", "48.0.7"] {
        assert_ne!(
            this_release,
            compatibility_under(wasmtime::ModuleVersionStrategy::Custom(earlier.to_owned())),
            "the earlier patch release {earlier} shares this one's compatibility hash"
        );
    }
}

// KR-REQ-11.41: a cache another engine release filed is compiled again, and left alone.
#[test]
fn kr_req_11_41_a_cache_another_engine_release_filed_is_compiled_again() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let directory = tempfile::tempdir().expect("a temporary directory");
    let root = directory.path().join("plugin-cache");
    let engine = engine();
    let current = key_for(&engine, &wasm);

    // What another release changes in a key is its version, its compatibility hash, or both. The
    // directory an entry is filed in names the first and is derived from the second, so each of
    // the three is a directory of its own.
    let mut by_version = current.clone();
    by_version.engine_version = "48.0.6".to_owned();
    let mut by_hash = current.clone();
    by_hash.engine_compatibility = "another release's compatibility".to_owned();
    let mut by_both = by_version.clone();
    by_both.engine_compatibility = by_hash.engine_compatibility.clone();
    let earlier = [by_version, by_hash, by_both];

    let filed = kr_plugin_runtime::runtime::cache::CompiledCache::open(&root).expect("a cache");
    let artefact = compiled_by_this_host(&engine, &wasm);
    let mut held = Vec::new();
    for key in &earlier {
        assert_ne!(key.engine_directory(), current.engine_directory());
        filed.store(key, &artefact).expect("the entry is filed");
        held.push((
            std::fs::read(filed.artefact_path(key)).expect("its artefact"),
            std::fs::read(filed.manifest_path(key)).expect("its manifest"),
        ));
    }

    // A host that starts afresh over that directory finds nothing under its own engine, so it
    // compiles, and no earlier entry is loaded, refused or touched.
    let restarted = kr_plugin_runtime::runtime::cache::CompiledCache::open(&root).expect("a cache");
    let compiled = compile_or_load(&engine, &restarted, &wasm, no_compile_work_bound())
        .expect("the component compiles");
    assert_eq!(compiled.origin, CompileOrigin::Compiled);
    for (key, (artefact, manifest)) in earlier.iter().zip(&held) {
        assert_eq!(
            &std::fs::read(restarted.artefact_path(key)).expect("its artefact"),
            artefact
        );
        assert_eq!(
            &std::fs::read(restarted.manifest_path(key)).expect("its manifest"),
            manifest
        );
    }

    // And the entry this engine filed is the one it loads the next time.
    let again = kr_plugin_runtime::runtime::cache::CompiledCache::open(&root).expect("a cache");
    let loaded = compile_or_load(&engine, &again, &wasm, no_compile_work_bound())
        .expect("the component loads");
    assert_eq!(loaded.origin, CompileOrigin::Cached);
}

// KR-REQ-11.41: compiled code another target filed is compiled again, and left alone.
//
// Machine code is for one instruction set, so the target is part of what an entry is filed under:
// the same component under the same engine release, filed for another target, is another entry.
#[test]
fn kr_req_11_41_a_cache_another_target_filed_is_compiled_again() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let directory = tempfile::tempdir().expect("a temporary directory");
    let root = directory.path().join("plugin-cache");
    let engine = engine();
    let current = key_for(&engine, &wasm);

    let mut elsewhere = current.clone();
    elsewhere.target = format!("another-{}", current.target);
    assert_eq!(elsewhere.engine_version, current.engine_version);
    assert_eq!(elsewhere.engine_compatibility, current.engine_compatibility);
    assert_ne!(
        elsewhere.engine_directory(),
        current.engine_directory(),
        "an entry for another target shares this target's directory"
    );

    let filed = kr_plugin_runtime::runtime::cache::CompiledCache::open(&root).expect("a cache");
    filed
        .store(&elsewhere, &compiled_by_this_host(&engine, &wasm))
        .expect("the entry is filed");
    let artefact = std::fs::read(filed.artefact_path(&elsewhere)).expect("its artefact");
    let manifest = std::fs::read(filed.manifest_path(&elsewhere)).expect("its manifest");

    // A host that starts afresh over that directory finds nothing under its own target, so it
    // compiles, and the other target's entry is neither loaded, refused nor touched.
    let restarted = kr_plugin_runtime::runtime::cache::CompiledCache::open(&root).expect("a cache");
    let compiled = compile_or_load(&engine, &restarted, &wasm, no_compile_work_bound())
        .expect("the component compiles");
    assert_eq!(compiled.origin, CompileOrigin::Compiled);
    assert_eq!(
        std::fs::read(restarted.artefact_path(&elsewhere)).expect("its artefact"),
        artefact
    );
    assert_eq!(
        std::fs::read(restarted.manifest_path(&elsewhere)).expect("its manifest"),
        manifest
    );

    // And this target's entry is the one it loads the next time.
    let loaded = compile_or_load(&engine, &restarted, &wasm, no_compile_work_bound())
        .expect("the component loads");
    assert_eq!(loaded.origin, CompileOrigin::Cached);
}

// KR-REQ-11.41: an entry another engine release made is refused by its manifest, wherever it is
// found, and the component is compiled again.
#[test]
fn kr_req_11_41_an_entry_another_engine_release_made_is_refused_and_compiled_again() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let directory = tempfile::tempdir().expect("a temporary directory");
    let engine = engine();
    let current = key_for(&engine, &wasm);
    let mut earlier = current.clone();
    earlier.engine_version = "48.0.3".to_owned();
    earlier.engine_compatibility = "another release's compatibility".to_owned();
    // The artefact is one this engine accepts on load, as an earlier patch release's is under the
    // same configuration: nothing but the manifest stands between it and being loaded.
    let component = compiled_by_this_host(&engine, &wasm);

    // The control: the same artefact under this engine's own manifest loads.
    let control = directory.path().join("control");
    kr_plugin_runtime::runtime::cache::CompiledCache::open(&control)
        .expect("a cache")
        .store(&current, &component)
        .expect("the entry is filed");
    assert!(
        kr_plugin_runtime::runtime::cache::CompiledCache::open(&control)
            .expect("a cache")
            .load(engine.engine(), &current)
            .expect("a lookup")
            .is_some(),
        "an entry under this engine's own manifest was not loaded"
    );

    // The earlier release's own entry, moved by hand into the directory this engine reads.
    let root = directory.path().join("plugin-cache");
    let filed = kr_plugin_runtime::runtime::cache::CompiledCache::open(&root).expect("a cache");
    filed
        .store(&earlier, &component)
        .expect("the entry is filed");
    let artefact = std::fs::read(filed.artefact_path(&earlier)).expect("its artefact");
    let manifest = std::fs::read(filed.manifest_path(&earlier)).expect("its manifest");
    kr_ipc::paths::create_private_directory(&filed.directory_for(&current)).expect("a directory");
    kr_ipc::paths::write_owner_only_file(&filed.artefact_path(&current), &artefact)
        .expect("the artefact");
    kr_ipc::paths::write_owner_only_file(&filed.manifest_path(&current), &manifest)
        .expect("the manifest");

    let restarted = kr_plugin_runtime::runtime::cache::CompiledCache::open(&root).expect("a cache");
    let error = restarted
        .verify(&current)
        .expect_err("an entry another release made is refused");
    assert!(
        error.to_string().contains("an engine with compatibility"),
        "the refusal was {error}"
    );
    assert!(
        restarted.load(engine.engine(), &current).is_err(),
        "an entry another release made was loaded"
    );

    // The refusal is the entry's and not the binding's: the component compiles, the refused entry
    // goes, and what is filed in its place loads. The earlier release's own entry stays as it was.
    let compiled = compile_or_load(&engine, &restarted, &wasm, no_compile_work_bound())
        .expect("the component compiles");
    assert_eq!(compiled.origin, CompileOrigin::Compiled);
    let again = kr_plugin_runtime::runtime::cache::CompiledCache::open(&root).expect("a cache");
    let loaded = compile_or_load(&engine, &again, &wasm, no_compile_work_bound())
        .expect("the component loads");
    assert_eq!(loaded.origin, CompileOrigin::Cached);
    assert_eq!(
        std::fs::read(again.manifest_path(&earlier)).expect("its manifest"),
        manifest
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
    let compiled = compile_or_load(&engine, &cache, &wasm, no_compile_work_bound())
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

/// A component with one core module whose one function declares an `i32` result and returns an
/// `i64`. It parses, and fails only when the engine compiles the function, so the engine's error
/// names the function in its outermost message and the fault in a cause beneath it.
fn component_with_a_function_of_the_wrong_type() -> Vec<u8> {
    let module: [u8; 27] = [
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // the module header
        0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f, // one type: () -> i32
        0x03, 0x02, 0x01, 0x00, // one function, of that type
        0x0a, 0x06, 0x01, 0x04, 0x00, 0x42, 0x00, 0x0b, // its body: i64.const 0
    ];
    let mut component = b"\0asm\x0d\0\x01\0".to_vec();
    component.push(0x01); // a core module section
    component.push(u8::try_from(module.len()).expect("a short module"));
    component.extend_from_slice(&module);
    component
}

// A component the engine refuses while compiling it is refused with the engine's whole account of
// why, every cause and not only the outermost message, which names the function and says nothing
// of what was wrong with it. A compile error such as an over-long `br_table` reaches the person
// the same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_component_the_engine_refuses_to_compile_is_refused_with_every_cause() {
    let wasm = component_with_a_function_of_the_wrong_type();
    let engine = engine();
    let direct = wasmtime::component::Component::new(engine.engine(), &wasm)
        .expect_err("the function does not compile");
    let causes: Vec<String> = direct.chain().map(ToString::to_string).collect();
    assert!(
        causes.len() > 1,
        "the engine's error has one message, so the case shows nothing: {causes:?}"
    );

    let host = host();
    let error = host
        .runtime
        .compile(Payload::new(Arc::from(wasm)))
        .expect("the compile is queued")
        .wait(COMPILE_WAIT)
        .await
        .expect_err("a function of the wrong type is refused");
    let RuntimeError::InvalidComponent { detail } = error else {
        panic!("the refusal was {error:?}");
    };
    for cause in &causes {
        assert!(
            detail.contains(cause.as_str()),
            "the refusal {detail:?} leaves out the cause {cause:?}"
        );
    }
}

// KR-REQ-11.41: a cold compile is not inside a call deadline, and does not count as a fault.
//
// A call's deadline is a count of the epoch's ticks from the moment the call starts, and the epoch
// is held, so what the machine does decides nothing. The compile registers no call in flight, and
// the epoch is then moved by several observation deadlines, which is what a compile and an
// instantiation that took that long between them look like to a clock that kept time: the
// observation that follows is given its own deadline all the same, finishes inside it, and is no
// fault.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_41_a_cold_compile_is_not_inside_an_observation_deadline() {
    let Some(wasm) = components::component("slow-compile") else {
        return;
    };
    let host = held_host();
    let (events, mut received) = events();

    let ticks_before = host.runtime.engine().ticks();
    let compiled = host
        .runtime
        .compile(Payload::new(Arc::clone(&wasm)))
        .expect("a compile")
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
    assert_eq!(
        host.runtime.engine().ticks(),
        ticks_before,
        "the compile put a call in flight, which the epoch counts"
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

    // The time the preparation took, as the epoch would have counted it had it been a call: several
    // observation deadlines. The observation's own deadline starts when its call does.
    let owed = CallBudget::of(CallKind::Observe)
        .epoch_ticks(kr_plugin_runtime::runtime::engine::EPOCH_TICK_MS)
        .expect("an observation has a deadline");
    for _ in 0..owed * 4 {
        host.runtime.engine().advance_epoch();
    }

    let admission = handle.enqueue_observation(components::scrape("se-1", "x"));
    assert_eq!(admission, Admission::Queued);
    let event = next_event(&mut received, LIVENESS)
        .await
        .expect("the observation produced something");
    match event {
        BindingEvent::Document { call, nodes, .. } => {
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
        .compile(Payload::new(wasm))
        .expect("a compile")
        .wait(COMPILE_WAIT)
        .await
        .expect("the component loads");
    assert_eq!(cached.origin, CompileOrigin::Cached);
}

// KR-REQ-11.41: a compile is queued at background priority and the caller goes on, never blocking
// on it.
//
// The pool is held, so the component cannot be compiled while the case looks: a compile that
// waited for its result would never return, and the case would end at its liveness bound; one that
// returns has the compile still undone, and the caller is given the result once the hold is let go.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_41_a_compile_is_queued_and_the_caller_goes_on_while_it_is_not_done() {
    let Some(wasm) = components::component("slow-compile") else {
        return;
    };
    let host = host();
    let hold = host.runtime.hold_compiles();

    // The call is made on a thread of its own, so that one that blocks fails the case rather than
    // holding it.
    let payload = Payload::new(wasm);
    let (returned, queued) = std::sync::mpsc::channel();
    let caller = std::thread::spawn({
        let runtime = Arc::clone(&host.runtime);
        move || {
            let compilation = runtime.compile(payload);
            let _ = returned.send(());
            compilation
        }
    });
    queued
        .recv_timeout(LIVENESS)
        .expect("the compile returned while its work was held");
    let mut compilation = caller
        .join()
        .expect("the caller finished")
        .expect("a compile is queued");
    assert!(
        compilation.poll().is_none(),
        "the compile has a result although the pool was held"
    );

    drop(hold);
    let compiled = compilation
        .wait(COMPILE_WAIT)
        .await
        .expect("the held compile finishes once it is let go");
    assert_eq!(compiled.origin, CompileOrigin::Compiled);
}

// KR-REQ-11.41: a compile that uses more processor time than the compile bound is refused with the
// bound named, and its result is discarded rather than filed.
//
// The bound is nothing, so the component is past it however fast the machine is: compiling a
// component of this size takes the thread some processor time. What follows is the same component
// compiled again, because the refused one was not filed in the cache that the next preparation
// reads. On Windows a thread's times advance with the scheduler's accounting, which a compile of a
// millisecond may not move, so this case reads the platform's clock where that is nanoseconds.
#[cfg(not(windows))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_41_a_compile_past_the_compile_bound_is_refused_and_not_filed() {
    let Some(wasm) = components::component("slow-compile") else {
        return;
    };
    let directory = tempfile::tempdir().expect("a temporary directory");
    let mut config = RuntimeConfig::new(directory.path().join("plugin-cache"));
    config.compile = CompileBudget {
        processor_ms: 0,
        ..CompileBudget::defaults()
    };
    let runtime = Runtime::new(config).expect("a runtime");

    let error = runtime
        .compile(Payload::new(Arc::clone(&wasm)))
        .expect("a compile")
        .wait(COMPILE_WAIT)
        .await
        .expect_err("a compile past the bound is refused");
    let RuntimeError::CompilationOverBudget { budget_ms, .. } = error else {
        panic!("the refusal was {error:?}");
    };
    assert_eq!(budget_ms, 0, "the refusal names the bound it was held to");

    let again = compile_or_load(
        runtime.engine(),
        runtime.cache(),
        &wasm,
        no_compile_work_bound(),
    )
    .expect("the component compiles");
    assert_eq!(
        again.origin,
        CompileOrigin::Compiled,
        "the refused compile was filed all the same"
    );
}

// KR-REQ-11.41: the compile bound is on the work the compile did and not on the clock, so a compile
// that a busy machine kept off the processor is accepted and filed when its work was within the
// bound.
//
// The calling thread's processor-time clock is scripted to say that the compile used nothing, and
// the bound is nothing; the compile itself takes the clock more than that, as any real compile of
// this component does. A bound held to the clock refuses it, which is what a thread starved of the
// processor met. What follows is the same component loaded, because the accepted compile was filed.
#[test]
fn kr_req_11_41_a_compile_kept_off_the_processor_is_held_to_the_work_it_did() {
    let Some(wasm) = components::component("slow-compile") else {
        return;
    };
    let directory = tempfile::tempdir().expect("a temporary directory");
    let cache = kr_plugin_runtime::runtime::cache::CompiledCache::open(directory.path().join("c"))
        .expect("a cache");
    let engine = engine();
    let nothing = CompileBudget {
        processor_ms: 0,
        ..CompileBudget::defaults()
    };

    let compiled = with_scripted_thread_cpu_time(
        || Some(core::time::Duration::from_millis(5)),
        || compile_or_load(&engine, &cache, &wasm, nothing),
    )
    .expect("a compile that used no processor time is within a bound of none");
    assert_eq!(compiled.origin, CompileOrigin::Compiled);

    let loaded = compile_or_load(&engine, &cache, &wasm, no_compile_work_bound())
        .expect("the component loads");
    assert_eq!(
        loaded.origin,
        CompileOrigin::Cached,
        "the accepted compile was not filed"
    );
}

// KR-REQ-11.41: the requests that wait for one compile are held to the pool's queue bound, and a
// request whose caller has stopped waiting holds no place.
//
// The pool is held, so the compile is not done while the requests are made. The queue's worth of
// requests join the first and the next is refused as pressure; once their callers are gone a new one
// is taken.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_41_the_requests_waiting_for_one_compile_are_held_to_the_queue_bound() {
    const QUEUE: usize = 3;

    let directory = tempfile::tempdir().expect("a temporary directory");
    let cache = kr_plugin_runtime::runtime::cache::CompiledCache::open(directory.path().join("c"))
        .expect("a cache");
    let engine = engine();
    let pool = CompilePool::with_threads(1, QUEUE);
    let not_wasm: Arc<[u8]> = Arc::from(&b"not wasm at all"[..]);
    let hold = pool.hold();
    let ask = || {
        pool.submit(
            &engine,
            &cache,
            Payload::new(Arc::clone(&not_wasm)),
            no_compile_work_bound(),
        )
    };

    let leader = ask().expect("the first request is queued");
    let mut waiting = Vec::new();
    for _ in 0..QUEUE {
        waiting.push(ask().expect("a request joins the compile"));
    }
    assert!(
        matches!(ask(), Err(RuntimeError::CompilationPressure { .. })),
        "a request past the bound was taken"
    );
    drop(waiting);
    let again = ask().expect("a request takes the place of one whose caller is gone");
    drop(hold);

    answer_of(leader)
        .await
        .expect_err("the component is refused");
    answer_of(again)
        .await
        .expect_err("the component is refused");
    assert_eq!(
        pool.compiles_started(),
        1,
        "the component was compiled more than once"
    );
}

// KR-REQ-11.41: a request on another engine does not join a compile, because a component compiled
// for one engine is not one another can run.
//
// The two engines are built alike, so the component's key is the same on both; each request is
// compiled for its own engine.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_41_a_request_on_another_engine_does_not_join_a_compile() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let cache = kr_plugin_runtime::runtime::cache::CompiledCache::open(directory.path().join("c"))
        .expect("a cache");
    let (one, another) = (engine(), engine());
    let pool = CompilePool::with_threads(2, 8);
    let not_wasm: Arc<[u8]> = Arc::from(&b"not wasm at all"[..]);
    let hold = pool.hold();

    let first = pool
        .submit(
            &one,
            &cache,
            Payload::new(Arc::clone(&not_wasm)),
            no_compile_work_bound(),
        )
        .expect("the first request is queued");
    let second = pool
        .submit(
            &another,
            &cache,
            Payload::new(Arc::clone(&not_wasm)),
            no_compile_work_bound(),
        )
        .expect("the second request is queued");
    drop(hold);

    answer_of(first)
        .await
        .expect_err("the component is refused");
    answer_of(second)
        .await
        .expect_err("the component is refused");
    assert_eq!(
        (pool.compiles_started(), pool.requests_joined()),
        (2, 0),
        "a request joined a compile on another engine"
    );
}

// KR-REQ-11.41: where the platform does not say what a thread has used, the budget is held to the
// clock.
//
// The calling thread's processor-time clock is scripted to say nothing, and the bound is nothing,
// so the compile is past it however fast the machine is: compiling a component of this size takes
// the clock some time.
#[test]
fn kr_req_11_41_where_a_platform_does_not_say_what_a_thread_used_the_budget_is_held_to_the_clock() {
    let Some(wasm) = components::component("slow-compile") else {
        return;
    };
    let directory = tempfile::tempdir().expect("a temporary directory");
    let cache = kr_plugin_runtime::runtime::cache::CompiledCache::open(directory.path().join("c"))
        .expect("a cache");
    let engine = engine();
    let nothing = CompileBudget {
        processor_ms: 0,
        ..CompileBudget::defaults()
    };

    let error =
        with_scripted_thread_cpu_time(|| None, || compile_or_load(&engine, &cache, &wasm, nothing))
            .expect_err("a compile past the bound on the clock is refused");
    assert!(
        matches!(
            error,
            RuntimeError::CompilationOverBudget { budget_ms: 0, .. }
        ),
        "the refusal was {error:?}"
    );
}

// KR-REQ-11.41: a component loaded from the cache is held to the same budget as one compiled.
//
// The component is compiled once with no bound, which files it. It is then loaded under the host's
// bound while the calling thread's processor-time clock is scripted to say that the load used 31
// seconds, and the load is refused with the work it came to.
#[test]
fn kr_req_11_41_a_load_that_used_more_than_the_bound_is_refused() {
    let Some(wasm) = components::component("well-behaved") else {
        return;
    };
    let directory = tempfile::tempdir().expect("a temporary directory");
    let cache = kr_plugin_runtime::runtime::cache::CompiledCache::open(directory.path().join("c"))
        .expect("a cache");
    let engine = engine();
    compile_or_load(&engine, &cache, &wasm, no_compile_work_bound())
        .expect("the component compiles");
    assert!(
        cache
            .resident_component(engine.engine(), &key_for(&engine, &wasm))
            .is_some(),
        "the compile was not filed, so the call below would not be a load"
    );

    let mut readings = 0_u64;
    let error = with_scripted_thread_cpu_time(
        move || {
            readings += 1;
            Some(core::time::Duration::from_secs(if readings == 1 {
                0
            } else {
                31
            }))
        },
        || compile_or_load(&engine, &cache, &wasm, CompileBudget::defaults()),
    )
    .expect_err("a load that used more than the bound is refused");
    assert!(
        matches!(
            error,
            RuntimeError::CompilationOverBudget {
                used_ms: 31_000,
                budget_ms: 30_000
            }
        ),
        "the refusal was {error:?}"
    );
}

// KR-REQ-11.41: the processor time the budget counts is that of the compiling thread, and of no
// other thing: a thread that waits uses none, however long it waits and whatever other threads do.
//
// One thread reads its processor time and waits. Another spins until its own processor time has
// advanced 300 ms, and says how far it did. The waiting thread then reads its processor time again,
// and what it used while it waited is far less than what the other used. A clock that ran with the
// wall, or with the process, would show it nearly the same.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    windows
))]
#[test]
fn kr_req_11_41_the_budget_counts_the_compiling_threads_own_processor_time() {
    use kr_plugin_runtime::runtime::thread_time::thread_cpu_time;

    let (said, hears) = std::sync::mpsc::channel::<core::time::Duration>();
    let (read, go) = std::sync::mpsc::channel::<()>();
    let waiting = std::thread::spawn(move || {
        let before = thread_cpu_time().expect("this platform reads a thread's processor time");
        read.send(()).expect("the other thread is there");
        let used_elsewhere = hears.recv().expect("the other thread said how far it spun");
        let after = thread_cpu_time().expect("this platform reads a thread's processor time");
        (after.saturating_sub(before), used_elsewhere)
    });
    let spinning = std::thread::spawn(move || {
        // Not before the other thread has read its clock, so that it is waiting while this spins.
        go.recv().expect("the other thread read its clock");
        let from = thread_cpu_time().expect("this platform reads a thread's processor time");
        let mut sum = 0_u64;
        let mut used = core::time::Duration::ZERO;
        // A clock that never reaches 300 ms ends the loop by its count, and the case fails on the
        // figures it reads.
        for _ in 0..1_000_000 {
            for step in 0..10_000_u64 {
                sum = sum.wrapping_add(std::hint::black_box(step));
            }
            used = thread_cpu_time()
                .expect("this platform reads a thread's processor time")
                .saturating_sub(from);
            if used >= core::time::Duration::from_millis(300) {
                break;
            }
        }
        std::hint::black_box(sum);
        said.send(used).expect("the waiting thread is there");
    });
    spinning.join().expect("the spinning thread ended");
    let (waited, spun) = waiting.join().expect("the waiting thread ended");
    assert!(
        waited.saturating_mul(4) < spun,
        "the waiting thread used {waited:?} while the other used {spun:?}"
    );
}

// KR-REQ-11.41: a compile that did too much work is still refused, and not filed, whatever the
// clock says.
//
// The calling thread's processor-time clock is scripted to say that the compile used 31 seconds
// against the host's bound of 30, when the clock itself passed a fraction of that. The refusal names
// the figure the work came to, and the same component compiles again afterwards because the
// refused one was not filed.
#[test]
fn kr_req_11_41_a_compile_that_did_more_work_than_the_bound_is_refused_and_not_filed() {
    let Some(wasm) = components::component("slow-compile") else {
        return;
    };
    let directory = tempfile::tempdir().expect("a temporary directory");
    let cache = kr_plugin_runtime::runtime::cache::CompiledCache::open(directory.path().join("c"))
        .expect("a cache");
    let engine = engine();

    let mut readings = 0_u64;
    let error = with_scripted_thread_cpu_time(
        move || {
            readings += 1;
            Some(core::time::Duration::from_secs(if readings == 1 {
                0
            } else {
                31
            }))
        },
        || compile_or_load(&engine, &cache, &wasm, CompileBudget::defaults()),
    )
    .expect_err("a compile that did more work than the bound is refused");
    let RuntimeError::CompilationOverBudget { used_ms, budget_ms } = error else {
        panic!("the refusal was {error:?}");
    };
    assert_eq!(
        (used_ms, budget_ms),
        (31_000, 30_000),
        "the refusal names the work done and the bound"
    );

    let again = compile_or_load(&engine, &cache, &wasm, no_compile_work_bound())
        .expect("the component compiles");
    assert_eq!(
        again.origin,
        CompileOrigin::Compiled,
        "the refused compile was filed all the same"
    );
}

/// Waits for a compile's answer, for as long as a compile may take.
async fn answer_of(
    request: tokio::sync::oneshot::Receiver<
        Result<kr_plugin_runtime::runtime::compile::Compiled, RuntimeError>,
    >,
) -> Result<kr_plugin_runtime::runtime::compile::Compiled, RuntimeError> {
    tokio::time::timeout(COMPILE_WAIT, request)
        .await
        .expect("the compile was answered")
        .expect("the pool answered")
}

// KR-REQ-11.41: two requests for one component, the second while the first is queued or being
// compiled, compile it once, and both are given it.
//
// The pool is held, so the first request has not begun its compile when the second is made. A worker
// that offers a component again while its first offer's compile is still going on is this second
// request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_41_two_requests_for_one_component_compile_it_once_and_both_are_given_it() {
    let Some(wasm) = components::component("slow-compile") else {
        return;
    };
    let directory = tempfile::tempdir().expect("a temporary directory");
    let cache = kr_plugin_runtime::runtime::cache::CompiledCache::open(directory.path().join("c"))
        .expect("a cache");
    let engine = engine();
    let pool = CompilePool::with_threads(2, 8);
    let hold = pool.hold();

    let first = pool
        .submit(
            &engine,
            &cache,
            Payload::new(Arc::clone(&wasm)),
            no_compile_work_bound(),
        )
        .expect("the first request is queued");
    let second = pool
        .submit(
            &engine,
            &cache,
            Payload::new(Arc::clone(&wasm)),
            no_compile_work_bound(),
        )
        .expect("the second request is made");
    drop(hold);

    let first = answer_of(first).await.expect("the first is given it");
    let second = answer_of(second).await.expect("the second is given it");
    assert_eq!(
        (pool.compiles_started(), pool.requests_joined()),
        (1, 1),
        "the pool compiled for one request and held the other for it"
    );
    assert_eq!(first.origin, CompileOrigin::Compiled);
    assert_eq!(second.origin, CompileOrigin::Compiled);
    assert_eq!(first.key, second.key);
}

// KR-REQ-11.41: a compile that fails fails every request that waited for it, with the same refusal.
//
// The component is not Wasm, so it is refused whatever the machine does. Two requests for it, the
// second while the first is queued, are both told why, and the component was compiled once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_41_a_compile_that_fails_fails_every_request_that_waited_for_it() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let cache = kr_plugin_runtime::runtime::cache::CompiledCache::open(directory.path().join("c"))
        .expect("a cache");
    let engine = engine();
    let pool = CompilePool::with_threads(2, 8);
    let not_wasm: Arc<[u8]> = Arc::from(&b"not wasm at all"[..]);
    let hold = pool.hold();

    let first = pool
        .submit(
            &engine,
            &cache,
            Payload::new(Arc::clone(&not_wasm)),
            no_compile_work_bound(),
        )
        .expect("the first request is queued");
    let second = pool
        .submit(
            &engine,
            &cache,
            Payload::new(Arc::clone(&not_wasm)),
            no_compile_work_bound(),
        )
        .expect("the second request is made");
    drop(hold);

    let first = answer_of(first).await.expect_err("the first is refused");
    let second = answer_of(second).await.expect_err("the second is refused");
    assert!(
        matches!(first, RuntimeError::InvalidComponent { .. }),
        "the first was told {first:?}"
    );
    assert_eq!(first, second, "the two were told different things");
    assert_eq!(
        (pool.compiles_started(), pool.requests_joined()),
        (1, 1),
        "the pool compiled for one request and held the other for it"
    );
}

// KR-REQ-11.41: a request joins a compile by the digest of the component's bytes and not by their
// number, so two components of one size are two compiles, each answered with its own result.
//
// The pool is held while both are queued, so a request that joined the other's compile would be
// counted before either runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_41_two_components_of_one_size_are_two_compiles() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let cache = kr_plugin_runtime::runtime::cache::CompiledCache::open(directory.path().join("c"))
        .expect("a cache");
    let engine = engine();
    let pool = CompilePool::with_threads(1, 2);
    let one: Arc<[u8]> = Arc::from(&b"one, not wasm"[..]);
    let other: Arc<[u8]> = Arc::from(&b"two, not wasm"[..]);
    assert_eq!(one.len(), other.len());
    let hold = pool.hold();

    let first = pool
        .submit(&engine, &cache, Payload::new(one), no_compile_work_bound())
        .expect("the first component is queued");
    let second = pool
        .submit(
            &engine,
            &cache,
            Payload::new(other),
            no_compile_work_bound(),
        )
        .expect("the second component is queued");
    assert_eq!(
        pool.requests_joined(),
        0,
        "a component joined the compile of another of its size"
    );
    drop(hold);

    answer_of(first)
        .await
        .expect_err("the first component is refused");
    answer_of(second)
        .await
        .expect_err("the second component is refused");
    assert_eq!(pool.compiles_started(), 2);
}

// KR-REQ-11.41: a request for a component that is queued behind another compile joins it, with no
// thread free to take it up and no place in the queue.
//
// The pool has one thread and a queue of two, and the thread is held. The first component is
// taken up by the thread or waits in the queue; the second waits in the queue; a second request
// for the second component is made while it waits, and joins it. A request that took a place in
// the queue instead would be a third compile, and would be refused when the queue was full.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_41_a_request_for_a_queued_component_joins_it_without_a_thread_to_take_it_up() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let cache = kr_plugin_runtime::runtime::cache::CompiledCache::open(directory.path().join("c"))
        .expect("a cache");
    let engine = engine();
    let pool = CompilePool::with_threads(1, 2);
    let first: Arc<[u8]> = Arc::from(&b"the first, not wasm"[..]);
    let second: Arc<[u8]> = Arc::from(&b"the second, not wasm"[..]);
    let hold = pool.hold();

    let ahead = pool
        .submit(
            &engine,
            &cache,
            Payload::new(Arc::clone(&first)),
            no_compile_work_bound(),
        )
        .expect("the first component is queued");
    let queued = pool
        .submit(
            &engine,
            &cache,
            Payload::new(Arc::clone(&second)),
            no_compile_work_bound(),
        )
        .expect("the second component is queued");
    let again = pool
        .submit(
            &engine,
            &cache,
            Payload::new(Arc::clone(&second)),
            no_compile_work_bound(),
        )
        .expect("a second request for the second component joins it");
    assert_eq!(
        pool.requests_joined(),
        1,
        "the request took a place of its own"
    );
    drop(hold);

    answer_of(ahead)
        .await
        .expect_err("the first component is refused");
    let queued = answer_of(queued).await.expect_err("the second is refused");
    let again = answer_of(again)
        .await
        .expect_err("the second again is refused");
    assert_eq!(queued, again, "the two were told different things");
    assert_eq!(
        (pool.compiles_started(), pool.requests_joined()),
        (2, 1),
        "the second component was compiled once"
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
        .compile(Payload::new(wasm))
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
    let host = held_host();
    let (events, mut received) = events();
    let compiled = host
        .runtime
        .compile(Payload::new(wasm))
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

    // Filling the queue while the component has read nothing from it. The first observation wakes
    // the binding's pass over the queue, which is stopped before it takes anything; once the stop
    // is acknowledged, how fast the component reads and how fast this thread offers decide
    // nothing. Each event is 64 KiB, so sixty-five of them are already more than the 4 MiB the
    // queue holds, and the limit only ends a queue that never overflows.
    let filler = "y".repeat(64 * 1024);
    let mut stop = handle.stop_next_pump();
    let first = handle.enqueue_observation(components::scrape("se-0", &filler));
    assert!(
        !matches!(first, Admission::QueuedWithGap { .. }),
        "one observation of 64 KiB overflowed a 4 MiB queue"
    );
    assert!(
        handle.queued_bytes() <= OBSERVATION_QUEUE_BYTES,
        "the queue holds {} bytes, over its {OBSERVATION_QUEUE_BYTES} byte bound",
        handle.queued_bytes()
    );
    // The wait ends when the pass stands. The bound only ends a pass that never comes.
    assert!(
        tokio::time::timeout(core::time::Duration::from_secs(60), stop.reached())
            .await
            .expect("the binding's pass stands at the stop"),
        "the stop was replaced before a pass reached it"
    );
    let mut gapped = false;
    for index in 1..=130 {
        let admission =
            handle.enqueue_observation(components::scrape(&format!("se-{index}"), &filler));
        assert!(
            handle.queued_bytes() <= OBSERVATION_QUEUE_BYTES,
            "the queue holds {} bytes, over its {OBSERVATION_QUEUE_BYTES} byte bound",
            handle.queued_bytes()
        );
        if matches!(admission, Admission::QueuedWithGap { .. }) {
            gapped = true;
            break;
        }
    }
    assert!(
        gapped,
        "a hundred and thirty 64 KiB observations did not overflow a 4 MiB queue"
    );
    stop.release();

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
        .compile(Payload::new(Arc::clone(&wasm)))
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
    second.binding_id = kr_plugin_service::client::new_binding_id();
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

    let first = compile_or_load(&engine, &cache, &wasm, no_compile_work_bound())
        .expect("the component compiles");
    assert_eq!(first.origin, CompileOrigin::Compiled);
    assert_eq!(cache.resident(), 1);
    assert!(
        cache
            .resident_component(engine.engine(), &first.key)
            .is_some()
    );

    // Removing the files leaves the one in memory, which is the one this process produced: no
    // question of provenance arises for it, because no file is read.
    std::fs::remove_file(cache.artefact_path(&first.key)).expect("the artefact is removed");
    std::fs::remove_file(cache.manifest_path(&first.key)).expect("the manifest is removed");
    let second = compile_or_load(&engine, &cache, &wasm, no_compile_work_bound())
        .expect("the component loads");
    assert_eq!(second.origin, CompileOrigin::Cached);

    // Removing the entry removes the one in memory too, so a later load is a real miss.
    cache.remove(&first.key).expect("the entry is removed");
    assert_eq!(cache.resident(), 0);
    let third = compile_or_load(&engine, &cache, &wasm, no_compile_work_bound())
        .expect("the component compiles again");
    assert_eq!(third.origin, CompileOrigin::Compiled);
}

// KR-REQ-11.41: a component held in memory is served only to the engine that holds it. A component
// belongs to the engine that compiled or loaded it and no other engine can instantiate it, and two
// engines built alike share one compatibility identity, so the cache cannot tell them apart by key:
// the engine that asks second is given a component of its own, loaded from the artefact the first
// filed.
#[test]
fn kr_req_11_41_a_component_in_one_engines_memory_is_not_served_to_another_engine() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let directory = tempfile::tempdir().expect("a temporary directory");
    let first = engine();
    let second = engine();
    assert_eq!(
        key_for(&first, &wasm),
        key_for(&second, &wasm),
        "two engines built alike are told apart by the key"
    );
    let cache = kr_plugin_runtime::runtime::cache::CompiledCache::open(
        directory.path().join("plugin-cache"),
    )
    .expect("a cache");

    let filed = compile_or_load(&first, &cache, &wasm, no_compile_work_bound())
        .expect("the component compiles");
    assert_eq!(filed.origin, CompileOrigin::Compiled);
    assert!(wasmtime::Engine::same(
        filed.component.engine(),
        first.engine()
    ));

    let served = compile_or_load(&second, &cache, &wasm, no_compile_work_bound())
        .expect("the component loads");
    assert_eq!(served.origin, CompileOrigin::Cached);
    assert!(
        wasmtime::Engine::same(served.component.engine(), second.engine()),
        "the engine that asked was given a component another engine holds"
    );
    Instance::new(
        &second,
        &served.component,
        components::facts("well-behaved"),
        InstanceLimiter::defaults(),
        kr_plugin_runtime::runtime::budget::FUEL_PER_DEADLINE_MS,
    )
    .expect("the component instantiates on the engine that asked for it");

    // What the cache holds in memory under the key is the component of the engine that loaded last,
    // and the first engine is not served the second's.
    assert_eq!(cache.resident(), 1);
    assert!(
        cache
            .resident_component(second.engine(), &served.key)
            .is_some()
    );
    assert!(
        cache
            .resident_component(first.engine(), &served.key)
            .is_none()
    );
}

// A replaced instance is told what the host holds now, not what it held when the binding was made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replacement_after_a_fault_is_bound_to_the_current_revision() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let directory = tempfile::tempdir().expect("a temporary directory");
    // The epoch is held: the case reads what a replacement is bound to, and no deadline is its claim.
    let engine = held_engine();
    let cache = kr_plugin_runtime::runtime::cache::CompiledCache::open(
        directory.path().join("plugin-cache"),
    )
    .expect("a cache");
    let compiled = compile_or_load(&engine, &cache, &wasm, no_compile_work_bound())
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
    facts.activity = kr_plugin_service::vocabulary::BindingActivity::AwaitingPerson;
    instance.set_binding_facts(facts);
    instance.set_attachments(vec![kr_plugin_service::vocabulary::AttachmentFact {
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

// A component that spends a good part of a call and still answers: the shape a test about what
// happens *while* a component is running needs, because a component that faults is one that is soon
// disabled and no longer running at all.
//
// How much a call spends is decided by the fuel it uses, which is the same on every machine, and
// not by how long it takes, which is the machine's. The engine's epoch is held, so no time a
// loaded machine takes counts towards the deadline, and every call is left to answer.
#[test]
fn a_slow_component_spends_its_call_and_still_answers() {
    let Some(wasm) = components::component("slow-observe") else {
        return;
    };
    let engine = held_engine();
    let (_directory, mut instance) = bound_on(&engine, &wasm, "slow-observe");
    let allowance = CallBudget::of(CallKind::Observe).fuel;

    // As many calls as it takes a component that faults to be disabled, and a few more: this one
    // does not fault, so every one of them answers.
    for call in 0..FAULTS_BEFORE_DISABLE + 5 {
        let outcome = instance.observe(components::scrape("se-1", "output"));
        assert!(
            matches!(outcome.result, Ok(Ok(()))),
            "call {call} did not answer: {:?}",
            outcome.result
        );
        assert!(
            !outcome.nodes.is_empty(),
            "the call drew nothing, so nothing can see that it happened"
        );
        // Long enough to be worth queueing against: a call that did nothing would not keep a
        // binding's thread occupied, which is the whole reason this fixture exists. And short
        // enough to leave room to return: a call that used its whole allowance would be a fault,
        // and a fault is what this component exists not to be.
        assert!(
            outcome.fuel_used >= allowance / 100 && outcome.fuel_used < allowance / 2,
            "call {call} used {} of its {allowance} fuel",
            outcome.fuel_used
        );
    }
}

// A document the caller never received leaves a stale view, and the answer is the one a lost
// observation gets: the component draws again.
//
// The runtime's epoch is held: a snapshot call is stopped by its elapsed deadline, so a machine
// that keeps the thread making the call off the CPU for that long faults the component, which says
// nothing about whether it is asked to draw again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_document_nobody_received_asks_the_component_to_draw_again() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let host = held_host();
    let (events, mut received) = events();
    let handle = host
        .runtime
        .prepare(
            host.owner,
            components::request("well-behaved", 11),
            Payload::new(Arc::clone(&wasm)),
            COMPILE_WAIT,
            events,
        )
        .await
        .expect("the component binds");

    // Nothing is owed yet: the component has just drawn what `bind` produced.
    assert!(!handle.snapshot_required());

    // Whoever was to read that document did not. Saying so is what puts the obligation back, and
    // the pump discharges it with a fresh snapshot without anybody asking for one. That the asking
    // raises the obligation is the queue's own test,
    // `queue::tests::a_snapshot_can_be_asked_for_without_anything_having_been_lost`; asserting it
    // here would race the pump, which may already have discharged it by the next line.
    handle.require_snapshot();

    let deadline = std::time::Instant::now() + LIVENESS;
    let mut drew = false;
    while !drew && std::time::Instant::now() < deadline {
        match next_event(&mut received, core::time::Duration::from_millis(200)).await {
            Some(BindingEvent::Document { call, nodes, .. }) => {
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

    // The document leaves from inside the snapshot call, and the obligation is cleared once that
    // call has returned and answered -- it has to be, because a draw that failed or was declined
    // leaves the obligation standing. Holding the document therefore says the component drew, not
    // that the binding has finished with the obligation, so this waits for it as the loop above
    // waits for the document.
    let cleared_by = std::time::Instant::now() + LIVENESS;
    while handle.snapshot_required() && std::time::Instant::now() < cleared_by {
        tokio::time::sleep(core::time::Duration::from_millis(10)).await;
    }
    assert!(
        !handle.snapshot_required(),
        "the obligation was not cleared"
    );
}
