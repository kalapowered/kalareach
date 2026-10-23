//! The protocol a worker and the plugin host speak, over a real socket.
//!
//! The host here is in this process rather than its own, because what these tests are about is the
//! conversation: the handshake, the challenge, a registration, a delivery, a call, a refusal and a
//! health report. The separate process, its supervision and its death are in
//! `crates/kr-plugin-host/tests/service.rs`, where there is a real one to kill.
//!
//! Requirement rows touched here: KR-REQ-04.07, KR-REQ-06.06, KR-REQ-11.38, KR-REQ-11.40.

mod components;

use std::sync::Arc;

use kr_plugin_runtime::service::host::{HostConfig, PluginHost};
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_service::client::{PluginClient, new_binding_id};
use kr_plugin_service::error::ServiceError;
use kr_plugin_service::launcher::{HostIdentity, host_endpoint};
use kr_plugin_service::protocol::{
    ComponentSource, Frame, HostDescriptor, HostProtocol, Notice, RequestBody, ResponseBody,
};
use kr_plugin_service::vocabulary::Admission;

/// A plugin host serving in this process, with a client connected to it.
struct Served {
    _temp: kr_ipc::testing::TempHost,
    packages: std::path::PathBuf,
    descriptor: HostDescriptor,
    host: Arc<PluginHost>,
    serving: tokio::task::JoinHandle<()>,
}

impl Served {
    async fn start() -> Self {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        // Owner-only: it holds the payloads this host compiles, and the host refuses a packages
        // directory anybody else could write to.
        let packages = environment.state_dir().join("packages");
        kr_ipc::paths::create_private_directory(&packages).expect("the packages directory");
        let identity = HostIdentity::generate(temp.environment_id()).expect("an identity");
        let endpoint = host_endpoint(&environment, &HostProtocol::THIS).expect("an endpoint");
        let descriptor = HostDescriptor {
            protocol: HostProtocol::THIS.name.to_owned(),
            environment_id: temp.environment_id(),
            reservation_id: kr_protocol::worker::ReservationId::new(kr_ipc::new_uuid()),
            endpoint: endpoint.as_text(),
            boot_identity: identity.boot_identity().clone(),
            process_start_identity: identity.process_start_identity().clone(),
            host_public_key: *identity.public_key(),
        };
        let host = Arc::new(
            PluginHost::new(
                identity,
                HostConfig {
                    endpoint,
                    packages_root: packages.clone(),
                    cache_root: environment.state_dir().join("plugin-cache"),
                },
            )
            .expect("a plugin host"),
        );
        let endpoint_for_wait =
            kr_ipc::paths::Endpoint::from_path(&descriptor.endpoint).expect("an endpoint");
        let serving = tokio::spawn({
            let host = Arc::clone(&host);
            async move {
                let _ = host.serve(core::future::pending::<()>()).await;
            }
        });
        // The endpoint is bound inside `serve`, so a client that connects at once may arrive
        // first. Waited for rather than slept through: a fixed delay is a guess about a machine,
        // and this machine runs other work.
        let ready = std::time::Instant::now();
        loop {
            if kr_ipc::endpoint::Connection::connect(&endpoint_for_wait)
                .await
                .is_ok()
            {
                break;
            }
            assert!(
                ready.elapsed() < core::time::Duration::from_secs(10),
                "the host never bound its endpoint"
            );
            tokio::time::sleep(core::time::Duration::from_millis(10)).await;
        }
        Self {
            _temp: temp,
            packages,
            descriptor,
            host,
            serving,
        }
    }

    async fn client(&self) -> PluginClient {
        let endpoint =
            kr_ipc::paths::Endpoint::from_path(&self.descriptor.endpoint).expect("an endpoint");
        let connection = kr_ipc::endpoint::Connection::connect(&endpoint)
            .await
            .expect("connects to the plugin host");
        PluginClient::over(connection, self.descriptor.clone())
            .await
            .expect("the host answers the handshake and the challenge")
    }

    /// Puts a component in the packages directory and returns how to name it.
    fn install(&self, name: &str, wasm: &[u8]) -> (String, PayloadDigest, u64) {
        let path = self.packages.join(format!("{name}.wasm"));
        std::fs::write(&path, wasm).expect("the component is installed");
        (
            path.display().to_string(),
            PayloadDigest::of(wasm),
            wasm.len() as u64,
        )
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

/// Collects the nodes of the next document one binding's `call` produced.
///
/// Documents arrive as notices and a component draws one whenever it has something to say, so a
/// test that wanted one export's document had to be able to say which. Anything else that arrives
/// while it waits is returned to the caller's attention by being asserted on: a fault here would be
/// a test passing for the wrong reason.
async fn documents_until(
    client: &mut PluginClient,
    binding_id: kr_plugin_service::vocabulary::BindingId,
    call: &str,
) -> Option<Vec<kr_plugin_service::protocol::WireNode>> {
    let deadline = std::time::Instant::now() + core::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        match tokio::time::timeout(core::time::Duration::from_millis(200), client.notice()).await {
            Ok(Some(Notice::Document {
                binding_id: bound,
                call: drew,
                nodes,
                ..
            })) => {
                assert_eq!(bound, binding_id.get());
                if drew == call {
                    return Some(nodes);
                }
            }
            Ok(Some(other @ (Notice::Fault { .. } | Notice::Disabled { .. }))) => {
                panic!("the binding produced {other:?}")
            }
            Ok(Some(Notice::Gap { .. })) | Ok(None) | Err(_) => {}
        }
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_host_answers_a_challenge_before_it_is_trusted() {
    let served = Served::start().await;
    // Connecting runs the handshake and the challenge; a host that could not answer would make
    // this fail rather than serve.
    let client = served.client().await;
    assert_eq!(client.descriptor().protocol, HostProtocol::THIS.name);

    let health = client.health().await.expect("the host reports itself");
    assert_eq!(health.live_bindings, 0);
    assert!(!health.engine_version.is_empty());
    assert!(!health.target.is_empty());
    assert!(!health.engine_compatibility.is_empty());
    assert!(
        health.deadlines_enforceable,
        "a host that cannot enforce an elapsed deadline says so"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_verifies_against_the_wrong_key_is_refused() {
    let served = Served::start().await;
    let endpoint =
        kr_ipc::paths::Endpoint::from_path(&served.descriptor.endpoint).expect("an endpoint");
    let connection = kr_ipc::endpoint::Connection::connect(&endpoint)
        .await
        .expect("connects");
    // A descriptor naming somebody else's key. The endpoint is right and the process is right, and
    // the challenge still fails, which is the point of challenging rather than reading a file.
    let other = HostIdentity::generate(served.descriptor.environment_id).expect("an identity");
    let mut wrong = served.descriptor.clone();
    wrong.host_public_key = *other.public_key();
    let error = PluginClient::over(connection, wrong)
        .await
        .expect_err("a host that cannot answer for that key is refused");
    assert!(matches!(error, ServiceError::Protocol { .. }), "{error}");
}

// KR-REQ-06.06, KR-REQ-11.38: a registration, a delivery and a call, over the protocol.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_06_06_a_worker_registers_delivers_and_calls_over_the_protocol() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let served = Served::start().await;
    let mut client = served.client().await;
    let (path, digest, bytes) = served.install("well-behaved", &wasm);

    let request = components::request("well-behaved", 1);
    let binding_id = request.binding_id;
    let registration = client
        .register(
            binding_id,
            &request.identity,
            &request.facts,
            &request.executable,
            &ComponentSource {
                path: path.clone(),
                digest,
                bytes,
            },
        )
        .await
        .expect("the binding registers");
    assert!(
        !registration.cached,
        "the first registration of a component compiles it"
    );
    assert_eq!(
        client
            .health()
            .await
            .expect("a health report")
            .live_bindings,
        1
    );

    // Delivering an event is a queue push. The answer is the queue's.
    let admission = client
        .deliver(binding_id, &components::scrape("se-1", "building"))
        .await
        .expect("the event is offered");
    assert_eq!(admission, Admission::Queued);

    // Documents arrive as notices, stamped with the binding they belong to. Two of them: what
    // `bind` drew when the binding was registered, and what the observation drew. Both are the
    // component's presentation and neither is discarded.
    let bound = documents_until(&mut client, binding_id, "bind")
        .await
        .expect("bind drew a document");
    assert!(!bound.is_empty());
    let observed = documents_until(&mut client, binding_id, "observe")
        .await
        .expect("the observation produced a document");
    assert!(
        observed
            .iter()
            .any(|node| node.body_json.contains("building")),
        "the document did not carry the observation"
    );

    // A call returns the component's answer. The nodes it drew travel as notices of their own,
    // because one call may draw more than one frame carries.
    let called = client
        .snapshot(binding_id, core::time::Duration::from_millis(500))
        .await
        .expect("the snapshot runs");
    assert!(called.answered());
    let drawn = documents_until(&mut client, binding_id, "snapshot")
        .await
        .expect("the snapshot drew a document");
    assert!(!drawn.is_empty());

    // Checkpoint and restore round-trip the component's own state.
    let checkpointed = client
        .checkpoint(binding_id, core::time::Duration::from_millis(500))
        .await
        .expect("the checkpoint runs");
    let state = checkpointed.state.expect("the component has state");
    assert!(!state.is_empty());
    let restored = client
        .restore(binding_id, state, core::time::Duration::from_millis(500))
        .await
        .expect("the restore runs");
    assert!(restored.answered());

    // A connection accounts for the bindings it holds, and gives a place back exactly once: a
    // place given back twice would let it hold more bindings than it may.
    assert_eq!(
        client
            .health()
            .await
            .expect("a health report")
            .connection_bindings,
        1
    );

    // Unbinding removes the instance, and a second unbind says there was nothing to remove.
    assert!(client.unbind(binding_id).await.expect("the unbind runs"));
    assert!(!client.unbind(binding_id).await.expect("the unbind runs"));
    assert_eq!(
        client
            .health()
            .await
            .expect("a health report")
            .live_bindings,
        0
    );

    // The host accounts for what it is holding, the compiled cache included: "how many entries"
    // is not resource accounting, and section 5 asks for the shared service and its caches.
    let health = client.health().await.expect("a health report");
    assert!(
        health.resident_components > 0,
        "the cache holds nothing after a compile"
    );
    assert!(
        health.resident_bytes > 0,
        "the cache reports no bytes for the components it holds"
    );
    assert!(health.queued_notice_bytes <= 4 * 1024 * 1024);

    assert_eq!(
        client
            .health()
            .await
            .expect("a health report")
            .connection_bindings,
        0,
        "the binding's place was not given back"
    );

    // A second registration of the same component finds the artefact rather than compiling again.
    let again = client
        .register(
            new_binding_id(),
            &request.identity,
            &request.facts,
            &request.executable,
            &ComponentSource {
                path: path.clone(),
                digest,
                bytes,
            },
        )
        .await
        .expect("the binding registers");
    assert!(again.cached, "the second registration recompiled");
}

// KR-REQ-04.07, KR-REQ-11.40: the refusal a worker gets for a component that wants more than the
// sandbox offers names the import.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_40_a_component_with_ambient_imports_is_refused_by_name() {
    let Some(wasm) = components::component("ambient-import") else {
        return;
    };
    let served = Served::start().await;
    let client = served.client().await;
    let (path, digest, bytes) = served.install("ambient-import", &wasm);
    let request = components::request("ambient-import", 2);

    let error = client
        .register(
            request.binding_id,
            &request.identity,
            &request.facts,
            &request.executable,
            &ComponentSource {
                path: path.clone(),
                digest,
                bytes,
            },
        )
        .await
        .expect_err("a component with ambient imports is refused");
    let text = error.to_string();
    assert!(text.contains("wasi:"), "the refusal was {text}");
    assert_eq!(
        client
            .health()
            .await
            .expect("a health report")
            .live_bindings,
        0,
        "a refused component left a binding behind"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_component_outside_the_packages_directory_is_refused() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let served = Served::start().await;
    let client = served.client().await;
    // A real component, in a real file, in the wrong place.
    let elsewhere = served._temp.root().join("smuggled.wasm");
    std::fs::write(&elsewhere, &wasm[..]).expect("a file");
    let request = components::request("well-behaved", 3);

    let error = client
        .register(
            request.binding_id,
            &request.identity,
            &request.facts,
            &request.executable,
            &ComponentSource {
                path: elsewhere.display().to_string(),
                digest: PayloadDigest::of(&wasm),
                bytes: wasm.len() as u64,
            },
        )
        .await
        .expect_err("a path outside the packages directory is refused");
    assert!(
        error.to_string().contains("outside the packages directory"),
        "the refusal was {error}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_component_whose_bytes_are_not_what_the_worker_verified_is_refused() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let served = Served::start().await;
    let client = served.client().await;
    let (path, _digest, bytes) = served.install("well-behaved", &wasm);
    let request = components::request("well-behaved", 4);

    let error = client
        .register(
            request.binding_id,
            &request.identity,
            &request.facts,
            &request.executable,
            &ComponentSource {
                path: path.clone(),
                // The digest of something else entirely: what a tampered payload would fail
                // against.
                digest: PayloadDigest::of(b"a component the catalogue signed"),
                bytes,
            },
        )
        .await
        .expect_err("a payload that is not what the worker verified is refused");
    assert!(
        error
            .to_string()
            .contains("not the payload the caller verified"),
        "the refusal was {error}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_on_a_binding_nobody_registered_is_refused() {
    let served = Served::start().await;
    let client = served.client().await;
    let error = client
        .snapshot(new_binding_id(), core::time::Duration::from_millis(200))
        .await
        .expect_err("there is no such binding");
    assert!(error.to_string().contains("no binding"), "{error}");
    let _ = &served.host;
}

// KR-REQ-11.38: the queue's overflow is reported to the worker rather than hidden.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_38_a_worker_is_told_when_the_queue_overflowed() {
    // A component that reads slowly, as the claim is about one that does; what decides this is the
    // queue's bound, because the pass that would read the queue is held while it is filled.
    let Some(wasm) = components::component("slow-observe") else {
        return;
    };
    let served = Served::start().await;
    let client = served.client().await;
    let (path, digest, bytes) = served.install("slow-observe", &wasm);
    let request = components::request("slow-observe", 5);
    client
        .register(
            request.binding_id,
            &request.identity,
            &request.facts,
            &request.executable,
            &ComponentSource {
                path: path.clone(),
                digest,
                bytes,
            },
        )
        .await
        .expect("the binding registers");

    // The binding's pass over its queue is stopped before it takes anything, so that how fast the
    // component reads and how fast events are offered decide nothing: the first delivery wakes the
    // pass, the case waits until it stands, and the events after it are held by the queue alone.
    // Each event is 64 KiB, so sixty-five of them are already more than the 4 MiB the queue holds,
    // and the limit only ends a queue that never overflows.
    let mut stop = served
        .host
        .runtime()
        .stop_next_pump(request.binding_id)
        .expect("the binding is live");
    let filler = "z".repeat(64 * 1024);
    let first = client
        .deliver(request.binding_id, &components::scrape("se-0", &filler))
        .await
        .expect("the event is offered");
    assert!(
        !matches!(first, Admission::QueuedWithGap { .. }),
        "one observation of 64 KiB overflowed a 4 MiB queue"
    );
    assert!(
        tokio::time::timeout(core::time::Duration::from_secs(60), stop.reached())
            .await
            .expect("the binding's pass stands at the stop"),
        "the stop was replaced before a pass reached it"
    );
    let mut told = None;
    let mut seen: std::collections::BTreeMap<&'static str, u32> = std::collections::BTreeMap::new();
    for index in 1..=130 {
        let admission = client
            .deliver(
                request.binding_id,
                &components::scrape(&format!("se-{index}"), &filler),
            )
            .await
            .expect("the event is offered");
        *seen.entry(admission_name(&admission)).or_insert(0) += 1;
        if let Admission::QueuedWithGap { events, bytes } = admission {
            told = Some((events, bytes));
            break;
        }
    }
    stop.release();

    let (events, bytes) = told.unwrap_or_else(|| {
        panic!(
            "the worker was never told the observation queue overflowed; the admissions were {seen:?}"
        )
    });
    assert!(events > 0);
    assert!(bytes > 0);
}

// KR-REQ-05.07: a binding belongs to the connection that registered it, and to nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_binding_belongs_to_the_connection_that_registered_it() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let served = Served::start().await;
    let first = served.client().await;
    let second = served.client().await;
    let (path, digest, bytes) = served.install("well-behaved", &wasm);
    let request = components::request("well-behaved", 6);
    first
        .register(
            request.binding_id,
            &request.identity,
            &request.facts,
            &request.executable,
            &ComponentSource {
                path: path.clone(),
                digest,
                bytes,
            },
        )
        .await
        .expect("the binding registers");

    // The identifier is not a capability. Another connection that has it finds no binding, which
    // is the same answer it would get for one nobody ever registered.
    let error = second
        .snapshot(request.binding_id, core::time::Duration::from_millis(500))
        .await
        .expect_err("another connection cannot call this binding");
    assert!(
        error.to_string().contains("no binding"),
        "the refusal was {error}"
    );
    assert!(
        !second
            .unbind(request.binding_id)
            .await
            .expect("the unbind runs"),
        "another connection removed a binding that was not its own"
    );

    // And the owner still has it.
    let called = first
        .snapshot(request.binding_id, core::time::Duration::from_millis(500))
        .await
        .expect("the owner's call runs");
    assert!(called.answered());

    // A connection that ends takes its own bindings with it and leaves the host running.
    drop(first);
    let deadline = std::time::Instant::now() + core::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if second
            .health()
            .await
            .expect("a health report")
            .live_bindings
            == 0
        {
            break;
        }
        tokio::time::sleep(core::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        second
            .health()
            .await
            .expect("a health report")
            .live_bindings,
        0,
        "a connection that ended left its binding behind"
    );
}

/// How many observations are offered before the call and the observation that follow them.
const OFFERED_FIRST: usize = 64;

// KR-REQ-11.39: an observation and a call, offered together on one connection, are both answered.
//
// What this establishes. Sixty-four observations are offered, a call is made and an observation is
// delivered on the same connection, and each of those comes back. The observation comes back as
// one of the three admissions. The call comes back as an answer, as a fault, or as one of the two
// errors this case allows: the caller's own deadline, or a protocol error, which is what this
// client raises for a host that refused the call as well as for an answer it could not read. The
// handoff comes back without waiting. And the host's count of finished calls is higher at the
// second of two samples than at the first, so at least one call into the component completed
// between those two samples. The observation is answered between them too, which is why they are
// taken where they are.
//
// What this does not establish, and why it is written the way it is. It does not establish that a
// call was inside the component at the instant the observation's answer was produced, nor that the
// observation was taken into the queue rather than refused, nor that the call reached the
// component at all: a refusal and a caller's own deadline are both allowed here, and a count of
// calls that have finished fixes a completion somewhere between two samples rather than at any one
// answer taken between them. The first of those would need a component that says when a call has
// entered it and holds there until it is released, and the four interfaces in the SDK's package
// give a component nothing to wait on, so that handshake needs an import that does not yet exist.
//
// Three figures here are lengths of time: the call's own deadline, the watchdog on the loop that
// samples the count, and the handoff's limit at the end. The call's deadline expiring is one of
// the outcomes this case accepts, so it decides nothing. The watchdog does decide one thing: a
// host whose count never grows fails here rather than holding this test for ever. The handoff
// keeps the limit it already had.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_39_an_observation_and_a_call_on_one_connection_are_both_answered() {
    let Some(wasm) = components::component("slow-observe") else {
        return;
    };
    let served = Served::start().await;
    let client = Arc::new(served.client().await);
    let (path, digest, bytes) = served.install("slow-observe", &wasm);
    let request = components::request("slow-observe", 7);
    client
        .register(
            request.binding_id,
            &request.identity,
            &request.facts,
            &request.executable,
            &ComponentSource {
                path: path.clone(),
                digest,
                bytes,
            },
        )
        .await
        .expect("the binding registers");

    // Work for the component to be getting on with. Each observation is a call the host makes into
    // it, and the component spends a good part of an observation's deadline on every one.
    for index in 0..OFFERED_FIRST {
        let _queued = client.offer(
            request.binding_id,
            &components::scrape(&format!("se-q{index}"), "x"),
        );
    }

    // The first sample of the count of finished calls. A handoff writes no frame of its own, so
    // this report is not a barrier for the observations above and is not treated as one.
    let before = client
        .health()
        .await
        .expect("a health report")
        .component_calls;

    // A call a caller can see, made on the same connection. Which request the host read first is
    // not asserted: a spawned task says nothing about that.
    let calling = tokio::spawn({
        let client = Arc::clone(&client);
        let binding_id = request.binding_id;
        async move {
            client
                .snapshot(binding_id, core::time::Duration::from_millis(100))
                .await
        }
    });

    // The observation, which comes back with one of the admissions the host has for an event
    // rather than with a failure or not at all.
    let admission = client
        .deliver(request.binding_id, &components::scrape("se-1", "x"))
        .await
        .expect("the event comes back with an admission");
    assert!(
        matches!(
            admission,
            Admission::Queued | Admission::QueuedWithGap { .. } | Admission::Refused { .. }
        ),
        "the event was {admission:?}"
    );

    // The second sample of the count, asked for until it is higher than the first. That is one
    // call into the component completed somewhere between the two samples; which call, and where
    // between them, is not something the count says, and it may as easily be after the observation
    // was answered as before. Asking again costs nothing and is bounded only so that a host which
    // has stopped answering says so instead of holding this test for ever.
    let watchdog = std::time::Instant::now();
    loop {
        let after = client
            .health()
            .await
            .expect("a health report")
            .component_calls;
        if after > before {
            break;
        }
        assert!(
            watchdog.elapsed() < core::time::Duration::from_secs(60),
            "the component completed no call between the two samples of the count"
        );
        tokio::task::yield_now().await;
    }

    let outcome = calling.await.expect("the call finished");
    // The call came back, and as one of the outcomes this case allows: an answer, a fault, the
    // caller's own deadline, or a protocol error. That last one is wider than its name: this
    // client raises it both for an answer it could not read and for a host that refused the call
    // outright, so a refusal passes here too.
    match outcome {
        Ok(called) => assert!(
            called.answered() || called.fault.is_some(),
            "the snapshot returned neither an answer nor a fault"
        ),
        Err(error) => assert!(
            matches!(
                error,
                ServiceError::CallerDeadline { .. } | ServiceError::Protocol { .. }
            ),
            "the snapshot came back as none of the outcomes this case allows: {error}"
        ),
    }

    // And the handoff that never waits at all does not even write a frame.
    let offered = std::time::Instant::now();
    let handoff = client.offer(request.binding_id, &components::scrape("se-2", "y"));
    let waited = offered.elapsed();
    assert!(
        matches!(
            handoff,
            kr_plugin_service::client::Handoff::Accepted
                | kr_plugin_service::client::Handoff::Refused { .. }
        ),
        "the handoff was {handoff:?}"
    );
    assert!(
        waited < core::time::Duration::from_millis(20),
        "handing an event over took {waited:?}"
    );

    // Health, too: nothing about this connection is behind the component.
    let health = client.health().await.expect("a health report");
    assert_eq!(health.connection_bindings, 1);
    assert_eq!(health.binding_bound, 64);
}

// An event larger than a frame is refused at the handoff rather than stopping every later one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_event_no_frame_could_carry_is_refused_at_the_handoff() {
    let served = Served::start().await;
    let client = served.client().await;
    let binding_id = new_binding_id();

    let enormous = "x".repeat(2 * 1024 * 1024);
    let handoff = client.offer(binding_id, &components::scrape("se-big", &enormous));
    assert!(
        matches!(handoff, kr_plugin_service::client::Handoff::TooLarge { .. }),
        "the handoff was {handoff:?}"
    );

    // And the connection still works: one event nothing could deliver did not take the rest with
    // it.
    assert_eq!(client.offered_bytes(), 0);
    let health = client.health().await.expect("a health report");
    assert_eq!(health.live_bindings, 0);
}

// KR-REQ-05.07: a client whose host is gone is told at once rather than waiting out its deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_whose_connection_failed_is_told_without_waiting() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let identity = HostIdentity::generate(temp.environment_id()).expect("an identity");
    let endpoint = host_endpoint(&environment, &HostProtocol::THIS).expect("an endpoint");
    let descriptor = HostDescriptor {
        protocol: HostProtocol::THIS.name.to_owned(),
        environment_id: temp.environment_id(),
        reservation_id: kr_protocol::worker::ReservationId::new(kr_ipc::new_uuid()),
        endpoint: endpoint.as_text(),
        boot_identity: identity.boot_identity().clone(),
        process_start_identity: identity.process_start_identity().clone(),
        host_public_key: *identity.public_key(),
    };
    let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("a listener");

    // A host that completes the handshake and then goes. Its connection closing is what every
    // caller waiting on it is told by, at once, rather than each waiting out its own deadline.
    let serving = tokio::spawn({
        let descriptor = descriptor.clone();
        async move {
            let (connection, _peer) = listener.accept().await.expect("a connection");
            let (mut reader, mut writer) =
                kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
            for _ in 0..2 {
                let request: kr_plugin_service::protocol::Request = reader
                    .read_message_without_schema()
                    .await
                    .expect("a request");
                let body = match request.body {
                    RequestBody::Hello { .. } => ResponseBody::Hello {
                        protocol: HostProtocol::THIS.name.to_owned(),
                        descriptor: Box::new(descriptor.clone()),
                    },
                    RequestBody::Verify { nonce } => ResponseBody::Verified(Box::new(
                        identity
                            .answer(&nonce, &descriptor.endpoint)
                            .expect("an answer"),
                    )),
                    other => panic!("the client asked for {other:?}"),
                };
                writer
                    .write_message(&Frame::Response {
                        reply_to: request.request_id,
                        body,
                    })
                    .await
                    .expect("the answer is written");
            }
            // And then it is gone, the way a plugin host that crashed is gone.
        }
    });

    let connection = kr_ipc::endpoint::Connection::connect(&endpoint)
        .await
        .expect("connects");
    let client = PluginClient::over(connection, descriptor)
        .await
        .expect("the handshake and the challenge");
    serving.await.expect("the host finished");

    let asked = std::time::Instant::now();
    let error = client
        .health()
        .await
        .expect_err("a host that is gone cannot report itself");
    let waited = asked.elapsed();
    assert!(
        matches!(error, ServiceError::Unavailable { .. }),
        "the failure was {error}"
    );
    assert!(
        waited < core::time::Duration::from_secs(2),
        "the client waited {waited:?} for a connection that had failed"
    );

    // And a call made afterwards is refused at once too, rather than being written to a socket
    // nobody is reading.
    let asked = std::time::Instant::now();
    let error = client
        .unbind(new_binding_id())
        .await
        .expect_err("the connection is gone");
    assert!(matches!(error, ServiceError::Unavailable { .. }));
    assert!(asked.elapsed() < core::time::Duration::from_millis(500));
}

// KR-REQ-11.38: an event the client was handed is counted until it has been written. A caller that
// asks for a snapshot once the count is zero, which is what the worker's pump does, so has it
// written after every event it handed over. The host here only reads and records, because what
// the case is about is the order the client writes in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_38_an_event_handed_over_is_counted_until_it_is_written_and_a_snapshot_asked_for_then_follows_it()
 {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let identity = HostIdentity::generate(temp.environment_id()).expect("an identity");
    let endpoint = host_endpoint(&environment, &HostProtocol::THIS).expect("an endpoint");
    let descriptor = HostDescriptor {
        protocol: HostProtocol::THIS.name.to_owned(),
        environment_id: temp.environment_id(),
        reservation_id: kr_protocol::worker::ReservationId::new(kr_ipc::new_uuid()),
        endpoint: endpoint.as_text(),
        boot_identity: identity.boot_identity().clone(),
        process_start_identity: identity.process_start_identity().clone(),
        host_public_key: *identity.public_key(),
    };
    let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("a listener");

    // What the host reads after the handshake, in the order it reads it. A snapshot is answered, so
    // that the client's call comes back.
    let read = Arc::new(std::sync::Mutex::new(Vec::<&'static str>::new()));
    let serving = tokio::spawn({
        let descriptor = descriptor.clone();
        let read = Arc::clone(&read);
        async move {
            let (connection, _peer) = listener.accept().await.expect("a connection");
            let (mut reader, mut writer) =
                kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
            while let Ok(request) = reader
                .read_message_without_schema::<kr_plugin_service::protocol::Request>()
                .await
            {
                let body = match request.body {
                    RequestBody::Hello { .. } => ResponseBody::Hello {
                        protocol: kr_protocol::retained::PLUGIN_HOST_PROTOCOL.to_owned(),
                        descriptor: Box::new(descriptor.clone()),
                    },
                    RequestBody::Verify { nonce } => ResponseBody::Verified(Box::new(
                        identity
                            .answer(&nonce, &descriptor.endpoint)
                            .expect("an answer"),
                    )),
                    RequestBody::Event { .. } => {
                        read.lock().expect("the record").push("event");
                        continue;
                    }
                    RequestBody::Snapshot { .. } => {
                        read.lock().expect("the record").push("snapshot");
                        ResponseBody::Called {
                            value: None,
                            fault: None,
                            document: None,
                        }
                    }
                    other => panic!("the client asked for {other:?}"),
                };
                writer
                    .write_message(&Frame::Response {
                        reply_to: request.request_id,
                        body,
                    })
                    .await
                    .expect("the answer is written");
            }
        }
    });

    let connection = kr_ipc::endpoint::Connection::connect(&endpoint)
        .await
        .expect("connects");
    let client = PluginClient::over(connection, descriptor)
        .await
        .expect("the handshake and the challenge");
    let binding_id = new_binding_id();

    // The writer is held with an event in hand: taken off the queue, not yet written.
    let hold = client.hold_offered_writes();
    let handed = client.offer(binding_id, &components::scrape("se-1", "first"));
    assert_eq!(handed, kr_plugin_service::client::Handoff::Accepted);
    let watchdog = std::time::Instant::now();
    while !hold.parked() {
        assert!(
            watchdog.elapsed() < core::time::Duration::from_secs(60),
            "the writer never took the event off the queue"
        );
        tokio::task::yield_now().await;
    }
    assert_ne!(
        client.offered_bytes(),
        0,
        "an event that has not been written is not counted, so a count of zero does not mean the \
         events handed over are written"
    );

    // Written: the count falls to zero, and a snapshot asked for then is written after the event.
    hold.release();
    while client.offered_bytes() != 0 {
        assert!(
            watchdog.elapsed() < core::time::Duration::from_secs(60),
            "the event was never written"
        );
        tokio::task::yield_now().await;
    }
    client
        .snapshot(binding_id, core::time::Duration::from_secs(5))
        .await
        .expect("the snapshot is answered");
    assert_eq!(
        *read.lock().expect("the record"),
        ["event", "snapshot"],
        "the host read the snapshot before the event it was handed first"
    );
    drop(client);
    serving.await.expect("the host finished");
}

fn admission_name(admission: &Admission) -> &'static str {
    match admission {
        Admission::Queued => "queued",
        Admission::QueuedWithGap { .. } => "queued_with_gap",
        Admission::Refused { .. } => "refused",
    }
}

/// The token a worker presents to a component for one invocation, and its arguments.
fn invocation(action: &str) -> kr_plugin_service::protocol::WireToken {
    kr_plugin_service::protocol::WireToken {
        actor_id: "local:501".to_owned(),
        grant_id: String::new(),
        binding_revision: 3,
        thread_revision: None,
        action_id: action.to_owned(),
        parameter_hash: vec![7; 32],
        expires_at_ms: 1_700_000_005_000,
    }
}

/// Registers the component that prepares actions, and returns the client and the binding.
async fn preparing(
    served: &Served,
) -> Option<(PluginClient, kr_plugin_service::vocabulary::BindingId)> {
    let wasm = components::component("preparing")?;
    let client = served.client().await;
    let (path, digest, bytes) = served.install("preparing", &wasm);
    let request = components::request("preparing", 5);
    client
        .register(
            request.binding_id,
            &request.identity,
            &request.facts,
            &request.executable,
            &ComponentSource {
                path,
                digest,
                bytes,
            },
        )
        .await
        .expect("the binding registers");
    Some((client, request.binding_id))
}

// A component's plan travels back as the plain data it is, whatever it proposes: the plan it was
// invited to prepare, and each way of proposing something else. The host does not judge any of
// them; the worker compares them with the invocation and the declaration.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_asks_the_component_to_prepare_an_action_and_is_given_its_plan_as_proposed() {
    use kr_plugin_sdk::effect::EffectClass;
    use kr_plugin_service::protocol::{WireArgument, WireNamedArgument, WireOperation};

    let served = Served::start().await;
    let Some((client, binding_id)) = preparing(&served).await else {
        return;
    };
    let given = vec![WireNamedArgument {
        name: "reason".to_owned(),
        value: WireArgument::Text("because".to_owned()),
    }];
    let deadline = core::time::Duration::from_millis(500);

    // The plan the action is invited to prepare comes back as it was proposed.
    let called = client
        .prepare_action(
            binding_id,
            invocation("turn.cancel"),
            given.clone(),
            deadline,
        )
        .await
        .expect("the call runs");
    let plan = called.plan.expect("the component answered with a plan");
    assert_eq!(plan.action_id, "turn.cancel");
    assert_eq!(plan.class, EffectClass::UpstreamCancel);
    assert_eq!(plan.operation, WireOperation::UpstreamCancel);
    assert_eq!(plan.arguments, given);

    // A plan for another action, one that fills in a field and one that names another method are
    // each returned as proposed, so the worker can see what was proposed and refuse it by name.
    let other = client
        .prepare_action(
            binding_id,
            invocation("cancel.other.action"),
            given.clone(),
            deadline,
        )
        .await
        .expect("the call runs")
        .plan
        .expect("a plan");
    assert_eq!(other.action_id, "turn.cancel");
    let fields = client
        .prepare_action(
            binding_id,
            invocation("prompt.with.fields"),
            given.clone(),
            deadline,
        )
        .await
        .expect("the call runs")
        .plan
        .expect("a plan");
    let WireOperation::UpstreamMethod { fields, .. } = fields.operation else {
        panic!("the operation was not a routed method");
    };
    assert_eq!(fields.len(), 1);
    let altered = client
        .prepare_action(
            binding_id,
            invocation("cancel.other.arguments"),
            given.clone(),
            deadline,
        )
        .await
        .expect("the call runs")
        .plan
        .expect("a plan");
    assert_ne!(altered.arguments, given);

    // A fault the component declares is an answer: no plan, and what it said.
    let declined = client
        .prepare_action(
            binding_id,
            invocation("cancel.fault"),
            given.clone(),
            deadline,
        )
        .await
        .expect("the call runs");
    assert!(declined.plan.is_none());
    assert!(
        declined
            .fault
            .is_some_and(|fault| fault.contains("not something to do"))
    );
}

// A component that never returns costs its own call and nothing else: the call ends at the
// component's deadline, the host refuses it by name, and the connection serves the next call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_component_that_never_prepares_its_action_costs_its_call_and_not_the_connection() {
    let served = Served::start().await;
    let Some((client, binding_id)) = preparing(&served).await else {
        return;
    };
    let deadline = core::time::Duration::from_millis(500);
    let stuck = client
        .prepare_action(binding_id, invocation("cancel.loop"), Vec::new(), deadline)
        .await
        .expect_err("a call that used its whole allowance is refused by the host");
    assert!(
        matches!(&stuck, ServiceError::Protocol { detail } if detail.contains("prepare-action")),
        "{stuck}"
    );
    let next = client
        .prepare_action(binding_id, invocation("turn.cancel"), Vec::new(), deadline)
        .await
        .expect("the host answers the next call")
        .plan;
    assert!(next.is_some(), "and the binding still prepares");
}

// A plugin runtime of the protocol before this one is refused at the handshake, by name, and is
// sent nothing it would end the connection over: the earlier protocol has no request that prepares
// an action.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_plugin_runtime_of_an_earlier_protocol_is_refused_at_the_handshake() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let identity = HostIdentity::generate(temp.environment_id()).expect("an identity");
    let endpoint = host_endpoint(&environment, &HostProtocol::THIS).expect("an endpoint");
    let mut descriptor = HostDescriptor {
        protocol: HostProtocol::THIS.name.to_owned(),
        environment_id: temp.environment_id(),
        reservation_id: kr_protocol::worker::ReservationId::new(kr_ipc::new_uuid()),
        endpoint: endpoint.as_text(),
        boot_identity: identity.boot_identity().clone(),
        process_start_identity: identity.process_start_identity().clone(),
        host_public_key: *identity.public_key(),
    };
    let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("a listener");
    // A host of an earlier build, which answers the handshake with the protocol it speaks and reads
    // whatever else it is sent, recording it.
    descriptor.protocol = "kr-plugin-host/1".to_owned();
    let received = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let serving = tokio::spawn({
        let descriptor = descriptor.clone();
        let received = Arc::clone(&received);
        async move {
            let (connection, _peer) = listener.accept().await.expect("a connection");
            let (mut reader, mut writer) =
                kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
            while let Ok(request) = reader
                .read_message_without_schema::<kr_plugin_service::protocol::Request>()
                .await
            {
                let body = match request.body {
                    RequestBody::Hello { .. } => ResponseBody::Hello {
                        protocol: descriptor.protocol.clone(),
                        descriptor: Box::new(descriptor.clone()),
                    },
                    other => {
                        received
                            .lock()
                            .expect("not poisoned")
                            .push(other.name().to_owned());
                        return;
                    }
                };
                writer
                    .write_message(&Frame::Response {
                        reply_to: request.request_id,
                        body,
                    })
                    .await
                    .expect("the answer is written");
            }
        }
    });
    let connection = kr_ipc::endpoint::Connection::connect(&endpoint)
        .await
        .expect("connects");
    let Err(refused) = PluginClient::over(connection, descriptor).await else {
        panic!("a runtime of another protocol was taken for one to call");
    };
    assert!(
        matches!(&refused, ServiceError::Protocol { detail } if detail.contains("kr-plugin-host/1")),
        "{refused}"
    );
    serving.abort();
    assert!(
        received.lock().expect("not poisoned").is_empty(),
        "the earlier host was sent {:?}",
        received.lock().expect("not poisoned")
    );
}

/// Registers a component by name and returns the client and the binding.
async fn registered(
    served: &Served,
    name: &str,
    seed: u8,
) -> Option<(PluginClient, kr_plugin_service::vocabulary::BindingId)> {
    let wasm = components::component(name)?;
    let client = served.client().await;
    let (path, digest, bytes) = served.install(name, &wasm);
    let request = components::request(name, seed);
    client
        .register(
            request.binding_id,
            &request.identity,
            &request.facts,
            &request.executable,
            &ComponentSource {
                path,
                digest,
                bytes,
            },
        )
        .await
        .expect("the binding registers");
    Some((client, request.binding_id))
}

/// The broker's record of a pending request, as the plugin contract reads it.
fn pending_request(
    request_id: &str,
    method: &str,
) -> kr_plugin_service::protocol::WireRequestSnapshot {
    kr_plugin_service::protocol::WireRequestSnapshot {
        request_id: request_id.to_owned(),
        handle: kr_protocol::ids::SourceEventHandle::new("se-1").expect("a bounded handle"),
        method: method.to_owned(),
        class: kr_plugin_service::protocol::WireMethodClass::Mutation,
        received_at_ms: 1_700_000_000_002,
        deadline_at_ms: None,
        offered_decisions: vec!["allow".to_owned(), "deny".to_owned()],
        binding_revision: 3,
    }
}

/// What a component says it holds, read from its checkpoint.
async fn account_of(
    client: &PluginClient,
    binding_id: kr_plugin_service::vocabulary::BindingId,
) -> String {
    let state = client
        .checkpoint(binding_id, core::time::Duration::from_millis(500))
        .await
        .expect("the checkpoint runs")
        .state
        .expect("the component has state");
    String::from_utf8(state).expect("the account is text")
}

// KR-REQ-06.07: a request is decoded from the bytes and the provenance the broker retained it
// with, and what a scrape or an identifier-less event looks like is refused by the host before any
// component runs. The same binding decodes the request first, so a host that refused every decode
// would not pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_06_07_a_native_request_is_decoded_and_a_scrape_or_an_unnamed_request_is_refused_before_a_component_runs()
 {
    let served = Served::start().await;
    let Some((client, binding_id)) = registered(&served, "hostile-decoder", 11).await else {
        return;
    };
    let deadline = core::time::Duration::from_millis(500);

    let request = components::native_request("se-1", "7", "a request to write");
    let called = client
        .decode(binding_id, &request, deadline)
        .await
        .expect("a native request is decoded");
    let decoded = called.decoded.expect("the component's proposal came back");
    assert_eq!(decoded.request_id, "7");
    assert_eq!(decoded.decisions, ["allow", "deny"]);
    assert!(!decoded.summary.is_empty());
    assert_eq!(decoded.presentation.len(), 1);
    let account = account_of(&client, binding_id).await;
    assert!(
        account.contains("decode=1;") && account.contains("native_protocol/7/18/"),
        "the component was given {account}"
    );

    // A terminal scrape that looks exactly like a request is not one.
    let scrape = components::scrape("se-2", "a request to write");
    let refused = client
        .decode(binding_id, &scrape, deadline)
        .await
        .expect_err("a scrape is not a request");
    assert!(
        matches!(&refused, ServiceError::Protocol { detail } if detail.contains("scrape")),
        "{refused}"
    );
    // A native event with no identifier names nothing to answer.
    let unnamed = kr_plugin_service::vocabulary::ScopedSourceEvent::new(
        kr_protocol::ids::SourceEventHandle::new("se-3").expect("a bounded handle"),
        kr_plugin_service::vocabulary::SourceProvenance::NativeProtocol,
        1_700_000_000_003,
        None,
        b"a notification".to_vec(),
    );
    let refused = client
        .decode(binding_id, &unnamed, deadline)
        .await
        .expect_err("an event with no identifier is not a request");
    assert!(
        matches!(&refused, ServiceError::Protocol { detail } if detail.contains("identifier")),
        "{refused}"
    );
    // An identifier longer than the broker records one is not a request's.
    let unbounded = kr_plugin_service::vocabulary::ScopedSourceEvent::new(
        kr_protocol::ids::SourceEventHandle::new("se-4").expect("a bounded handle"),
        kr_plugin_service::vocabulary::SourceProvenance::NativeProtocol,
        1_700_000_000_004,
        Some("9".repeat(kr_plugin_service::vocabulary::MAX_REQUEST_ID_BYTES + 1)),
        b"a request".to_vec(),
    );
    let refused = client
        .decode(binding_id, &unbounded, deadline)
        .await
        .expect_err("an identifier past its bound is not a request's");
    assert!(
        matches!(&refused, ServiceError::Protocol { detail } if detail.contains("identifier")),
        "{refused}"
    );
    // None reached the component.
    assert!(
        account_of(&client, binding_id).await.contains("decode=1;"),
        "a component was asked to decode what the host refused"
    );
}

// KR-REQ-11.21: an encode returns the bytes of a response for an offered decision and has nowhere
// to send them. What the host can see is wrong with the question is refused before the component
// runs, and what it cannot see until the answer is back is refused when it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_21_an_encode_returns_bytes_for_an_offered_decision_and_what_is_wrong_is_refused()
{
    let served = Served::start().await;
    let Some((client, binding_id)) = registered(&served, "hostile-decoder", 12).await else {
        return;
    };
    let deadline = core::time::Duration::from_millis(500);
    let source = components::native_request("se-1", "7", "a request to write");

    let called = client
        .encode(
            binding_id,
            pending_request("7", "session/request_permission"),
            "allow",
            Some(&source),
            deadline,
        )
        .await
        .expect("an offered decision is encoded");
    let encoded = called.encoded.expect("the component's bytes came back");
    assert_eq!(encoded.request_id, "7");
    assert_eq!(encoded.bytes, br#"{"id":"7","result":"allow"}"#);

    // An identifier the upstream gave as a string of 255 characters is 257 bytes in the form the
    // broker records it in, quotes included, and is a request like any other.
    let long = format!("\"{}\"", "a".repeat(255));
    let called = client
        .encode(
            binding_id,
            pending_request(&long, "session/request_permission"),
            "allow",
            None,
            deadline,
        )
        .await
        .expect("a long identifier is encoded");
    assert_eq!(called.encoded.expect("bytes").request_id, long);

    // A decision the request does not offer, an event that is not the request's, and an event of
    // another request: refused by the host, so the component is not asked.
    for (name, request, decision, event) in [
        (
            "unoffered",
            pending_request("7", "session/request_permission"),
            "reboot",
            Some(&source),
        ),
        (
            "another source",
            pending_request("8", "session/request_permission"),
            "allow",
            Some(&source),
        ),
    ] {
        let refused = client
            .encode(binding_id, request, decision, event, deadline)
            .await
            .expect_err(name);
        assert!(
            matches!(&refused, ServiceError::Protocol { .. }),
            "{name}: {refused}"
        );
    }
    // A component that answers another request than the one it was asked about is refused when it
    // does, after it ran.
    let refused = client
        .encode(
            binding_id,
            pending_request("7", "!other-request"),
            "allow",
            None,
            deadline,
        )
        .await
        .expect_err("another request's answer is not this request's");
    assert!(
        matches!(&refused, ServiceError::Protocol { detail } if detail.contains("another request")),
        "{refused}"
    );
    let account = account_of(&client, binding_id).await;
    assert!(
        account.contains("encode=3;"),
        "the component ran {account}: for the two answers and for the one the host refused after"
    );
}

// KR-REQ-11.38, KR-REQ-11.40: a decode and an encode that never return are stopped by their
// bounds, each counts as a fault, and the third in a minute disables the binding: the host then
// refuses a decode and an event as a disabled binding's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_38_a_decode_and_an_encode_that_never_return_are_stopped_and_the_third_fault_disables_the_binding()
 {
    let served = Served::start().await;
    let Some((client, binding_id)) = registered(&served, "hostile-decoder", 13).await else {
        return;
    };
    let deadline = core::time::Duration::from_millis(500);
    let spinning = components::native_request("se-1", "7", "!spin");

    for _ in 0..2 {
        let stopped = client
            .decode(binding_id, &spinning, deadline)
            .await
            .expect_err("a decode that never returns is refused by the host");
        assert!(
            matches!(&stopped, ServiceError::Protocol { detail } if detail.contains("decode-request")),
            "{stopped}"
        );
    }
    let stopped = client
        .encode(
            binding_id,
            pending_request("7", "!spin"),
            "allow",
            None,
            deadline,
        )
        .await
        .expect_err("an encode that never returns is refused by the host");
    assert!(
        matches!(&stopped, ServiceError::Protocol { detail } if detail.contains("encode-response")),
        "{stopped}"
    );

    let honest = components::native_request("se-2", "8", "a request to write");
    let disabled = client
        .decode(binding_id, &honest, deadline)
        .await
        .expect_err("the third fault disabled the binding");
    assert!(
        matches!(&disabled, ServiceError::Disabled { .. }),
        "{disabled}"
    );
    // What an offered event is told is the same, so a worker stops offering it.
    let offered = client
        .deliver(binding_id, &components::scrape("se-3", "building"))
        .await
        .expect_err("a disabled binding takes no events");
    assert!(
        matches!(&offered, ServiceError::Disabled { .. }),
        "{offered}"
    );
    let watchdog = std::time::Instant::now();
    loop {
        assert!(
            watchdog.elapsed() < core::time::Duration::from_secs(30),
            "the host never said the binding was disabled"
        );
        if let Some(Notice::Disabled {
            binding_id: told, ..
        }) = client.notice().await
        {
            assert_eq!(told, binding_id.get());
            break;
        }
    }
}

// KR-REQ-24.27: once the host has acknowledged that privacy mode stands, no document of the
// connection is written, though one was taken off the queue before and is held at the writer when
// the acknowledgement is made; and when privacy mode ends the reader is told that documents were
// lost, so it expects a fresh one, which the component is asked to draw.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_27_no_document_is_written_after_privacy_mode_is_acknowledged_and_a_fresh_one_follows_its_end()
 {
    let served = Served::start().await;
    let Some((client, binding_id)) = registered(&served, "hostile-decoder", 14).await else {
        return;
    };
    let deadline = core::time::Duration::from_millis(500);

    // A document taken off the queue and held at the writer.
    let hold = served.host.hold_notice_writes();
    let first = client
        .snapshot(binding_id, deadline)
        .await
        .expect("the snapshot runs");
    assert_eq!(first.document, Some(1));
    let watchdog = std::time::Instant::now();
    while !hold.parked() {
        assert!(
            watchdog.elapsed() < core::time::Duration::from_secs(60),
            "the writer never took the document off the queue"
        );
        tokio::task::yield_now().await;
    }
    client
        .privacy(true)
        .await
        .expect("privacy mode is acknowledged");
    hold.release();

    // A fault is a notice that is not a document, and it is written after the document the writer
    // held: reading it says the writer is past that document, and nothing it wrote in between
    // may be one.
    client
        .decode(
            binding_id,
            &components::native_request("se-2", "8", "!trap"),
            deadline,
        )
        .await
        .expect_err("a decode that traps is refused");
    loop {
        assert!(
            watchdog.elapsed() < core::time::Duration::from_secs(60),
            "the fault was never written"
        );
        match client.notice().await.expect("the connection is open") {
            Notice::Document { document, .. } => {
                panic!("document {document} was written after privacy mode was acknowledged")
            }
            Notice::Fault { .. } => break,
            Notice::Gap { .. } | Notice::Disabled { .. } => {}
        }
    }

    // Privacy mode ends: the reader is told documents were lost, and a fresh one follows.
    client
        .privacy(false)
        .await
        .expect("the end is acknowledged");
    let mut lost = false;
    loop {
        assert!(
            watchdog.elapsed() < core::time::Duration::from_secs(60),
            "no fresh document followed the end of privacy mode"
        );
        match client.notice().await.expect("the connection is open") {
            Notice::Gap { documents, .. } if documents > 0 => lost = true,
            Notice::Document { document, last, .. } => {
                assert!(
                    lost,
                    "a document arrived before the reader was told some were lost"
                );
                assert_ne!(document, 1, "the document held at the writer was written");
                if last {
                    break;
                }
            }
            Notice::Gap { .. } | Notice::Fault { .. } | Notice::Disabled { .. } => {}
        }
    }
}

// KR-REQ-24.27: a decoded request's presentation is a document too, and is not sent while privacy
// mode stands. What the worker uses of it, the summary and the decisions, is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_27_a_decoded_request_carries_no_presentation_while_privacy_mode_stands() {
    let served = Served::start().await;
    let Some((client, binding_id)) = registered(&served, "hostile-decoder", 15).await else {
        return;
    };
    let deadline = core::time::Duration::from_millis(500);
    let request = components::native_request("se-1", "7", "a request to write");

    client
        .privacy(true)
        .await
        .expect("privacy mode is acknowledged");
    let private = client
        .decode(binding_id, &request, deadline)
        .await
        .expect("a request is decoded in privacy mode")
        .decoded
        .expect("the proposal came back");
    assert!(private.presentation.is_empty());
    assert!(!private.summary.is_empty());
    assert_eq!(private.decisions, ["allow", "deny"]);

    client
        .privacy(false)
        .await
        .expect("the end is acknowledged");
    let open = client
        .decode(binding_id, &request, deadline)
        .await
        .expect("a request is decoded")
        .decoded
        .expect("the proposal came back");
    assert_eq!(open.presentation.len(), 1);
}

// What a worker tells a binding's component about its execution and its draft is what the component
// reads in its next call, however many revisions came before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revision_of_a_bindings_facts_and_attachments_is_what_its_component_reads_next() {
    let served = Served::start().await;
    let Some((client, binding_id)) = registered(&served, "recording", 16).await else {
        return;
    };
    let before = account_of(&client, binding_id).await;
    assert!(
        before.contains("facts=3/running/thread-1/turn-1/"),
        "the component was registered with {before}"
    );

    let mut facts = components::facts("recording");
    facts.binding_revision = 9;
    facts.activity = kr_plugin_service::vocabulary::BindingActivity::AwaitingPerson;
    facts.thread_id = Some("thread-9".to_owned());
    facts.turn_id = None;
    facts.held_rights = Vec::new();
    client
        .revise_facts(binding_id, &facts)
        .await
        .expect("the facts are accepted");
    client
        .revise_attachments(
            binding_id,
            &[
                kr_plugin_service::vocabulary::AttachmentFact {
                    attachment_id: "att-1".to_owned(),
                    name: "a picture".to_owned(),
                    media_type: "image/png".to_owned(),
                    size_bytes: 1024,
                    completed_at_ms: 1_700_000_000_100,
                },
                kr_plugin_service::vocabulary::AttachmentFact {
                    attachment_id: "att-2".to_owned(),
                    name: "notes".to_owned(),
                    media_type: "text/plain".to_owned(),
                    size_bytes: 5,
                    completed_at_ms: 1_700_000_000_200,
                },
            ],
        )
        .await
        .expect("the attachments are accepted");
    let after = account_of(&client, binding_id).await;
    assert!(
        after.contains("facts=9/awaiting_person/thread-9/-/;attachments=att-1:image/png:1024|att-2:text/plain:5"),
        "the component reads {after}"
    );
}

// What a worker may ask is bounded, and what is refused for being beyond a bound costs nothing: the
// binding goes on, and nothing reached its component.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revision_or_a_call_beyond_its_bounds_is_refused_and_the_binding_goes_on() {
    let served = Served::start().await;
    let Some((client, binding_id)) = registered(&served, "hostile-decoder", 17).await else {
        return;
    };
    let request = components::native_request("se-1", "7", "a request to write");

    // A deadline of nothing or of half a minute and more is not a deadline.
    for deadline in [
        core::time::Duration::from_millis(0),
        core::time::Duration::from_secs(31),
    ] {
        let refused = client
            .decode(binding_id, &request, deadline)
            .await
            .expect_err("a call's deadline is bounded");
        assert!(
            matches!(&refused, ServiceError::Protocol { detail } if detail.contains("deadline")),
            "{refused}"
        );
    }
    // Facts of another plugin, and facts longer than a fact is.
    let mut facts = components::facts("hostile-decoder");
    facts.plugin_id = "kalareach/another".to_owned();
    let refused = client
        .revise_facts(binding_id, &facts)
        .await
        .expect_err("a binding serves one plugin");
    assert!(
        matches!(&refused, ServiceError::Protocol { .. }),
        "{refused}"
    );
    let mut facts = components::facts("hostile-decoder");
    facts.thread_id = Some("t".repeat(2_000));
    let refused = client
        .revise_facts(binding_id, &facts)
        .await
        .expect_err("a fact is bounded");
    assert!(
        matches!(&refused, ServiceError::Protocol { .. }),
        "{refused}"
    );
    // More attachments than a draft holds.
    let many: Vec<kr_plugin_service::vocabulary::AttachmentFact> = (0..65)
        .map(|number| kr_plugin_service::vocabulary::AttachmentFact {
            attachment_id: format!("att-{number}"),
            name: "n".to_owned(),
            media_type: "text/plain".to_owned(),
            size_bytes: 1,
            completed_at_ms: 1,
        })
        .collect();
    let refused = client
        .revise_attachments(binding_id, &many)
        .await
        .expect_err("a draft's attachments are bounded");
    assert!(
        matches!(&refused, ServiceError::Protocol { .. }),
        "{refused}"
    );
    // A request no frame could carry is refused by the client, which writes nothing, and the
    // connection is the same one afterwards.
    let huge = kr_plugin_service::vocabulary::ScopedSourceEvent::new(
        kr_protocol::ids::SourceEventHandle::new("se-4").expect("a bounded handle"),
        kr_plugin_service::vocabulary::SourceProvenance::NativeProtocol,
        1_700_000_000_004,
        Some("9".to_owned()),
        vec![b'x'; 1_100_000],
    );
    let refused = client
        .decode(binding_id, &huge, core::time::Duration::from_millis(500))
        .await
        .expect_err("a request larger than a frame is refused");
    assert!(
        matches!(&refused, ServiceError::Protocol { detail } if detail.contains("frame")),
        "{refused}"
    );
    let mut huge_facts = components::facts("hostile-decoder");
    huge_facts.thread_id = Some("t".repeat(1_100_000));
    let refused = client
        .revise_facts(binding_id, &huge_facts)
        .await
        .expect_err("facts larger than a frame are refused");
    assert!(
        matches!(&refused, ServiceError::Protocol { detail } if detail.contains("frame")),
        "{refused}"
    );
    // None of it reached the component, and the binding decodes.
    assert!(account_of(&client, binding_id).await.contains("decode=0;"));
    client
        .decode(binding_id, &request, core::time::Duration::from_millis(500))
        .await
        .expect("the binding goes on");
}
