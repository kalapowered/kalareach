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

use kr_plugin_runtime::RuntimeError;
use kr_plugin_runtime::runtime::queue::Admission;
use kr_plugin_runtime::service::client::{PluginClient, new_binding_id};
use kr_plugin_runtime::service::host::{HostConfig, PluginHost};
use kr_plugin_runtime::service::launcher::{HostIdentity, host_endpoint};
use kr_plugin_runtime::service::protocol::{
    ComponentSource, Frame, HostDescriptor, Notice, PROTOCOL, RequestBody, ResponseBody,
};
use kr_plugin_sdk::digest::PayloadDigest;

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
        let endpoint = host_endpoint(&environment).expect("an endpoint");
        let descriptor = HostDescriptor {
            protocol: PROTOCOL.to_owned(),
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
    binding_id: kr_plugin_runtime::runtime::binding::BindingId,
    call: &str,
) -> Option<Vec<kr_plugin_runtime::service::protocol::WireNode>> {
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
    assert_eq!(client.descriptor().protocol, PROTOCOL);

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
    assert!(
        matches!(error, RuntimeError::ServiceProtocol { .. }),
        "{error}"
    );
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
    // The slow component, so that the queue's bound is what decides this rather than the
    // scheduler: a component that answered instantly could drain the events as fast as they were
    // offered, and then nothing would overflow and the test would be measuring the machine.
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

    // Delivered concurrently, the way a worker with a busy upstream would: one acknowledgement at a
    // time would let the component drain each event before the next arrived, and then the queue
    // would never fill. The bound is on what the queue holds, not on how patiently it is offered.
    let client = Arc::new(client);
    let filler = Arc::new("z".repeat(64 * 1024));
    let mut delivering = tokio::task::JoinSet::new();
    for index in 0..256 {
        let client = Arc::clone(&client);
        let filler = Arc::clone(&filler);
        let binding_id = request.binding_id;
        delivering.spawn(async move {
            client
                .deliver(
                    binding_id,
                    &components::scrape(&format!("se-{index}"), &filler),
                )
                .await
        });
    }
    let mut gapped = false;
    let mut seen: std::collections::BTreeMap<&'static str, u32> = std::collections::BTreeMap::new();
    while let Some(joined) = delivering.join_next().await {
        let admission = joined
            .expect("the delivery ran")
            .expect("the event is offered");
        *seen.entry(admission_name(&admission)).or_insert(0) += 1;
        if let Admission::QueuedWithGap { events, bytes } = admission {
            assert!(events > 0);
            assert!(bytes > 0);
            gapped = true;
        }
    }

    assert!(
        gapped,
        "the worker was never told the observation queue overflowed; the admissions were {seen:?}"
    );
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

// KR-REQ-11.39: an observation is answered while a call is running on the same connection.
//
// The claim is about order rather than about this machine's speed, so that is what is asserted: the
// observation's answer comes back before the call it was offered behind has finished. A threshold
// in milliseconds would pass on an idle machine and say nothing about a loaded one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_39_an_observation_is_not_behind_a_call_on_the_same_connection() {
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

    // A snapshot this component spends a good part of its deadline on, and several observations
    // behind it so its thread stays occupied.
    for index in 0..64 {
        let _queued = client.offer(
            request.binding_id,
            &components::scrape(&format!("se-q{index}"), "x"),
        );
    }
    let calling = tokio::spawn({
        let client = Arc::clone(&client);
        let binding_id = request.binding_id;
        async move {
            let outcome = client
                .snapshot(binding_id, core::time::Duration::from_millis(100))
                .await;
            (outcome, std::time::Instant::now())
        }
    });

    // While that call is in flight, an observation is answered by the queue rather than behind it.
    // What makes that an overlap rather than a coincidence is the order of two instants taken by
    // this thread from one clock: the observation was answered before the call it was offered
    // behind had finished, and that call is a call into the component.
    let admission = client
        .deliver(request.binding_id, &components::scrape("se-1", "x"))
        .await
        .expect("the event is offered while a call is running");
    let answered_at = std::time::Instant::now();
    assert!(
        matches!(
            admission,
            Admission::Queued | Admission::QueuedWithGap { .. } | Admission::Refused { .. }
        ),
        "the event was {admission:?}"
    );

    let (outcome, finished_at) = calling.await.expect("the call finished");
    // The call ran: either the component answered it or its own deadline stopped it. Both are the
    // component executing; what would not be is the call never having started, and a refusal that
    // named no binding would be exactly that.
    match outcome {
        Ok(called) => assert!(
            called.answered() || called.fault.is_some(),
            "the snapshot returned neither an answer nor a fault"
        ),
        Err(error) => assert!(
            matches!(
                error,
                RuntimeError::CallerDeadline { .. } | RuntimeError::ServiceProtocol { .. }
            ),
            "the snapshot never reached the component: {error}"
        ),
    }
    assert!(
        answered_at < finished_at,
        "the observation was answered after the call it was offered behind had finished"
    );

    // And the component finished calls across that stretch, so the binding was working rather than
    // idle while the observation was being answered.
    let health = client.health().await.expect("a health report");
    assert!(
        health.component_calls > 0,
        "the component finished no calls at all"
    );

    // And the handoff that never waits at all does not even write a frame.
    let offered = std::time::Instant::now();
    let handoff = client.offer(request.binding_id, &components::scrape("se-2", "y"));
    let waited = offered.elapsed();
    assert!(
        matches!(
            handoff,
            kr_plugin_runtime::service::client::Handoff::Accepted
                | kr_plugin_runtime::service::client::Handoff::Refused { .. }
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
        matches!(
            handoff,
            kr_plugin_runtime::service::client::Handoff::TooLarge { .. }
        ),
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
    let endpoint = host_endpoint(&environment).expect("an endpoint");
    let descriptor = HostDescriptor {
        protocol: PROTOCOL.to_owned(),
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
                let request: kr_plugin_runtime::service::protocol::Request =
                    reader.read_message().await.expect("a request");
                let body = match request.body {
                    RequestBody::Hello { .. } => ResponseBody::Hello {
                        protocol: PROTOCOL.to_owned(),
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
        matches!(error, RuntimeError::ServiceUnavailable { .. }),
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
    assert!(matches!(error, RuntimeError::ServiceUnavailable { .. }));
    assert!(asked.elapsed() < core::time::Duration::from_millis(500));
}

fn admission_name(admission: &Admission) -> &'static str {
    match admission {
        Admission::Queued => "queued",
        Admission::QueuedWithGap { .. } => "queued_with_gap",
        Admission::Refused { .. } => "refused",
    }
}
