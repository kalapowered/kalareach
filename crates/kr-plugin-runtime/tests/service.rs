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
use kr_plugin_runtime::service::protocol::{ComponentSource, HostDescriptor, Notice, PROTOCOL};
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
        let packages = environment.state_dir().join("packages");
        std::fs::create_dir_all(&packages).expect("the packages directory");
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
        let serving = tokio::spawn({
            let host = Arc::clone(&host);
            async move {
                let _ = host.serve(core::future::pending::<()>()).await;
            }
        });
        // The endpoint is bound inside `serve`, so a client that connects at once may arrive first.
        tokio::time::sleep(core::time::Duration::from_millis(50)).await;
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

    // The document arrives as a notice, stamped with the binding it belongs to.
    let deadline = std::time::Instant::now() + core::time::Duration::from_secs(5);
    let mut document = None;
    while std::time::Instant::now() < deadline && document.is_none() {
        match tokio::time::timeout(core::time::Duration::from_millis(200), client.notice()).await {
            Ok(Some(Notice::Document {
                binding_id: bound,
                call,
                nodes,
            })) => {
                assert_eq!(bound, binding_id.get());
                assert_eq!(call, "observe");
                document = Some(nodes);
            }
            Ok(Some(other)) => panic!("the binding produced {other:?}"),
            Ok(None) | Err(_) => {}
        }
    }
    let nodes = document.expect("the observation produced a document");
    assert!(
        nodes.iter().any(|node| node.body_json.contains("building")),
        "the document did not carry the observation"
    );

    // A call returns the component's answer and the nodes it emitted.
    let called = client
        .snapshot(binding_id, core::time::Duration::from_millis(500))
        .await
        .expect("the snapshot runs");
    assert!(called.answered());
    assert!(!called.nodes.is_empty());

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
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let served = Served::start().await;
    let client = served.client().await;
    let (path, digest, bytes) = served.install("well-behaved", &wasm);
    let request = components::request("well-behaved", 5);
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
    while let Some(joined) = delivering.join_next().await {
        let admission = joined
            .expect("the delivery ran")
            .expect("the event is offered");
        if let Admission::QueuedWithGap { events, bytes } = admission {
            assert!(events > 0);
            assert!(bytes > 0);
            gapped = true;
        }
    }
    assert!(
        gapped,
        "the worker was never told the observation queue overflowed"
    );
}
