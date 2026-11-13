//! The protocol a worker and the plugin host speak, over a real socket.
//!
//! The host here is in this process rather than its own, because what these tests are about is the
//! conversation: the handshake, the challenge, a registration, a delivery, a call, a refusal and a
//! health report. The separate process, its supervision and its death are in
//! `crates/kr-plugin-host/tests/service.rs`, where there is a real one to kill.

mod components;

use std::sync::Arc;

use kr_plugin_runtime::runtime::binding::BindingRequest;
use kr_plugin_runtime::service::host::{HostConfig, MAX_PENDING_UNBINDS, PluginHost};
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_service::client::{PluginClient, new_binding_id};
use kr_plugin_service::error::ServiceError;
use kr_plugin_service::launcher::{HostIdentity, host_endpoint};
use kr_plugin_service::protocol::{
    ComponentSource, Frame, HostDescriptor, HostProtocol, Notice, RequestBody, ResponseBody,
};
use kr_plugin_service::vocabulary::Admission;

/// How long a registration may take in these cases. A registration contains a compile at
/// background priority, which a machine that other work keeps busy leaves a hundredth of a
/// processor or less, so it takes minutes; a case that registers a component decides by what the
/// registration comes to, and this ends only a registration that never does. The client waits
/// a little longer than the host, as it does by default, so the answer is the host's own.
const REGISTRATION_PATIENCE: core::time::Duration = core::time::Duration::from_secs(60 * 60);

/// How long a case waits for something it has made happen: a host's answer, a notice, the blocking
/// pool's one thread to be held, a pass to stand at its stop, work to run on the pool once it is let
/// go. None of them is decided by it, because each of them comes when the code under test does what
/// the case waits for, however long a loaded machine takes. It ends only a wait for something that
/// never comes, so that a run does not hang for ever.
const HANG_GUARD: core::time::Duration = core::time::Duration::from_secs(60 * 60);

/// A plugin host serving in this process, with a client connected to it.
struct Served {
    packages: std::path::PathBuf,
    descriptor: HostDescriptor,
    host: Arc<PluginHost>,
    serving: tokio::task::JoinHandle<()>,
    // Declared last: the directory is removed after every field above has let go of its files.
    _temp: kr_ipc::testing::TempHost,
}

impl Served {
    /// A host whose epoch runs, so that a call into a component is stopped by its deadline when the
    /// machine's time passes it.
    async fn start() -> Self {
        Self::start_with(false, None).await
    }

    /// A host whose epoch no time advances: a call into a component is stopped by its deadline only
    /// when the case advances the epoch ([`Served::with_the_epoch_moving`]), so a machine that is
    /// slow to run a call cannot make a component fault. For the cases that read what a call
    /// returns and are not about a deadline.
    async fn start_held() -> Self {
        Self::start_with(true, None).await
    }

    /// A host that gives an unbind `deadline` to be answered in, instead of half a second short of
    /// what a worker's client waits for it, and whose epoch no time advances, so that nothing
    /// registering a component on it is stopped by a deadline of the component's.
    async fn start_unbinding_within(deadline: core::time::Duration) -> Self {
        Self::start_with(true, Some(deadline)).await
    }

    async fn start_with(epoch_held: bool, unbinding_within: Option<core::time::Duration>) -> Self {
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
        let config = HostConfig {
            endpoint,
            packages_root: packages.clone(),
            cache_root: environment.state_dir().join("plugin-cache"),
        };
        let host = if epoch_held {
            PluginHost::new_with_epoch_held(identity, config)
        } else {
            PluginHost::new(identity, config)
        }
        .expect("a plugin host")
        .registering_within(REGISTRATION_PATIENCE);
        let host = Arc::new(match unbinding_within {
            Some(deadline) => host.unbinding_within(deadline),
            None => host,
        });
        // The endpoint is bound here, before the host serves on it, so a client that connects at
        // once is queued by the socket until the host accepts it: nothing waits for the host to
        // have bound its endpoint, and no delay stands in for it.
        let listener = kr_ipc::endpoint::Listener::bind(
            &kr_ipc::paths::Endpoint::from_path(&descriptor.endpoint).expect("an endpoint"),
        )
        .expect("the endpoint is bound");
        let serving = tokio::spawn({
            let host = Arc::clone(&host);
            async move {
                let _ = host.serve_on(listener, core::future::pending::<()>()).await;
            }
        });
        Self {
            _temp: temp,
            packages,
            descriptor,
            host,
            serving,
        }
    }

    /// Awaits `call` while the host's epoch is advanced a tick at a time, which is what its
    /// deadlines are a count of. For the cases about a deadline, on a host started held. A call
    /// that no deadline of the component stops ends at the deadline the caller gave it, and the
    /// case then fails on what that is.
    async fn with_the_epoch_moving<T>(&self, call: impl core::future::Future<Output = T>) -> T {
        let runtime = Arc::clone(self.host.runtime());
        let moving = tokio::spawn(async move {
            loop {
                runtime.engine().advance_epoch();
                tokio::time::sleep(core::time::Duration::from_millis(1)).await;
            }
        });
        let outcome = call.await;
        moving.abort();
        outcome
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
            .registering_within(REGISTRATION_PATIENCE + core::time::Duration::from_secs(5))
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
/// a test passing for the wrong reason. The wait ends when the document comes, or when the
/// connection does.
async fn documents_until(
    client: &mut PluginClient,
    binding_id: kr_plugin_service::vocabulary::BindingId,
    call: &str,
) -> Option<Vec<kr_plugin_service::protocol::WireNode>> {
    tokio::time::timeout(HANG_GUARD, async {
        loop {
            match client.notice().await? {
                Notice::Document {
                    binding_id: bound,
                    call: drew,
                    nodes,
                    ..
                } => {
                    assert_eq!(bound, binding_id.get());
                    if drew == call {
                        return Some(nodes);
                    }
                }
                other @ (Notice::Fault { .. } | Notice::Disabled { .. }) => {
                    panic!("the binding produced {other:?}")
                }
                Notice::Gap { .. } => {}
            }
        }
    })
    .await
    .expect("the document the case waits for never came")
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
    let served = Served::start_held().await;
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

/// How long the cases below let the host take to answer an unbind that nothing can run. The cases
/// wait for the answer for as long as it takes, so this is only the figure the host is told to be
/// ready by.
const HELD_UNBIND_DEADLINE: core::time::Duration = core::time::Duration::from_millis(1);

/// A connection that speaks the protocol's frames itself, with no client between it and the host,
/// so that what it waits for is the host's answer and nothing shorter.
struct Raw {
    reader: kr_ipc::framed::FrameReader,
    writer: kr_ipc::framed::FrameWriter,
    next: u64,
    /// Answers that came while the connection waited for another.
    answers: std::collections::HashMap<u64, ResponseBody>,
}

impl Raw {
    async fn connect(served: &Served) -> Self {
        let endpoint =
            kr_ipc::paths::Endpoint::from_path(&served.descriptor.endpoint).expect("an endpoint");
        let connection = kr_ipc::endpoint::Connection::connect(&endpoint)
            .await
            .expect("connects to the plugin host");
        let (reader, writer) =
            kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
        Self {
            reader,
            writer,
            next: 0,
            answers: std::collections::HashMap::new(),
        }
    }

    /// Asks the host something without waiting for the answer, and returns what to wait for.
    async fn send(&mut self, body: RequestBody) -> u64 {
        self.next += 1;
        let request_id = self.next;
        self.writer
            .write_message(&kr_plugin_service::protocol::Request { request_id, body })
            .await
            .expect("the request is written");
        request_id
    }

    /// Waits for the answers to the requests named, whatever notices come first.
    async fn collect(&mut self, requests: &[u64]) -> Vec<ResponseBody> {
        while !requests.iter().all(|id| self.answers.contains_key(id)) {
            let frame: Frame = self
                .reader
                .read_message_without_schema()
                .await
                .expect("the host answers");
            if let Frame::Response { reply_to, body } = frame {
                self.answers.insert(reply_to, body);
            }
        }
        requests
            .iter()
            .map(|id| self.answers.remove(id).expect("the answer is there"))
            .collect()
    }

    /// Asks the host something and returns its answer, whatever notices come first.
    async fn ask(&mut self, body: RequestBody) -> ResponseBody {
        let request_id = self.send(body).await;
        self.collect(&[request_id]).await.pop().expect("one answer")
    }

    async fn health(&mut self) -> kr_plugin_service::protocol::HostHealth {
        match self.ask(RequestBody::Health).await {
            ResponseBody::Health(health) => *health,
            other => panic!("the host answered a health request with {other:?}"),
        }
    }

    /// Asks the host for its health until `reached` holds of it. See [`health_until`].
    async fn health_until(
        &mut self,
        reached: impl Fn(&kr_plugin_service::protocol::HostHealth) -> bool,
    ) -> kr_plugin_service::protocol::HostHealth {
        tokio::time::timeout(HANG_GUARD, async {
            loop {
                let health = self.health().await;
                if reached(&health) {
                    return health;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the host never reached the state the case waits for")
    }

    /// Registers a binding with the component at `component`, and returns the host's answer.
    async fn register(
        &mut self,
        request: &BindingRequest,
        component: &ComponentSource,
    ) -> ResponseBody {
        let asked = self.send_register(request, component).await;
        self.collect(&[asked]).await.pop().expect("one answer")
    }

    /// Asks the host to register a binding, without waiting for the answer.
    async fn send_register(
        &mut self,
        request: &BindingRequest,
        component: &ComponentSource,
    ) -> u64 {
        self.send(RequestBody::RegisterBinding(Box::new(
            kr_plugin_service::protocol::BindingRegistration {
                binding_id: request.binding_id.get(),
                identity: request.identity.clone(),
                facts: kr_plugin_service::vocabulary::wire_facts(&request.facts),
                executable: request.executable.clone(),
                component: component.clone(),
            },
        )))
        .await
    }

    /// Asks the host to remove a binding, without waiting for the answer.
    async fn send_unbind(&mut self, request: &BindingRequest) -> u64 {
        self.send(RequestBody::Unbind {
            binding_id: request.binding_id.get(),
        })
        .await
    }

    /// Asks the host to remove a binding and waits for its answer for as long as it takes.
    async fn unbind(&mut self, request: &BindingRequest) -> ResponseBody {
        let asked = self.send_unbind(request).await;
        tokio::time::timeout(HANG_GUARD, self.collect(&[asked]))
            .await
            .expect("the host answered the unbind, and did not wait for the pool")
            .pop()
            .expect("one answer")
    }
}

/// An executor whose blocking pool has one thread, so that a case can hold it.
fn executor_with_one_blocking_thread() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .expect("an executor with one blocking thread")
}

/// The blocking pool's only thread, held by work that ends when the hold is let go.
struct HeldPool {
    release: std::sync::mpsc::Sender<()>,
    blocker: tokio::task::JoinHandle<()>,
}

impl HeldPool {
    async fn take() -> Self {
        let (running, occupied) = tokio::sync::oneshot::channel::<()>();
        let (release, held) = std::sync::mpsc::channel::<()>();
        let blocker = tokio::task::spawn_blocking(move || {
            let _ = running.send(());
            let _ = held.recv();
        });
        tokio::time::timeout(HANG_GUARD, occupied)
            .await
            .expect("the pool's thread was held")
            .expect("the held work started");
        Self { release, blocker }
    }

    /// Gives the pool its thread back, and returns once work spawned after the release has run on
    /// it, which is after every task that was queued before.
    async fn let_go(self) {
        drop(self.release);
        self.blocker.await.expect("the held work ended");
        quiet_pool().await;
    }
}

/// Returns once work spawned now has run on the blocking pool's thread, which is after every task
/// that was queued before it.
async fn quiet_pool() {
    tokio::time::timeout(HANG_GUARD, tokio::task::spawn_blocking(|| ()))
        .await
        .expect("work ran on the pool's thread")
        .expect("the work ended");
}

// An unbind waits for the binding's thread, on the blocking pool. A pool that other work keeps busy
// leaves it waiting for a thread of its own, and the request is answered at the host's deadline
// all the same: with a refusal that says the binding was taken out of the runtime without the wait,
// and with the binding out of the runtime, as a worker takes any answer as the binding gone. The
// removal is not taken back: it runs when the pool has a thread, and finds nothing to remove.
//
// The host can have only so many of those removals waiting, whichever connections asked for them: a
// worker that ends its connection and opens another finds the removals it left still counted. An
// unbind that finds no place in the time it has queues nothing. It takes its binding out of the
// runtime the same way, and says so.
//
// The pool has one thread, which the case holds once the bindings are registered. A task spawned
// after the unbinds runs after them on that thread, so by the time it has run they have too.
// Nothing in the case is decided by how long anything takes: it waits for the host's answer, and
// for the host's account of its bindings to say what the case waits for.
#[test]
fn an_unbind_a_busy_blocking_pool_holds_up_is_refused_in_time_and_runs_when_the_pool_has_a_thread()
{
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let executor = executor_with_one_blocking_thread();
    executor.block_on(async {
        let served = Served::start_unbinding_within(HELD_UNBIND_DEADLINE).await;
        let (path, digest, bytes) = served.install("well-behaved", &wasm);
        let component = ComponentSource {
            path,
            digest,
            bytes,
        };
        // The first connection is the worker that leaves its removals behind, one for each place
        // the host has; the second is another, that has asked for nothing.
        let mut host = Raw::connect(&served).await;
        let mut other = Raw::connect(&served).await;
        let leaving: Vec<BindingRequest> = (1..=MAX_PENDING_UNBINDS as u8)
            .map(|seed| components::request("well-behaved", seed))
            .collect();
        let second = components::request("well-behaved", 100);
        for request in &leaving {
            let registered = host.register(request, &component).await;
            assert!(
                matches!(registered, ResponseBody::Registered { .. }),
                "the binding was answered with {registered:?}"
            );
        }
        let registered = other.register(&second, &component).await;
        assert!(
            matches!(registered, ResponseBody::Registered { .. }),
            "the binding was answered with {registered:?}"
        );
        let health = host.health().await;
        assert_eq!(
            (health.live_bindings, health.connection_bindings),
            (MAX_PENDING_UNBINDS as u64 + 1, MAX_PENDING_UNBINDS as u64)
        );
        let pool = HeldPool::take().await;

        // A caller that stops waiting leaves its removal behind, and the host may have only so many
        // waiting: each of these is answered at the deadline, and each takes one of the places.
        for request in &leaving {
            let answered = host.unbind(request).await;
            assert!(
                matches!(&answered, ResponseBody::Refused { detail, .. }
                    if detail.contains(&format!("{} ms", HELD_UNBIND_DEADLINE.as_millis()))),
                "the unbind was answered with {answered:?}"
            );
        }
        // The host answered, and the removals are still to be run: the bindings are not in the
        // runtime for them, and their places go as their threads end.
        let health = host
            .health_until(|health| health.connection_bindings == 0)
            .await;
        assert_eq!(health.live_bindings, 1);

        // The worker's connection ends. Its removals are still on the pool, so the other
        // connection, which has asked for none, finds no place for its unbind. Nothing is queued,
        // and the binding is not left in the runtime: it is stopped without the wait.
        drop(host);
        let answered = other.unbind(&second).await;
        assert!(
            matches!(&answered, ResponseBody::Refused { detail, .. }
                if detail.contains("unbinds it may have waiting")),
            "an unbind on another connection, with the host's places held, was answered with {answered:?}"
        );
        let health = other
            .health_until(|health| health.connection_bindings == 0)
            .await;
        assert_eq!(
            health.live_bindings, 0,
            "the binding of the unbind that found no place was left in the runtime"
        );

        // The pool gets its thread back. The removals run on it ahead of the work that tells the
        // case they have, and find nothing to remove.
        pool.let_go().await;
        let health = other.health().await;
        assert_eq!((health.live_bindings, health.connection_bindings), (0, 0));

        // The binding the host stopped without the wait is one its worker can register again.
        let registered = other.register(&second, &component).await;
        assert!(
            matches!(registered, ResponseBody::Registered { .. }),
            "the binding was answered with {registered:?}"
        );
        // The removals that ran gave their places back: one more unbind is not refused for want of
        // one. It is answered at the deadline or with what it found, and either is right here.
        let answered = other.unbind(&second).await;
        assert!(
            !matches!(&answered, ResponseBody::Refused { detail, .. }
                if detail.contains("unbinds it may have waiting")),
            "a host whose removals have all run refused an unbind for the removals it has waiting: {answered:?}"
        );
        quiet_pool().await;
        let health = other
            .health_until(|health| health.connection_bindings == 0)
            .await;
        assert_eq!(
            health.live_bindings, 0,
            "the unbind that was asked again was not carried out"
        );
    });
    executor.shutdown_timeout(HANG_GUARD);
}

// Removals that many connections ask for at once are not refused for want of a place: an unbind
// that finds every place taken waits for one, in the time the worker gives it, and is carried out
// as any other is, with its binding's thread waited for.
//
// The host here has the time a worker gives an unbind to be an hour, which only ends an answer that
// never comes. The pool's one thread is held, and two connections have asked, between them, for as
// many unbinds as the host has places, each of which takes one and waits for the pool (each stays
// well under the calls a connection may have running). A third connection asks for its own: it
// finds no place, and waits. Nothing is answered until the pool is let go.
#[test]
fn an_unbind_that_finds_every_place_taken_waits_for_one_and_is_carried_out() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let executor = executor_with_one_blocking_thread();
    executor.block_on(async {
        let served = Served::start_unbinding_within(HANG_GUARD).await;
        let (path, digest, bytes) = served.install("well-behaved", &wasm);
        let component = ComponentSource {
            path,
            digest,
            bytes,
        };
        let mut host = Raw::connect(&served).await;
        let mut other = Raw::connect(&served).await;
        let mut third = Raw::connect(&served).await;
        let first = components::request("well-behaved", 1);
        let second = components::request("well-behaved", 2);
        let third_binding = components::request("well-behaved", 3);
        for (connection, request) in [
            (&mut host, &first),
            (&mut other, &second),
            (&mut third, &third_binding),
        ] {
            let registered = connection.register(request, &component).await;
            assert!(
                matches!(registered, ResponseBody::Registered { .. }),
                "the binding was answered with {registered:?}"
            );
        }
        let pool = HeldPool::take().await;

        // Half of the places are taken by each of two connections, so that neither is near the
        // calls a connection may have running, whatever its last request has not yet given back.
        let mut taking = Vec::new();
        for _ in 0..MAX_PENDING_UNBINDS / 2 {
            taking.push(host.send_unbind(&first).await);
        }
        let mut taking_too = Vec::new();
        for _ in 0..MAX_PENDING_UNBINDS / 2 {
            taking_too.push(third.send_unbind(&third_binding).await);
        }
        tokio::time::timeout(HANG_GUARD, async {
            while served.host.unbinds_waiting() < MAX_PENDING_UNBINDS {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the host took a place for each unbind");

        // The host says when an unbind has found every place taken, which is before it waits for
        // one and long before the pool is let go.
        let waiting = other.send_unbind(&second).await;
        tokio::time::timeout(HANG_GUARD, async {
            while served.host.unbinds_found_full() < 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the host found every place taken");
        let health = other.health().await;
        assert_eq!(health.live_bindings, 3, "an unbind was carried out at once");

        pool.let_go().await;
        for (connection, asked) in [(&mut host, &taking), (&mut third, &taking_too)] {
            for answered in connection.collect(asked).await {
                assert!(
                    matches!(answered, ResponseBody::Unbound { .. }),
                    "an unbind that took a place was answered with {answered:?}"
                );
            }
        }
        let answered = other.collect(&[waiting]).await.pop().expect("one answer");
        assert!(
            matches!(answered, ResponseBody::Unbound { existed: true }),
            "an unbind that found every place taken was answered with {answered:?}"
        );
        let health = other.health().await;
        assert_eq!(
            (health.live_bindings, health.connection_bindings),
            (0, 0),
            "the unbinds were not all carried out"
        );
    });
    executor.shutdown_timeout(HANG_GUARD);
}

/// Asks the host for its health until `reached` holds of it, for a case that waits for the host to
/// have done something that no answer says it has done. The wait ends when the host gets there, and
/// only a host that never does is held to the hour.
async fn health_until(
    client: &PluginClient,
    reached: impl Fn(&kr_plugin_service::protocol::HostHealth) -> bool,
) -> kr_plugin_service::protocol::HostHealth {
    tokio::time::timeout(HANG_GUARD, async {
        loop {
            let health = client.health().await.expect("a health report");
            if reached(&health) {
                return health;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the host never reached the state the case waits for")
}

/// Reads notices until the last piece of `document` that `call` drew for `binding_id`, and returns
/// everything it read, that document included.
async fn notices_through(
    client: &PluginClient,
    binding_id: kr_plugin_service::vocabulary::BindingId,
    call: &str,
    document: u64,
) -> Vec<Notice> {
    tokio::time::timeout(HANG_GUARD, async {
        let mut read = Vec::new();
        loop {
            let notice = client
                .notice()
                .await
                .expect("the connection ended before the document came");
            let ends = matches!(
                &notice,
                Notice::Document {
                    binding_id: named,
                    call: drew,
                    document: number,
                    last: true,
                    ..
                } if *named == binding_id.get() && drew == call && *number == document
            );
            read.push(notice);
            if ends {
                return read;
            }
        }
    })
    .await
    .expect("the document the case waits for never came")
}

/// Registers `request` over `component` on `client`.
async fn register_on(client: &PluginClient, request: &BindingRequest, component: &ComponentSource) {
    client
        .register(
            request.binding_id,
            &request.identity,
            &request.facts,
            &request.executable,
            component,
        )
        .await
        .expect("the binding registers");
}

/// Fills the observation queue of a binding whose next pass over it is stopped, until the queue
/// has overflowed. The binding owes a fresh snapshot then, and sends the gap and the snapshot's
/// document once the pass is let go, whether or not the binding has been told to stop by then.
async fn overflow_behind_a_stopped_pass(
    served: &Served,
    client: &PluginClient,
    request: &BindingRequest,
) -> kr_plugin_runtime::runtime::binding::PumpStop {
    let mut stop = served
        .host
        .runtime()
        .stop_next_pump(request.binding_id)
        .expect("the binding is live");
    let filler = "z".repeat(64 * 1024);
    let fitting = kr_plugin_sdk::limits::OBSERVATION_QUEUE_BYTES / filler.len() as u64;
    client
        .deliver(request.binding_id, &components::scrape("se-0", &filler))
        .await
        .expect("the event is offered");
    assert!(
        tokio::time::timeout(HANG_GUARD, stop.reached())
            .await
            .expect("the binding's pass stands at the stop"),
        "the stop was replaced before a pass reached it"
    );
    for index in 1..=2 * fitting {
        let admission = client
            .deliver(
                request.binding_id,
                &components::scrape(&format!("se-{index}"), &filler),
            )
            .await
            .expect("the event is offered");
        if matches!(admission, Admission::QueuedWithGap { .. }) {
            return stop;
        }
    }
    panic!("the observation queue never overflowed");
}

/// What a worker is shown after it registered a binding again while the thread of the binding it
/// had removed was still finishing a pass: the notices up to and including the document of the new
/// registration's snapshot.
///
/// The documents the two registrations drew when they were bound are read first, one of each, so
/// that what is left is what came after.
async fn what_the_new_registration_is_shown(
    client: &PluginClient,
    request: &BindingRequest,
) -> Vec<Notice> {
    // The caller waits far longer than the call takes, so that what the case decides by is what the
    // call comes to and not how long a machine took to get to it.
    let called = client
        .snapshot(request.binding_id, core::time::Duration::from_secs(20))
        .await
        .expect("the snapshot runs");
    let document = called.document.expect("the snapshot drew a document");
    notices_through(client, request.binding_id, "snapshot", document).await
}

// A binding that has been removed can still be finishing a pass on its own thread, and the worker
// can register the same identifier again before that thread is done. What the removed binding's
// thread produces after that is the removed registration's, and it reaches nobody: not the queue
// the new registration's notices go through, and not the new registration as a gap, a document or a
// fault of its own.
//
// The removal here waits for the thread. The first registration's pass over its observation queue
// is stopped, with the queue overflowed behind it, so that the pass owes a gap and a snapshot, and
// both are sent whether or not the binding was told to stop. The unbind takes the binding out of the
// runtime and waits for the thread; the identifier is registered again while it waits; the pass is
// let go. The unbind is answered after the thread has ended and after everything it produced has
// been passed on or dropped, so the notice the new registration's snapshot draws is behind
// anything the removed one left in the queue.
//
// The unbind stays open for as long as the case takes to get from the removal to the pass it lets
// go, so the host and the client are both told to wait for it for the hour that only ends an
// answer that never comes, and the epoch no time advances.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_the_thread_of_a_removed_binding_produces_after_the_identifier_is_registered_again_reaches_nobody()
 {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let served = Served::start_unbinding_within(HANG_GUARD).await;
    let client = Arc::new(served.client().await.unbinding_within(HANG_GUARD));
    let (path, digest, bytes) = served.install("well-behaved", &wasm);
    let component = ComponentSource {
        path,
        digest,
        bytes,
    };
    let request = components::request("well-behaved", 1);
    register_on(&client, &request, &component).await;
    let drawn = notices_through(&client, request.binding_id, "bind", 1).await;
    assert_eq!(drawn.len(), 1, "the registration drew {drawn:?}");

    let stop = overflow_behind_a_stopped_pass(&served, &client, &request).await;

    // The unbind removes the binding from the runtime and waits for its thread, which stands at the
    // stop; the case sees the identifier let go by the runtime's count.
    let removing = tokio::spawn({
        let client = Arc::clone(&client);
        let binding_id = request.binding_id;
        async move { client.unbind(binding_id).await }
    });
    health_until(&client, |health| health.live_bindings == 0).await;
    register_on(&client, &request, &component).await;
    let bound = notices_through(&client, request.binding_id, "bind", 1).await;
    assert_eq!(bound.len(), 1, "the new registration drew {bound:?}");

    stop.release();
    let existed = tokio::time::timeout(HANG_GUARD, removing)
        .await
        .expect("the unbind was answered")
        .expect("the unbind task ended")
        .expect("the unbind ran");
    assert!(existed, "the removed binding was not there to remove");

    let shown = what_the_new_registration_is_shown(&client, &request).await;
    assert!(
        shown.iter().all(|notice| matches!(
            notice,
            Notice::Document { call, .. } if call == "snapshot"
        )),
        "the new registration was shown what the removed one's thread sent: {shown:?}"
    );
    assert_eq!(
        shown.len(),
        1,
        "the new registration was shown more than its own snapshot: {shown:?}"
    );
}

// An unbind that the blocking pool cannot run in the time a worker gives it answers with the
// binding already out of the runtime, whatever it found: the worker takes any answer to an unbind
// as the binding gone, and a binding left in the runtime until the queued removal ran would be one
// it could not register again. The removal stays queued, and finds nothing to remove when it runs.
//
// The thread of the binding that was taken out without the wait is a thread still, and it holds
// the connection's place for the binding until it has ended, so the connection never holds more
// instances than it may. Here the thread stands at a stopped pass with a gap and a snapshot owed;
// when it is let go it sends both, and neither reaches the worker, which is shown the next
// registration of the identifier and nothing of the one that was removed.
#[test]
fn an_unbind_the_blocking_pool_cannot_run_in_time_takes_the_binding_out_of_the_runtime_and_keeps_its_place_until_the_thread_has_ended()
 {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let executor = executor_with_one_blocking_thread();
    executor.block_on(async {
        let served = Served::start_unbinding_within(HELD_UNBIND_DEADLINE).await;
        let client = served.client().await;
        let (path, digest, bytes) = served.install("well-behaved", &wasm);
        let component = ComponentSource {
            path,
            digest,
            bytes,
        };
        let request = components::request("well-behaved", 1);
        register_on(&client, &request, &component).await;
        notices_through(&client, request.binding_id, "bind", 1).await;
        let stop = overflow_behind_a_stopped_pass(&served, &client, &request).await;
        let pool = HeldPool::take().await;

        let answered = client.unbind(request.binding_id).await;
        assert!(
            matches!(&answered, Err(ServiceError::Protocol { detail })
                if detail.contains(&format!("{} ms", HELD_UNBIND_DEADLINE.as_millis()))),
            "the unbind was answered with {answered:?}"
        );
        let health = client.health().await.expect("a health report");
        assert_eq!(
            health.live_bindings, 0,
            "the binding was left in the runtime for the removal that is queued"
        );
        assert_eq!(
            health.connection_bindings, 1,
            "the connection gave the binding's place back while its thread stood"
        );

        // The thread is let go and ends, and the place goes with it.
        stop.release();
        health_until(&client, |health| health.connection_bindings == 0).await;

        // The removal the pool ran has nothing left to remove, and the identifier registers again.
        pool.let_go().await;
        register_on(&client, &request, &component).await;
        let bound = notices_through(&client, request.binding_id, "bind", 1).await;
        assert_eq!(
            bound.len(),
            1,
            "the new registration was shown more than its own bind: {bound:?}"
        );
        let shown = what_the_new_registration_is_shown(&client, &request).await;
        assert_eq!(
            shown.len(),
            1,
            "the new registration was shown more than its own snapshot: {shown:?}"
        );
    });
    executor.shutdown_timeout(HANG_GUARD);
}

// A connection that ends takes its bindings out of the runtime without a thread of the blocking
// pool: the host cannot have more removals waiting than it has connections that ended, and a pool
// that other work keeps busy would hold them, and the bindings in them, for as long.
//
// The pool's one thread is held, the worker's connection ends with a binding on it, and the case
// waits for the runtime to hold none.
#[test]
fn a_connection_that_ends_takes_its_bindings_out_without_a_thread_of_the_blocking_pool() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let executor = executor_with_one_blocking_thread();
    executor.block_on(async {
        let served = Served::start().await;
        let watching = served.client().await;
        let worker = served.client().await;
        let (path, digest, bytes) = served.install("well-behaved", &wasm);
        let component = ComponentSource {
            path,
            digest,
            bytes,
        };
        let request = components::request("well-behaved", 1);
        register_on(&worker, &request, &component).await;
        assert_eq!(
            watching
                .health()
                .await
                .expect("a health report")
                .live_bindings,
            1
        );
        let pool = HeldPool::take().await;

        drop(worker);
        health_until(&watching, |health| health.live_bindings == 0).await;
        pool.let_go().await;
    });
    executor.shutdown_timeout(HANG_GUARD);
}

// An unbind can come between the connection's record of a registration and the runtime's
// reservation of its identifier. It finds nothing in the runtime to remove and is answered, and the
// registration then goes live: a binding the worker asked to be rid of, which nothing records. The
// host takes it out of the runtime again and refuses the registration, so that the identifier can
// be registered and the worker is not told a binding exists that its unbind took away.
//
// The registration is held at the step between the two, and the case lets it go once the unbind
// has been answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_registration_unbound_before_the_runtime_reserves_its_identifier_is_refused_and_leaves_nothing_behind()
 {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let served = Served::start().await;
    let client = Arc::new(served.client().await);
    let (path, digest, bytes) = served.install("well-behaved", &wasm);
    let component = ComponentSource {
        path,
        digest,
        bytes,
    };
    let request = components::request("well-behaved", 1);
    let hold = served.host.hold_registrations_before_the_runtime();
    let registering = tokio::spawn({
        let client = Arc::clone(&client);
        let request = request.clone();
        let component = component.clone();
        async move {
            client
                .register(
                    request.binding_id,
                    &request.identity,
                    &request.facts,
                    &request.executable,
                    &component,
                )
                .await
        }
    });
    tokio::time::timeout(HANG_GUARD, async {
        while !hold.parked() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the registration never reached the step before the runtime");

    client
        .unbind(request.binding_id)
        .await
        .expect("the unbind of a binding being registered is answered");
    hold.release();
    let registered = tokio::time::timeout(HANG_GUARD, registering)
        .await
        .expect("the registration was answered")
        .expect("the registration task ended");
    assert!(
        registered.is_err(),
        "a registration that was unbound meanwhile was answered as registered"
    );
    assert_eq!(
        client
            .health()
            .await
            .expect("a health report")
            .live_bindings,
        0,
        "the registration left a binding in the runtime"
    );

    // The identifier is free.
    register_on(&client, &request, &component).await;
    assert_eq!(
        client
            .health()
            .await
            .expect("a health report")
            .live_bindings,
        1
    );
}

// A connection that has all the calls it may have running is told its next call is refused, and an
// unbind is among the calls: it is answered with the binding out of the runtime like any other,
// because the worker takes any answer to an unbind as the binding gone and would otherwise be left
// with a binding it could not register again.
//
// The calls that fill the connection are snapshots that the binding's thread has not got to: its
// next pass over the observation queue is stopped, so they stay in flight, whatever a component
// would have done with them, until the case lets the pass go. A snapshot that finds the connection
// full is refused and answered before the request after it is read, so the case asks for the
// host's health after each and counts the snapshots that were not answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unbind_a_connection_has_no_place_for_a_call_to_run_is_answered_with_the_binding_out_of_the_runtime()
 {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let served = Served::start().await;
    let (path, digest, bytes) = served.install("well-behaved", &wasm);
    let component = ComponentSource {
        path,
        digest,
        bytes,
    };
    let mut raw = Raw::connect(&served).await;
    let request = components::request("well-behaved", 1);
    let registered = raw.register(&request, &component).await;
    assert!(
        matches!(registered, ResponseBody::Registered { .. }),
        "the binding was answered with {registered:?}"
    );
    let mut stop = served
        .host
        .runtime()
        .stop_next_pump(request.binding_id)
        .expect("the binding is live");
    let woken = raw
        .ask(RequestBody::Event {
            binding_id: request.binding_id.get(),
            event: kr_plugin_service::vocabulary::wire_event(&components::scrape("se-0", "x")),
        })
        .await;
    assert!(
        matches!(woken, ResponseBody::Admitted { .. }),
        "the event was answered with {woken:?}"
    );
    assert!(
        tokio::time::timeout(HANG_GUARD, stop.reached())
            .await
            .expect("the binding's pass stands at the stop"),
        "the stop was replaced before a pass reached it"
    );

    let mut calls = Vec::new();
    while calls.len() < 16 {
        let asked = raw
            .send(RequestBody::Snapshot {
                binding_id: request.binding_id.get(),
                deadline_ms: u64::try_from(HANG_GUARD.as_millis()).expect("milliseconds"),
            })
            .await;
        let probe = raw.send(RequestBody::Health).await;
        raw.collect(&[probe]).await;
        match raw.answers.remove(&asked) {
            // The registration's own place had not come back yet: ask again.
            Some(ResponseBody::Refused { .. }) => {}
            Some(other) => panic!("the snapshot was answered with {other:?}"),
            None => calls.push(asked),
        }
    }
    let answered = raw.unbind(&request).await;
    assert!(
        matches!(&answered, ResponseBody::Refused { detail, .. }
            if detail.contains("calls it may have running")),
        "the unbind was answered with {answered:?}"
    );
    assert_eq!(
        raw.health().await.live_bindings,
        0,
        "the binding was left in the runtime"
    );

    // The pass is let go, and the binding's thread, which was told to stop, ends without calling
    // the component.
    stop.release();
    tokio::time::timeout(HANG_GUARD, raw.collect(&calls))
        .await
        .expect("the calls were answered");
}

// Two unbinds of one identifier, and a registration of it, can overlap: the first unbind has taken
// the first registration out of the runtime and waits for its thread, the identifier is registered
// again, and the second unbind comes while that registration is being made. It is about the
// registration being made, and not the one on its way out: it is answered without waiting for the
// thread of the first, and the registration it is about is refused.
//
// The first registration's thread stands at a stopped pass until the case lets it go, and the second
// registration is held between the connection's record of it and the runtime's reservation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unbind_is_about_the_registration_being_made_and_not_the_one_on_its_way_out() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let served = Served::start_unbinding_within(HANG_GUARD).await;
    let client = Arc::new(served.client().await.unbinding_within(HANG_GUARD));
    let (path, digest, bytes) = served.install("well-behaved", &wasm);
    let component = ComponentSource {
        path,
        digest,
        bytes,
    };
    let request = components::request("well-behaved", 1);
    register_on(&client, &request, &component).await;
    notices_through(&client, request.binding_id, "bind", 1).await;
    let stop = overflow_behind_a_stopped_pass(&served, &client, &request).await;

    let removing = tokio::spawn({
        let client = Arc::clone(&client);
        let binding_id = request.binding_id;
        async move { client.unbind(binding_id).await }
    });
    health_until(&client, |health| health.live_bindings == 0).await;

    let hold = served.host.hold_registrations_before_the_runtime();
    let registering = tokio::spawn({
        let client = Arc::clone(&client);
        let request = request.clone();
        let component = component.clone();
        async move {
            client
                .register(
                    request.binding_id,
                    &request.identity,
                    &request.facts,
                    &request.executable,
                    &component,
                )
                .await
        }
    });
    tokio::time::timeout(HANG_GUARD, async {
        while !hold.parked() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the second registration never reached the step before the runtime");

    // The first registration's thread is still at its stop, so an unbind that waited for it would
    // not be answered.
    tokio::time::timeout(HANG_GUARD, client.unbind(request.binding_id))
        .await
        .expect("the second unbind was answered")
        .expect("the second unbind ran");
    hold.release();
    let registered = tokio::time::timeout(HANG_GUARD, registering)
        .await
        .expect("the second registration was answered")
        .expect("the registration task ended");
    assert!(
        registered.is_err(),
        "the registration the second unbind was about was answered as registered"
    );

    stop.release();
    let existed = tokio::time::timeout(HANG_GUARD, removing)
        .await
        .expect("the first unbind was answered")
        .expect("the unbind task ended")
        .expect("the first unbind ran");
    assert!(existed, "the first registration was not there to remove");
    let health = health_until(&client, |health| health.connection_bindings == 0).await;
    assert_eq!(health.live_bindings, 0);
    register_on(&client, &request, &component).await;
}

/// Asks for a snapshot of `request`'s binding within `deadline` and returns the number of the
/// document it drew.
async fn snapshot_drawn(
    client: &PluginClient,
    request: &BindingRequest,
    deadline: core::time::Duration,
) -> u64 {
    client
        .snapshot(request.binding_id, deadline)
        .await
        .expect("the snapshot runs")
        .document
        .expect("the snapshot drew a document")
}

/// Returns once a task has stopped at `hold`.
async fn reached(hold: &kr_plugin_service::hold::HoldHandle, what: &str) {
    tokio::time::timeout(HANG_GUARD, async {
        while !hold.parked() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect(what);
}

/// Returns once the file at `path` exists.
async fn appears(path: &std::path::Path) {
    tokio::time::timeout(HANG_GUARD, async {
        while !path.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the file the case waits for never appeared");
}

/// Returns once the client has written the request it last sent in full, which is when the request
/// is on the wire for the host to read whatever the caller does next. The request in the middle of
/// its write holds the writer, so taking the writer is waiting for the write to end. A caller that
/// is stopped before that would end the connection, and not stop waiting for one request.
async fn on_the_wire(client: &PluginClient) {
    drop(client.hold_writer().await);
}

/// A host that is a program of the case's own, for the cases about the order of the frames a client
/// reads. It answers the handshake and the challenge, then hands the connection's two halves to
/// `script`, which is the rest of what the host does. The client the case drives is connected to it.
async fn scripted_host<Script, Running>(
    script: Script,
) -> (PluginClient, tokio::task::JoinHandle<()>)
where
    Script: FnOnce(kr_ipc::framed::FrameReader, kr_ipc::framed::FrameWriter) -> Running
        + Send
        + 'static,
    Running: core::future::Future<Output = ()> + Send + 'static,
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
    let serving = tokio::spawn({
        let descriptor = descriptor.clone();
        async move {
            let _temp = temp;
            let (connection, _peer) = listener.accept().await.expect("a connection");
            let (mut reader, mut writer) =
                kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
            for _ in 0..2 {
                let request: kr_plugin_service::protocol::Request = reader
                    .read_message_without_schema()
                    .await
                    .expect("the handshake request");
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
                    other => panic!("the client asked for {other:?} in the handshake"),
                };
                writer
                    .write_message(&Frame::Response {
                        reply_to: request.request_id,
                        body,
                    })
                    .await
                    .expect("the handshake answer is written");
            }
            script(reader, writer).await;
        }
    });
    let connection = kr_ipc::endpoint::Connection::connect(&endpoint)
        .await
        .expect("connects");
    let client = PluginClient::over(connection, descriptor)
        .await
        .expect("the handshake and the challenge")
        .registering_within(HANG_GUARD);
    (client, serving)
}

/// Reads the client's notices through `last`, the notice the host program writes after everything
/// the case is about, and returns them with it.
async fn notices_until(client: &PluginClient, last: &Notice) -> Vec<Notice> {
    tokio::time::timeout(HANG_GUARD, async {
        let mut read = Vec::new();
        loop {
            let notice = client.notice().await.expect("the connection stood");
            let ends = notice == *last;
            read.push(notice);
            if ends {
                return read;
            }
        }
    })
    .await
    .expect("the notice that is always read never came")
}

// What the host's notice queue holds for a binding when it is removed is the removed registration's,
// and no later registration of the identifier is shown it. Notices carry the binding's identifier
// and nothing else, so a worker cannot tell them from the new registration's own.
//
// The notice writer is held with one document in hand, taken off the queue and not yet written, and
// another waits in the queue behind it. The binding is removed and its identifier registered again
// while the writer is held. The queue gives up what it held when the binding is removed, and the
// document in hand is not written when the writer goes on: the worker is shown the new
// registration's first document and nothing before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_a_removed_binding_left_in_the_notice_queue_is_shown_to_no_later_registration() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let served = Served::start_unbinding_within(HANG_GUARD).await;
    let client = served.client().await.unbinding_within(HANG_GUARD);
    let (path, digest, bytes) = served.install("well-behaved", &wasm);
    let component = ComponentSource {
        path,
        digest,
        bytes,
    };
    let request = components::request("well-behaved", 1);
    register_on(&client, &request, &component).await;
    notices_through(&client, request.binding_id, "bind", 1).await;

    let hold = served.host.hold_notice_writes();
    let deadline = core::time::Duration::from_secs(20);
    snapshot_drawn(&client, &request, deadline).await;
    reached(
        &hold,
        "the writer never took the first document off the queue",
    )
    .await;
    snapshot_drawn(&client, &request, deadline).await;
    health_until(&client, |health| health.queued_notice_bytes > 0).await;

    client
        .unbind(request.binding_id)
        .await
        .expect("the unbind ran");
    assert_eq!(
        client
            .health()
            .await
            .expect("a health report")
            .queued_notice_bytes,
        0,
        "the queue still held what the removed binding left in it"
    );

    register_on(&client, &request, &component).await;
    hold.release();
    let shown = notices_through(&client, request.binding_id, "bind", 1).await;
    assert_eq!(
        shown.len(),
        1,
        "the new registration was shown what the removed one left: {shown:?}"
    );
}

// A loss the queue owes a binding is a loss of the registration that suffered it. A document the
// queue withheld while privacy mode stood is reported as lost when it ends, and the component is
// asked to draw a fresh one; when the registration it was lost for has been removed, the report is
// neither written to the worker nor passed to the identifier's next registration, which would
// draw a document nobody asked it for.
//
// The notice writer is held with that report in hand, taken off the queue and not yet acted on,
// while the binding is removed and its identifier registered again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_loss_owed_to_a_removed_binding_is_neither_told_to_nor_made_up_by_a_later_registration() {
    let Some(wasm) = components::component("hostile-decoder") else {
        return;
    };
    let served = Served::start_unbinding_within(HANG_GUARD).await;
    let client = served.client().await.unbinding_within(HANG_GUARD);
    let (path, digest, bytes) = served.install("hostile-decoder", &wasm);
    let component = ComponentSource {
        path,
        digest,
        bytes,
    };
    let request = components::request("hostile-decoder", 14);
    register_on(&client, &request, &component).await;
    let deadline = core::time::Duration::from_secs(20);

    // A document taken off the queue and held at the writer when privacy mode is acknowledged, so
    // that it is withheld and owed.
    let hold = served.host.hold_notice_writes();
    let first = client
        .snapshot(request.binding_id, deadline)
        .await
        .expect("the snapshot runs");
    assert_eq!(first.document, Some(1));
    reached(&hold, "the writer never took the document off the queue").await;
    client
        .privacy(true)
        .await
        .expect("privacy mode is acknowledged");
    hold.release();
    // A fault is written after the document the writer held, so reading it says the writer is past
    // that document.
    client
        .decode(
            request.binding_id,
            &components::native_request("se-2", "8", "!trap"),
            deadline,
        )
        .await
        .expect_err("a decode that traps is refused");
    tokio::time::timeout(HANG_GUARD, async {
        loop {
            match client.notice().await.expect("the connection is open") {
                Notice::Fault { .. } => break,
                Notice::Document { .. } | Notice::Gap { .. } | Notice::Disabled { .. } => {}
            }
        }
    })
    .await
    .expect("the fault was never written");

    // Privacy mode ends. The writer takes the report of the lost document and is held with it.
    let hold = served.host.hold_notice_writes();
    client
        .privacy(false)
        .await
        .expect("the end is acknowledged");
    reached(&hold, "the writer never took the report off the queue").await;

    client
        .unbind(request.binding_id)
        .await
        .expect("the unbind ran");
    register_on(&client, &request, &component).await;
    // A fault of the new registration waits in the queue behind the report in the writer's hand.
    // Once the worker reads it the writer is past the report, and so is whatever the report asked
    // of the new registration: a redraw is a command the registration's thread has in its input
    // before the call below, which runs after it.
    client
        .decode(
            request.binding_id,
            &components::native_request("se-3", "9", "!trap"),
            deadline,
        )
        .await
        .expect_err("a decode that traps is refused");
    hold.release();
    let told = tokio::time::timeout(HANG_GUARD, async {
        let mut told = Vec::new();
        loop {
            let notice = client.notice().await.expect("the connection is open");
            let fault = matches!(notice, Notice::Fault { .. });
            told.push(notice);
            if fault {
                return told;
            }
        }
    })
    .await
    .expect("the fault was never written");
    assert!(
        matches!(told.as_slice(), [Notice::Fault { .. }]),
        "the new registration was told what the removed one was owed: {told:?}"
    );

    // The new registration's first document is the one its caller asks for.
    let drawn = snapshot_drawn(&client, &request, deadline).await;
    assert_eq!(
        drawn, 1,
        "the new registration drew a document nobody asked it for"
    );
}

// The client's own notice queue is another place a removed binding's notices can wait. The host
// writes everything a registration produced before it answers that registration's unbind, so what
// the client's queue holds for the binding when the answer comes is the removed registration's, and
// a worker registers the identifier again only after it has the answer. An answer that says the
// host held no registration removed nothing: what the queue holds for that identifier may be a
// newer registration's, written while the request was still to be answered, and is kept.
//
// The host here is a program of the case's, because what the case needs is the order of the
// frames: a disabling of a binding and the answer to its unbind, the same for a binding the host
// holds none of, and then, once the client has been asked for something else, a notice of another
// binding that is always read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_shows_a_later_registration_nothing_its_queue_held_for_the_binding_it_removed() {
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
    let binding_id = new_binding_id();
    let newer = new_binding_id();
    let sentinel = new_binding_id();
    let left_behind = Notice::Disabled {
        binding_id: binding_id.get(),
        reason: "the removed registration's".to_owned(),
    };
    let kept = Notice::Disabled {
        binding_id: newer.get(),
        reason: "a newer registration's".to_owned(),
    };
    let after_it = Notice::Disabled {
        binding_id: sentinel.get(),
        reason: "the notice that is always read".to_owned(),
    };

    let serving = tokio::spawn({
        let descriptor = descriptor.clone();
        let left_behind = left_behind.clone();
        let kept = kept.clone();
        let after_it = after_it.clone();
        async move {
            let (connection, _peer) = listener.accept().await.expect("a connection");
            let (mut reader, mut writer) =
                kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
            // Until the client ends the connection, as the case does.
            while let Ok(request) = reader
                .read_message_without_schema::<kr_plugin_service::protocol::Request>()
                .await
            {
                let reply_to = request.request_id;
                let (notice, body) = match request.body {
                    RequestBody::Hello { .. } => (
                        None,
                        ResponseBody::Hello {
                            protocol: HostProtocol::THIS.name.to_owned(),
                            descriptor: Box::new(descriptor.clone()),
                        },
                    ),
                    RequestBody::Verify { nonce } => (
                        None,
                        ResponseBody::Verified(Box::new(
                            identity
                                .answer(&nonce, &descriptor.endpoint)
                                .expect("an answer"),
                        )),
                    ),
                    RequestBody::Unbind { binding_id: asked } if asked == newer.get() => {
                        (Some(kept.clone()), ResponseBody::Unbound { existed: false })
                    }
                    RequestBody::Unbind { .. } => (
                        Some(left_behind.clone()),
                        ResponseBody::Unbound { existed: true },
                    ),
                    RequestBody::Privacy { private } => {
                        (Some(after_it.clone()), ResponseBody::PrivacySet { private })
                    }
                    other => panic!("the client asked for {other:?}"),
                };
                if let Some(notice) = notice {
                    writer
                        .write_message(&Frame::Notice(notice))
                        .await
                        .expect("a notice is written");
                }
                writer
                    .write_message(&Frame::Response { reply_to, body })
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
    assert!(
        client
            .unbind(binding_id)
            .await
            .expect("the unbind is answered"),
        "the host's answer was not read as the binding removed"
    );
    assert!(
        !client.unbind(newer).await.expect("the unbind is answered"),
        "the host's answer was not read as no binding found"
    );
    // The worker registers the identifier again now; what it is sent for that is asked for by
    // something it says to the host.
    client.privacy(false).await.expect("privacy is set");

    let read = tokio::time::timeout(HANG_GUARD, async {
        let mut read = Vec::new();
        loop {
            let notice = client.notice().await.expect("the connection stood");
            let last = notice == after_it;
            read.push(notice);
            if last {
                return read;
            }
        }
    })
    .await
    .expect("the notice that is always read never came");
    assert_eq!(
        read,
        [kept, after_it],
        "the client kept what a removal that found nothing could not have left, or handed on what \
         its queue held for the binding it removed"
    );
    drop(client);
    serving.await.expect("the host program ended");
}

// What the client's queue holds for a binding goes when the host answers the removal, whether or not
// the caller of the unbind is still waiting for the answer. A caller that gives up on an unbind
// after the host has read it has no answer to act on, but the host has removed the registration all
// the same and a retry finds none to remove, so nothing but the client's own reading of the answer
// can empty the queue of what the removed registration left in it, and the identifier's next
// registration would be shown it.
//
// The host here is a program of the case's, because what the case needs is the order of the frames
// and when the answer comes: the unbind is read, its caller stops waiting for it, and only then does
// the host write a notice of the removed registration and the answer. The privacy request that
// follows is answered after the unbind's answer, with a notice that is always read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_empties_its_queue_for_an_unbind_whose_caller_stopped_waiting_when_the_host_answers_it()
 {
    let binding_id = new_binding_id();
    let left_behind = Notice::Disabled {
        binding_id: binding_id.get(),
        reason: "the removed registration's".to_owned(),
    };
    let after_it = Notice::Disabled {
        binding_id: new_binding_id().get(),
        reason: "the notice that is always read".to_owned(),
    };
    let (read_sender, read) = tokio::sync::oneshot::channel::<()>();
    let (go_sender, go) = tokio::sync::oneshot::channel::<()>();
    let (client, serving) = scripted_host({
        let left_behind = left_behind.clone();
        let after_it = after_it.clone();
        move |mut reader, mut writer| async move {
            let unbind: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the unbind");
            assert!(
                matches!(unbind.body, RequestBody::Unbind { .. }),
                "the client asked for {:?}",
                unbind.body
            );
            read_sender.send(()).expect("the case waits for the unbind");
            go.await.expect("the case lets the answer go");
            writer
                .write_message(&Frame::Notice(left_behind))
                .await
                .expect("a notice is written");
            writer
                .write_message(&Frame::Response {
                    reply_to: unbind.request_id,
                    body: ResponseBody::Unbound { existed: true },
                })
                .await
                .expect("the answer is written");
            let privacy: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the privacy request");
            let RequestBody::Privacy { private } = privacy.body else {
                panic!("the client asked for {:?}", privacy.body);
            };
            writer
                .write_message(&Frame::Notice(after_it))
                .await
                .expect("a notice is written");
            writer
                .write_message(&Frame::Response {
                    reply_to: privacy.request_id,
                    body: ResponseBody::PrivacySet { private },
                })
                .await
                .expect("the answer is written");
        }
    })
    .await;
    // The unbind is stopped by the case, and not by a deadline of its own.
    let client = Arc::new(client.unbinding_within(HANG_GUARD));

    let unbinding = tokio::spawn({
        let client = Arc::clone(&client);
        async move { client.unbind(binding_id).await }
    });
    tokio::time::timeout(HANG_GUARD, read)
        .await
        .expect("the host never read the unbind")
        .expect("the host program ended");
    on_the_wire(&client).await;
    unbinding.abort();
    assert!(
        unbinding
            .await
            .expect_err("the caller was stopped")
            .is_cancelled(),
        "the unbind's caller ended some other way"
    );
    go_sender.send(()).expect("the host program waits");
    client.privacy(false).await.expect("privacy is set");

    let notices = notices_until(&client, &after_it).await;
    assert_eq!(
        notices,
        [after_it],
        "the client kept what its queue held for the binding whose removal was answered after the \
         caller stopped waiting"
    );
    serving.await.expect("the host program ended");
}

// What a registration the host refused wrote is not shown to a later registration of the
// identifier. The host retracts what a refused registration left in its queue, but a notice the
// writer had already written is in the client's queue before the refusal comes, and the refusal is
// the only word the client has that the registration it was from is gone. A registration that is
// refused after nothing of the identifier was live leaves nothing of it in the queue.
//
// The host here is a program of the case's, because what the case needs is a notice from a
// registration that then fails. The privacy request that follows is answered with a notice that is
// always read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_shows_a_later_registration_nothing_a_registration_the_host_refused_wrote() {
    let request = components::request("well-behaved", 1);
    let component = ComponentSource {
        path: "unused".to_owned(),
        digest: PayloadDigest::of(b"unused"),
        bytes: 0,
    };
    let written = Notice::Disabled {
        binding_id: request.binding_id.get(),
        reason: "the refused registration's".to_owned(),
    };
    let after_it = Notice::Disabled {
        binding_id: new_binding_id().get(),
        reason: "the notice that is always read".to_owned(),
    };
    let (client, serving) = scripted_host({
        let written = written.clone();
        let after_it = after_it.clone();
        move |mut reader, mut writer| async move {
            let registration: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the registration");
            assert!(
                matches!(registration.body, RequestBody::RegisterBinding(_)),
                "the client asked for {:?}",
                registration.body
            );
            writer
                .write_message(&Frame::Notice(written))
                .await
                .expect("a notice is written");
            writer
                .write_message(&Frame::Response {
                    reply_to: registration.request_id,
                    body: ResponseBody::Refused {
                        request: "register_binding".to_owned(),
                        detail: "the binding could not be bound".to_owned(),
                        disabled: false,
                    },
                })
                .await
                .expect("the refusal is written");
            let privacy: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the privacy request");
            let RequestBody::Privacy { private } = privacy.body else {
                panic!("the client asked for {:?}", privacy.body);
            };
            writer
                .write_message(&Frame::Notice(after_it))
                .await
                .expect("a notice is written");
            writer
                .write_message(&Frame::Response {
                    reply_to: privacy.request_id,
                    body: ResponseBody::PrivacySet { private },
                })
                .await
                .expect("the answer is written");
        }
    })
    .await;

    let registered = client
        .register(
            request.binding_id,
            &request.identity,
            &request.facts,
            &request.executable,
            &component,
        )
        .await;
    assert!(
        matches!(&registered, Err(ServiceError::Protocol { .. })),
        "the refusal was read as {registered:?}"
    );
    client.privacy(false).await.expect("privacy is set");

    let notices = notices_until(&client, &after_it).await;
    assert_eq!(
        notices,
        [after_it],
        "the client kept what a registration the host refused wrote"
    );
    serving.await.expect("the host program ended");
}

// A registration the host refuses empties the client's queue only when no registration of the
// identifier is live: the refusal of a second registration of an identifier that is live (the host
// refuses it by name) says nothing of the live one, whose notices are the queue's and are shown.
//
// The host here is a program of the case's: the first registration is answered, a notice follows
// it, and a second registration of the identifier is refused. The privacy request that follows is
// answered with a notice that is always read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_keeps_what_a_live_registration_wrote_when_a_second_registration_of_the_identifier_is_refused()
 {
    let request = components::request("well-behaved", 1);
    let component = ComponentSource {
        path: "unused".to_owned(),
        digest: PayloadDigest::of(b"unused"),
        bytes: 0,
    };
    let live = Notice::Disabled {
        binding_id: request.binding_id.get(),
        reason: "the live registration's".to_owned(),
    };
    let after_it = Notice::Disabled {
        binding_id: new_binding_id().get(),
        reason: "the notice that is always read".to_owned(),
    };
    let (client, serving) = scripted_host({
        let live = live.clone();
        let after_it = after_it.clone();
        move |mut reader, mut writer| async move {
            let first: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the first registration");
            writer
                .write_message(&Frame::Response {
                    reply_to: first.request_id,
                    body: ResponseBody::Registered {
                        origin: "compiled".to_owned(),
                        elapsed_ms: 0,
                    },
                })
                .await
                .expect("the answer is written");
            writer
                .write_message(&Frame::Notice(live))
                .await
                .expect("a notice is written");
            let second: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the second registration");
            writer
                .write_message(&Frame::Response {
                    reply_to: second.request_id,
                    body: ResponseBody::Refused {
                        request: "register_binding".to_owned(),
                        detail: "binding is already live".to_owned(),
                        disabled: false,
                    },
                })
                .await
                .expect("the refusal is written");
            let privacy: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the privacy request");
            let RequestBody::Privacy { private } = privacy.body else {
                panic!("the client asked for {:?}", privacy.body);
            };
            writer
                .write_message(&Frame::Notice(after_it))
                .await
                .expect("a notice is written");
            writer
                .write_message(&Frame::Response {
                    reply_to: privacy.request_id,
                    body: ResponseBody::PrivacySet { private },
                })
                .await
                .expect("the answer is written");
        }
    })
    .await;

    let register = || {
        client.register(
            request.binding_id,
            &request.identity,
            &request.facts,
            &request.executable,
            &component,
        )
    };
    register()
        .await
        .expect("the first registration is answered");
    let second = register().await;
    assert!(
        matches!(&second, Err(ServiceError::Protocol { .. })),
        "the refusal was read as {second:?}"
    );
    client.privacy(false).await.expect("privacy is set");

    let notices = notices_until(&client, &after_it).await;
    assert_eq!(
        notices,
        [live, after_it],
        "the client emptied its queue of what the live registration wrote"
    );
    serving.await.expect("the host program ended");
}

// A removal that a registration overlapped says nothing of the registrations the client counts as
// live. The host answers `existed` for the registration the removal was about, which can be one that
// was still being made and was refused: a registration the client never counted as live. If the
// client took that answer for the removal of the live registration that replaced it, a later
// registration of the identifier that the host refuses would empty the queue of what the live
// registration wrote.
//
// The host here is a program of the case's own, because what the case needs is the order of the
// frames: a registration is read, an unbind of the identifier is read while it is under way, and the
// registration is refused. A second registration is answered as registered and writes a notice.
// Then the unbind is answered as having removed one, and a third registration is refused. The privacy
// request that follows is answered with a notice that is always read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_keeps_what_a_live_registration_wrote_when_the_unbind_of_a_refused_one_is_answered_late()
 {
    let request = components::request("well-behaved", 1);
    let component = ComponentSource {
        path: "unused".to_owned(),
        digest: PayloadDigest::of(b"unused"),
        bytes: 0,
    };
    let live = Notice::Disabled {
        binding_id: request.binding_id.get(),
        reason: "the live registration's".to_owned(),
    };
    let after_it = Notice::Disabled {
        binding_id: new_binding_id().get(),
        reason: "the notice that is always read".to_owned(),
    };
    let (first_sender, first) = tokio::sync::oneshot::channel::<()>();
    let (unbind_sender, unbind_read) = tokio::sync::oneshot::channel::<()>();
    let (client, serving) = scripted_host({
        let live = live.clone();
        let after_it = after_it.clone();
        move |mut reader, mut writer| async move {
            let refused_first: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the first registration");
            first_sender
                .send(())
                .expect("the case waits for the first registration");
            let unbind: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the unbind");
            assert!(
                matches!(unbind.body, RequestBody::Unbind { .. }),
                "the client asked for {:?}",
                unbind.body
            );
            unbind_sender
                .send(())
                .expect("the case waits for the unbind");
            writer
                .write_message(&Frame::Response {
                    reply_to: refused_first.request_id,
                    body: ResponseBody::Refused {
                        request: "register_binding".to_owned(),
                        detail: "binding was unbound while it was being registered".to_owned(),
                        disabled: false,
                    },
                })
                .await
                .expect("the refusal is written");
            let second: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the second registration");
            writer
                .write_message(&Frame::Response {
                    reply_to: second.request_id,
                    body: ResponseBody::Registered {
                        origin: "compiled".to_owned(),
                        elapsed_ms: 0,
                    },
                })
                .await
                .expect("the answer is written");
            writer
                .write_message(&Frame::Notice(live))
                .await
                .expect("a notice is written");
            writer
                .write_message(&Frame::Response {
                    reply_to: unbind.request_id,
                    body: ResponseBody::Unbound { existed: true },
                })
                .await
                .expect("the answer is written");
            let third: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the third registration");
            writer
                .write_message(&Frame::Response {
                    reply_to: third.request_id,
                    body: ResponseBody::Refused {
                        request: "register_binding".to_owned(),
                        detail: "binding is already live".to_owned(),
                        disabled: false,
                    },
                })
                .await
                .expect("the refusal is written");
            let privacy: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the privacy request");
            let RequestBody::Privacy { private } = privacy.body else {
                panic!("the client asked for {:?}", privacy.body);
            };
            writer
                .write_message(&Frame::Notice(after_it))
                .await
                .expect("a notice is written");
            writer
                .write_message(&Frame::Response {
                    reply_to: privacy.request_id,
                    body: ResponseBody::PrivacySet { private },
                })
                .await
                .expect("the answer is written");
        }
    })
    .await;
    let client = Arc::new(client.unbinding_within(HANG_GUARD));

    let registering = tokio::spawn({
        let client = Arc::clone(&client);
        let request = request.clone();
        let component = component.clone();
        async move {
            client
                .register(
                    request.binding_id,
                    &request.identity,
                    &request.facts,
                    &request.executable,
                    &component,
                )
                .await
        }
    });
    tokio::time::timeout(HANG_GUARD, first)
        .await
        .expect("the host never read the first registration")
        .expect("the host program ended");
    let unbinding = tokio::spawn({
        let client = Arc::clone(&client);
        let binding_id = request.binding_id;
        async move { client.unbind(binding_id).await }
    });
    tokio::time::timeout(HANG_GUARD, unbind_read)
        .await
        .expect("the host never read the unbind")
        .expect("the host program ended");
    let refused = registering.await.expect("the first registration ended");
    assert!(
        matches!(&refused, Err(ServiceError::Protocol { .. })),
        "the first registration was read as {refused:?}"
    );
    register_on(&client, &request, &component).await;
    let removed = unbinding
        .await
        .expect("the unbind task ended")
        .expect("the unbind was answered");
    assert!(
        removed,
        "the host's answer was not read as a binding removed"
    );
    let third = client
        .register(
            request.binding_id,
            &request.identity,
            &request.facts,
            &request.executable,
            &component,
        )
        .await;
    assert!(
        matches!(&third, Err(ServiceError::Protocol { .. })),
        "the third registration was read as {third:?}"
    );
    client.privacy(false).await.expect("privacy is set");

    let notices = notices_until(&client, &after_it).await;
    assert_eq!(
        notices,
        [live, after_it],
        "the refusal of a registration emptied the queue of what the live registration wrote"
    );
    serving.await.expect("the host program ended");
}

// A count of live registrations that an overlap left too high ends at the next removal that nothing
// overlapped, whatever the host answers it: the host holds no registration of the identifier when
// it answers, so the client counts none, and the refusal of a later registration empties the queue
// of what it wrote.
//
// The host here is a program of the case's own. A registration is answered as registered; a second
// is read, and an unbind is read while it is under way; the second is refused as already live, and
// the unbind is answered as having removed one, so the client counts one registration that the host
// no longer holds, which the overlap keeps it from correcting. A second unbind, which nothing
// overlaps, is answered as having found nothing. A third registration writes a notice and is
// refused. The privacy request that follows is answered with a notice that is always read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_count_of_live_registrations_that_an_overlap_left_too_high_ends_at_the_next_removal_nothing_overlapped()
 {
    let request = components::request("well-behaved", 1);
    let component = ComponentSource {
        path: "unused".to_owned(),
        digest: PayloadDigest::of(b"unused"),
        bytes: 0,
    };
    let written = Notice::Disabled {
        binding_id: request.binding_id.get(),
        reason: "the refused registration's".to_owned(),
    };
    let after_it = Notice::Disabled {
        binding_id: new_binding_id().get(),
        reason: "the notice that is always read".to_owned(),
    };
    let (second_sender, second_read) = tokio::sync::oneshot::channel::<()>();
    let (unbind_sender, unbind_read) = tokio::sync::oneshot::channel::<()>();
    let (client, serving) = scripted_host({
        let written = written.clone();
        let after_it = after_it.clone();
        move |mut reader, mut writer| async move {
            let first: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the first registration");
            writer
                .write_message(&Frame::Response {
                    reply_to: first.request_id,
                    body: ResponseBody::Registered {
                        origin: "compiled".to_owned(),
                        elapsed_ms: 0,
                    },
                })
                .await
                .expect("the answer is written");
            let second: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the second registration");
            second_sender
                .send(())
                .expect("the case waits for the second registration");
            let unbind: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the unbind");
            assert!(
                matches!(unbind.body, RequestBody::Unbind { .. }),
                "the client asked for {:?}",
                unbind.body
            );
            unbind_sender
                .send(())
                .expect("the case waits for the unbind");
            writer
                .write_message(&Frame::Response {
                    reply_to: second.request_id,
                    body: ResponseBody::Refused {
                        request: "register_binding".to_owned(),
                        detail: "binding is already live".to_owned(),
                        disabled: false,
                    },
                })
                .await
                .expect("the refusal is written");
            writer
                .write_message(&Frame::Response {
                    reply_to: unbind.request_id,
                    body: ResponseBody::Unbound { existed: true },
                })
                .await
                .expect("the answer is written");
            let nothing: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the second unbind");
            writer
                .write_message(&Frame::Response {
                    reply_to: nothing.request_id,
                    body: ResponseBody::Unbound { existed: false },
                })
                .await
                .expect("the answer is written");
            let third: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the third registration");
            writer
                .write_message(&Frame::Notice(written))
                .await
                .expect("a notice is written");
            writer
                .write_message(&Frame::Response {
                    reply_to: third.request_id,
                    body: ResponseBody::Refused {
                        request: "register_binding".to_owned(),
                        detail: "the binding could not be bound".to_owned(),
                        disabled: false,
                    },
                })
                .await
                .expect("the refusal is written");
            let privacy: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the privacy request");
            let RequestBody::Privacy { private } = privacy.body else {
                panic!("the client asked for {:?}", privacy.body);
            };
            writer
                .write_message(&Frame::Notice(after_it))
                .await
                .expect("a notice is written");
            writer
                .write_message(&Frame::Response {
                    reply_to: privacy.request_id,
                    body: ResponseBody::PrivacySet { private },
                })
                .await
                .expect("the answer is written");
        }
    })
    .await;
    let client = Arc::new(client.unbinding_within(HANG_GUARD));

    register_on(&client, &request, &component).await;
    let second = tokio::spawn({
        let client = Arc::clone(&client);
        let request = request.clone();
        let component = component.clone();
        async move {
            client
                .register(
                    request.binding_id,
                    &request.identity,
                    &request.facts,
                    &request.executable,
                    &component,
                )
                .await
        }
    });
    tokio::time::timeout(HANG_GUARD, second_read)
        .await
        .expect("the host never read the second registration")
        .expect("the host program ended");
    let removing = tokio::spawn({
        let client = Arc::clone(&client);
        let binding_id = request.binding_id;
        async move { client.unbind(binding_id).await }
    });
    tokio::time::timeout(HANG_GUARD, unbind_read)
        .await
        .expect("the host never read the unbind")
        .expect("the host program ended");
    let refused = second.await.expect("the second registration ended");
    assert!(
        matches!(&refused, Err(ServiceError::Protocol { .. })),
        "the second registration was read as {refused:?}"
    );
    assert!(
        removing
            .await
            .expect("the unbind task ended")
            .expect("the unbind was answered"),
        "the host's answer was not read as a binding removed"
    );
    // Nothing overlaps this removal, and the host holds none.
    assert!(
        !client
            .unbind(request.binding_id)
            .await
            .expect("the second unbind is answered"),
        "the host's answer was not read as no binding found"
    );
    let third = client
        .register(
            request.binding_id,
            &request.identity,
            &request.facts,
            &request.executable,
            &component,
        )
        .await;
    assert!(
        matches!(&third, Err(ServiceError::Protocol { .. })),
        "the third registration was read as {third:?}"
    );
    client.privacy(false).await.expect("privacy is set");

    let notices = notices_until(&client, &after_it).await;
    assert_eq!(
        notices,
        [after_it],
        "the client still counted a registration as live after a removal nothing overlapped found \
         the host holding none"
    );
    serving.await.expect("the host program ended");
}

// Two removals of one registration, one of them refused, do not leave the client's account below
// what the host holds. The host answers the second unbind of a registration that its first one is
// removing as refused, with the registration out of the runtime, and the first as having removed
// one, which can come after a registration of the identifier that was started in between. That
// answer is overlapped by the registration and is not taken off the count, so the refusal of a
// later registration does not empty the queue of what the live registration wrote.
//
// The host here is a program of the case's own: a registration is answered, two unbinds are read,
// the second is answered as refused, a second registration is answered as registered and writes a
// notice, and only then the first unbind is answered as having removed one. A third registration
// is refused, and the privacy request that follows is answered with a notice that is always read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_keeps_what_a_live_registration_wrote_when_the_first_of_two_unbinds_is_answered_after_a_registration_started()
 {
    let request = components::request("well-behaved", 1);
    let component = ComponentSource {
        path: "unused".to_owned(),
        digest: PayloadDigest::of(b"unused"),
        bytes: 0,
    };
    let live = Notice::Disabled {
        binding_id: request.binding_id.get(),
        reason: "the live registration's".to_owned(),
    };
    let after_it = Notice::Disabled {
        binding_id: new_binding_id().get(),
        reason: "the notice that is always read".to_owned(),
    };
    let (first_sender, first_read) = tokio::sync::oneshot::channel::<()>();
    let (second_sender, second_read) = tokio::sync::oneshot::channel::<()>();
    let (client, serving) = scripted_host({
        let live = live.clone();
        let after_it = after_it.clone();
        move |mut reader, mut writer| async move {
            let registration: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the first registration");
            writer
                .write_message(&Frame::Response {
                    reply_to: registration.request_id,
                    body: ResponseBody::Registered {
                        origin: "compiled".to_owned(),
                        elapsed_ms: 0,
                    },
                })
                .await
                .expect("the answer is written");
            let first: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the first unbind");
            first_sender
                .send(())
                .expect("the case waits for the first unbind");
            let second: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the second unbind");
            second_sender
                .send(())
                .expect("the case waits for the second unbind");
            writer
                .write_message(&Frame::Response {
                    reply_to: second.request_id,
                    body: ResponseBody::Refused {
                        request: "unbind".to_owned(),
                        detail: "this connection already has the calls it may have running"
                            .to_owned(),
                        disabled: false,
                    },
                })
                .await
                .expect("the refusal is written");
            let again: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the second registration");
            writer
                .write_message(&Frame::Response {
                    reply_to: again.request_id,
                    body: ResponseBody::Registered {
                        origin: "compiled".to_owned(),
                        elapsed_ms: 0,
                    },
                })
                .await
                .expect("the answer is written");
            writer
                .write_message(&Frame::Notice(live))
                .await
                .expect("a notice is written");
            writer
                .write_message(&Frame::Response {
                    reply_to: first.request_id,
                    body: ResponseBody::Unbound { existed: true },
                })
                .await
                .expect("the answer is written");
            let third: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the third registration");
            writer
                .write_message(&Frame::Response {
                    reply_to: third.request_id,
                    body: ResponseBody::Refused {
                        request: "register_binding".to_owned(),
                        detail: "binding is already live".to_owned(),
                        disabled: false,
                    },
                })
                .await
                .expect("the refusal is written");
            let privacy: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the privacy request");
            let RequestBody::Privacy { private } = privacy.body else {
                panic!("the client asked for {:?}", privacy.body);
            };
            writer
                .write_message(&Frame::Notice(after_it))
                .await
                .expect("a notice is written");
            writer
                .write_message(&Frame::Response {
                    reply_to: privacy.request_id,
                    body: ResponseBody::PrivacySet { private },
                })
                .await
                .expect("the answer is written");
        }
    })
    .await;
    let client = Arc::new(client.unbinding_within(HANG_GUARD));

    register_on(&client, &request, &component).await;
    let first = tokio::spawn({
        let client = Arc::clone(&client);
        let binding_id = request.binding_id;
        async move { client.unbind(binding_id).await }
    });
    tokio::time::timeout(HANG_GUARD, first_read)
        .await
        .expect("the host never read the first unbind")
        .expect("the host program ended");
    let second = tokio::spawn({
        let client = Arc::clone(&client);
        let binding_id = request.binding_id;
        async move { client.unbind(binding_id).await }
    });
    tokio::time::timeout(HANG_GUARD, second_read)
        .await
        .expect("the host never read the second unbind")
        .expect("the host program ended");
    let refused = second.await.expect("the second unbind task ended");
    assert!(
        matches!(&refused, Err(ServiceError::Protocol { .. })),
        "the second unbind was read as {refused:?}"
    );
    register_on(&client, &request, &component).await;
    assert!(
        first
            .await
            .expect("the first unbind task ended")
            .expect("the first unbind was answered"),
        "the host's answer was not read as a binding removed"
    );
    let third = client
        .register(
            request.binding_id,
            &request.identity,
            &request.facts,
            &request.executable,
            &component,
        )
        .await;
    assert!(
        matches!(&third, Err(ServiceError::Protocol { .. })),
        "the third registration was read as {third:?}"
    );
    client.privacy(false).await.expect("privacy is set");

    let notices = notices_until(&client, &after_it).await;
    assert_eq!(
        notices,
        [live, after_it],
        "the refusal of a registration emptied the queue of what the live registration wrote"
    );
    serving.await.expect("the host program ended");
}

// The removal of the live registration takes it off the client's account of what is live: a
// registration of the identifier that the host refuses afterwards is one nothing else could own the
// notices of, and the client empties its queue of them.
//
// The host here is a program of the case's own: the first registration is answered, an unbind is
// answered as having removed one, and a second registration writes a notice and is refused. The
// privacy request that follows is answered with a notice that is always read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_empties_its_queue_when_a_registration_is_refused_after_the_live_one_was_removed()
{
    let request = components::request("well-behaved", 1);
    let component = ComponentSource {
        path: "unused".to_owned(),
        digest: PayloadDigest::of(b"unused"),
        bytes: 0,
    };
    let written = Notice::Disabled {
        binding_id: request.binding_id.get(),
        reason: "the refused registration's".to_owned(),
    };
    let after_it = Notice::Disabled {
        binding_id: new_binding_id().get(),
        reason: "the notice that is always read".to_owned(),
    };
    let (client, serving) = scripted_host({
        let written = written.clone();
        let after_it = after_it.clone();
        move |mut reader, mut writer| async move {
            let first: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the first registration");
            writer
                .write_message(&Frame::Response {
                    reply_to: first.request_id,
                    body: ResponseBody::Registered {
                        origin: "compiled".to_owned(),
                        elapsed_ms: 0,
                    },
                })
                .await
                .expect("the answer is written");
            let unbind: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the unbind");
            writer
                .write_message(&Frame::Response {
                    reply_to: unbind.request_id,
                    body: ResponseBody::Unbound { existed: true },
                })
                .await
                .expect("the answer is written");
            let second: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the second registration");
            writer
                .write_message(&Frame::Notice(written))
                .await
                .expect("a notice is written");
            writer
                .write_message(&Frame::Response {
                    reply_to: second.request_id,
                    body: ResponseBody::Refused {
                        request: "register_binding".to_owned(),
                        detail: "the binding could not be bound".to_owned(),
                        disabled: false,
                    },
                })
                .await
                .expect("the refusal is written");
            let privacy: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the privacy request");
            let RequestBody::Privacy { private } = privacy.body else {
                panic!("the client asked for {:?}", privacy.body);
            };
            writer
                .write_message(&Frame::Notice(after_it))
                .await
                .expect("a notice is written");
            writer
                .write_message(&Frame::Response {
                    reply_to: privacy.request_id,
                    body: ResponseBody::PrivacySet { private },
                })
                .await
                .expect("the answer is written");
        }
    })
    .await;
    let client = client.unbinding_within(HANG_GUARD);

    register_on(&client, &request, &component).await;
    assert!(
        client
            .unbind(request.binding_id)
            .await
            .expect("the unbind is answered"),
        "the host's answer was not read as the binding removed"
    );
    let second = client
        .register(
            request.binding_id,
            &request.identity,
            &request.facts,
            &request.executable,
            &component,
        )
        .await;
    assert!(
        matches!(&second, Err(ServiceError::Protocol { .. })),
        "the refusal was read as {second:?}"
    );
    client.privacy(false).await.expect("privacy is set");

    let notices = notices_until(&client, &after_it).await;
    assert_eq!(
        notices,
        [after_it],
        "the client still counted a registration as live after the host removed it"
    );
    serving.await.expect("the host program ended");
}

// The refusal of a registration says nothing of another registration of the identifier that is
// still waiting for its answer: the host refuses a second registration of an identifier it is
// registering by name, and the first goes on to write its notices. Those are the queue's, and the
// refusal leaves them.
//
// The host here is a program of the case's: it reads two registrations of one identifier, writes a
// notice, refuses the second, and only then answers the first. The privacy request that follows is
// answered with a notice that is always read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_keeps_what_a_registration_under_way_wrote_when_a_second_registration_of_the_identifier_is_refused()
 {
    let request = components::request("well-behaved", 1);
    let component = ComponentSource {
        path: "unused".to_owned(),
        digest: PayloadDigest::of(b"unused"),
        bytes: 0,
    };
    let under_way = Notice::Disabled {
        binding_id: request.binding_id.get(),
        reason: "the registration under way's".to_owned(),
    };
    let after_it = Notice::Disabled {
        binding_id: new_binding_id().get(),
        reason: "the notice that is always read".to_owned(),
    };
    let (first_sender, first) = tokio::sync::oneshot::channel::<()>();
    let (client, serving) = scripted_host({
        let under_way = under_way.clone();
        let after_it = after_it.clone();
        move |mut reader, mut writer| async move {
            let first_request: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the first registration");
            first_sender
                .send(())
                .expect("the case waits for the first registration");
            let second: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the second registration");
            writer
                .write_message(&Frame::Notice(under_way))
                .await
                .expect("a notice is written");
            writer
                .write_message(&Frame::Response {
                    reply_to: second.request_id,
                    body: ResponseBody::Refused {
                        request: "register_binding".to_owned(),
                        detail: "binding is already live".to_owned(),
                        disabled: false,
                    },
                })
                .await
                .expect("the refusal is written");
            writer
                .write_message(&Frame::Response {
                    reply_to: first_request.request_id,
                    body: ResponseBody::Registered {
                        origin: "compiled".to_owned(),
                        elapsed_ms: 0,
                    },
                })
                .await
                .expect("the answer is written");
            let privacy: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the privacy request");
            let RequestBody::Privacy { private } = privacy.body else {
                panic!("the client asked for {:?}", privacy.body);
            };
            writer
                .write_message(&Frame::Notice(after_it))
                .await
                .expect("a notice is written");
            writer
                .write_message(&Frame::Response {
                    reply_to: privacy.request_id,
                    body: ResponseBody::PrivacySet { private },
                })
                .await
                .expect("the answer is written");
        }
    })
    .await;
    let client = Arc::new(client);

    let registering = tokio::spawn({
        let client = Arc::clone(&client);
        let request = request.clone();
        let component = component.clone();
        async move { register_on(&client, &request, &component).await }
    });
    tokio::time::timeout(HANG_GUARD, first)
        .await
        .expect("the host never read the first registration")
        .expect("the host program ended");
    let second = client
        .register(
            request.binding_id,
            &request.identity,
            &request.facts,
            &request.executable,
            &component,
        )
        .await;
    assert!(
        matches!(&second, Err(ServiceError::Protocol { .. })),
        "the refusal was read as {second:?}"
    );
    registering
        .await
        .expect("the first registration was answered");
    client.privacy(false).await.expect("privacy is set");

    let notices = notices_until(&client, &after_it).await;
    assert_eq!(
        notices,
        [under_way, after_it],
        "the client emptied its queue of what the registration under way wrote"
    );
    serving.await.expect("the host program ended");
}

// A registration whose request was never written is not under way: its caller stopped before the
// client could write it, so the host knows nothing of it and will answer nothing, and the client
// does not wait for an answer to it. A removal of the identifier that comes after it is not
// overlapped by it.
//
// The connection's writer is held, so that the registration waits for it and is dropped there, after
// the client has recorded it and before it can have written anything. A removal then runs, and the
// host here, a program of the case's, answers it with a notice of the removed registration before
// the answer; the client empties its queue of that notice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_registration_whose_request_was_never_written_leaves_nothing_under_way() {
    let request = components::request("well-behaved", 1);
    let component = ComponentSource {
        path: "unused".to_owned(),
        digest: PayloadDigest::of(b"unused"),
        bytes: 0,
    };
    let left_behind = Notice::Disabled {
        binding_id: request.binding_id.get(),
        reason: "the removed registration's".to_owned(),
    };
    let after_it = Notice::Disabled {
        binding_id: new_binding_id().get(),
        reason: "the notice that is always read".to_owned(),
    };
    let (client, serving) = scripted_host({
        let left_behind = left_behind.clone();
        let after_it = after_it.clone();
        move |mut reader, mut writer| async move {
            let unbind: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the unbind");
            assert!(
                matches!(unbind.body, RequestBody::Unbind { .. }),
                "the client wrote {:?}, and the registration was dropped before it could write",
                unbind.body
            );
            writer
                .write_message(&Frame::Notice(left_behind))
                .await
                .expect("a notice is written");
            writer
                .write_message(&Frame::Response {
                    reply_to: unbind.request_id,
                    body: ResponseBody::Unbound { existed: true },
                })
                .await
                .expect("the answer is written");
            let privacy: kr_plugin_service::protocol::Request = reader
                .read_message_without_schema()
                .await
                .expect("the privacy request");
            let RequestBody::Privacy { private } = privacy.body else {
                panic!("the client asked for {:?}", privacy.body);
            };
            writer
                .write_message(&Frame::Notice(after_it))
                .await
                .expect("a notice is written");
            writer
                .write_message(&Frame::Response {
                    reply_to: privacy.request_id,
                    body: ResponseBody::PrivacySet { private },
                })
                .await
                .expect("the answer is written");
        }
    })
    .await;
    let client = client.unbinding_within(HANG_GUARD);

    let writer = client.hold_writer().await;
    {
        let mut registering = core::pin::pin!(client.register(
            request.binding_id,
            &request.identity,
            &request.facts,
            &request.executable,
            &component,
        ));
        // One poll takes the registration as far as the writer, which is held, and no further.
        core::future::poll_fn(|context| {
            assert!(
                registering.as_mut().poll(context).is_pending(),
                "the registration went on without the connection's writer"
            );
            core::task::Poll::Ready(())
        })
        .await;
    }
    drop(writer);

    assert!(
        client
            .unbind(request.binding_id)
            .await
            .expect("the unbind is answered"),
        "the host's answer was not read as the binding removed"
    );
    client.privacy(false).await.expect("privacy is set");

    let notices = notices_until(&client, &after_it).await;
    assert_eq!(
        notices,
        [after_it],
        "the client kept what its queue held for a removal that a registration never written \
         was said to overlap"
    );
    serving.await.expect("the host program ended");
}

// A caller that registers an identifier again before the host has answered the removal of its
// previous registration cannot be given an exact account of the client's queue: the host removes the
// binding from its runtime first and waits for its thread after, so the new registration can bind and
// write its first notices before the old one's removal is answered, and nothing in a notice says
// which registration it is from. The client keeps what its queue holds then, and does not empty it
// of the new registration's notices with the old one's.
//
// The first registration's thread stands at a stopped pass, so its removal waits. The identifier is
// registered again, and the case waits until the new registration's first document is in the
// client's queue, unread. Then the pass is let go and the removal answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_keeps_what_the_new_registration_wrote_before_the_removal_of_the_old_one_was_answered()
 {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let served = Served::start_unbinding_within(HANG_GUARD).await;
    let client = Arc::new(served.client().await.unbinding_within(HANG_GUARD));
    let (path, digest, bytes) = served.install("well-behaved", &wasm);
    let component = ComponentSource {
        path,
        digest,
        bytes,
    };
    let request = components::request("well-behaved", 1);
    register_on(&client, &request, &component).await;
    notices_through(&client, request.binding_id, "bind", 1).await;
    let stop = overflow_behind_a_stopped_pass(&served, &client, &request).await;

    let removing = tokio::spawn({
        let client = Arc::clone(&client);
        let binding_id = request.binding_id;
        async move { client.unbind(binding_id).await }
    });
    health_until(&client, |health| health.live_bindings == 0).await;
    register_on(&client, &request, &component).await;
    tokio::time::timeout(HANG_GUARD, async {
        while client.held_notice_bytes() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the new registration's first document never reached the client's queue");

    stop.release();
    let existed = tokio::time::timeout(HANG_GUARD, removing)
        .await
        .expect("the unbind was answered")
        .expect("the unbind task ended")
        .expect("the unbind ran");
    assert!(existed, "the removed binding was not there to remove");
    // Looked at as soon as the removal is answered: a queue emptied in error shows here, and not
    // when the case gives up on a document that is never coming.
    assert_ne!(
        client.held_notice_bytes(),
        0,
        "the unbind emptied the queue of what the new registration wrote"
    );
    let bound = notices_through(&client, request.binding_id, "bind", 1).await;
    assert_eq!(
        bound.len(),
        1,
        "the new registration's first document was not kept: {bound:?}"
    );
}

// The same holds when the registration of the identifier was under way before the removal began, and
// finished while it waited: the client cannot tell its first notices from the removed registration's
// either, so it keeps what its queue holds.
//
// The new registration is held where the host has read its request and nothing else, by the gate file
// the host honours in the state directory it files its cache in. The removal begins then: the host
// removes the live registration, whose thread stands at a stopped pass. The gate is opened, the
// registration finishes, its first document is in the client's queue unread, and the pass is let go.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_keeps_what_a_registration_already_under_way_wrote_before_the_removal_of_the_old_one_was_answered()
 {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let served = Served::start_unbinding_within(HANG_GUARD).await;
    let client = Arc::new(served.client().await.unbinding_within(HANG_GUARD));
    let (path, digest, bytes) = served.install("well-behaved", &wasm);
    let component = ComponentSource {
        path,
        digest,
        bytes,
    };
    let request = components::request("well-behaved", 1);
    register_on(&client, &request, &component).await;
    notices_through(&client, request.binding_id, "bind", 1).await;
    let stop = overflow_behind_a_stopped_pass(&served, &client, &request).await;

    let state = served._temp.environment().state_dir().to_path_buf();
    let gate = state.join("hold-registrations");
    std::fs::write(&gate, b"").expect("the gate is closed");
    let registering = tokio::spawn({
        let client = Arc::clone(&client);
        let request = request.clone();
        let component = component.clone();
        async move { register_on(&client, &request, &component).await }
    });
    appears(&state.join("hold-registrations.reached")).await;

    let removing = tokio::spawn({
        let client = Arc::clone(&client);
        let binding_id = request.binding_id;
        async move { client.unbind(binding_id).await }
    });
    health_until(&client, |health| health.live_bindings == 0).await;
    std::fs::remove_file(&gate).expect("the gate is opened");
    tokio::time::timeout(HANG_GUARD, registering)
        .await
        .expect("the new registration was answered")
        .expect("the registration task ended");
    tokio::time::timeout(HANG_GUARD, async {
        while client.held_notice_bytes() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the new registration's first document never reached the client's queue");

    stop.release();
    let existed = tokio::time::timeout(HANG_GUARD, removing)
        .await
        .expect("the unbind was answered")
        .expect("the unbind task ended")
        .expect("the unbind ran");
    assert!(existed, "the removed binding was not there to remove");
    // Looked at as soon as the removal is answered, as in the case above.
    assert_ne!(
        client.held_notice_bytes(),
        0,
        "the unbind emptied the queue of what the registration under way wrote"
    );
    let bound = notices_through(&client, request.binding_id, "bind", 1).await;
    assert_eq!(
        bound.len(),
        1,
        "the new registration's first document was not kept: {bound:?}"
    );
}

// A registration is under way until the host has answered it, and not until its caller stops waiting.
// A caller that gives up on a registration after its request is on the wire leaves the host making
// it, and the registration writes its first notices as any other would, so a removal of the
// identifier that begins afterwards still overlaps it and the client keeps what its queue holds.
//
// The new registration is held where the host has read its request and nothing else, by the gate file
// the host honours in the state directory it files its cache in, and its caller stops waiting for it
// there. The removal begins: the host removes the live registration, whose thread stands at a stopped
// pass. The gate is opened, the registration finishes without its caller, its first document is in
// the client's queue unread, and the pass is let go. The queue is looked at as soon as the removal is
// answered, so a queue emptied in error shows then and not when the case gives up on the document.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_keeps_what_a_registration_wrote_whose_caller_stopped_waiting_for_it_before_the_removal_of_the_old_one_was_answered()
 {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let served = Served::start_unbinding_within(HANG_GUARD).await;
    let client = Arc::new(served.client().await.unbinding_within(HANG_GUARD));
    let (path, digest, bytes) = served.install("well-behaved", &wasm);
    let component = ComponentSource {
        path,
        digest,
        bytes,
    };
    let request = components::request("well-behaved", 1);
    register_on(&client, &request, &component).await;
    notices_through(&client, request.binding_id, "bind", 1).await;
    let stop = overflow_behind_a_stopped_pass(&served, &client, &request).await;

    let state = served._temp.environment().state_dir().to_path_buf();
    let gate = state.join("hold-registrations");
    std::fs::write(&gate, b"").expect("the gate is closed");
    let registering = tokio::spawn({
        let client = Arc::clone(&client);
        let request = request.clone();
        let component = component.clone();
        async move { register_on(&client, &request, &component).await }
    });
    appears(&state.join("hold-registrations.reached")).await;
    on_the_wire(&client).await;
    registering.abort();
    assert!(
        registering
            .await
            .expect_err("the caller was stopped")
            .is_cancelled(),
        "the registration's caller ended some other way"
    );

    let removing = tokio::spawn({
        let client = Arc::clone(&client);
        let binding_id = request.binding_id;
        async move { client.unbind(binding_id).await }
    });
    health_until(&client, |health| health.live_bindings == 0).await;
    std::fs::remove_file(&gate).expect("the gate is opened");
    tokio::time::timeout(HANG_GUARD, async {
        while client.held_notice_bytes() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the new registration's first document never reached the client's queue");

    stop.release();
    let existed = tokio::time::timeout(HANG_GUARD, removing)
        .await
        .expect("the unbind was answered")
        .expect("the unbind task ended")
        .expect("the unbind ran");
    assert!(existed, "the removed binding was not there to remove");
    assert_ne!(
        client.held_notice_bytes(),
        0,
        "the unbind emptied the queue of what the registration whose caller stopped waiting wrote"
    );
    let bound = notices_through(&client, request.binding_id, "bind", 1).await;
    assert_eq!(
        bound.len(),
        1,
        "the new registration's first document was not kept: {bound:?}"
    );
}

// A removal that no registration overlapped empties the client's queue of the identifier, whatever
// else is going on: another removal of the identifier that waits, because the registration it
// removes is stopped at a pass, does not make this one keep what the registration it removed wrote.
//
// The first registration's removal waits at a stopped pass. The identifier is registered again, the
// registration's first document is in the client's queue unread, and that registration is removed.
// The removal is answered with the registration's thread ended, and nothing started a registration
// while it waited, so the queue holds nothing of the identifier.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_empties_its_queue_for_a_removal_no_registration_overlapped_while_another_removal_waits()
 {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let served = Served::start_unbinding_within(HANG_GUARD).await;
    let client = Arc::new(served.client().await.unbinding_within(HANG_GUARD));
    let (path, digest, bytes) = served.install("well-behaved", &wasm);
    let component = ComponentSource {
        path,
        digest,
        bytes,
    };
    let request = components::request("well-behaved", 1);
    register_on(&client, &request, &component).await;
    notices_through(&client, request.binding_id, "bind", 1).await;
    let stop = overflow_behind_a_stopped_pass(&served, &client, &request).await;

    let removing = tokio::spawn({
        let client = Arc::clone(&client);
        let binding_id = request.binding_id;
        async move { client.unbind(binding_id).await }
    });
    health_until(&client, |health| health.live_bindings == 0).await;
    register_on(&client, &request, &component).await;
    tokio::time::timeout(HANG_GUARD, async {
        while client.held_notice_bytes() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the new registration's first document never reached the client's queue");

    let existed = client
        .unbind(request.binding_id)
        .await
        .expect("the second unbind ran");
    assert!(existed, "the second registration was not there to remove");
    assert_eq!(
        client.held_notice_bytes(),
        0,
        "the queue still held what the removed registration left in it"
    );

    stop.release();
    tokio::time::timeout(HANG_GUARD, removing)
        .await
        .expect("the first unbind was answered")
        .expect("the unbind task ended")
        .expect("the first unbind ran");
}

// An unbind is about the registration the connection holds under the identifier when the request
// is read, and not about whichever it holds when the request's task gets to run. A worker that
// unbinds twice and registers the identifier again must not have the second unbind take away the
// new registration.
//
// The first unbind is carried out. The second is read, and its task is held where it starts. The
// identifier is registered again, and only then does the task run: it finds the registration the
// connection held when the request was read, which was none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unbind_is_about_the_registration_the_connection_held_when_the_request_was_read() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let served = Served::start_unbinding_within(HANG_GUARD).await;
    let (path, digest, bytes) = served.install("well-behaved", &wasm);
    let component = ComponentSource {
        path,
        digest,
        bytes,
    };
    let mut raw = Raw::connect(&served).await;
    let request = components::request("well-behaved", 1);
    let registered = raw.register(&request, &component).await;
    assert!(
        matches!(registered, ResponseBody::Registered { .. }),
        "the binding was answered with {registered:?}"
    );
    let removed = raw.unbind(&request).await;
    assert!(
        matches!(removed, ResponseBody::Unbound { existed: true }),
        "the first unbind was answered with {removed:?}"
    );

    let hold = served.host.hold_unbinds_before_they_run();
    let again = raw.send_unbind(&request).await;
    reached(&hold, "the second unbind's task never started").await;
    let registered = raw.register(&request, &component).await;
    assert!(
        matches!(registered, ResponseBody::Registered { .. }),
        "the binding was answered with {registered:?}"
    );
    hold.release();

    let answered = raw.collect(&[again]).await.pop().expect("one answer");
    assert!(
        matches!(answered, ResponseBody::Unbound { existed: false }),
        "the second unbind was answered with {answered:?}"
    );
    let health = raw.health().await;
    assert_eq!(
        (health.live_bindings, health.connection_bindings),
        (1, 1),
        "the second unbind took the new registration away"
    );
}

/// Reads `call`, a call into the binding `request` registers, while the call's task is held; removes
/// the registration and registers the identifier again; and lets the task run. The call is about
/// the registration it was read under: its component is gone, so the call is refused, and the
/// component of the registration made after it has finished no call it was not asked for.
async fn a_call_read_before_the_registration_was_removed(
    name: &str,
    call: impl FnOnce(kr_protocol::scalars::Uuid) -> RequestBody,
) {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let served = Served::start_unbinding_within(HANG_GUARD).await;
    let (path, digest, bytes) = served.install("well-behaved", &wasm);
    let component = ComponentSource {
        path,
        digest,
        bytes,
    };
    let mut raw = Raw::connect(&served).await;
    let request = components::request("well-behaved", 1);
    let registered = raw.register(&request, &component).await;
    assert!(
        matches!(registered, ResponseBody::Registered { .. }),
        "the binding was answered with {registered:?}"
    );

    let hold = served.host.hold_calls_before_they_run();
    let asked = raw.send(call(request.binding_id.get())).await;
    reached(&hold, "the call's task never started").await;
    let removed = raw.unbind(&request).await;
    assert!(
        matches!(removed, ResponseBody::Unbound { existed: true }),
        "the unbind before the {name} ran was answered with {removed:?}"
    );
    let registered = raw.register(&request, &component).await;
    assert!(
        matches!(registered, ResponseBody::Registered { .. }),
        "the binding was answered with {registered:?}"
    );
    let before = raw.health().await.component_calls;
    hold.release();

    // Refused as a call on a binding that is gone, and not by a deadline of its own: a refusal for
    // the time the call took would be given just as well by a host that ran it in the registration
    // made after it, if that registration's thread were slow to take it.
    let answered = raw.collect(&[asked]).await.pop().expect("one answer");
    let gone = kr_plugin_runtime::RuntimeError::NoSuchBinding {
        binding: request.binding_id.get().to_string(),
    }
    .to_string();
    assert!(
        matches!(
            &answered,
            ResponseBody::Refused { detail, disabled: false, .. } if *detail == gone
        ),
        "a {name} read before the registration was removed was answered with {answered:?}, and not \
         as a call on a binding that is gone"
    );
    let after = raw.health().await.component_calls;
    assert_eq!(
        before, after,
        "a {name} read before the registration was removed was carried out in the registration \
         made after it"
    );
}

// A snapshot is about the registration the connection held under the identifier when the request
// was read, and not about whichever it holds when the request's task gets to run. The task is held
// where it starts, so that the registration can be removed and the identifier registered again
// before it runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_snapshot_is_about_the_registration_the_connection_held_when_the_request_was_read() {
    a_call_read_before_the_registration_was_removed("snapshot", |binding_id| {
        RequestBody::Snapshot {
            binding_id,
            deadline_ms: 20_000,
        }
    })
    .await;
}

// A restore is about the registration the connection held under the identifier when the request was
// read, as a snapshot is: a checkpoint of the registration that was removed is not applied to the
// one made after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restore_is_about_the_registration_the_connection_held_when_the_request_was_read() {
    a_call_read_before_the_registration_was_removed("restore", |binding_id| RequestBody::Restore {
        binding_id,
        state: Vec::new(),
        deadline_ms: 20_000,
    })
    .await;
}

/// Returns once `count` tasks have stopped at `hold`.
async fn reached_by(hold: &kr_plugin_service::hold::HoldHandle, count: usize, what: &str) {
    tokio::time::timeout(HANG_GUARD, async {
        while hold.parked_tasks() < count {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect(what);
}

// A hold that more than one call reaches lets every one of them go when it is released. Two
// snapshots are read while the calls are held, and both stand at the hold before it is released:
// a release that woke one of them would leave the other waiting for a release that has been made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hold_that_two_calls_reach_lets_both_of_them_go_when_it_is_released() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let served = Served::start_unbinding_within(HANG_GUARD).await;
    let (path, digest, bytes) = served.install("well-behaved", &wasm);
    let component = ComponentSource {
        path,
        digest,
        bytes,
    };
    let mut raw = Raw::connect(&served).await;
    let request = components::request("well-behaved", 1);
    let registered = raw.register(&request, &component).await;
    assert!(
        matches!(registered, ResponseBody::Registered { .. }),
        "the binding was answered with {registered:?}"
    );

    let hold = served.host.hold_calls_before_they_run();
    let mut asked = Vec::new();
    for _ in 0..2 {
        asked.push(
            raw.send(RequestBody::Snapshot {
                binding_id: request.binding_id.get(),
                deadline_ms: 20_000,
            })
            .await,
        );
    }
    reached_by(&hold, 2, "the two calls never both stopped at the hold").await;
    hold.release();

    let answered = tokio::time::timeout(HANG_GUARD, raw.collect(&asked))
        .await
        .expect("a call that was held when the hold was released was never let go");
    for answer in answered {
        assert!(
            matches!(answer, ResponseBody::Called { .. }),
            "a call held with another was answered with {answer:?}"
        );
    }
}

// A task stops at the hold it found and leaves it when that hold is released, whatever hold has been
// set since. A task that a release has woken must not go on to wait at the next hold: the test that
// sets one would then wait for a task that has no more to do with it than the one before.
//
// A hold is set and a task stops at it; a second hold is set before the first is released. That is
// the state a woken task finds when a test sets its next hold after the release and before the task
// runs again, reached here without a race. The release of the first lets the task go, and the second
// has no task at it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_task_leaves_the_hold_it_stopped_at_when_that_hold_is_released_whatever_hold_is_set_since()
 {
    let hold = Arc::new(kr_plugin_service::hold::Hold::default());
    let first = hold.set();
    let waiting = tokio::spawn({
        let hold = Arc::clone(&hold);
        async move { hold.pause().await }
    });
    reached(&first, "the task never stopped at the first hold").await;
    let second = hold.set();
    first.release();
    tokio::time::timeout(HANG_GUARD, waiting)
        .await
        .expect("the task stopped at a hold that was released did not leave it")
        .expect("the task ended");
    assert_eq!(
        second.parked_tasks(),
        0,
        "the task that left the first hold stopped at the second"
    );
}

// A request about a binding that is read after the unbind of it is about no binding, whatever it
// asks: the connection no longer stands behind the registration, which is still in the runtime
// until its removal has run. An event, a revision of the facts and a revision of the attachments
// are answered on the task that reads the connection, and are judged the way a call is, by what
// the connection stood behind when they were read, and not by whatever the runtime holds when the
// host gets to them: the registration that is leaving is not given an observation it will never
// interpret nor facts nobody will read, with an answer that says it was.
//
// The unbind is read and its task is held where it starts, so that the registration is still in
// the runtime when the three requests are read. Each is asked of the binding first, as a control.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_event_and_a_revision_read_after_the_unbind_of_a_binding_are_about_no_binding() {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let served = Served::start_unbinding_within(HANG_GUARD).await;
    let (path, digest, bytes) = served.install("well-behaved", &wasm);
    let component = ComponentSource {
        path,
        digest,
        bytes,
    };
    let mut raw = Raw::connect(&served).await;
    let request = components::request("well-behaved", 1);
    let registered = raw.register(&request, &component).await;
    assert!(
        matches!(registered, ResponseBody::Registered { .. }),
        "the binding was answered with {registered:?}"
    );
    let binding_id = request.binding_id.get();
    let event = || RequestBody::Event {
        binding_id,
        event: kr_plugin_service::vocabulary::wire_event(&components::scrape("se-0", "x")),
    };
    let facts = || RequestBody::ReviseFacts {
        binding_id,
        facts: kr_plugin_service::vocabulary::wire_facts(&components::facts("well-behaved")),
    };
    let attachments = || RequestBody::ReviseAttachments {
        binding_id,
        attachments: Vec::new(),
    };

    let admitted = raw.ask(event()).await;
    assert!(
        matches!(admitted, ResponseBody::Admitted { .. }),
        "an event for the standing registration was answered with {admitted:?}"
    );
    for (name, body) in [("facts", facts()), ("attachments", attachments())] {
        let revised = raw.ask(body).await;
        assert!(
            matches!(revised, ResponseBody::Revised),
            "a revision of the {name} of the standing registration was answered with {revised:?}"
        );
    }

    let hold = served.host.hold_unbinds_before_they_run();
    let leaving = raw.send_unbind(&request).await;
    reached(&hold, "the unbind's task never started").await;
    let gone = kr_plugin_runtime::RuntimeError::NoSuchBinding {
        binding: request.binding_id.get().to_string(),
    }
    .to_string();
    for (name, body) in [
        ("event", event()),
        ("revision of the facts", facts()),
        ("revision of the attachments", attachments()),
    ] {
        let answered = raw.ask(body).await;
        assert!(
            matches!(
                &answered,
                ResponseBody::Refused { detail, disabled: false, .. } if *detail == gone
            ),
            "an {name} read after the unbind of the binding was answered with {answered:?}, and \
             not as a request about a binding that is gone"
        );
    }
    hold.release();
    let removed = raw.collect(&[leaving]).await.pop().expect("one answer");
    assert!(
        matches!(removed, ResponseBody::Unbound { existed: true }),
        "the unbind was answered with {removed:?}"
    );
}

// A client whose connection has ended holds no record of the registrations it had made. What it
// knows of an identifier is there to act on the answers the host brings, and none will come: the
// client refuses every request from then on and cannot be connected again, so a record kept for
// each registration it had counted as live would stay for as long as the client does.
//
// The host here is a program of the case's own: it answers one registration and ends the
// connection when the case says so. The record is there while the connection stands, as a control.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_whose_connection_ended_holds_no_record_of_the_registrations_it_had_made() {
    let request = components::request("well-behaved", 1);
    let component = ComponentSource {
        path: "unused".to_owned(),
        digest: PayloadDigest::of(b"unused"),
        bytes: 0,
    };
    let (end_sender, end) = tokio::sync::oneshot::channel::<()>();
    let (client, serving) = scripted_host(move |mut reader, mut writer| async move {
        let registration: kr_plugin_service::protocol::Request = reader
            .read_message_without_schema()
            .await
            .expect("the registration");
        writer
            .write_message(&Frame::Response {
                reply_to: registration.request_id,
                body: ResponseBody::Registered {
                    origin: "compiled".to_owned(),
                    elapsed_ms: 0,
                },
            })
            .await
            .expect("the answer is written");
        end.await.expect("the case ends the connection");
    })
    .await;

    register_on(&client, &request, &component).await;
    assert_eq!(
        client.identifiers_in_flight_or_live(),
        1,
        "the client kept no account of the registration the host answered"
    );
    end_sender.send(()).expect("the host program is waiting");
    serving.await.expect("the host program ended");
    tokio::time::timeout(HANG_GUARD, async {
        while client.identifiers_in_flight_or_live() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the client kept its account of a registration after its connection ended");
}

// A registration is the connection's from the moment the request is read, and not from the moment
// its component has been read and compiled. An unbind that comes in between is about it: it is
// answered as an unbind of a binding that exists, and the registration is refused when it gets
// further, where otherwise it would go live as a binding the worker had asked to be rid of.
//
// The registration is held where the host has read the request and nothing else, by the gate file
// the host honours in the state directory it files its cache in, and the case lets it go once the
// unbind has been answered. It is refused where it would otherwise have gone on to the runtime, so
// the component it names is never entered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unbind_that_comes_before_the_registration_has_read_its_component_is_about_that_registration()
 {
    let Some(wasm) = components::well_behaved() else {
        return;
    };
    let served = Served::start_unbinding_within(HANG_GUARD).await;
    let (path, digest, bytes) = served.install("well-behaved", &wasm);
    let component = ComponentSource {
        path,
        digest,
        bytes,
    };
    let state = served._temp.environment().state_dir().to_path_buf();
    let gate = state.join("hold-registrations");
    std::fs::write(&gate, b"").expect("the gate is closed");
    let mut raw = Raw::connect(&served).await;
    let request = components::request("well-behaved", 1);
    let registering = raw.send_register(&request, &component).await;
    appears(&state.join("hold-registrations.reached")).await;

    let unbound = raw.unbind(&request).await;
    assert!(
        matches!(unbound, ResponseBody::Unbound { existed: true }),
        "an unbind of a registration being made was answered with {unbound:?}"
    );
    // A registration that went on would stand at this hold, before the runtime reserves its
    // identifier, and would not be answered until the case let it go.
    let hold = served.host.hold_registrations_before_the_runtime();
    std::fs::remove_file(&gate).expect("the gate is opened");
    let registered = tokio::time::timeout(HANG_GUARD, raw.collect(&[registering]))
        .await
        .expect(
            "the registration was not answered: it went on to the runtime although it was unbound",
        )
        .pop()
        .expect("one answer");
    assert!(
        matches!(registered, ResponseBody::Refused { .. }),
        "a registration that was unbound meanwhile was answered with {registered:?}"
    );
    hold.release();
    let health = raw
        .health_until(|health| health.connection_bindings == 0)
        .await;
    assert_eq!(
        health.live_bindings, 0,
        "the registration left a binding in the runtime"
    );

    // The identifier is free.
    let registered = raw.register(&request, &component).await;
    assert!(
        matches!(registered, ResponseBody::Registered { .. }),
        "the binding was answered with {registered:?}"
    );
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
    // Each event is 64 KiB, so as many as the queue's bound holds, and one more, overflow it; the
    // case offers twice that, and the count only ends a queue that never overflows.
    let mut stop = served
        .host
        .runtime()
        .stop_next_pump(request.binding_id)
        .expect("the binding is live");
    let filler = "z".repeat(64 * 1024);
    let fitting = kr_plugin_sdk::limits::OBSERVATION_QUEUE_BYTES / filler.len() as u64;
    let first = client
        .deliver(request.binding_id, &components::scrape("se-0", &filler))
        .await
        .expect("the event is offered");
    assert!(
        !matches!(first, Admission::QueuedWithGap { .. }),
        "one observation of 64 KiB overflowed the queue"
    );
    assert!(
        tokio::time::timeout(HANG_GUARD, stop.reached())
            .await
            .expect("the binding's pass stands at the stop"),
        "the stop was replaced before a pass reached it"
    );
    let mut told = None;
    let mut seen: std::collections::BTreeMap<&'static str, u32> = std::collections::BTreeMap::new();
    for index in 1..=2 * fitting {
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
    let served = Served::start_held().await;
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
    health_until(&second, |health| health.live_bindings == 0).await;
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
// The one figure here that is a length of time is the call's own deadline, and its expiring is one
// of the outcomes this case accepts, so it decides nothing. The loop that samples the count ends
// when the count grows, and only a host whose count never grows is held to the guard. The handoff
// at the end is shown not to wait for the connection's writer by holding the writer, and not by
// timing the handoff.
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
    tokio::time::timeout(HANG_GUARD, async {
        loop {
            let after = client
                .health()
                .await
                .expect("a health report")
                .component_calls;
            if after > before {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the component completed no call between the two samples of the count");

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

    // And the handoff that never waits at all does not even write a frame: another task holds the
    // connection's writer, and the events are handed over all the same, and written once it lets
    // go. Everything handed over so far is written first, so that the queue has room. The task that
    // writes them is held too, before it asks for the writer: a write that has asked for it is given
    // ten seconds to get it, which a machine that stops this case for that long would run out, and
    // the case decides by the steps it takes and not by that.
    tokio::time::timeout(HANG_GUARD, async {
        while client.offered_bytes() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the events handed over so far were never written");
    let writer = client.hold_writer().await;
    let writes = client.hold_offered_writes();
    for index in 2..4 {
        let handoff = client.offer(
            request.binding_id,
            &components::scrape(&format!("se-{index}"), "y"),
        );
        assert_eq!(
            handoff,
            kr_plugin_service::client::Handoff::Accepted,
            "an event was not handed over while another task held the connection's writer"
        );
    }
    // Held at the writer's task as well, so this shows the handed-over events are counted until they
    // are written; that the handoff itself never waits for the writer is what the `Accepted`
    // answers above show, while the writer is held.
    assert_ne!(
        client.offered_bytes(),
        0,
        "an event handed over was counted as written while the offered writes were held"
    );
    drop(writer);
    writes.release();
    tokio::time::timeout(HANG_GUARD, async {
        while client.offered_bytes() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the events handed over were never written");

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

    // Told that the host is unavailable, which a client that waited out its deadline would not
    // be: that is a caller's deadline, and a different failure.
    let error = client
        .health()
        .await
        .expect_err("a host that is gone cannot report itself");
    assert!(
        matches!(error, ServiceError::Unavailable { .. }),
        "the failure was {error}"
    );

    // And a call made afterwards is refused as unavailable too, rather than being written to a
    // socket nobody is reading.
    let error = client
        .unbind(new_binding_id())
        .await
        .expect_err("the connection is gone");
    assert!(
        matches!(error, ServiceError::Unavailable { .. }),
        "the failure was {error}"
    );
}

// A worker takes any answer to an unbind as the binding gone, and the client forgets what its queue
// held for the binding on every answer, a refusal that says the host took the binding out without
// waiting for the removal among them. What it held is the record of a document it dropped whose last
// piece had not come: left behind, it would drop the first document of the identifier's next
// registration, which is numbered from one again.
//
// The host here is a program of the case's, because the client's queue drops a document only when
// it is full and nothing reads it, and what the case needs is the order of the frames: the
// documents, the refusal, and then, once the client has asked for something else, the next
// registration's first document and a notice after it that is always read. Frames are read one at
// a time by the client's reader, so the refusal reaches the caller after the documents are in the
// queue, and a worker registers an identifier again only after it was told the binding was gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_forgets_what_its_queue_held_for_a_binding_when_the_host_answers_its_unbind_with_a_refusal()
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
    let binding_id = new_binding_id();
    let sentinel = new_binding_id();

    // Pieces of one document, none of them the last, which together fill the client's queue: the
    // one that does not fit makes the queue drop the document, and remember that it did until the
    // last piece comes.
    let piece = move || Notice::Document {
        binding_id: binding_id.get(),
        call: "snapshot".to_owned(),
        document: 1,
        last: false,
        nodes: vec![kr_plugin_service::protocol::WireNode {
            node_id: "n".to_owned(),
            node_revision: 0,
            body_json: "x".repeat(900 * 1024),
        }],
    };
    let first_of_the_next = Notice::Document {
        binding_id: binding_id.get(),
        call: "snapshot".to_owned(),
        document: 1,
        last: true,
        nodes: Vec::new(),
    };
    let after_it = Notice::Disabled {
        binding_id: sentinel.get(),
        reason: "the notice that is always read".to_owned(),
    };

    let serving = tokio::spawn({
        let descriptor = descriptor.clone();
        let first_of_the_next = first_of_the_next.clone();
        let after_it = after_it.clone();
        async move {
            let (connection, _peer) = listener.accept().await.expect("a connection");
            let (mut reader, mut writer) =
                kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
            // Until the client ends the connection, as the case does.
            while let Ok(request) = reader
                .read_message_without_schema::<kr_plugin_service::protocol::Request>()
                .await
            {
                let reply_to = request.request_id;
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
                    RequestBody::Unbind { .. } => {
                        for _ in 0..5 {
                            writer
                                .write_message(&Frame::Notice(piece()))
                                .await
                                .expect("a piece is written");
                        }
                        ResponseBody::Refused {
                            request: "unbind".to_owned(),
                            detail: "the binding was stopped without waiting for its thread"
                                .to_owned(),
                            disabled: false,
                        }
                    }
                    RequestBody::Privacy { private } => {
                        for notice in [first_of_the_next.clone(), after_it.clone()] {
                            writer
                                .write_message(&Frame::Notice(notice))
                                .await
                                .expect("a notice is written");
                        }
                        ResponseBody::PrivacySet { private }
                    }
                    other => panic!("the client asked for {other:?}"),
                };
                writer
                    .write_message(&Frame::Response { reply_to, body })
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
    let answered = client.unbind(binding_id).await;
    assert!(
        matches!(&answered, Err(ServiceError::Protocol { .. })),
        "the refusal was read as {answered:?}"
    );
    // The worker registers the identifier again now; what it is sent for that is asked for by
    // something it says to the host.
    client.privacy(false).await.expect("privacy is set");

    let read = tokio::time::timeout(HANG_GUARD, async {
        let mut read = Vec::new();
        loop {
            let notice = client.notice().await.expect("the connection stood");
            let last = notice == after_it;
            read.push(notice);
            if last {
                return read;
            }
        }
    })
    .await
    .expect("the notice that is always read never came");
    assert!(
        read.contains(&first_of_the_next),
        "the queue dropped the first document of the identifier's next registration: {} notices were read",
        read.len()
    );
    drop(client);
    serving.await.expect("the host program ended");
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
    tokio::time::timeout(HANG_GUARD, async {
        while !hold.parked() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the writer never took the event off the queue");
    assert_ne!(
        client.offered_bytes(),
        0,
        "an event that has not been written is not counted, so a count of zero does not mean the \
         events handed over are written"
    );

    // Written: the count falls to zero, and a snapshot asked for then is written after the event.
    hold.release();
    tokio::time::timeout(HANG_GUARD, async {
        while client.offered_bytes() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the event was never written");
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

    let served = Served::start_held().await;
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
    let served = Served::start_held().await;
    let Some((client, binding_id)) = preparing(&served).await else {
        return;
    };
    let deadline = core::time::Duration::from_millis(500);
    // The caller waits far longer than the component's deadline is worth in ticks, so that what
    // ends the call is the component's deadline and not the caller's own, whatever the machine does
    // with the ticks.
    let patient = core::time::Duration::from_secs(20);
    let stuck = served
        .with_the_epoch_moving(client.prepare_action(
            binding_id,
            invocation("cancel.loop"),
            Vec::new(),
            patient,
        ))
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
    let served = Served::start_held().await;
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
    let served = Served::start_held().await;
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
    tokio::time::timeout(HANG_GUARD, async {
        loop {
            if let Notice::Disabled {
                binding_id: told, ..
            } = client.notice().await.expect("the connection is open")
            {
                assert_eq!(told, binding_id.get());
                break;
            }
        }
    })
    .await
    .expect("the host never said the binding was disabled");
}

// KR-REQ-24.27: once the host has acknowledged that privacy mode stands, no document of the
// connection is written, though one was taken off the queue before and is held at the writer when
// the acknowledgement is made; and when privacy mode ends the reader is told that documents were
// lost, so it expects a fresh one, which the component is asked to draw.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_27_no_document_is_written_after_privacy_mode_is_acknowledged_and_a_fresh_one_follows_its_end()
 {
    let served = Served::start_held().await;
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
    tokio::time::timeout(HANG_GUARD, async {
        while !hold.parked() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the writer never took the document off the queue");
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
    tokio::time::timeout(HANG_GUARD, async {
        loop {
            match client.notice().await.expect("the connection is open") {
                Notice::Document { document, .. } => {
                    panic!("document {document} was written after privacy mode was acknowledged")
                }
                Notice::Fault { .. } => break,
                Notice::Gap { .. } | Notice::Disabled { .. } => {}
            }
        }
    })
    .await
    .expect("the fault was never written");

    // Privacy mode ends: the reader is told documents were lost, and a fresh one follows.
    client
        .privacy(false)
        .await
        .expect("the end is acknowledged");
    let mut lost = false;
    tokio::time::timeout(HANG_GUARD, async {
        loop {
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
    })
    .await
    .expect("no fresh document followed the end of privacy mode");
}

// KR-REQ-24.27: a decoded request's presentation is a document too, and is not sent while privacy
// mode stands. What the worker uses of it, the summary and the decisions, is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_27_a_decoded_request_carries_no_presentation_while_privacy_mode_stands() {
    let served = Served::start_held().await;
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
    let served = Served::start_held().await;
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
    let served = Served::start_held().await;
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
