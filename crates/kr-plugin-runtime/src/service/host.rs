//! Serving workers: the accept loop, the request handling and what is refused.
//!
//! The host owns instances and nothing else. It has no journal, no ledger and no durable state
//! beyond the compiled-code cache, which is a cache. That is deliberate, and it is what makes the
//! crash test in the requirement rows pass rather than be hoped for: there is nothing in this
//! process whose loss could destroy a request, because the requests are all in the workers.
//!
//! # What authenticates a caller
//!
//! The runtime directory is owner-only, so another user cannot reach the socket. Peer credentials
//! are checked before a frame is read, so a socket that somehow became reachable serves nobody
//! else. Neither of those proves human intent, and neither needs to: every authority decision is
//! the worker's, and a component only ever returns a plan.
//!
//! # What a worker gets to name
//!
//! A component's location, and only inside the packages directory this process was started with. A
//! path outside it is refused by name. The worker also supplies the digest it verified against the
//! catalogue, and the host checks the file against that digest before it compiles anything, so the
//! bytes that become machine code are the bytes the catalogue signed.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kr_ipc::endpoint::Listener;
use kr_ipc::framed::{FrameReader, FrameWriter, split};
use kr_ipc::paths::Endpoint;
use kr_plugin_sdk::digest::PayloadDigest;
use kr_protocol::frame::StreamKind;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Uuid;

use crate::runtime::binding::{BindingEvent, BindingId, BindingRequest, Runtime, RuntimeConfig};
use crate::runtime::budget::CallKind;
use crate::runtime::compile::CompileOrigin;
use crate::runtime::error::RuntimeError;
use crate::runtime::host::{BindingActivity, BindingFacts, ScopedSourceEvent, SourceProvenance};
use crate::runtime::queue::Admission;
use crate::service::launcher::{HostIdentity, LaunchError, LaunchResult};
use crate::service::protocol::{
    BindingRegistration, CallValue, ComponentSource, Frame, HostHealth, Notice, Request,
    RequestBody, ResponseBody, WireFacts, WireNode, WireSourceEvent,
};

/// How long a registration's compilation may keep a worker waiting.
///
/// The compile itself is bounded by the compilation budget. This is the caller-visible half: a
/// worker that has waited this long is told so and can carry on, and the compile continues and
/// files its result, so the next registration of the same component is quick.
pub const REGISTER_DEADLINE: core::time::Duration = core::time::Duration::from_secs(10);

/// What the plugin host was started with.
#[derive(Clone, Debug)]
pub struct HostConfig {
    /// The endpoint workers connect to.
    pub endpoint: Endpoint,
    /// The only directory a component payload may be read from.
    pub packages_root: PathBuf,
    /// Where compiled artefacts are filed.
    pub cache_root: PathBuf,
}

/// The plugin-runtime service.
pub struct PluginHost {
    identity: HostIdentity,
    runtime: Arc<Runtime>,
    config: HostConfig,
    started: std::time::Instant,
}

impl core::fmt::Debug for PluginHost {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PluginHost")
            .field("endpoint", &self.config.endpoint)
            .field("packages_root", &self.config.packages_root)
            .finish_non_exhaustive()
    }
}

impl PluginHost {
    /// Builds the service.
    ///
    /// # Errors
    ///
    /// Returns [`LaunchError::Refused`] when the engine or the cache cannot be prepared.
    pub fn new(identity: HostIdentity, config: HostConfig) -> LaunchResult<Self> {
        let runtime =
            Runtime::new(RuntimeConfig::new(config.cache_root.clone())).map_err(|error| {
                LaunchError::Refused {
                    detail: format!("the component runtime could not be built: {error}"),
                }
            })?;
        Ok(Self {
            identity,
            runtime: Arc::new(runtime),
            config,
            started: std::time::Instant::now(),
        })
    }

    /// Returns the host's own identity.
    #[must_use]
    pub const fn identity(&self) -> &HostIdentity {
        &self.identity
    }

    /// Returns the runtime the host serves.
    #[must_use]
    pub fn runtime(&self) -> &Arc<Runtime> {
        &self.runtime
    }

    /// Returns what the host was started with.
    #[must_use]
    pub const fn config(&self) -> &HostConfig {
        &self.config
    }

    /// Serves workers until `shutdown` resolves.
    ///
    /// Every accepted connection is served by its own task, so one worker's registration does not
    /// delay another's observation.
    ///
    /// # Errors
    ///
    /// Returns [`LaunchError::Endpoint`] when the endpoint cannot be bound.
    pub async fn serve(
        self: Arc<Self>,
        shutdown: impl core::future::Future<Output = ()> + Send,
    ) -> LaunchResult<()> {
        let listener = Listener::bind(&self.config.endpoint)?;
        let mut shutdown = core::pin::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => return Ok(()),
                accepted = listener.accept() => {
                    let (connection, peer) = match accepted {
                        Ok(accepted) => accepted,
                        // A failed accept is one caller's problem, not the service's.
                        Err(_error) => continue,
                    };
                    if peer.authorise(kr_ipc::paths::current_uid()).is_err() {
                        // Another user reached the socket. Dropping the connection without a frame
                        // is the whole answer they get.
                        continue;
                    }
                    let host = Arc::clone(&self);
                    tokio::spawn(async move { host.serve_connection(connection).await });
                }
            }
        }
    }

    async fn serve_connection(self: Arc<Self>, connection: kr_ipc::endpoint::Connection) {
        let (reader, writer) = split(connection, StreamKind::Control);
        let writer = Arc::new(tokio::sync::Mutex::new(writer));
        let (notices, mut pending) = tokio::sync::mpsc::unbounded_channel::<Notice>();
        let bindings: Arc<tokio::sync::Mutex<Vec<BindingId>>> =
            Arc::new(tokio::sync::Mutex::new(Vec::new()));

        // One task writes notices, so a burst of document nodes from one binding cannot interleave
        // with another's inside a frame.
        let notice_writer = Arc::clone(&writer);
        let notices_task = tokio::spawn(async move {
            while let Some(notice) = pending.recv().await {
                let mut writer = notice_writer.lock().await;
                if writer.write_message(&Frame::Notice(notice)).await.is_err() {
                    return;
                }
            }
        });

        let outcome = self
            .read_requests(reader, Arc::clone(&writer), &notices, Arc::clone(&bindings))
            .await;
        let _ = outcome;
        drop(notices);
        notices_task.abort();

        // The worker is gone. Its bindings go with it: a binding exists to serve one worker's
        // connection, and nothing durable was in it.
        let held = bindings.lock().await.clone();
        for binding_id in held {
            self.runtime.unbind(binding_id);
        }
    }

    async fn read_requests(
        &self,
        mut reader: FrameReader,
        writer: Arc<tokio::sync::Mutex<FrameWriter>>,
        notices: &tokio::sync::mpsc::UnboundedSender<Notice>,
        bindings: Arc<tokio::sync::Mutex<Vec<BindingId>>>,
    ) -> LaunchResult<()> {
        loop {
            let request: Request = match reader.read_message().await {
                Ok(request) => request,
                // A closed connection or a frame this protocol does not admit. Either way this
                // conversation is over; the union is closed so an unrecognised frame is a refusal
                // rather than something to guess at.
                Err(_error) => return Ok(()),
            };
            let reply_to = request.request_id;
            let body = self
                .handle(request.body, notices, &bindings)
                .await
                .unwrap_or_else(|(request, detail, disabled)| ResponseBody::Refused {
                    request,
                    detail,
                    disabled,
                });
            let mut writer = writer.lock().await;
            if writer
                .write_message(&Frame::Response { reply_to, body })
                .await
                .is_err()
            {
                return Ok(());
            }
        }
    }

    /// Starts a task that stamps one binding's events with its identifier.
    ///
    /// Each binding gets its own channel, so a connection with several bindings never attributes
    /// one binding's fault to another.
    fn forward_notices(
        binding_id: BindingId,
        notices: tokio::sync::mpsc::UnboundedSender<Notice>,
    ) -> tokio::sync::mpsc::UnboundedSender<BindingEvent> {
        let (events, mut pending) = tokio::sync::mpsc::unbounded_channel::<BindingEvent>();
        tokio::spawn(async move {
            while let Some(event) = pending.recv().await {
                if notices.send(notice_of(binding_id, event)).is_err() {
                    return;
                }
            }
        });
        events
    }

    async fn handle(
        &self,
        body: RequestBody,
        notices: &tokio::sync::mpsc::UnboundedSender<Notice>,
        bindings: &Arc<tokio::sync::Mutex<Vec<BindingId>>>,
    ) -> Result<ResponseBody, (String, String, bool)> {
        let name = body.name().to_owned();
        match body {
            RequestBody::Hello { protocol } => {
                if protocol != crate::service::protocol::PROTOCOL {
                    return Err((
                        name,
                        format!(
                            "this host speaks {} and the caller offered {protocol}",
                            crate::service::protocol::PROTOCOL
                        ),
                        false,
                    ));
                }
                Ok(ResponseBody::Hello {
                    protocol: crate::service::protocol::PROTOCOL.to_owned(),
                    descriptor: Box::new(self.descriptor()),
                })
            }
            RequestBody::Verify { nonce } => {
                let proof = self
                    .identity
                    .answer(&nonce, &self.config.endpoint.as_text())
                    .map_err(|error| (name, error.to_string(), false))?;
                Ok(ResponseBody::Verified(Box::new(proof)))
            }
            RequestBody::RegisterBinding(registration) => {
                let BindingRegistration {
                    binding_id,
                    identity,
                    facts,
                    executable,
                    component,
                } = *registration;
                let wasm = self
                    .read_component(&component)
                    .map_err(|detail| (name.clone(), detail, false))?;
                // Two steps rather than one, because they are two steps: the compile happens on a
                // background thread under its own budget, and only once an instance exists does any
                // call budget start.
                let compiled = self
                    .runtime
                    .compile(wasm)
                    .map_err(|error| (name.clone(), error.to_string(), false))?
                    .wait(REGISTER_DEADLINE)
                    .map_err(|error| (name.clone(), error.to_string(), false))?;
                let binding = BindingId::new(binding_id);
                let request = BindingRequest {
                    binding_id: binding,
                    identity,
                    facts: facts_of(&facts),
                    executable,
                };
                let events = Self::forward_notices(binding, notices.clone());
                self.runtime
                    .instantiate(request, &compiled, events)
                    .map_err(|error| (name, error.to_string(), false))?;
                bindings.lock().await.push(binding);
                Ok(ResponseBody::Registered {
                    origin: match compiled.origin {
                        CompileOrigin::Compiled => "compiled".to_owned(),
                        CompileOrigin::Cached => "cached".to_owned(),
                    },
                    elapsed_ms: compiled.elapsed_ms,
                })
            }
            RequestBody::Event { binding_id, event } => {
                let binding = self
                    .binding(binding_id)
                    .map_err(|detail| (name.clone(), detail, false))?;
                let scoped = event_of(&event).map_err(|detail| (name, detail, false))?;
                let admission = binding.enqueue_observation(scoped);
                Ok(admission_of(admission))
            }
            RequestBody::Snapshot {
                binding_id,
                deadline_ms,
            } => {
                let binding = self
                    .binding(binding_id)
                    .map_err(|detail| (name.clone(), detail, false))?;
                let result = binding
                    .snapshot(core::time::Duration::from_millis(deadline_ms))
                    .await;
                Ok(called_of(
                    result
                        .map(|result| (result.answer.map(|()| CallValue::Document), result.nodes)),
                    &name,
                )?)
            }
            RequestBody::Checkpoint {
                binding_id,
                deadline_ms,
            } => {
                let binding = self
                    .binding(binding_id)
                    .map_err(|detail| (name.clone(), detail, false))?;
                let result = binding
                    .checkpoint(core::time::Duration::from_millis(deadline_ms))
                    .await;
                Ok(called_of(
                    result.map(|result| (result.answer.map(CallValue::State), result.nodes)),
                    &name,
                )?)
            }
            RequestBody::Restore {
                binding_id,
                state,
                deadline_ms,
            } => {
                let binding = self
                    .binding(binding_id)
                    .map_err(|detail| (name.clone(), detail, false))?;
                let result = binding
                    .restore(state, core::time::Duration::from_millis(deadline_ms))
                    .await;
                Ok(called_of(
                    result
                        .map(|result| (result.answer.map(|()| CallValue::Document), result.nodes)),
                    &name,
                )?)
            }
            RequestBody::Unbind { binding_id } => {
                let existed = self.runtime.unbind(BindingId::new(binding_id));
                bindings
                    .lock()
                    .await
                    .retain(|held| held.get() != binding_id);
                Ok(ResponseBody::Unbound { existed })
            }
            RequestBody::Health => Ok(ResponseBody::Health(Box::new(HostHealth {
                live_bindings: self.runtime.live_bindings() as u64,
                engine_version: self.runtime.engine().version().to_owned(),
                target: self.runtime.engine().target().to_owned(),
                engine_compatibility: self.runtime.engine().compatibility().to_owned(),
                uptime_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
                deadlines_enforceable: self.runtime.engine().deadlines_enforceable(),
            }))),
        }
    }

    fn descriptor(&self) -> crate::service::protocol::HostDescriptor {
        crate::service::protocol::HostDescriptor {
            protocol: crate::service::protocol::PROTOCOL.to_owned(),
            environment_id: self.identity.environment_id(),
            reservation_id: kr_protocol::worker::ReservationId::new(
                kr_protocol::scalars::Uuid::from_bytes([0; 16]),
            ),
            endpoint: self.config.endpoint.as_text(),
            boot_identity: self.identity.boot_identity().clone(),
            process_start_identity: self.identity.process_start_identity().clone(),
            host_public_key: *self.identity.public_key(),
        }
    }

    fn binding(
        &self,
        binding_id: Uuid,
    ) -> Result<Arc<crate::runtime::binding::BindingHandle>, String> {
        self.runtime
            .binding(BindingId::new(binding_id))
            .ok_or_else(|| {
                RuntimeError::NoSuchBinding {
                    binding: binding_id.to_string(),
                }
                .to_string()
            })
    }

    /// Reads a component payload, refusing anything outside the packages directory.
    fn read_component(&self, source: &ComponentSource) -> Result<Arc<[u8]>, String> {
        let path = Path::new(&source.path);
        let root = self
            .config
            .packages_root
            .canonicalize()
            .unwrap_or_else(|_| self.config.packages_root.clone());
        let resolved = path
            .canonicalize()
            .map_err(|error| format!("{} is unreadable: {error}", path.display()))?;
        if !resolved.starts_with(&root) {
            return Err(format!(
                "{} is outside the packages directory {}",
                resolved.display(),
                root.display()
            ));
        }
        if source.bytes > crate::runtime::compile::MAX_COMPONENT_BYTES {
            return Err(format!(
                "the component declares {} bytes, over the {} byte compilation bound",
                source.bytes,
                crate::runtime::compile::MAX_COMPONENT_BYTES
            ));
        }
        let bytes = std::fs::read(&resolved)
            .map_err(|error| format!("{} is unreadable: {error}", resolved.display()))?;
        if bytes.len() as u64 != source.bytes {
            return Err(format!(
                "{} is {} bytes and the caller verified {}",
                resolved.display(),
                bytes.len(),
                source.bytes
            ));
        }
        // The digest the caller verified against the catalogue. Bytes that do not match it never
        // reach the compiler, so what becomes machine code is what the catalogue signed.
        let digest = PayloadDigest::of(&bytes);
        if digest != source.digest {
            return Err(format!(
                "{} is not the payload the caller verified",
                resolved.display()
            ));
        }
        Ok(Arc::from(bytes))
    }
}

fn called_of(
    result: Result<
        (
            Result<CallValue, String>,
            Vec<crate::runtime::host::EmittedNode>,
        ),
        RuntimeError,
    >,
    name: &str,
) -> Result<ResponseBody, (String, String, bool)> {
    match result {
        Ok((answer, nodes)) => {
            let nodes = nodes.iter().map(node_of).collect();
            match answer {
                Ok(value) => Ok(ResponseBody::Called {
                    value: Some(value),
                    fault: None,
                    nodes,
                }),
                Err(fault) => Ok(ResponseBody::Called {
                    value: None,
                    fault: Some(fault),
                    nodes,
                }),
            }
        }
        Err(error) => {
            let disabled = matches!(error, RuntimeError::Disabled { .. });
            Err((name.to_owned(), error.to_string(), disabled))
        }
    }
}

fn admission_of(admission: Admission) -> ResponseBody {
    match admission {
        Admission::Queued => ResponseBody::Admitted {
            admission: "queued".to_owned(),
            lost_events: 0,
            lost_bytes: 0,
        },
        Admission::QueuedWithGap { events, bytes } => ResponseBody::Admitted {
            admission: "queued_with_gap".to_owned(),
            lost_events: events,
            lost_bytes: bytes,
        },
        Admission::Refused { held_bytes } => ResponseBody::Admitted {
            admission: "refused".to_owned(),
            lost_events: 0,
            lost_bytes: held_bytes,
        },
    }
}

fn notice_of(binding_id: BindingId, event: BindingEvent) -> Notice {
    let binding_id = binding_id.get();
    match event {
        BindingEvent::Document { call, nodes } => Notice::Document {
            binding_id,
            call: call.as_str().to_owned(),
            nodes: nodes.iter().map(node_of).collect(),
        },
        BindingEvent::Gap(gap) => Notice::Gap {
            binding_id,
            events: gap.events,
            bytes: gap.bytes,
        },
        BindingEvent::Fault {
            call,
            detail,
            faults_in_window,
        } => Notice::Fault {
            binding_id,
            call: call.as_str().to_owned(),
            detail,
            faults_in_window,
        },
        BindingEvent::Disabled { reason } => Notice::Disabled { binding_id, reason },
    }
}

fn node_of(node: &crate::runtime::host::EmittedNode) -> WireNode {
    WireNode {
        node_id: node.node_id.clone(),
        node_revision: node.node_revision,
        body_json: node.body_json.clone(),
    }
}

/// Turns the facts a worker sent into the facts a component reads.
#[must_use]
pub fn facts_of(facts: &WireFacts) -> BindingFacts {
    BindingFacts {
        plugin_id: facts.plugin_id.clone(),
        binding_revision: facts.binding_revision,
        activity: activity_of(&facts.activity),
        thread_id: facts.thread_id.clone(),
        turn_id: facts.turn_id.clone(),
        updated_at_ms: facts.updated_at_ms,
        held_rights: facts.held_rights.clone(),
    }
}

/// Turns the facts a component reads into the facts that travel.
#[must_use]
pub fn wire_facts(facts: &BindingFacts) -> WireFacts {
    WireFacts {
        plugin_id: facts.plugin_id.clone(),
        binding_revision: facts.binding_revision,
        activity: facts.activity.as_str().to_owned(),
        thread_id: facts.thread_id.clone(),
        turn_id: facts.turn_id.clone(),
        updated_at_ms: facts.updated_at_ms,
        held_rights: facts.held_rights.clone(),
    }
}

/// Reads an activity name, treating anything unrecognised as idle.
///
/// An activity is presentation, not authority: a name this host does not know means the component
/// is told the execution is idle rather than being told something invented.
fn activity_of(name: &str) -> BindingActivity {
    match name {
        "running" => BindingActivity::Running,
        "awaiting_person" => BindingActivity::AwaitingPerson,
        "ended" => BindingActivity::Ended,
        _ => BindingActivity::Idle,
    }
}

/// Turns an event that travelled into one a component can be given.
///
/// # Errors
///
/// Returns the reason the event was refused: an unrecognised provenance. Provenance decides whether
/// an event can establish native approval authority, so a name this host does not know is a refusal
/// rather than a default.
pub fn event_of(event: &WireSourceEvent) -> Result<ScopedSourceEvent, String> {
    let provenance = SourceProvenance::from_wire(&event.provenance).ok_or_else(|| {
        format!(
            "{} is not a provenance this host knows, and provenance decides what an event can establish",
            event.provenance
        )
    })?;
    Ok(ScopedSourceEvent::new(
        event.handle.clone(),
        provenance,
        event.observed_at_ms,
        event.request_id.clone(),
        event.bytes.clone(),
    ))
}

/// Turns an event a host holds into one that travels.
#[must_use]
pub fn wire_event(event: &ScopedSourceEvent) -> WireSourceEvent {
    WireSourceEvent {
        handle: event.handle.clone(),
        provenance: event.provenance.as_str().to_owned(),
        observed_at_ms: event.observed_at_ms,
        request_id: event.request_id.clone(),
        bytes: event.bytes.to_vec(),
    }
}

/// Returns the call kinds a worker may ask the host for over the protocol.
///
/// `observe` is not one of them: an observation is a queue push rather than a call, which is what
/// keeps a caller on the terminal path from ever being behind a component. `bind` is not one
/// either, because it happens inside a registration.
#[must_use]
pub fn callable() -> &'static [CallKind] {
    &[CallKind::Snapshot, CallKind::Checkpoint, CallKind::Restore]
}

/// Returns the rights a component is told about by default.
///
/// The empty set. The `upstream` import reports what the actor holds so a component can present
/// controls that will work, and a host with nothing to report reports nothing rather than
/// guessing.
#[must_use]
pub fn no_rights() -> Vec<ActionRight> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire() -> WireFacts {
        WireFacts {
            plugin_id: "kalareach/example".to_owned(),
            binding_revision: 5,
            activity: "running".to_owned(),
            thread_id: Some("t".to_owned()),
            turn_id: None,
            updated_at_ms: 9,
            held_rights: vec![ActionRight::SessionView],
        }
    }

    #[test]
    fn the_facts_round_trip_through_the_wire() {
        let facts = facts_of(&wire());
        assert_eq!(facts.activity, BindingActivity::Running);
        assert_eq!(wire_facts(&facts), wire());
    }

    #[test]
    fn an_activity_this_host_does_not_know_reads_as_idle() {
        let mut wire = wire();
        wire.activity = "thinking-hard".to_owned();
        assert_eq!(facts_of(&wire).activity, BindingActivity::Idle);
    }

    #[test]
    fn a_provenance_this_host_does_not_know_is_refused() {
        let event = WireSourceEvent {
            handle: kr_protocol::ids::SourceEventHandle::new("se-1").expect("a bounded handle"),
            provenance: "trustworthy".to_owned(),
            observed_at_ms: 1,
            request_id: None,
            bytes: b"{}".to_vec(),
        };
        let error = event_of(&event).expect_err("an unknown provenance is refused");
        assert!(error.contains("trustworthy"));
        assert!(error.contains("provenance decides"));
    }

    #[test]
    fn an_event_round_trips_through_the_wire() {
        let event = WireSourceEvent {
            handle: kr_protocol::ids::SourceEventHandle::new("se-1").expect("a bounded handle"),
            provenance: "native_protocol".to_owned(),
            observed_at_ms: 1,
            request_id: Some("req-1".to_owned()),
            bytes: b"{}".to_vec(),
        };
        let scoped = event_of(&event).expect("the event is admitted");
        assert!(scoped.is_authoritative());
        assert_eq!(wire_event(&scoped), event);
    }

    #[test]
    fn an_observation_is_not_something_a_worker_calls() {
        assert!(!callable().contains(&CallKind::Observe));
        assert!(!callable().contains(&CallKind::Bind));
        assert!(callable().contains(&CallKind::Snapshot));
    }

    #[test]
    fn an_admission_reports_what_was_lost() {
        assert_eq!(
            admission_of(Admission::Queued),
            ResponseBody::Admitted {
                admission: "queued".to_owned(),
                lost_events: 0,
                lost_bytes: 0,
            }
        );
        assert_eq!(
            admission_of(Admission::QueuedWithGap {
                events: 3,
                bytes: 900,
            }),
            ResponseBody::Admitted {
                admission: "queued_with_gap".to_owned(),
                lost_events: 3,
                lost_bytes: 900,
            }
        );
        assert!(matches!(
            admission_of(Admission::Refused { held_bytes: 12 }),
            ResponseBody::Admitted { .. }
        ));
    }

    #[test]
    fn a_component_outside_the_packages_directory_is_refused() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let packages = directory.path().join("packages");
        std::fs::create_dir_all(&packages).expect("the packages directory");
        let elsewhere = directory.path().join("elsewhere.wasm");
        std::fs::write(&elsewhere, b"not a component").expect("a file");

        let identity = HostIdentity::generate(kr_protocol::ids::EnvironmentId::new(
            kr_protocol::scalars::Uuid::from_bytes([1; 16]),
        ))
        .expect("an identity");
        let host = PluginHost::new(
            identity,
            HostConfig {
                endpoint: Endpoint::from_path(directory.path().join("p.sock"))
                    .expect("an endpoint"),
                packages_root: packages.clone(),
                cache_root: directory.path().join("cache"),
            },
        )
        .expect("a host");

        let error = host
            .read_component(&ComponentSource {
                path: elsewhere.display().to_string(),
                digest: PayloadDigest::of(b"not a component"),
                bytes: 15,
            })
            .expect_err("a path outside the packages directory is refused");
        assert!(error.contains("outside the packages directory"));

        // Inside it, the digest still has to match what the caller verified.
        let inside = packages.join("component.wasm");
        std::fs::write(&inside, b"not a component").expect("a file");
        let error = host
            .read_component(&ComponentSource {
                path: inside.display().to_string(),
                digest: PayloadDigest::of(b"something else entirely"),
                bytes: 15,
            })
            .expect_err("a digest that does not match is refused");
        assert!(error.contains("not the payload the caller verified"));

        // And so does the length.
        let error = host
            .read_component(&ComponentSource {
                path: inside.display().to_string(),
                digest: PayloadDigest::of(b"not a component"),
                bytes: 99,
            })
            .expect_err("a length that does not match is refused");
        assert!(error.contains("the caller verified"));

        // With both right, the bytes are read.
        let bytes = host
            .read_component(&ComponentSource {
                path: inside.display().to_string(),
                digest: PayloadDigest::of(b"not a component"),
                bytes: 15,
            })
            .expect("the payload is read");
        assert_eq!(&bytes[..], b"not a component");
    }
}
