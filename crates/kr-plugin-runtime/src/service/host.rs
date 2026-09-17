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

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use kr_ipc::endpoint::Listener;
use kr_ipc::framed::{FrameReader, FrameWriter, split};
use kr_ipc::paths::Endpoint;
use kr_plugin_sdk::digest::PayloadDigest;
use kr_protocol::frame::StreamKind;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Uuid;

use crate::runtime::binding::{
    BindingEvent, BindingId, BindingOwner, BindingRequest, DEFAULT_EVENT_QUEUE, Runtime,
    RuntimeConfig, Unbound, remaining_of,
};
use crate::runtime::budget::CallKind;
use crate::runtime::compile::CompileOrigin;
use crate::runtime::error::RuntimeError;
use crate::runtime::host::{
    BindingActivity, BindingFacts, MAX_NODE_BYTES, ScopedSourceEvent, SourceProvenance,
};
use crate::runtime::queue::Admission;
use crate::service::launcher::{HostIdentity, LaunchError, LaunchResult};
use crate::service::notices::{NoticeSink, NoticeStream, Offered, node_bytes};
use crate::service::protocol::{
    BindingRegistration, CallValue, ComponentSource, Frame, HostHealth, Notice, Request,
    RequestBody, ResponseBody, WireFacts, WireNode, WireSourceEvent,
};

/// How long a registration may keep a worker waiting.
///
/// The compilation budget is what bounds the compile, and this is the same figure: a host that
/// accepted a compile of up to that long has to be willing to wait for one. It covers the whole
/// registration -- reading the payload, compiling it, instantiating and binding -- rather than each
/// stage in turn, because what the worker is waiting for is the registration. The worker's own
/// deadline is a little longer again, so the answer a worker gets is the host's own rather than its
/// patience running out first.
pub const REGISTER_DEADLINE: core::time::Duration =
    core::time::Duration::from_millis(crate::runtime::compile::COMPILE_DEADLINE_MS);

/// How many bindings one worker connection may hold.
///
/// A binding is an instance, a thread and a queue, and a connection that could register without
/// limit could make this process hold without limit. The figure is far above what a session with
/// rich bindings uses and far below what would exhaust a host.
pub const MAX_BINDINGS_PER_CONNECTION: usize = 64;

/// How many requests that enter a component one connection may have in flight.
///
/// Reading the next request never waits for the last one to finish, so that an observation, which
/// enters no component, is never behind a call that does. What keeps that from being unbounded work
/// is this: a connection with this many calls already running is told its next one is refused
/// rather than having it queued behind the others.
const MAX_CONCURRENT_CALLS: usize = 16;

/// How long a connection's notices are given to finish being written once it is over.
const NOTICE_DRAIN: core::time::Duration = core::time::Duration::from_secs(2);

/// How long one frame is given to reach a worker.
///
/// A worker that has not taken a frame in this long is a worker that has stopped reading, and this
/// host will not hold a task and the connection's writer waiting for it. Every frame this host
/// sends is bounded and its queues are bounded, so the only reason a write waits this long is the
/// peer.
const WRITE_DEADLINE: core::time::Duration = core::time::Duration::from_secs(10);

/// How much of a refusal is carried back to the worker.
///
/// A refusal names a component's own failure, and a component chooses those words. Clipping them
/// keeps a response inside one frame whatever the component said.
const MAX_REFUSAL_BYTES: usize = 4 * 1024;

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
    /// The packages directory, opened once. Every payload is opened relative to this handle, which
    /// is what keeps a component's location inside it a property of the open rather than of a
    /// comparison made before it.
    packages: Arc<cap_std::fs::Dir>,
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
        // Created if it is not there yet, owner-only. A host is started the first time a binding
        // needs a component, and an environment that has never installed one has no such directory;
        // that is a first state rather than a misconfiguration. Opening it once here is what lets
        // every payload afterwards be opened relative to this handle.
        kr_ipc::paths::create_private_directory(&config.packages_root).map_err(|error| {
            LaunchError::Refused {
                detail: format!(
                    "the packages directory {} cannot be made: {error}",
                    config.packages_root.display()
                ),
            }
        })?;
        let packages =
            cap_std::fs::Dir::open_ambient_dir(&config.packages_root, cap_std::ambient_authority())
                .map_err(|error| LaunchError::Refused {
                    detail: format!(
                        "the packages directory {} cannot be opened: {error}",
                        config.packages_root.display()
                    ),
                })?;
        Ok(Self {
            identity,
            runtime: Arc::new(runtime),
            config,
            packages: Arc::new(packages),
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
        self.serve_on(listener, shutdown).await
    }

    /// Serves workers on an endpoint this process already holds.
    ///
    /// The startup path uses this one. A host binds its endpoint before it reports itself and keeps
    /// that listener through the report, so there is no moment between proving which process owns
    /// the endpoint and answering on it during which another process could take it.
    ///
    /// # Errors
    ///
    /// Returns [`LaunchError::Endpoint`] when the listener fails.
    pub async fn serve_on(
        self: Arc<Self>,
        listener: Listener,
        shutdown: impl core::future::Future<Output = ()> + Send,
    ) -> LaunchResult<()> {
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
        let (sink, stream) = crate::service::notices::channel();
        let conversation = Arc::new(Conversation::new());
        let served = Arc::new(Served {
            owner: BindingOwner::next(),
            notices: sink.clone(),
            writer: Arc::clone(&writer),
            work: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CALLS)),
            bindings: BindingPlaces::default(),
            conversation: Arc::clone(&conversation),
        });

        // One task writes notices, so a burst of document nodes from one binding cannot interleave
        // with another's inside a frame.
        let notice_writer = Arc::clone(&writer);
        let mut notices_task = tokio::spawn(write_notices(
            stream,
            notice_writer,
            Arc::clone(&conversation),
        ));

        Arc::clone(&self).read_requests(reader, &served).await;
        conversation.end();

        // The queue is closed first, so the writer stops waiting for more; it is then given a
        // bounded moment to finish what it holds before it is abandoned. A peer that has stopped
        // reading does not get to keep this task alive.
        sink.close();
        if tokio::time::timeout(NOTICE_DRAIN, &mut notices_task)
            .await
            .is_err()
        {
            notices_task.abort();
        }

        // Work that was already running is waited for first. Every task that could still be
        // registering a binding holds one of these permits, so taking them all is how this waits
        // for them without a second way of counting them; each is bounded by its own deadline. A
        // registration that finished after its bindings were released would leave an instance
        // running that nothing could reach.
        let all = u32::try_from(MAX_CONCURRENT_CALLS).unwrap_or(u32::MAX);
        let _finished = served.work.acquire_many(all).await;

        // The worker is gone. Its bindings go with it: a binding exists to serve one worker's
        // connection, and nothing durable was in it. Stopping one joins its thread, so it happens
        // off the executor.
        let runtime = Arc::clone(&self.runtime);
        let owner = served.owner;
        let _stopped = tokio::task::spawn_blocking(move || runtime.release_owner(owner)).await;
    }

    async fn read_requests(self: Arc<Self>, mut reader: FrameReader, served: &Arc<Served>) {
        loop {
            let request: Request = tokio::select! {
                // Anything that decided this connection is over ends the reading too, rather than
                // leaving a reader waiting for a request nobody could be answered about.
                () = served.conversation.ended() => return,
                read = reader.read_message() => match read {
                    Ok(request) => request,
                    // A closed connection or a frame this protocol does not admit. Either way this
                    // conversation is over; the union is closed so an unrecognised frame is a
                    // refusal rather than something to guess at.
                    Err(_error) => return,
                },
            };
            if served.conversation.is_over() {
                return;
            }
            let reply_to = request.request_id;
            let name = request.body.name();
            if immediate(&request.body) {
                // Answered on the reading task, because none of these enters a component: the
                // answer is this host's own and it is already known.
                let body = self.answer(request.body, served).await;
                if !respond(&served.writer, reply_to, name, body).await {
                    return;
                }
                continue;
            }
            // Everything that can enter a component runs in a task of its own, so reading the next
            // request never waits for it. That is what keeps an observation from queueing behind a
            // snapshot, and a registration from delaying either.
            let Ok(permit) = Arc::clone(&served.work).try_acquire_owned() else {
                let body = ResponseBody::Refused {
                    request: name.to_owned(),
                    detail: format!(
                        "this connection already has the {MAX_CONCURRENT_CALLS} calls it may have running"
                    ),
                    disabled: false,
                };
                if !respond(&served.writer, reply_to, name, body).await {
                    return;
                }
                continue;
            };
            let host = Arc::clone(&self);
            let served = Arc::clone(served);
            tokio::spawn(async move {
                let _permit = permit;
                let body = host.answer(request.body, &served).await;
                // An answer that could not be delivered ends the connection. Leaving the reader
                // waiting for the next request on a connection whose last answer never arrived
                // would be serving a worker that cannot hear.
                if !respond(&served.writer, reply_to, name, body).await {
                    served.conversation.end();
                }
            });
        }
    }

    /// Answers one request, turning a refusal into the answer that carries it.
    async fn answer(&self, body: RequestBody, served: &Arc<Served>) -> ResponseBody {
        let name = body.name();
        self.handle(body, served)
            .await
            .unwrap_or_else(|(detail, disabled)| ResponseBody::Refused {
                request: name.to_owned(),
                detail: clipped(detail),
                disabled,
            })
    }

    /// Starts a task that stamps one binding's events with its identifier.
    ///
    /// Each binding gets its own channel, so a connection with several bindings never attributes
    /// one binding's fault to another.
    fn forward_notices(
        binding_id: BindingId,
        notices: NoticeSink,
        binding: Arc<tokio::sync::OnceCell<Arc<crate::runtime::binding::BindingHandle>>>,
        conversation: Arc<Conversation>,
    ) -> tokio::sync::mpsc::Sender<BindingEvent> {
        let (events, mut pending) = tokio::sync::mpsc::channel::<BindingEvent>(DEFAULT_EVENT_QUEUE);
        let mut documents = 0_u64;
        tokio::spawn(async move {
            while let Some(event) = pending.recv().await {
                if matches!(event, BindingEvent::Document { .. }) {
                    documents = documents.saturating_add(1);
                }
                for notice in notices_of(binding_id, documents, event) {
                    match notices.send(notice) {
                        Offered::Kept => {}
                        // The reader never saw what the component drew, so the component draws
                        // again. Without this the binding would sit on a document nobody has.
                        Offered::Dropped => {
                            if let Some(handle) = binding.get() {
                                handle.require_snapshot();
                            }
                        }
                        // What had to arrive would not fit. Nothing further this connection said
                        // could be answered honestly, so it is over.
                        Offered::Overflowed => {
                            conversation.end();
                            return;
                        }
                        Offered::Closed => return,
                    }
                }
            }
        });
        events
    }

    async fn handle(
        &self,
        body: RequestBody,
        served: &Arc<Served>,
    ) -> Result<ResponseBody, (String, bool)> {
        match body {
            RequestBody::Hello { protocol } => {
                if protocol != crate::service::protocol::PROTOCOL {
                    return Err((
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
                    .map_err(|error| (error.to_string(), false))?;
                Ok(ResponseBody::Verified(Box::new(proof)))
            }
            RequestBody::RegisterBinding(registration) => {
                self.register(*registration, served).await
            }
            RequestBody::Event { binding_id, event } => {
                let binding = self.binding(served.owner, binding_id)?;
                let scoped = event_of(&event).map_err(|detail| (detail, false))?;
                let admission = binding.enqueue_observation(scoped);
                Ok(admission_of(admission))
            }
            RequestBody::Snapshot {
                binding_id,
                deadline_ms,
            } => {
                let binding = self.binding(served.owner, binding_id)?;
                let result = binding
                    .snapshot(core::time::Duration::from_millis(deadline_ms))
                    .await;
                called_of(result.map(|result| result.answer.map(|()| CallValue::Document)))
            }
            RequestBody::Checkpoint {
                binding_id,
                deadline_ms,
            } => {
                let binding = self.binding(served.owner, binding_id)?;
                let result = binding
                    .checkpoint(core::time::Duration::from_millis(deadline_ms))
                    .await;
                called_of(result.map(|result| result.answer.map(CallValue::State)))
            }
            RequestBody::Restore {
                binding_id,
                state,
                deadline_ms,
            } => {
                let binding = self.binding(served.owner, binding_id)?;
                let result = binding
                    .restore(state, core::time::Duration::from_millis(deadline_ms))
                    .await;
                called_of(result.map(|result| result.answer.map(|()| CallValue::Document)))
            }
            RequestBody::Unbind { binding_id } => {
                // Removing a binding waits for its thread, so it happens off the executor.
                let runtime = Arc::clone(&self.runtime);
                let owner = served.owner;
                let binding = BindingId::new(binding_id);
                let removed = tokio::task::spawn_blocking(move || runtime.unbind(owner, binding))
                    .await
                    .unwrap_or(Unbound::Absent);
                // Only a binding that existed had a place of its own. A preparation that was still
                // running holds its place until it finishes and gives it back itself, so counting
                // it here as well would let this connection hold more bindings than it may.
                if matches!(removed, Unbound::Stopped) {
                    served.bindings.give_back();
                }
                Ok(ResponseBody::Unbound {
                    existed: removed.existed(),
                })
            }
            RequestBody::Health => Ok(ResponseBody::Health(Box::new(HostHealth {
                live_bindings: self.runtime.live_bindings() as u64,
                connection_bindings: served.bindings.taken() as u64,
                binding_bound: MAX_BINDINGS_PER_CONNECTION as u64,
                resident_components: self.runtime.cache().resident() as u64,
                queued_notice_bytes: served.notices.held_bytes(),
                dropped_documents: served.notices.dropped_documents(),
                engine_version: self.runtime.engine().version().to_owned(),
                target: self.runtime.engine().target().to_owned(),
                engine_compatibility: self.runtime.engine().compatibility().to_owned(),
                uptime_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
                deadlines_enforceable: self.runtime.engine().deadlines_enforceable(),
            }))),
        }
    }

    /// Registers one binding inside one deadline.
    ///
    /// The deadline is absolute across every stage: reading the payload, compiling it, and creating
    /// and binding the instance. Giving each stage the whole figure would let a registration take
    /// three times what the worker was told to expect, and the worker would give up first.
    async fn register(
        &self,
        registration: BindingRegistration,
        served: &Arc<Served>,
    ) -> Result<ResponseBody, (String, bool)> {
        let started = std::time::Instant::now();
        let BindingRegistration {
            binding_id,
            identity,
            facts,
            executable,
            component,
        } = registration;
        let admitted = served.bindings.admit()?;

        // Reading a file is blocking work, and a payload is up to sixteen mebibytes. Neither
        // belongs on the executor that is reading this connection's next request.
        let packages = Arc::clone(&self.packages);
        let root = self.config.packages_root.clone();
        let reading =
            tokio::task::spawn_blocking(move || read_component(&packages, &root, &component));
        // Inside the registration's own deadline, like every other stage: a read that is somehow
        // still going when the worker has stopped waiting is not one this host keeps waiting for.
        let remaining = remaining_of(started, REGISTER_DEADLINE).map_err(refusal)?;
        let wasm = tokio::time::timeout(remaining, reading)
            .await
            .map_err(|_elapsed| {
                (
                    RuntimeError::CallerDeadline {
                        deadline_ms: u64::try_from(REGISTER_DEADLINE.as_millis())
                            .unwrap_or(u64::MAX),
                    }
                    .to_string(),
                    false,
                )
            })?
            .map_err(|error| (format!("the payload could not be read: {error}"), false))?
            .map_err(|detail| (detail, false))?;

        // Two steps rather than one, because they are two steps: the compile happens on a
        // background thread under its own budget, and only once an instance exists does any
        // call budget start.
        let remaining = remaining_of(started, REGISTER_DEADLINE).map_err(refusal)?;
        let compiled = self
            .runtime
            .compile(wasm)
            .map_err(refusal)?
            .wait(remaining)
            .await
            .map_err(refusal)?;
        let binding = BindingId::new(binding_id);
        let request = BindingRequest {
            binding_id: binding,
            identity,
            facts: facts_of(&facts),
            executable,
        };
        // The forwarder is started before the instance exists, because the instance reports what
        // `bind` drew as it is created. The cell is how it learns which binding it is forwarding
        // for, so that a document the worker never received can be asked for again.
        let handle = Arc::new(tokio::sync::OnceCell::new());
        let events = Self::forward_notices(
            binding,
            served.notices.clone(),
            Arc::clone(&handle),
            Arc::clone(&served.conversation),
        );
        let remaining = remaining_of(started, REGISTER_DEADLINE).map_err(refusal)?;
        let bound = self
            .runtime
            .instantiate(served.owner, request, &compiled, events, remaining)
            .await
            .map_err(refusal)?;
        let _first = handle.set(bound);
        admitted.keep();
        Ok(ResponseBody::Registered {
            origin: match compiled.origin {
                CompileOrigin::Compiled => "compiled".to_owned(),
                CompileOrigin::Cached => "cached".to_owned(),
            },
            elapsed_ms: compiled.elapsed_ms,
        })
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
        owner: BindingOwner,
        binding_id: Uuid,
    ) -> Result<Arc<crate::runtime::binding::BindingHandle>, (String, bool)> {
        self.runtime
            .binding(owner, BindingId::new(binding_id))
            .ok_or_else(|| {
                (
                    RuntimeError::NoSuchBinding {
                        binding: binding_id.to_string(),
                    }
                    .to_string(),
                    false,
                )
            })
    }
}

/// What one worker connection holds.
struct Served {
    /// Who the bindings on this connection belong to.
    owner: BindingOwner,
    /// Where this connection's notices are put.
    notices: NoticeSink,
    /// The one writer, so two answers never interleave inside a frame.
    writer: Arc<tokio::sync::Mutex<FrameWriter>>,
    /// How much work that enters a component this connection may have running.
    work: Arc<tokio::sync::Semaphore>,
    /// How many bindings it holds.
    bindings: BindingPlaces,
    /// Whether it is still worth talking on.
    conversation: Arc<Conversation>,
}

/// Whether one connection is still worth talking on.
///
/// One place a connection ends, whatever ended it: the worker closed it, a frame could not be
/// written, or what had to be reported would not fit. Everything serving that connection watches
/// this, so a failure in one direction is not something the other direction keeps working past.
#[derive(Debug)]
struct Conversation {
    over: tokio::sync::watch::Sender<bool>,
}

impl Conversation {
    fn new() -> Self {
        Self {
            over: tokio::sync::watch::channel(false).0,
        }
    }

    /// Ends the connection. Saying so twice is the same as saying it once.
    fn end(&self) {
        let _told = self.over.send(true);
    }

    /// Returns true once the connection is over.
    fn is_over(&self) -> bool {
        *self.over.borrow()
    }

    /// Waits until the connection is over.
    async fn ended(&self) {
        let mut watching = self.over.subscribe();
        if *watching.borrow_and_update() {
            return;
        }
        let _changed = watching.changed().await;
    }
}

/// How many bindings one connection holds, and how many it may.
#[derive(Debug, Default)]
struct BindingPlaces {
    held: AtomicUsize,
}

/// One taken place, given back if its registration does not finish.
struct Place<'a> {
    places: &'a BindingPlaces,
    kept: bool,
}

impl Place<'_> {
    /// Keeps the place: the binding exists now.
    fn keep(mut self) {
        self.kept = true;
    }
}

impl Drop for Place<'_> {
    fn drop(&mut self) {
        if !self.kept {
            self.places.give_back();
        }
    }
}

impl BindingPlaces {
    /// Takes one place, or says they are all taken.
    fn admit(&self) -> Result<Place<'_>, (String, bool)> {
        self.held
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                (held < MAX_BINDINGS_PER_CONNECTION).then_some(held + 1)
            })
            .map(|_held| Place {
                places: self,
                kept: false,
            })
            .map_err(|held| {
                (
                    format!(
                        "this connection holds {held} bindings, which is the {MAX_BINDINGS_PER_CONNECTION} it may hold"
                    ),
                    false,
                )
            })
    }

    /// Gives one place back.
    fn give_back(&self) {
        let _held = self
            .held
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                held.checked_sub(1)
            });
    }

    /// Returns how many places are taken.
    fn taken(&self) -> usize {
        self.held.load(Ordering::Acquire)
    }
}

/// Writes one connection's notices, one frame at a time.
async fn write_notices(
    mut notices: NoticeStream,
    writer: Arc<tokio::sync::Mutex<FrameWriter>>,
    conversation: Arc<Conversation>,
) {
    while let Some(notice) = notices.recv().await {
        let written = tokio::time::timeout(WRITE_DEADLINE, async {
            let mut writer = writer.lock().await;
            writer.write_message(&Frame::Notice(notice)).await
        })
        .await;
        // A failed write and a peer that never took the frame end the same way: there is nobody to
        // tell any more, and a connection whose news cannot be delivered is over.
        if !matches!(written, Ok(Ok(()))) {
            conversation.end();
            return;
        }
    }
    // The queue closed. If it closed because what had to arrive would not fit, that is the
    // connection's end rather than the writer's.
    if notices.overflowed() {
        conversation.end();
    }
}

/// Writes one answer, and says whether the connection is still usable.
///
/// An answer that will not fit a frame is this host's failure to bound something, not the
/// connection's end: the caller is told so by name and the connection carries on.
async fn respond(
    writer: &Arc<tokio::sync::Mutex<FrameWriter>>,
    reply_to: u64,
    name: &str,
    body: ResponseBody,
) -> bool {
    // The whole of it, the wait for the writer included: a peer that has stopped reading would
    // otherwise hold this task and every other answer on this connection behind it.
    let written = tokio::time::timeout(WRITE_DEADLINE, async {
        let mut writer = writer.lock().await;
        match writer
            .write_message(&Frame::Response { reply_to, body })
            .await
        {
            Ok(()) => true,
            Err(kr_ipc::IpcError::Frame(error)) => {
                let refused = ResponseBody::Refused {
                    request: name.to_owned(),
                    detail: format!("this host could not deliver its own answer: {error}"),
                    disabled: false,
                };
                writer
                    .write_message(&Frame::Response {
                        reply_to,
                        body: refused,
                    })
                    .await
                    .is_ok()
            }
            Err(_error) => false,
        }
    })
    .await;
    written.unwrap_or(false)
}

/// Returns true for the requests this host answers without entering a component.
///
/// An observation is one of them: it is a queue push, and answering it on the reading task is what
/// makes a worker's delivery independent of whatever a component is doing.
const fn immediate(body: &RequestBody) -> bool {
    matches!(
        body,
        RequestBody::Hello { .. }
            | RequestBody::Verify { .. }
            | RequestBody::Event { .. }
            | RequestBody::Health
    )
}

/// Turns a runtime failure into a refusal, saying whether the binding is now disabled.
fn refusal(error: RuntimeError) -> (String, bool) {
    let disabled = matches!(error, RuntimeError::Disabled { .. });
    (error.to_string(), disabled)
}

/// Returns `text`, or as much of it as one refusal carries.
fn clipped(text: String) -> String {
    if text.len() <= MAX_REFUSAL_BYTES {
        return text;
    }
    let mut end = MAX_REFUSAL_BYTES;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{} (and {} more bytes)", &text[..end], text.len() - end)
}

fn called_of(
    result: Result<Result<CallValue, String>, RuntimeError>,
) -> Result<ResponseBody, (String, bool)> {
    match result {
        Ok(Ok(value)) => Ok(ResponseBody::Called {
            value: Some(value),
            fault: None,
        }),
        Ok(Err(fault)) => Ok(ResponseBody::Called {
            value: None,
            fault: Some(clipped(fault)),
        }),
        Err(error) => Err(refusal(error)),
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

/// Turns one thing a binding produced into the notices that carry it.
///
/// A document becomes as many notices as it takes for each to fit one frame. One call may draw a
/// mebibyte across many nodes, and a control frame carries a mebibyte including its envelope, so a
/// document sent whole would be a document that fitted every stated bound and still could not be
/// delivered. Each node is already bounded below one frame, so every chunk holds at least one node.
fn notices_of(binding_id: BindingId, document: u64, event: BindingEvent) -> Vec<Notice> {
    let binding_id = binding_id.get();
    match event {
        BindingEvent::Document { call, nodes } => {
            let call = call.as_str().to_owned();
            let mut chunks: Vec<Notice> = Vec::new();
            let mut holding: Vec<WireNode> = Vec::new();
            let mut held = 0;
            for node in nodes.iter().map(node_of) {
                let cost = node_bytes(&node);
                if !holding.is_empty() && held + cost > MAX_NODE_BYTES {
                    chunks.push(Notice::Document {
                        binding_id,
                        call: call.clone(),
                        document,
                        last: false,
                        nodes: core::mem::take(&mut holding),
                    });
                    held = 0;
                }
                held += cost;
                holding.push(node);
            }
            if !holding.is_empty() {
                chunks.push(Notice::Document {
                    binding_id,
                    call,
                    document,
                    last: true,
                    nodes: holding,
                });
            }
            chunks
        }
        BindingEvent::Gap(gap) => vec![Notice::Gap {
            binding_id,
            events: gap.events,
            bytes: gap.bytes,
            documents: 0,
        }],
        // A dropped presentation is a gap in what the worker has seen rather than in what the
        // component has: no event was lost, and the component is rebuilding its document. The
        // worker is told by the same notice, counted apart from lost observations, so it knows to
        // expect a fresh document rather than a continuation.
        BindingEvent::PresentationDropped { documents } => vec![Notice::Gap {
            binding_id,
            events: 0,
            bytes: 0,
            documents: u64::from(documents),
        }],
        BindingEvent::Fault {
            call,
            detail,
            faults_in_window,
        } => vec![Notice::Fault {
            binding_id,
            call: call.as_str().to_owned(),
            detail,
            faults_in_window,
        }],
        BindingEvent::Disabled { reason } => vec![Notice::Disabled { binding_id, reason }],
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
/// Reads a component payload from inside the packages directory, and nowhere else.
///
/// Blocking work, called off the executor and inside the registration's own deadline.
///
/// The directory is opened once, when the host is built, and every payload is opened relative to
/// that handle. That is what makes containment a property of the open rather than of a comparison
/// made before it: a name that becomes a link out of the directory between the check and the open
/// is refused by the open, because there is no check to race.
///
/// What else it refuses, in order: a declared length over what this host compiles, a path that is
/// not a plain name inside the directory, something that is not a regular file, a length the caller
/// did not declare, and bytes that are not the payload whose digest the caller verified against the
/// catalogue. The digest is taken over the bytes this read returned and no others.
fn read_component(
    packages: &cap_std::fs::Dir,
    root: &Path,
    source: &ComponentSource,
) -> Result<Arc<[u8]>, String> {
    if source.bytes > crate::runtime::compile::MAX_COMPONENT_BYTES {
        return Err(format!(
            "the component declares {} bytes, over the {} byte compilation bound",
            source.bytes,
            crate::runtime::compile::MAX_COMPONENT_BYTES
        ));
    }
    let inside = inside_packages(root, &source.path)?;

    // The open refuses a link and does not wait. Without `FollowSymlinks::No` a name replaced by a
    // link would redirect the read; without `O_NONBLOCK` a name replaced by a named pipe would hold
    // this read open until somebody wrote to it, and no declared length would bound that.
    let mut options = cap_std::fs::OpenOptions::new();
    {
        use cap_fs_ext::OpenOptionsFollowExt as _;
        options.read(true).follow(cap_fs_ext::FollowSymlinks::No);
    }
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let mut file = packages.open_with(&inside, &options).map_err(|error| {
        format!(
            "{} is not a readable payload inside {}: {error}",
            inside.display(),
            root.display()
        )
    })?;
    let opened = file
        .metadata()
        .map_err(|error| format!("{} is unreadable: {error}", inside.display()))?;
    if !opened.is_file() {
        return Err(format!(
            "{} is not a regular file, and a component payload is",
            inside.display()
        ));
    }
    if opened.len() != source.bytes {
        return Err(format!(
            "{} is {} bytes and the caller verified {}",
            inside.display(),
            opened.len(),
            source.bytes
        ));
    }

    // Bounded by what the caller declared rather than by what the file says now, and read one byte
    // past it so a file that grew between the check and the read is refused rather than truncated.
    let limit = source.bytes.saturating_add(1);
    let mut bytes = Vec::with_capacity(usize::try_from(source.bytes).unwrap_or(0));
    file.by_ref()
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{} is unreadable: {error}", inside.display()))?;
    if bytes.len() as u64 != source.bytes {
        return Err(format!(
            "{} read as {} bytes and the caller verified {}",
            inside.display(),
            bytes.len(),
            source.bytes
        ));
    }

    // The digest the caller verified against the catalogue, over the bytes this read returned.
    // Bytes that do not match it never reach the compiler, so what becomes machine code is what the
    // catalogue signed.
    let digest = PayloadDigest::of(&bytes);
    if digest != source.digest {
        return Err(format!(
            "{} is not the payload the caller verified",
            inside.display()
        ));
    }
    Ok(Arc::from(bytes))
}

/// Turns what a worker named into a path inside the packages directory.
///
/// A worker may name the payload absolutely or relative to the directory; either way what comes out
/// is a plain relative path with no `..` and no root in it. The open then does the rest: a path this
/// accepts still cannot leave the directory, because it is opened relative to the directory's own
/// handle and links are not followed.
fn inside_packages(root: &Path, named: &str) -> Result<PathBuf, String> {
    let named = Path::new(named);
    let relative = if named.is_absolute() {
        // Either spelling of the directory: the one this host was started with, and the one the
        // filesystem resolves it to. On a host where the state directory is reached through a link,
        // a worker that resolved the path and a worker that did not are both naming the same file.
        let canonical = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        named
            .strip_prefix(root)
            .or_else(|_| named.strip_prefix(&canonical))
            .map_err(|_| {
                format!(
                    "{} is outside the packages directory {}",
                    named.display(),
                    root.display()
                )
            })?
    } else {
        named
    };
    if relative.as_os_str().is_empty() {
        return Err("a component payload has a name".to_owned());
    }
    for part in relative.components() {
        match part {
            std::path::Component::Normal(_) => {}
            _ => {
                return Err(format!(
                    "{} is outside the packages directory {}",
                    named.display(),
                    root.display()
                ));
            }
        }
    }
    Ok(relative.to_path_buf())
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

    /// Opens a packages directory and returns it with its path.
    fn packages() -> (tempfile::TempDir, cap_std::fs::Dir, std::path::PathBuf) {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let packages = directory.path().join("packages");
        std::fs::create_dir_all(&packages).expect("the packages directory");
        let opened = cap_std::fs::Dir::open_ambient_dir(&packages, cap_std::ambient_authority())
            .expect("the packages directory opens");
        (directory, opened, packages)
    }

    #[test]
    fn a_component_outside_the_packages_directory_is_refused() {
        let (directory, opened, packages) = packages();
        let elsewhere = directory.path().join("elsewhere.wasm");
        std::fs::write(&elsewhere, b"not a component").expect("a file");

        let error = read_component(
            &opened,
            &packages,
            &ComponentSource {
                path: elsewhere.display().to_string(),
                digest: PayloadDigest::of(b"not a component"),
                bytes: 15,
            },
        )
        .expect_err("a path outside the packages directory is refused");
        assert!(error.contains("outside the packages directory"));

        // Nor by climbing out of it.
        let error = read_component(
            &opened,
            &packages,
            &ComponentSource {
                path: "../elsewhere.wasm".to_owned(),
                digest: PayloadDigest::of(b"not a component"),
                bytes: 15,
            },
        )
        .expect_err("a path that climbs out is refused");
        assert!(error.contains("outside the packages directory"));

        // Nor through a link that points out of it: the open does not follow one.
        let inside = packages.join("component.wasm");
        std::fs::write(&inside, b"not a component").expect("a file");
        #[cfg(unix)]
        {
            let link = packages.join("link.wasm");
            std::os::unix::fs::symlink(&elsewhere, &link).expect("a link");
            let error = read_component(
                &opened,
                &packages,
                &ComponentSource {
                    path: "link.wasm".to_owned(),
                    digest: PayloadDigest::of(b"not a component"),
                    bytes: 15,
                },
            )
            .expect_err("a link out of the packages directory is refused");
            assert!(
                error.contains("not a readable payload"),
                "the refusal was {error}"
            );
        }

        // Inside it, the digest still has to match what the caller verified.
        let error = read_component(
            &opened,
            &packages,
            &ComponentSource {
                path: inside.display().to_string(),
                digest: PayloadDigest::of(b"something else entirely"),
                bytes: 15,
            },
        )
        .expect_err("a digest that does not match is refused");
        assert!(error.contains("not the payload the caller verified"));

        // And so does the length.
        let error = read_component(
            &opened,
            &packages,
            &ComponentSource {
                path: inside.display().to_string(),
                digest: PayloadDigest::of(b"not a component"),
                bytes: 99,
            },
        )
        .expect_err("a length that does not match is refused");
        assert!(error.contains("the caller verified"));

        // With both right, the bytes are read, whether the worker named the payload absolutely or
        // relative to the directory.
        for named in [inside.display().to_string(), "component.wasm".to_owned()] {
            let bytes = read_component(
                &opened,
                &packages,
                &ComponentSource {
                    path: named,
                    digest: PayloadDigest::of(b"not a component"),
                    bytes: 15,
                },
            )
            .expect("the payload is read");
            assert_eq!(&bytes[..], b"not a component");
        }
    }

    #[test]
    fn a_declared_length_is_refused_before_anything_is_read() {
        let (_directory, opened, packages) = packages();
        std::fs::write(packages.join("component.wasm"), b"small").expect("a file");

        // The declared length is over the compilation bound. Nothing is opened and nothing is
        // allocated: the refusal is the declaration's own.
        let error = read_component(
            &opened,
            &packages,
            &ComponentSource {
                path: "component.wasm".to_owned(),
                digest: PayloadDigest::of(b"small"),
                bytes: crate::runtime::compile::MAX_COMPONENT_BYTES + 1,
            },
        )
        .expect_err("a declared length over the bound is refused");
        assert!(error.contains("over the"));
        assert!(error.contains("compilation bound"));
    }

    #[test]
    fn something_that_is_not_a_regular_file_is_refused_without_being_read() {
        let (_directory, opened, packages) = packages();
        // A directory where a payload should be. On a Unix host this opens and then reads nothing
        // useful; a named pipe would wait for a writer that never comes. Neither is a component,
        // and the file kind is what says so before anything is read.
        std::fs::create_dir(packages.join("component.wasm")).expect("a directory");

        let error = read_component(
            &opened,
            &packages,
            &ComponentSource {
                path: "component.wasm".to_owned(),
                digest: PayloadDigest::of(b""),
                bytes: 0,
            },
        )
        .expect_err("a directory is not a component payload");
        assert!(
            error.contains("not a regular file") || error.contains("not a readable payload"),
            "the refusal was {error}"
        );
    }

    #[test]
    fn a_document_is_split_into_frames_that_can_be_delivered() {
        let binding = BindingId::new(Uuid::from_bytes([4; 16]));
        // Four nodes, each a third of a frame: more than one frame holds, so more than one notice.
        let big = usize::try_from(MAX_NODE_BYTES / 3).expect("a usize bound");
        let nodes: Vec<crate::runtime::host::EmittedNode> = (0..4)
            .map(|index| crate::runtime::host::EmittedNode {
                node_id: format!("n{index}"),
                node_revision: 1,
                body_json: "x".repeat(big),
            })
            .collect();
        let notices = notices_of(
            binding,
            7,
            BindingEvent::Document {
                call: CallKind::Snapshot,
                nodes,
            },
        );
        assert!(notices.len() > 1, "the document was not split");
        let mut carried = 0;
        for (index, notice) in notices.iter().enumerate() {
            let Notice::Document {
                nodes,
                document,
                last,
                ..
            } = notice
            else {
                panic!("a document became {notice:?}");
            };
            let bytes: u64 = nodes.iter().map(node_bytes).sum();
            assert!(bytes <= MAX_NODE_BYTES, "a frame would carry {bytes} bytes");
            // Every piece names the document it belongs to, and only the last says so, which is
            // how a reader knows which notices go together and when it has all of them.
            assert_eq!(*document, 7);
            assert_eq!(*last, index + 1 == notices.len());
            carried += nodes.len();
        }
        assert_eq!(carried, 4, "a node was lost in the splitting");
    }

    #[test]
    fn one_node_is_one_notice_and_the_other_kinds_are_left_alone() {
        let binding = BindingId::new(Uuid::from_bytes([5; 16]));
        let notices = notices_of(
            binding,
            1,
            BindingEvent::Document {
                call: CallKind::Observe,
                nodes: vec![crate::runtime::host::EmittedNode {
                    node_id: "n0".to_owned(),
                    node_revision: 3,
                    body_json: "{}".to_owned(),
                }],
            },
        );
        assert_eq!(notices.len(), 1);
        let faults = notices_of(
            binding,
            1,
            BindingEvent::Fault {
                call: CallKind::Observe,
                detail: "the component trapped".to_owned(),
                faults_in_window: 2,
            },
        );
        assert_eq!(faults.len(), 1);
        assert!(matches!(faults[0], Notice::Fault { .. }));
    }

    #[test]
    fn an_observation_is_answered_without_entering_a_component() {
        let binding_id = Uuid::from_bytes([6; 16]);
        assert!(immediate(&RequestBody::Event {
            binding_id,
            event: WireSourceEvent {
                handle: kr_protocol::ids::SourceEventHandle::new("se-1").expect("a bounded handle"),
                provenance: "terminal_scrape".to_owned(),
                observed_at_ms: 0,
                request_id: None,
                bytes: Vec::new(),
            },
        }));
        assert!(immediate(&RequestBody::Health));
        // And everything that can enter one is not: those run in a task of their own so that the
        // observation above never queues behind them.
        assert!(!immediate(&RequestBody::Snapshot {
            binding_id,
            deadline_ms: 100,
        }));
        assert!(!immediate(&RequestBody::Unbind { binding_id }));
    }

    #[test]
    fn a_connection_holds_the_bindings_it_may_hold_and_no_more() {
        let places = BindingPlaces::default();
        let mut kept = Vec::new();
        for _ in 0..MAX_BINDINGS_PER_CONNECTION {
            kept.push(places.admit().expect("a place"));
        }
        assert_eq!(places.taken(), MAX_BINDINGS_PER_CONNECTION);
        let (detail, _disabled) = places.admit().err().expect("the places are all taken");
        assert!(detail.contains("may hold"));

        // A registration that did not finish gives its place back.
        kept.pop();
        assert_eq!(places.taken(), MAX_BINDINGS_PER_CONNECTION - 1);
        let taken = places.admit().expect("the place came back");
        // And one that did keeps it.
        taken.keep();
        assert_eq!(places.taken(), MAX_BINDINGS_PER_CONNECTION);
        for place in kept {
            place.keep();
        }
        // Unbinding is what gives a kept place back.
        places.give_back();
        assert_eq!(places.taken(), MAX_BINDINGS_PER_CONNECTION - 1);
    }
}
