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
use kr_protocol::frame::StreamKind;
use kr_protocol::scalars::Uuid;

use kr_plugin_service::launcher::{HostIdentity, LaunchError, LaunchResult};
use kr_plugin_service::notices::{
    Delivered, NoticeSink, NoticeStream, Offered, Origin, node_bytes,
};
use kr_plugin_service::protocol::{
    BindingRegistration, CallValue, ComponentSource, DecodeCall, EncodeCall, Frame, HostHealth,
    HostProtocol, Notice, PrepareActionCall, Request, RequestBody, ResponseBody, WireNode,
    WireSourceEvent,
};
use kr_plugin_service::vocabulary::{
    Admission, BindingId, COMPILE_DEADLINE_MS, MAX_NODE_BYTES, MAX_REQUEST_ID_BYTES,
    MAX_REQUEST_TEXT_BYTES, ScopedSourceEvent, attachments_of, check_attachments, check_facts,
    check_snapshot, deadline_of, event_of, facts_of,
};

use crate::runtime::binding::{
    BindingEvent, BindingHandle, BindingOwner, BindingRequest, DEFAULT_EVENT_QUEUE, Incarnation,
    Runtime, RuntimeConfig, Unbound, remaining_of,
};
use crate::runtime::budget::CallKind;
use crate::runtime::compile::{CompileOrigin, Payload};
use crate::runtime::error::RuntimeError;
use crate::service::wire;

/// How long a registration may keep a worker waiting.
///
/// The compilation budget bounds the compile's processor time, and this is the same figure on the
/// clock: a host that accepted a compile of up to that much work has to be willing to wait that long
/// for one. It covers the whole registration -- reading the payload, compiling it, instantiating and
/// binding -- rather than each stage in turn, because what the worker is waiting for is the
/// registration. The worker's own deadline is a little longer again, so the answer a worker gets is
/// the host's own rather than its patience running out first.
pub const REGISTER_DEADLINE: core::time::Duration =
    core::time::Duration::from_millis(COMPILE_DEADLINE_MS);

/// How long an unbind may keep a worker waiting.
///
/// An unbind carries no deadline of its own, so a worker's client waits for it as long as it waits
/// for any request that has none, less the round trip, and this is that figure: the answer a worker
/// gets is the host's own, and not its patience running out first. The removal waits for a thread of
/// the blocking pool, which other work can keep busy, and then for the binding's thread, which ends
/// when the call it is in does.
const UNBIND_DEADLINE: core::time::Duration = kr_plugin_service::client::DEFAULT_DEADLINE
    .saturating_sub(kr_plugin_service::client::ROUND_TRIP_ALLOWANCE);

/// How many unbinds the host may have queued or running on the blocking pool, whichever connections
/// asked for them.
///
/// A request that stops waiting at its deadline does not take its removal back, so a removal is
/// counted from the request that queued it until it has run, and it is counted for the host: a
/// worker that closes its connection and opens another leaves its removals behind and finds them
/// still counted. An unbind that finds this many waiting does not queue another task behind them, so
/// the removals a host leaves on the pool are bounded however many connections asked for them.
pub const MAX_PENDING_UNBINDS: usize = 16;

/// The file, in the state directory beside the compiled-code cache, that holds every registration
/// for as long as it exists. A host built without the `testing` feature reads no such file.
#[cfg(feature = "testing")]
const REGISTRATION_GATE: &str = "hold-registrations";

/// The file a host makes beside [`REGISTRATION_GATE`] when a registration has reached the gate
/// while it is closed.
#[cfg(feature = "testing")]
const REGISTRATION_GATE_REACHED: &str = "hold-registrations.reached";

/// The file, in the state directory beside the compiled-code cache, that holds every compile this
/// host queues for as long as it exists. A host built without the `testing` feature reads no such
/// file.
#[cfg(feature = "testing")]
const COMPILE_GATE: &str = "hold-compiles";

/// The file a host makes beside [`COMPILE_GATE`] when a registration has queued a compile behind
/// the closed gate.
#[cfg(feature = "testing")]
const COMPILE_GATE_REACHED: &str = "hold-compiles.reached";

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

/// How many payloads this host will have in hand at once, from the read of one to the queueing of
/// its compile.
///
/// A read, and the digest of what it read, are blocking work on a thread of their own, and a caller
/// that stopped waiting for one does not stop it: the file is still being read, or the payload is
/// still being digested. Without a bound, a worker that registered, gave up, and registered again
/// could leave a growing number of them behind it. The permit is held inside the blocking work
/// rather than by the caller, so it is released when the work ends rather than when the caller
/// does.
const MAX_CONCURRENT_PAYLOADS: usize = 8;

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
    /// How many payloads may be in hand at once, across every connection.
    payloads: Arc<tokio::sync::Semaphore>,
    /// How many unbinds may be queued or running on the blocking pool at once, across every
    /// connection.
    unbinds: Arc<tokio::sync::Semaphore>,
    /// How many unbinds found every place taken, for the tests of what one does then.
    #[cfg(feature = "testing")]
    unbinds_found_full: std::sync::atomic::AtomicUsize,
    /// The packages directory, opened once. Every payload is opened relative to this handle, which
    /// is what keeps a component's location inside it a property of the open rather than of a
    /// comparison made before it.
    packages: Arc<cap_std::fs::Dir>,
    started: std::time::Instant,
    /// How long a registration may keep a worker waiting.
    register_deadline: core::time::Duration,
    /// How long an unbind may keep a worker waiting.
    unbind_deadline: core::time::Duration,
    /// The pause the notice writers take between taking a notice and writing it, which a test
    /// holds to stand where a document has left the queue and not yet been written.
    #[cfg(feature = "testing")]
    notice_hold: Arc<kr_plugin_service::hold::Hold>,
    /// The pause a registration takes after the connection has recorded it and before the runtime
    /// reserves its identifier, which a test holds to stand where an unbind can come between the
    /// two.
    #[cfg(feature = "testing")]
    reserving_hold: Arc<kr_plugin_service::hold::Hold>,
    /// The pause an unbind's task takes when it starts, which a test holds to stand where the
    /// connection has read an unbind and its task has not yet run.
    #[cfg(feature = "testing")]
    unbinding_hold: Arc<kr_plugin_service::hold::Hold>,
    /// The pause the task of a call into a binding takes when it starts, which a test holds to
    /// stand where the connection has read the call and its task has not yet run.
    #[cfg(feature = "testing")]
    calling_hold: Arc<kr_plugin_service::hold::Hold>,
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

/// The refusal a host gives when its runtime cannot be built.
fn runtime_refused(error: crate::RuntimeError) -> LaunchError {
    LaunchError::Refused {
        detail: format!("the component runtime could not be built: {error}"),
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
            Runtime::new(RuntimeConfig::new(config.cache_root.clone())).map_err(runtime_refused)?;
        Self::around(identity, config, runtime)
    }

    /// Builds the service over a runtime whose epoch no time advances, for the tests of what a
    /// terminal does beside a component that is working: a call into a component is then stopped
    /// by its deadline only when a test advances the epoch, so a machine that is slow to schedule
    /// the host cannot make a component fault. See [`Runtime::with_epoch_held`].
    ///
    /// # Errors
    ///
    /// Returns what [`Self::new`] does.
    #[cfg(feature = "testing")]
    pub fn new_with_epoch_held(identity: HostIdentity, config: HostConfig) -> LaunchResult<Self> {
        let runtime = Runtime::with_epoch_held(RuntimeConfig::new(config.cache_root.clone()))
            .map_err(runtime_refused)?;
        Self::around(identity, config, runtime)
    }

    fn around(identity: HostIdentity, config: HostConfig, runtime: Runtime) -> LaunchResult<Self> {
        // The directory belongs to whoever filed the components in it, which is the catalogue: it
        // holds every repository's store, made with the catalogue's own permissions. This host
        // opens it and nothing more. It does not create it, because a host started where no
        // package was ever installed has no component to read, and it does not judge its mode,
        // because the owner-only directory above it is what keeps other accounts out. A name that
        // is a link or not a directory is refused, and opening it once here is what lets every
        // payload afterwards be opened relative to this handle.
        match std::fs::symlink_metadata(&config.packages_root) {
            Ok(found) if found.is_dir() => {}
            Ok(_) => {
                return Err(LaunchError::Refused {
                    detail: format!(
                        "the packages directory {} is a link or not a directory",
                        config.packages_root.display()
                    ),
                });
            }
            Err(error) => {
                return Err(LaunchError::Refused {
                    detail: format!(
                        "the packages directory {} cannot be read: {error}",
                        config.packages_root.display()
                    ),
                });
            }
        }
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
            payloads: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_PAYLOADS)),
            unbinds: Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_UNBINDS)),
            #[cfg(feature = "testing")]
            unbinds_found_full: std::sync::atomic::AtomicUsize::new(0),
            packages: Arc::new(packages),
            started: std::time::Instant::now(),
            register_deadline: REGISTER_DEADLINE,
            unbind_deadline: UNBIND_DEADLINE,
            #[cfg(feature = "testing")]
            notice_hold: Arc::new(kr_plugin_service::hold::Hold::default()),
            #[cfg(feature = "testing")]
            reserving_hold: Arc::new(kr_plugin_service::hold::Hold::default()),
            #[cfg(feature = "testing")]
            unbinding_hold: Arc::new(kr_plugin_service::hold::Hold::default()),
            #[cfg(feature = "testing")]
            calling_hold: Arc::new(kr_plugin_service::hold::Hold::default()),
        })
    }

    /// Gives a registration `deadline` instead of [`REGISTER_DEADLINE`], for the tests of a
    /// registration: it contains a compile, which a machine that other work keeps busy delays for
    /// minutes, and a test that registers a component decides by what the registration comes to
    /// and not by how busy the machine was.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn registering_within(mut self, deadline: core::time::Duration) -> Self {
        self.register_deadline = deadline;
        self
    }

    /// Gives an unbind `deadline` instead of the time a worker's client waits for one, less the
    /// round trip, for the test of what a host does with an unbind that a busy blocking pool holds
    /// up: a test that needs the host's answer to be due long before the client's has to say how
    /// long before.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn unbinding_within(mut self, deadline: core::time::Duration) -> Self {
        self.unbind_deadline = deadline;
        self
    }

    /// Returns how many of the places for unbinds the host has taken, for the tests of what an
    /// unbind does when it finds them all taken.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn unbinds_waiting(&self) -> usize {
        MAX_PENDING_UNBINDS.saturating_sub(self.unbinds.available_permits())
    }

    /// Returns how many unbinds have found every place taken, which they find before they wait for
    /// one.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn unbinds_found_full(&self) -> usize {
        self.unbinds_found_full.load(Ordering::Acquire)
    }

    /// Holds the notice writers, for the tests of what a connection writes: until the returned hold
    /// is released a writer that took a notice stops with it in hand, before it takes the
    /// connection's writer, and writes nothing.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn hold_notice_writes(&self) -> kr_plugin_service::hold::HoldHandle {
        self.notice_hold.set()
    }

    /// Holds registrations after the connection has recorded them and before the runtime reserves
    /// their identifiers, for the tests of what an unbind does when it comes between the two: until
    /// the returned hold is released a registration that reached that step stops there.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn hold_registrations_before_the_runtime(&self) -> kr_plugin_service::hold::HoldHandle {
        self.reserving_hold.set()
    }

    /// Holds the next unbind at the start of its task, for the tests of what an unbind is about
    /// when its task runs after other requests were read: until the returned hold is released the
    /// task stops there, with the connection long past reading the request.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn hold_unbinds_before_they_run(&self) -> kr_plugin_service::hold::HoldHandle {
        self.unbinding_hold.set()
    }

    /// Holds the next call into a binding at the start of its task, for the tests of what a call
    /// is about when its task runs after other requests were read: until the returned hold is
    /// released the task stops there, with the connection long past reading the request.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn hold_calls_before_they_run(&self) -> kr_plugin_service::hold::HoldHandle {
        self.calling_hold.set()
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
        let (sink, stream) = kr_plugin_service::notices::channel();
        let conversation = Arc::new(Conversation::new());
        let served = Arc::new(Served {
            owner: BindingOwner::next(),
            notices: sink.clone(),
            writer: Arc::clone(&writer),
            work: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CALLS)),
            bindings: Arc::default(),
            conversation: Arc::clone(&conversation),
            registered: Registered::default(),
        });

        // One task writes notices, so a burst of document nodes from one binding cannot interleave
        // with another's inside a frame.
        let notice_writer = Arc::clone(&writer);
        let mut notices_task = tokio::spawn(write_notices(
            stream,
            notice_writer,
            Arc::clone(&conversation),
            Arc::clone(&served.registered),
            #[cfg(feature = "testing")]
            Arc::clone(&self.notice_hold),
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

        if let Ok(mut held) = served.registered.lock() {
            held.live.clear();
            held.preparing.clear();
            held.owed.clear();
            held.standing.clear();
            held.ends.clear();
        }

        // The worker is gone. Its bindings go with it: a binding exists to serve one worker's
        // connection, and nothing durable was in it. Each thread is told to stop and is not waited
        // for, so the end of a connection queues nothing on the blocking pool, whatever else keeps
        // the pool busy: a thread ends on its own after at most one bounded call.
        self.runtime.release_owner(served.owner);
    }

    async fn read_requests(self: Arc<Self>, mut reader: FrameReader, served: &Arc<Served>) {
        loop {
            let request: Request = tokio::select! {
                // Anything that decided this connection is over ends the reading too, rather than
                // leaving a reader waiting for a request nobody could be answered about.
                () = served.conversation.ended() => return,
                read = reader.read_message_without_schema() => match read {
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
            if let RequestBody::Privacy { private } = request.body {
                // Answered by the one function that holds the writer while it sets the flag, so
                // that the answer is after every document the connection wrote.
                if !set_privacy(served, reply_to, private).await {
                    return;
                }
                continue;
            }
            if immediate(&request.body) {
                // Answered on the reading task, because none of these enters a component: the
                // answer is this host's own and it is already known.
                let body = self.answer(request.body, Settled::default(), served).await;
                if !respond(served, reply_to, name, body).await {
                    return;
                }
                continue;
            }
            // Everything that can enter a component runs in a task of its own, so reading the next
            // request never waits for it. That is what keeps an observation from queueing behind a
            // snapshot, and a registration from delaying either.
            let Ok(permit) = Arc::clone(&served.work).try_acquire_owned() else {
                let body = match request.body {
                    // An unbind is answered with the binding out of the runtime like any other,
                    // and taking it out waits for nothing.
                    RequestBody::Unbind { binding_id } => {
                        self.unbind_without_a_call(binding_id, served)
                    }
                    _ => ResponseBody::Refused {
                        request: name.to_owned(),
                        detail: format!(
                            "this connection already has the {MAX_CONCURRENT_CALLS} calls it may have running"
                        ),
                        disabled: false,
                    },
                };
                if !respond(served, reply_to, name, body).await {
                    return;
                }
                continue;
            };
            // What the request is about is settled here, as it is read, and not when its task
            // runs: the requests after it are read before the task starts, and the registrations
            // they make are not what this one is about.
            let settled = settle(&request.body, served);
            let host = Arc::clone(&self);
            let served = Arc::clone(served);
            tokio::spawn(async move {
                let _permit = permit;
                #[cfg(feature = "testing")]
                if called_binding(&request.body).is_some() {
                    host.calling_hold.pause().await;
                }
                let body = host.answer(request.body, settled, &served).await;
                // An answer that could not be delivered ends the connection. Leaving the reader
                // waiting for the next request on a connection whose last answer never arrived
                // would be serving a worker that cannot hear.
                if !respond(&served, reply_to, name, body).await {
                    served.conversation.end();
                }
            });
        }
    }

    /// Answers one request, turning a refusal into the answer that carries it.
    async fn answer(
        &self,
        body: RequestBody,
        settled: Settled,
        served: &Arc<Served>,
    ) -> ResponseBody {
        let name = body.name();
        self.handle(body, settled, served)
            .await
            .unwrap_or_else(|(detail, disabled)| ResponseBody::Refused {
                request: name.to_owned(),
                detail: clipped(detail),
                disabled,
            })
    }

    /// Starts a task that stamps one registration's events with its identifier, and returns the
    /// channel the registration's thread sends them on and what says when the task has ended.
    ///
    /// Each registration gets its own channel, so a connection with several bindings never
    /// attributes one binding's fault to another, and its own task, which passes a notice on only
    /// while the connection stands behind the registration. The identifier alone cannot say that:
    /// the registration may have been removed and the identifier registered again while its thread
    /// finishes a call, and what that thread produces is not the new registration's. The check and
    /// the sending of everything one event became are one step under the connection's record, so a
    /// removal that takes the registration out and forgets what the queue holds for the identifier
    /// is not overtaken by a notice that passed the check before it, and a document is not left
    /// in the queue without its end.
    ///
    /// What it passes on says which registration it comes from, so that the notice writer can
    /// leave unwritten what a registration the connection no longer stands behind left in the
    /// queue or in its hands.
    ///
    /// The task goes on receiving, and dropping, what a registration the connection no longer
    /// stands behind sends, so that its thread never waits on a full channel. It ends when the
    /// thread has, which closes the channel, and the place it holds goes then, before it is said
    /// to have ended.
    fn forward_notices(
        binding_id: BindingId,
        incarnation: Incarnation,
        notices: NoticeSink,
        registered: Registered,
        conversation: Arc<Conversation>,
        place: Place,
    ) -> (tokio::sync::mpsc::Sender<BindingEvent>, Ended) {
        let (events, mut pending) = tokio::sync::mpsc::channel::<BindingEvent>(DEFAULT_EVENT_QUEUE);
        let (ending, ended) = Ended::new();
        let origin = origin_of(incarnation);
        tokio::spawn(async move {
            // Dropped in the reverse order, so the place is back when the task is said to be over.
            let _ending = ending;
            let _place = place;
            while let Some(event) = pending.recv().await {
                let pieces = notices_of(binding_id, event);
                let outcome = {
                    let Ok(held) = registered.lock() else {
                        continue;
                    };
                    if !held.stands(incarnation) {
                        continue;
                    }
                    let mut outcome = Offered::Kept;
                    for notice in pieces {
                        match notices.send_from(origin, notice) {
                            // A dropped document is answered where the loss is reported, because
                            // the binding that lost one is not always the binding that made room.
                            Offered::Kept | Offered::Dropped | Offered::Withheld => {}
                            end @ (Offered::Overflowed | Offered::Closed) => {
                                outcome = end;
                                break;
                            }
                        }
                    }
                    outcome
                };
                match outcome {
                    // What had to arrive would not fit. Nothing further this connection said
                    // could be answered honestly, so it is over.
                    Offered::Overflowed => {
                        conversation.end();
                        return;
                    }
                    Offered::Closed => return,
                    Offered::Kept | Offered::Dropped | Offered::Withheld => {}
                }
            }
        });
        (events, ended)
    }

    async fn handle(
        &self,
        body: RequestBody,
        settled: Settled,
        served: &Arc<Served>,
    ) -> Result<ResponseBody, (String, bool)> {
        match body {
            RequestBody::Hello { protocol } => {
                if protocol != HostProtocol::THIS.name {
                    return Err((
                        format!(
                            "this host speaks {} and the caller offered {protocol}",
                            HostProtocol::THIS.name
                        ),
                        false,
                    ));
                }
                Ok(ResponseBody::Hello {
                    protocol: HostProtocol::THIS.name.to_owned(),
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
                self.register(*registration, settled.registering, served)
                    .await
            }
            RequestBody::Event { binding_id, event } => {
                let binding = standing_binding(served, binding_id)?;
                // A binding the runtime disabled interprets nothing, and a worker that is told so
                // stops offering it anything.
                if let Some(reason) = binding.disabled_reason() {
                    return Err((reason, true));
                }
                let scoped = event_of(&event).map_err(|detail| (detail, false))?;
                let admission = binding.enqueue_observation(scoped);
                Ok(admission_of(admission))
            }
            RequestBody::Snapshot {
                binding_id,
                deadline_ms,
            } => {
                let binding = settled.binding_of(binding_id)?;
                let result = binding
                    .snapshot(core::time::Duration::from_millis(deadline_ms))
                    .await;
                called_of(
                    result.map(|result| {
                        (result.answer.map(|()| CallValue::Document), result.document)
                    }),
                )
            }
            RequestBody::PrepareAction(call) => {
                let PrepareActionCall {
                    binding_id,
                    token,
                    arguments,
                    deadline_ms,
                } = *call;
                let binding = settled.binding_of(binding_id)?;
                let result = binding
                    .prepare_action(
                        wire::token_of(token),
                        wire::arguments_of(arguments),
                        core::time::Duration::from_millis(deadline_ms),
                    )
                    .await;
                called_of(result.map(|result| {
                    (
                        result
                            .answer
                            .map(|plan| CallValue::Plan(Box::new(wire::wire_plan_of(plan)))),
                        result.document,
                    )
                }))
            }
            RequestBody::Checkpoint {
                binding_id,
                deadline_ms,
            } => {
                let binding = settled.binding_of(binding_id)?;
                let result = binding
                    .checkpoint(core::time::Duration::from_millis(deadline_ms))
                    .await;
                called_of(
                    result.map(|result| (result.answer.map(CallValue::State), result.document)),
                )
            }
            RequestBody::Restore {
                binding_id,
                state,
                deadline_ms,
            } => {
                let binding = settled.binding_of(binding_id)?;
                let result = binding
                    .restore(state, core::time::Duration::from_millis(deadline_ms))
                    .await;
                called_of(
                    result.map(|result| {
                        (result.answer.map(|()| CallValue::Document), result.document)
                    }),
                )
            }
            RequestBody::Decode(call) => {
                let DecodeCall {
                    binding_id,
                    event,
                    deadline_ms,
                } = *call;
                let deadline = deadline_of(deadline_ms).map_err(refused)?;
                // A request is a native one with an identifier of the upstream's. Refused here, so
                // that what a scrape looks like never reaches a component that was asked to
                // interpret a request.
                let scoped = native_request_of(&event)?;
                let binding = settled.binding_of(binding_id)?;
                let result = binding.decode_request(scoped, deadline).await;
                called_of(result.map(|result| {
                    (
                        result.answer.map(|decoded| {
                            CallValue::Decoded(Box::new(wire::wire_decoded_of(decoded)))
                        }),
                        result.document,
                    )
                }))
            }
            RequestBody::Encode(call) => {
                let EncodeCall {
                    binding_id,
                    request,
                    decision,
                    event,
                    deadline_ms,
                } = *call;
                let deadline = deadline_of(deadline_ms).map_err(refused)?;
                check_snapshot(&request).map_err(refused)?;
                // The decision is one the request offers and the event is the request's own: the
                // component is given nothing the broker's record of the request does not say.
                if decision.len() > MAX_REQUEST_TEXT_BYTES
                    || !request.offered_decisions.contains(&decision)
                {
                    return Err(refused(
                        "the decision is not one of the decisions the request offers".to_owned(),
                    ));
                }
                let scoped = match event.as_ref() {
                    None => None,
                    Some(event) => {
                        let scoped = native_request_of(event)?;
                        if event.handle != request.handle
                            || scoped.request_id.as_deref() != Some(request.request_id.as_str())
                        {
                            return Err(refused(
                                "the event is not the source of the request being answered"
                                    .to_owned(),
                            ));
                        }
                        Some(scoped)
                    }
                };
                let binding = settled.binding_of(binding_id)?;
                let asked = request.request_id.clone();
                let result = binding
                    .encode_response(
                        wire::request_snapshot_of(&request),
                        decision,
                        scoped,
                        deadline,
                    )
                    .await;
                // What a component answers is its own claim about which request it answered, and
                // an answer for another request is one it was not asked for.
                if let Ok(result) = result.as_ref()
                    && let Ok(encoded) = result.answer.as_ref()
                    && encoded.request_id != asked
                {
                    return Err(refused(
                        "the component's answer names another request than the one it was asked \
                         about"
                            .to_owned(),
                    ));
                }
                called_of(result.map(|result| {
                    (
                        result.answer.map(|encoded| {
                            CallValue::Encoded(Box::new(wire::wire_encoded_of(encoded)))
                        }),
                        result.document,
                    )
                }))
            }
            RequestBody::ReviseFacts { binding_id, facts } => {
                check_facts(&facts).map_err(refused)?;
                let binding = standing_binding(served, binding_id)?;
                // The plugin a binding serves is fixed when it is registered.
                if facts.plugin_id != binding.request().facts.plugin_id {
                    return Err(refused(
                        "the facts name another plugin than the binding serves".to_owned(),
                    ));
                }
                binding.set_facts(facts_of(&facts));
                Ok(ResponseBody::Revised)
            }
            RequestBody::ReviseAttachments {
                binding_id,
                attachments,
            } => {
                check_attachments(&attachments).map_err(refused)?;
                let binding = standing_binding(served, binding_id)?;
                binding.set_attachments(attachments_of(&attachments));
                Ok(ResponseBody::Revised)
            }
            RequestBody::Privacy { .. } => Err(refused(
                "privacy is answered by the task that reads this connection".to_owned(),
            )),
            RequestBody::Unbind { binding_id } => {
                self.unbind(binding_id, settled.leaving, served).await
            }
            RequestBody::Health => Ok(ResponseBody::Health(Box::new(HostHealth {
                live_bindings: self.runtime.live_bindings() as u64,
                connection_bindings: served.bindings.taken() as u64,
                binding_bound: MAX_BINDINGS_PER_CONNECTION as u64,
                component_calls: served.registered.lock().map_or(0, |held| {
                    held.live
                        .values()
                        .map(|handle| handle.completed_calls())
                        .sum()
                }),
                resident_components: self.runtime.cache().resident() as u64,
                resident_bytes: self.runtime.cache().resident_bytes(),
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

    /// Holds a registration, before it reads or compiles anything, for as long as the gate file
    /// exists in the state directory this host files its cache in, and makes a file of its own
    /// beside the gate when one has reached it.
    ///
    /// It serves the by-hand Windows case that ends a plugin host with a registration unanswered
    /// (`a_plugin_host_that_ends_with_a_registration_unanswered_takes_no_worker_with_it_on_windows`,
    /// in kr-cli's `shell_windows` suite): a registration held here has been neither compiled nor
    /// answered, which no reading of a running host from outside shows. The gate is the case's own
    /// file, in the case's own state directory.
    #[cfg(feature = "testing")]
    async fn hold_at_the_registration_gate(&self) {
        let Some(directory) = self.config.cache_root.parent() else {
            return;
        };
        let gate = directory.join(REGISTRATION_GATE);
        if !gate.exists() {
            return;
        }
        let _ = std::fs::write(directory.join(REGISTRATION_GATE_REACHED), b"");
        while gate.exists() {
            tokio::time::sleep(core::time::Duration::from_millis(20)).await;
        }
    }

    /// Takes the compile pool's hold, before a compile is queued, for as long as the compile gate
    /// file exists in the state directory this host files its cache in.
    ///
    /// It serves the case that shows a compile which is queued and not done leaves the terminal
    /// alone: the pool is held, so the component cannot be compiled however fast the machine is, and
    /// the gate file is the case's own, in the case's own state directory.
    #[cfg(feature = "testing")]
    fn hold_compiles_at_the_gate(&self) -> Option<HeldCompiles> {
        let gate = self.config.cache_root.parent()?.join(COMPILE_GATE);
        gate.exists().then(|| HeldCompiles {
            hold: self.runtime.hold_compiles(),
            gate,
        })
    }

    /// Registers one binding inside one deadline.
    ///
    /// The deadline is absolute across every stage: reading the payload, compiling it, and creating
    /// and binding the instance. Giving each stage the whole figure would let a registration take
    /// three times what the worker was told to expect, and the worker would give up first.
    ///
    /// The connection recorded the registration, under `registering`, as it read the request, so an
    /// unbind that comes in before the payload has been read or compiled is about this
    /// registration, and the registration finds out when it gets further and is refused. There is
    /// no incarnation when the identifier already had a registration in flight, which is refused.
    async fn register(
        &self,
        registration: BindingRegistration,
        registering: Option<Incarnation>,
        served: &Arc<Served>,
    ) -> Result<ResponseBody, (String, bool)> {
        let BindingRegistration {
            binding_id,
            identity,
            facts,
            executable,
            component,
        } = registration;
        let binding = BindingId::new(binding_id);
        let Some(incarnation) = registering else {
            return Err(refused(format!("binding {binding} is already live")));
        };
        // Forgets the registration if it does not finish, wherever it stops.
        let registering = Registering {
            registered: &served.registered,
            notices: &served.notices,
            binding_id,
            incarnation,
            kept: false,
        };
        #[cfg(feature = "testing")]
        self.hold_at_the_registration_gate().await;
        let started = std::time::Instant::now();
        let deadline = self.register_deadline;
        check_facts(&facts).map_err(refused)?;
        // The connection's place for this binding. It is handed to the binding's forwarder once
        // there is one, and given back when the binding's thread has ended; a registration that
        // fails before that gives it back at once.
        let binding_place = served.bindings.admit()?;

        // Reading a file is blocking work, and so is the digest of what was read, and a payload is
        // up to sixteen mebibytes. Neither belongs on the executor that is reading this
        // connection's next request.
        //
        // A place among the payloads this host will have in hand is taken first, and the blocking
        // work holds it rather than this caller: a caller whose deadline ran out does not stop the
        // read, so a place released here would let abandoned reads accumulate behind the ones this
        // host is still waiting for. The read hands the place back with the payload, and it is
        // given up once the payload's compile is queued.
        let remaining = remaining_of(started, deadline).map_err(refusal)?;
        let payloads = Arc::clone(&self.payloads);
        let place = tokio::time::timeout(remaining, payloads.acquire_owned())
            .await
            .map_err(|_elapsed| caller_deadline(deadline))?
            .map_err(|_closed| ("this host is no longer reading payloads".to_owned(), false))?;
        let packages = Arc::clone(&self.packages);
        let root = self.config.packages_root.clone();
        let reading = tokio::task::spawn_blocking(move || {
            (read_component(&packages, &root, &component), place)
        });
        // Inside the registration's own deadline, like every other stage: a read that is somehow
        // still going when the worker has stopped waiting is not one this host keeps waiting for.
        let remaining = remaining_of(started, deadline).map_err(refusal)?;
        let (read, place) = tokio::time::timeout(remaining, reading)
            .await
            .map_err(|_elapsed| caller_deadline(deadline))?
            .map_err(|error| (format!("the payload could not be read: {error}"), false))?;
        let payload = read.map_err(refused)?;

        // Two steps rather than one, because they are two steps: the compile happens on a
        // background thread under its own budget, and only once an instance exists does any
        // call budget start. Queueing it waits for nothing and hashes nothing, so it is done here
        // and not on a thread of the blocking pool. A registration that has already run out of time
        // does not queue a compile for a worker that has gone.
        remaining_of(started, deadline).map_err(refusal)?;
        #[cfg(feature = "testing")]
        let held = self.hold_compiles_at_the_gate();
        let compilation = self.runtime.compile(payload).map_err(refusal)?;
        drop(place);
        #[cfg(feature = "testing")]
        if let Some(held) = held {
            held.queued();
        }
        let remaining = remaining_of(started, deadline).map_err(refusal)?;
        let compiled = compilation.wait(remaining).await.map_err(refusal)?;
        let request = BindingRequest {
            binding_id: binding,
            identity,
            facts: facts_of(&facts),
            executable,
        };
        // This registration's own number, which everything that concerns it is kept and removed
        // by: the notices its thread produces, the place it holds and its entry in the runtime.
        // The identifier names whichever registration holds it now, and that is not always this
        // one. The connection chose it when it read the request.
        let (events, ended) = Self::forward_notices(
            binding,
            incarnation,
            served.notices.clone(),
            Arc::clone(&served.registered),
            Arc::clone(&served.conversation),
            binding_place,
        );
        // Standing behind the registration is what lets its forwarder pass its notices on, and
        // the forwarder is attached in one step with finding out that the connection still does,
        // so an unbind cannot come between the two. Recorded before the instance exists, because
        // what `bind` draws reaches the notice queue before this registration returns: a document
        // lost in that moment has to be an obligation this connection can still discharge.
        let standing = served
            .registered
            .lock()
            .is_ok_and(|mut held| held.attach(incarnation, ended));
        if !standing {
            // An unbind came in while the payload was being read or compiled. What it was about is
            // this registration, which has nothing in the runtime yet.
            return Err(refused(format!(
                "binding {binding} was unbound while it was being registered"
            )));
        }
        #[cfg(feature = "testing")]
        self.reserving_hold.pause().await;
        let remaining = remaining_of(started, deadline).map_err(refusal)?;
        let bound = self
            .runtime
            .instantiate(
                served.owner,
                incarnation,
                request,
                &compiled,
                events,
                remaining,
            )
            .await
            .map_err(refusal)?;
        let kept = served
            .registered
            .lock()
            .is_ok_and(|mut held| held.joined(binding_id, incarnation, bound));
        if !kept {
            // An unbind retired this registration between the connection's record of it and now.
            // Its removal found nothing, or the binding that has just gone live, or removed it
            // already; what it was about is this binding, so it goes if it is still there, and
            // the worker is told that it did.
            self.runtime.detach(served.owner, binding, incarnation);
            return Err(refused(format!(
                "binding {binding} was unbound while it was being registered"
            )));
        }
        registering.keep();
        Ok(ResponseBody::Registered {
            origin: match compiled.origin {
                CompileOrigin::Compiled => "compiled".to_owned(),
                CompileOrigin::Cached => "cached".to_owned(),
            },
            elapsed_ms: compiled.elapsed_ms,
        })
    }

    /// Removes one binding, and answers inside the time a worker waits for the answer.
    ///
    /// The request is about the registration this connection holds under the identifier when it
    /// is read, which `leaving` is, and it removes that registration and no other: an identifier
    /// registered again by the time the removal runs is another registration's. A connection that
    /// holds none has nothing to remove. From the moment the request is read, nothing the
    /// registration's thread produces reaches the notice queue, and what the queue held of it is
    /// gone.
    ///
    /// Removing a binding waits for its thread, so it happens off the executor, and the removal is
    /// one task of the blocking pool's. A blocking pool that other work keeps busy can leave that
    /// task waiting for a thread for longer than the worker waits, and a request that waited for it
    /// would hold its place among the calls the connection may have running, and with it the
    /// connection's cleanup, for as long. So the wait is held to the time a worker gives it. A
    /// caller that stops waiting does not take the task back: it runs when it gets a thread, and
    /// finds nothing to remove by then, as the request has taken the binding out already.
    ///
    /// The tasks the host has waiting are counted across its connections, [`MAX_PENDING_UNBINDS`]
    /// at most. A request that finds them all taken waits for a place, in the time it has, as
    /// removals that many connections ask for at once do.
    ///
    /// A request that finds no place, or whose removal has not finished when its time is up, takes
    /// the binding out of the runtime and tells its thread to stop, without waiting for the thread,
    /// and says why it did not wait. That includes a place that was found near the end of the time,
    /// which leaves the removal almost none. A worker takes any answer to an unbind as the binding
    /// gone, so every answer is given with the binding out of the runtime: one left in it would be
    /// one its worker could not register again. That holds for a request that finds none of the
    /// connection's places for calls too, which [`Self::unbind_without_a_call`] answers. The
    /// connection keeps the binding's place until its thread has ended, and a removal that was
    /// queued and runs later finds nothing to remove.
    ///
    /// An unbind that was carried out is answered after the binding's thread has ended and after
    /// everything it produced was passed on or dropped, so no notice the registration produced
    /// after the request began follows the answer. A second request about a registration whose
    /// removal is under way, that arrives while the connection still records the registration, is
    /// answered at the same point; one that arrives after it is recorded no more finds nothing
    /// to remove.
    async fn unbind(
        &self,
        binding_id: Uuid,
        leaving: Option<Leaving>,
        served: &Arc<Served>,
    ) -> Result<ResponseBody, (String, bool)> {
        let started = std::time::Instant::now();
        #[cfg(feature = "testing")]
        self.unbinding_hold.pause().await;
        let Some(leaving) = leaving else {
            return Ok(ResponseBody::Unbound { existed: false });
        };
        let incarnation = leaving.incarnation;
        let owner = served.owner;
        let binding = BindingId::new(binding_id);
        #[cfg(feature = "testing")]
        if self.unbinds.available_permits() == 0 {
            self.unbinds_found_full.fetch_add(1, Ordering::Release);
        }
        // A place among the removals this host may have waiting, held by the task until it has run
        // and not by this request, which stops waiting at its deadline, nor by the connection,
        // which may be over by then.
        let Ok(Ok(waiting)) = tokio::time::timeout(
            self.unbind_deadline,
            Arc::clone(&self.unbinds).acquire_owned(),
        )
        .await
        else {
            return Err(self.detached(
                served,
                binding_id,
                incarnation,
                &format!(
                    "this host already has the {MAX_PENDING_UNBINDS} unbinds it may have waiting"
                ),
            ));
        };
        let runtime = Arc::clone(&self.runtime);
        // Only what the task needs: it is not given the connection's writer, so a connection that is
        // over does not stay open for the task.
        let registered = Arc::clone(&served.registered);
        let removal = tokio::task::spawn_blocking(move || {
            let _waiting = waiting;
            let removed = runtime.unbind(owner, binding, incarnation);
            if let Ok(mut held) = registered.lock() {
                held.withdraw(binding_id, incarnation);
            }
            removed
        });
        let remaining = self.unbind_deadline.saturating_sub(started.elapsed());
        let carried_out = tokio::time::timeout(remaining, async {
            let removed = removal.await?;
            // The binding's thread has ended, or is ending: its removal has been waited for, here
            // or by the request that took it out, and the answer is given after its forwarder
            // has ended too. A registration that was withdrawn while it was being prepared has no
            // thread to wait for yet, and a registration that was not in the runtime yet has none.
            let waited_for = match removed {
                Unbound::Stopped => true,
                Unbound::Absent => leaving.was_live,
                Unbound::Preparing => false,
            };
            if waited_for && let Some(ended) = leaving.ended {
                ended.wait().await;
            }
            Ok::<_, tokio::task::JoinError>(removed)
        })
        .await;
        match carried_out {
            Ok(Ok(_removed)) => Ok(ResponseBody::Unbound {
                // Whether this request is the one that ended the connection's registration. Which
                // of two requests about one registration found its entry in the runtime first is
                // for scheduling to say, and a registration still being made has no entry yet.
                existed: leaving.retired,
            }),
            Ok(Err(error)) => Err(self.detached(
                served,
                binding_id,
                incarnation,
                &format!("the binding could not be removed: {error}"),
            )),
            Err(_elapsed) => Err(self.detached(
                served,
                binding_id,
                incarnation,
                &format!(
                    "the unbind did not finish within {} ms",
                    self.unbind_deadline.as_millis()
                ),
            )),
        }
    }

    /// Answers an unbind that found none of the connection's places for calls to run in. Nothing
    /// is queued and nothing waits: the binding is taken out of the runtime, and the refusal says
    /// so.
    fn unbind_without_a_call(&self, binding_id: Uuid, served: &Arc<Served>) -> ResponseBody {
        let Some(leaving) = leave(served, binding_id) else {
            return ResponseBody::Unbound { existed: false };
        };
        let (detail, disabled) = self.detached(
            served,
            binding_id,
            leaving.incarnation,
            &format!(
                "this connection already has the {MAX_CONCURRENT_CALLS} calls it may have running"
            ),
        );
        ResponseBody::Refused {
            request: "unbind".to_owned(),
            detail: clipped(detail),
            disabled,
        }
    }

    /// Takes one registration out of the runtime without waiting for its thread, and returns the
    /// refusal that says why the removal was not waited for and what was found.
    fn detached(
        &self,
        served: &Served,
        binding_id: Uuid,
        incarnation: Incarnation,
        why: &str,
    ) -> (String, bool) {
        let removed = self
            .runtime
            .detach(served.owner, BindingId::new(binding_id), incarnation);
        if let Ok(mut held) = served.registered.lock() {
            held.withdraw(binding_id, incarnation);
        }
        let outcome = match removed {
            Unbound::Stopped => "the binding was stopped without waiting for its thread",
            Unbound::Preparing => "the registration of the binding was withdrawn",
            Unbound::Absent => "the host no longer holds the binding",
        };
        refused(format!("{why}, and {outcome}"))
    }

    fn descriptor(&self) -> kr_plugin_service::protocol::HostDescriptor {
        kr_plugin_service::protocol::HostDescriptor {
            protocol: HostProtocol::THIS.name.to_owned(),
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
}

/// Returns the binding this connection stands behind under an identifier now, for the requests the
/// reading task answers without entering a component. The runtime may still hold a registration
/// the connection stopped standing behind when it read an unbind, until the removal has run, and
/// a request read after that unbind is not about it.
fn standing_binding(
    served: &Served,
    binding_id: Uuid,
) -> Result<Arc<BindingHandle>, (String, bool)> {
    served
        .registered
        .lock()
        .ok()
        .and_then(|held| held.standing_binding(binding_id))
        .ok_or_else(|| no_such_binding(binding_id))
}

/// The compile pool's hold, and the gate file that keeps it.
#[cfg(feature = "testing")]
struct HeldCompiles {
    hold: crate::runtime::compile::CompileHold,
    gate: std::path::PathBuf,
}

#[cfg(feature = "testing")]
impl HeldCompiles {
    /// Says a compile is queued behind the hold, by the file beside the gate, and lets the hold go
    /// once the gate file is removed.
    fn queued(self) {
        let Self { hold, gate } = self;
        let _ = std::fs::write(gate.with_file_name(COMPILE_GATE_REACHED), b"");
        tokio::spawn(async move {
            while gate.exists() {
                tokio::time::sleep(core::time::Duration::from_millis(20)).await;
            }
            drop(hold);
        });
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
    ///
    /// Shared, so that the forwarder of a binding whose thread outlives the connection can still
    /// give its place back without holding the rest of what the connection held.
    bindings: Arc<BindingPlaces>,
    /// Whether it is still worth talking on.
    conversation: Arc<Conversation>,
    /// The bindings this connection holds, by identifier.
    ///
    /// The notice writer needs them: when it tells a worker that documents were lost, it asks the
    /// binding they belonged to to draw again. A document can be evicted to make room for another
    /// binding's, so which binding lost one is the queue's answer rather than the forwarder's.
    registered: Registered,
}

/// The bindings one connection holds, and what they owe.
type Registered = Arc<std::sync::Mutex<Held>>;

/// What a registration's forwarder holds, and says when it is dropped that the forwarder is over.
#[derive(Debug)]
struct Ending(tokio::sync::watch::Sender<bool>);

impl Drop for Ending {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

/// Says when a registration's forwarder has ended, which is when its thread has ended and
/// everything the thread produced has been passed on or dropped, and the connection's place for
/// the registration is back. Any number of removals of one registration can wait for it.
#[derive(Clone, Debug)]
struct Ended(tokio::sync::watch::Receiver<bool>);

impl Ended {
    fn new() -> (Ending, Self) {
        let (ending, ended) = tokio::sync::watch::channel(false);
        (Ending(ending), Self(ended))
    }

    /// Waits until the forwarder has ended.
    async fn wait(mut self) {
        let _ended = self.0.wait_for(|over| *over).await;
    }
}

/// One connection's bindings, and the redraws they owe.
#[derive(Debug, Default)]
struct Held {
    live: std::collections::HashMap<Uuid, Arc<BindingHandle>>,
    /// Bindings this connection is registering, by the incarnation that is registering each.
    ///
    /// What `bind` draws reaches the notice queue before the registration that started it has
    /// returned, so a document lost in that moment has no handle to ask. The incarnation is what
    /// keeps one registration's cleanup from clearing another's: an identifier can be registered
    /// twice, and the one that fails must not take the other's state with it.
    preparing: std::collections::HashMap<Uuid, Incarnation>,
    /// Redraws owed to bindings that were still being registered when the loss was reported.
    ///
    /// Only for identifiers in `preparing`: a loss reported for a binding that has already gone is
    /// a loss with nobody to tell, and remembering those would be a record that grew for as long as
    /// the connection lasted.
    owed: std::collections::HashSet<Uuid>,
    /// The registrations this connection stands behind, by the origin their notices carry.
    ///
    /// A registration is here from the moment the connection reads its request until the
    /// connection stops standing behind it: a removal began, or it failed to finish registering.
    /// A forwarder passes nothing on for a registration that is not here, whatever its thread still
    /// produces, and the notice writer writes nothing that registration left behind.
    standing: std::collections::HashSet<Origin>,
    /// When each registration's forwarder has ended, for as long as the connection records the
    /// registration, which is after it stops standing behind it and until it is out of the runtime.
    /// A registration has none until its forwarder starts.
    ends: std::collections::HashMap<Incarnation, Ended>,
}

impl Held {
    /// Records that this connection has started registering a binding, and says whether it did.
    ///
    /// Not when a registration of that identifier is already under way: the host refuses a second
    /// registration of one identifier, and letting it overwrite the first one's record would leave
    /// the first with nothing to clean up by.
    fn preparing(&mut self, binding_id: Uuid, incarnation: Incarnation) -> bool {
        if self.preparing.contains_key(&binding_id) {
            return false;
        }
        self.preparing.insert(binding_id, incarnation);
        true
    }

    /// Records a binding, and discharges any redraw it owed from before it existed. Says whether
    /// the connection still stands behind the registration: when it does not, an unbind retired it
    /// after the connection recorded it, the binding is not recorded, and the caller takes it out
    /// of the runtime.
    fn joined(
        &mut self,
        binding_id: Uuid,
        incarnation: Incarnation,
        handle: Arc<BindingHandle>,
    ) -> bool {
        // The redraw first: it is taken before the cleanup that would otherwise remove it, because
        // a document lost while this binding was being registered is a document the binding still
        // has to draw again. It is owed to the registration that is being made now, which is this
        // one only while the identifier is recorded as its.
        let owed =
            self.preparing.get(&binding_id) == Some(&incarnation) && self.owed.remove(&binding_id);
        self.gave_up(binding_id, incarnation);
        if owed {
            handle.require_snapshot();
        }
        let stands = self.stands(incarnation);
        if stands {
            self.live.insert(binding_id, handle);
        }
        stands
    }

    /// Forgets one registration, if it is still the one this identifier is being registered by.
    fn gave_up(&mut self, binding_id: Uuid, incarnation: Incarnation) {
        if self.preparing.get(&binding_id) == Some(&incarnation) {
            self.preparing.remove(&binding_id);
            self.owed.remove(&binding_id);
        }
    }

    /// Asks one binding to draw again, or remembers that it owes a drawing.
    ///
    /// A loss for an identifier this connection neither holds nor is registering is a loss with
    /// nobody to tell: the binding has gone, and its next incarnation will draw from scratch.
    ///
    /// The loss is `origin`'s, and is owed to that registration and to no other: a registration the
    /// connection no longer stands behind has nobody to draw for, and the identifier's next
    /// registration will draw from scratch.
    fn redraw(&mut self, origin: Origin, binding_id: Uuid) {
        if !self.stands_behind(origin) {
            return;
        }
        match self
            .live
            .get(&binding_id)
            .filter(|handle| origin_of(handle.incarnation()) == origin)
        {
            Some(handle) => handle.require_snapshot(),
            None => {
                if self
                    .preparing
                    .get(&binding_id)
                    .is_some_and(|incarnation| origin_of(*incarnation) == origin)
                {
                    self.owed.insert(binding_id);
                }
            }
        }
    }

    /// Starts standing behind a registration the connection has read.
    fn stand(&mut self, incarnation: Incarnation) {
        self.standing.insert(origin_of(incarnation));
    }

    /// Records when a registration's forwarder ends, and says whether the connection still stands
    /// behind the registration: when it does not, an unbind came first, and the registration is
    /// not to go on.
    fn attach(&mut self, incarnation: Incarnation, ended: Ended) -> bool {
        let stands = self.stands(incarnation);
        if stands {
            self.ends.insert(incarnation, ended);
        }
        stands
    }

    /// Returns true while this connection stands behind the registration.
    fn stands(&self, incarnation: Incarnation) -> bool {
        self.stands_behind(origin_of(incarnation))
    }

    /// Returns true while this connection stands behind the registration that `origin` names.
    fn stands_behind(&self, origin: Origin) -> bool {
        self.standing.contains(&origin)
    }

    /// Returns when the registration's forwarder has ended, while this connection records it.
    fn ended_of(&self, incarnation: Incarnation) -> Option<Ended> {
        self.ends.get(&incarnation).cloned()
    }

    /// Returns the live binding this connection stands behind under an identifier now: the one a
    /// call read now is about. A registration the connection stopped standing behind, because an
    /// unbind has been read, is not one a worker can still ask anything of.
    fn standing_binding(&self, binding_id: Uuid) -> Option<Arc<BindingHandle>> {
        let handle = self.live.get(&binding_id)?;
        self.stands(handle.incarnation())
            .then(|| Arc::clone(handle))
    }

    /// Returns the registration this connection holds under an identifier now: the binding that is
    /// live and stood behind, or else the one being registered, or else one that was stood behind
    /// and is on its way out, for a second request about it. A registration on its way out is
    /// never preferred to the one that replaces it.
    fn registration_of(&self, binding_id: Uuid) -> Option<Incarnation> {
        let live = self
            .live
            .get(&binding_id)
            .map(|handle| handle.incarnation());
        live.filter(|incarnation| self.stands(*incarnation))
            .or_else(|| self.preparing.get(&binding_id).copied())
            .or(live)
    }

    /// Stops standing behind a registration, and says whether it did: it does not for a
    /// registration this connection had stopped standing behind already.
    ///
    /// From here nothing that registration's thread produces reaches the notice queue: the
    /// forwarder checks and sends under this record.
    fn retire(&mut self, incarnation: Incarnation) -> bool {
        self.standing.remove(&origin_of(incarnation))
    }

    /// Removes one registration's entries once it is out of the runtime: its binding, if it is the
    /// one held, and its place among those being registered.
    ///
    /// By incarnation rather than by name: an identifier can be unbound and registered again, and
    /// the removal of the old binding must not take the new one's place in this record with it.
    fn withdraw(&mut self, binding_id: Uuid, incarnation: Incarnation) {
        if self
            .live
            .get(&binding_id)
            .is_some_and(|held| held.incarnation() == incarnation)
        {
            self.live.remove(&binding_id);
        }
        self.gave_up(binding_id, incarnation);
        self.ends.remove(&incarnation);
    }
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
    ///
    /// Replaced rather than sent: a `send` with nobody currently watching keeps the old value, and
    /// the reading loop only watches while it is between requests. A connection that failed while
    /// its last request was being answered would otherwise be one nothing ever recorded as over.
    fn end(&self) {
        let _previous = self.over.send_replace(true);
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

/// One registration in progress, forgotten if it does not finish.
///
/// A registration that failed leaves an identifier nothing is preparing any more, and a redraw owed
/// to it is owed to nobody. Forgetting it here is what keeps that record from growing, and the
/// connection stops standing behind it, so that nothing its thread still produces reaches the
/// queue, and what it left there goes.
struct Registering<'a> {
    registered: &'a Registered,
    notices: &'a NoticeSink,
    binding_id: Uuid,
    incarnation: Incarnation,
    kept: bool,
}

impl Registering<'_> {
    fn keep(mut self) {
        self.kept = true;
    }
}

impl Drop for Registering<'_> {
    fn drop(&mut self) {
        if !self.kept
            && let Ok(mut held) = self.registered.lock()
        {
            if held.retire(self.incarnation) {
                // Under the record the forwarder sends under, so nothing follows it.
                self.notices.retract(origin_of(self.incarnation));
            }
            held.gave_up(self.binding_id, self.incarnation);
            held.ends.remove(&self.incarnation);
        }
    }
}

/// One of a connection's places for bindings, given back when it is dropped.
///
/// A binding's forwarder holds the place, and the forwarder ends when the binding's thread has
/// ended, so the places a connection has taken are the instances it still has, those that were told
/// to stop and have not yet ended among them.
struct Place {
    places: Arc<BindingPlaces>,
}

impl Drop for Place {
    fn drop(&mut self) {
        self.places.give_back();
    }
}

impl BindingPlaces {
    /// Takes one place, or says they are all taken.
    fn admit(self: &Arc<Self>) -> Result<Place, (String, bool)> {
        self.held
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                (held < MAX_BINDINGS_PER_CONNECTION).then_some(held + 1)
            })
            .map(|_held| Place {
                places: Arc::clone(self),
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
    registered: Registered,
    #[cfg(feature = "testing")] hold: Arc<kr_plugin_service::hold::Hold>,
) {
    while let Some(Delivered { origin, notice }) = notices.recv_delivered().await {
        #[cfg(feature = "testing")]
        hold.pause().await;
        // A document the worker never received leaves it with a stale view, and the component is
        // the only thing that can rebuild one. Which binding lost a document is the queue's answer
        // rather than any one forwarder's: a document is evicted to make room for whatever needed
        // it, which may belong to another binding entirely.
        if let Notice::Gap {
            binding_id,
            documents,
            ..
        } = &notice
            && *documents > 0
            && let Some(origin) = origin
            && let Ok(mut held) = registered.lock()
        {
            held.redraw(origin, *binding_id);
        }
        let written = tokio::time::timeout(WRITE_DEADLINE, async {
            let mut writer = writer.lock().await;
            if leaves_unwritten(&notices, &registered, origin, &notice) {
                return Ok(());
            }
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

/// Says whether the notice writer, holding the connection's writer, leaves a notice unwritten.
///
/// Looked at under the writer, which the answer to an unbind is written under: what a registration
/// the connection no longer stands behind left in the queue or in this writer's hands is not
/// written, and what was written before the connection stopped standing behind it is before the
/// answer to the unbind that did. The connection's record is held for the whole of the look, so a
/// removal cannot retract the registration between the check and the record of a withheld piece,
/// which would leave the record behind with nothing to clear it.
///
/// Looked at under the writer also because `set_privacy` holds it while it sets the flag: a
/// document is written before the answer that says documents are withheld or is not written at
/// all, whichever of the two tasks took the lock first.
fn leaves_unwritten(
    notices: &NoticeStream,
    registered: &Registered,
    origin: Option<Origin>,
    notice: &Notice,
) -> bool {
    let Ok(held) = registered.lock() else {
        return true;
    };
    if let Some(origin) = origin
        && !held.stands_behind(origin)
    {
        return true;
    }
    notices.skips_withheld(origin, notice)
}

/// Writes one answer, and says whether the connection is still usable.
///
/// An answer that will not fit a frame is this host's failure to bound something, not the
/// connection's end: the caller is told so by name and the connection carries on.
async fn respond(served: &Served, reply_to: u64, name: &str, body: ResponseBody) -> bool {
    // The whole of it, the wait for the writer included: a peer that has stopped reading would
    // otherwise hold this task and every other answer on this connection behind it.
    let written = tokio::time::timeout(WRITE_DEADLINE, async {
        let mut writer = served.writer.lock().await;
        // Looked at under the writer, as a document is: while documents are withheld the
        // presentation of a decoded request is as much a document as a notice is.
        let body = if served.notices.documents_withheld() {
            without_presentation(body)
        } else {
            body
        };
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

/// Withholds documents on a connection, or stops, and answers once that holds.
///
/// The flag is set while the connection's writer is held, so every document the notice writer
/// wrote is before the answer in the stream and none is written after it while documents are
/// withheld. The queue drops what it held for the same reason.
async fn set_privacy(served: &Served, reply_to: u64, private: bool) -> bool {
    let written = tokio::time::timeout(WRITE_DEADLINE, async {
        let mut writer = served.writer.lock().await;
        served.notices.withhold_documents(private);
        writer
            .write_message(&Frame::Response {
                reply_to,
                body: ResponseBody::PrivacySet { private },
            })
            .await
            .is_ok()
    })
    .await;
    written.unwrap_or(false)
}

/// Returns an answer with the presentation of a decoded request left out.
fn without_presentation(body: ResponseBody) -> ResponseBody {
    match body {
        ResponseBody::Called {
            value: Some(CallValue::Decoded(mut decoded)),
            fault,
            document,
        } => {
            decoded.presentation.clear();
            ResponseBody::Called {
                value: Some(CallValue::Decoded(decoded)),
                fault,
                document,
            }
        }
        other => other,
    }
}

/// Reads an event that is a native request: a framed message on the connector's own upstream
/// connection, with the identifier the upstream gave it.
///
/// What a scrape or a machine-readable stream shows may look exactly like a request and is not one,
/// and a component asked to interpret it would be asked to establish authority that bytes of that
/// provenance do not have.
fn native_request_of(event: &WireSourceEvent) -> Result<ScopedSourceEvent, (String, bool)> {
    let scoped = event_of(event).map_err(refused)?;
    if !scoped.provenance.establishes_native_authority() {
        return Err(refused(
            "a scrape does not establish native approval authority, so there is no request to \
             interpret"
                .to_owned(),
        ));
    }
    match scoped.request_id.as_deref() {
        None => {
            return Err(refused(
                "the event carries no native request identifier".to_owned(),
            ));
        }
        Some(id) if id.len() > MAX_REQUEST_ID_BYTES => {
            return Err(refused(
                "the event's request identifier is over its bound".to_owned(),
            ));
        }
        Some(_) => {}
    }
    if scoped.bytes.len() as u64 > MAX_NODE_BYTES {
        return Err(refused(
            "the request is larger than this host carries to a component".to_owned(),
        ));
    }
    Ok(scoped)
}

/// The refusal of a request this host will not run: nothing is disabled by it.
fn refused(detail: String) -> (String, bool) {
    (detail, false)
}

/// The refusal for a call into a binding that the connection holds none of.
fn no_such_binding(binding_id: Uuid) -> (String, bool) {
    (
        RuntimeError::NoSuchBinding {
            binding: binding_id.to_string(),
        }
        .to_string(),
        false,
    )
}

/// What the connection settled about a request when it read it, before the request's task ran.
#[derive(Default)]
struct Settled {
    /// For a registration, the incarnation the connection recorded it under; none when the
    /// identifier already had a registration in flight, which is refused.
    registering: Option<Incarnation>,
    /// For an unbind, the registration it is about; none when the connection held none.
    leaving: Option<Leaving>,
    /// For a call into a binding, the binding it is about; none when the connection stood behind
    /// none under the identifier.
    binding: Option<Arc<BindingHandle>>,
}

impl Settled {
    /// Returns the binding a call into a component is about: the one the connection stood behind
    /// under the identifier when it read the request, and not whichever it holds when the
    /// request's task gets to run, which may be the registration of an identifier that was removed
    /// and registered again in between.
    fn binding_of(self, binding_id: Uuid) -> Result<Arc<BindingHandle>, (String, bool)> {
        self.binding.ok_or_else(|| no_such_binding(binding_id))
    }
}

/// Settles what one request is about: the registration a request to register records, the one a
/// request to unbind is about, and the binding a call into a component is about.
fn settle(body: &RequestBody, served: &Served) -> Settled {
    match body {
        RequestBody::RegisterBinding(registration) => Settled {
            registering: begin(served, registration.binding_id),
            ..Settled::default()
        },
        RequestBody::Unbind { binding_id } => Settled {
            leaving: leave(served, *binding_id),
            ..Settled::default()
        },
        _ => Settled {
            binding: called_binding(body).and_then(|binding_id| {
                served
                    .registered
                    .lock()
                    .ok()
                    .and_then(|held| held.standing_binding(binding_id))
            }),
            ..Settled::default()
        },
    }
}

/// Returns the identifier of the binding a request calls into, for the requests that run in a
/// binding's component and are about a binding that is already registered.
fn called_binding(body: &RequestBody) -> Option<Uuid> {
    match body {
        RequestBody::Snapshot { binding_id, .. }
        | RequestBody::Checkpoint { binding_id, .. }
        | RequestBody::Restore { binding_id, .. } => Some(*binding_id),
        RequestBody::PrepareAction(call) => Some(call.binding_id),
        RequestBody::Decode(call) => Some(call.binding_id),
        RequestBody::Encode(call) => Some(call.binding_id),
        _ => None,
    }
}

/// Records a registration the connection has just read, and starts standing behind it.
///
/// An identifier has one registration in flight at a time: nothing is recorded, and there is no
/// incarnation, when it already has one.
fn begin(served: &Served, binding_id: Uuid) -> Option<Incarnation> {
    let incarnation = Incarnation::next();
    let mut held = served.registered.lock().ok()?;
    if !held.preparing(binding_id, incarnation) {
        return None;
    }
    held.stand(incarnation);
    Some(incarnation)
}

/// What an unbind is about: the registration the connection holds under the identifier.
struct Leaving {
    incarnation: Incarnation,
    /// Whether the registration was live.
    was_live: bool,
    /// Whether this request is the one that stopped the connection standing behind the
    /// registration, which a second request about it, read before the removal finished, is not.
    retired: bool,
    /// When the registration's forwarder has ended, once it has started.
    ended: Option<Ended>,
}

/// Finds the registration an unbind is about, and stops standing behind it.
///
/// From here nothing the registration's thread produces reaches the notice queue, and what the
/// registration put in the queue is taken out, so that the next registration of the identifier
/// starts with a queue that knows nothing about this one. That happens under the record the
/// forwarder sends under, so no notice follows it, and before the runtime lets the identifier go,
/// so no later registration has any. Nothing is taken out when another request stopped standing
/// behind the registration already: it has been, and what the identifier holds now may be another
/// registration's.
///
/// Nothing, when the connection holds none under the identifier.
fn leave(served: &Served, binding_id: Uuid) -> Option<Leaving> {
    let mut held = served.registered.lock().ok()?;
    let incarnation = held.registration_of(binding_id)?;
    let was_live = held
        .live
        .get(&binding_id)
        .is_some_and(|handle| handle.incarnation() == incarnation);
    let retired = held.retire(incarnation);
    if retired {
        served.notices.retract(origin_of(incarnation));
    }
    Some(Leaving {
        incarnation,
        was_live,
        retired,
        ended: held.ended_of(incarnation),
    })
}

/// Names a registration to the notice queue, which does not know what an incarnation is.
fn origin_of(incarnation: Incarnation) -> Origin {
    Origin::new(incarnation.number())
}

/// The refusal for a request that has run out of the time it was given.
fn caller_deadline(deadline: core::time::Duration) -> (String, bool) {
    (
        RuntimeError::CallerDeadline {
            deadline_ms: u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX),
        }
        .to_string(),
        false,
    )
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
            | RequestBody::ReviseFacts { .. }
            | RequestBody::ReviseAttachments { .. }
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
    result: Result<(Result<CallValue, String>, Option<u64>), RuntimeError>,
) -> Result<ResponseBody, (String, bool)> {
    match result {
        Ok((Ok(value), document)) => Ok(ResponseBody::Called {
            value: Some(value),
            fault: None,
            document,
        }),
        Ok((Err(fault), document)) => Ok(ResponseBody::Called {
            value: None,
            fault: Some(clipped(fault)),
            document,
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
fn notices_of(binding_id: BindingId, event: BindingEvent) -> Vec<Notice> {
    let binding_id = binding_id.get();
    match event {
        BindingEvent::Document {
            call,
            document,
            nodes,
        } => {
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

/// Returns the call kinds a worker may ask the host for over the protocol.
///
/// `observe` is not one of them: an observation is a queue push rather than a call, which is what
/// keeps a caller on the terminal path from ever being behind a component. `bind` is not one
/// either, because it happens inside a registration.
#[must_use]
pub fn callable() -> &'static [CallKind] {
    &[
        CallKind::Snapshot,
        CallKind::PrepareAction,
        CallKind::DecodeRequest,
        CallKind::EncodeResponse,
        CallKind::Checkpoint,
        CallKind::Restore,
    ]
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
/// catalogue. The digest is taken over the bytes this read returned and no others, and it is the
/// only pass over them: the payload that is returned carries it, and the compile is keyed by it.
fn read_component(
    packages: &cap_std::fs::Dir,
    root: &Path,
    source: &ComponentSource,
) -> Result<Payload, String> {
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
    Payload::checked(Arc::from(bytes), &source.digest).ok_or_else(|| {
        format!(
            "{} is not the payload the caller verified",
            inside.display()
        )
    })
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
    use kr_plugin_sdk::digest::PayloadDigest;
    use kr_plugin_service::protocol::WireSourceEvent;

    use super::*;

    #[test]
    fn a_registration_is_given_longer_by_the_client_than_the_host_gives_itself() {
        // A client that gave up first would report its own patience as the host's failure.
        assert!(kr_plugin_service::client::REGISTER_DEADLINE > REGISTER_DEADLINE);
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

    #[cfg(unix)]
    fn config_over(packages: &Path, scratch: &Path) -> HostConfig {
        HostConfig {
            endpoint: kr_ipc::paths::Endpoint::from_path(scratch.join(HostProtocol::THIS.endpoint))
                .expect("an endpoint"),
            packages_root: packages.to_path_buf(),
            cache_root: scratch.join("cache"),
        }
    }

    /// The catalogue makes the directory the host reads components from, with its own permissions.
    /// A host that demanded owner-only on it would refuse to start in every real environment.
    #[cfg(unix)]
    #[test]
    fn a_packages_directory_the_catalogue_made_is_opened_as_it_is_and_never_made() {
        use std::os::unix::fs::PermissionsExt as _;

        let scratch = tempfile::tempdir().expect("a temporary directory");
        let packages = scratch.path().join("repositories");
        let identity = || {
            HostIdentity::generate(kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid()))
                .expect("an identity")
        };

        let absent = PluginHost::new(identity(), config_over(&packages, scratch.path()))
            .expect_err("a host does not make the catalogue's directory");
        assert!(absent.to_string().contains("cannot be read"), "{absent}");
        assert!(!packages.exists());

        std::fs::create_dir(&packages).expect("the catalogue's directory");
        std::fs::set_permissions(&packages, std::fs::Permissions::from_mode(0o755))
            .expect("the permissions a default umask gives");
        PluginHost::new(identity(), config_over(&packages, scratch.path()))
            .expect("a directory readable by others is the catalogue's own");

        let link = scratch.path().join("linked");
        std::os::unix::fs::symlink(&packages, &link).expect("a link");
        let linked = PluginHost::new(identity(), config_over(&link, scratch.path()))
            .expect_err("a link is not the catalogue's directory");
        assert!(linked.to_string().contains("not a directory"), "{linked}");
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
            let payload = read_component(
                &opened,
                &packages,
                &ComponentSource {
                    path: named,
                    digest: PayloadDigest::of(b"not a component"),
                    bytes: 15,
                },
            )
            .expect("the payload is read");
            assert_eq!(payload.bytes(), b"not a component");
            assert_eq!(*payload.digest(), PayloadDigest::of(b"not a component"));
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
            BindingEvent::Document {
                call: CallKind::Snapshot,
                document: 7,
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
            BindingEvent::Document {
                call: CallKind::Observe,
                document: 1,
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
        let places = Arc::new(BindingPlaces::default());
        let mut held = Vec::new();
        for _ in 0..MAX_BINDINGS_PER_CONNECTION {
            held.push(places.admit().expect("a place"));
        }
        assert_eq!(places.taken(), MAX_BINDINGS_PER_CONNECTION);
        let (detail, _disabled) = places.admit().err().expect("the places are all taken");
        assert!(detail.contains("may hold"));

        // A place comes back when whatever holds it ends, and not before.
        held.pop();
        assert_eq!(places.taken(), MAX_BINDINGS_PER_CONNECTION - 1);
        let again = places.admit().expect("the place came back");
        assert_eq!(places.taken(), MAX_BINDINGS_PER_CONNECTION);
        drop(again);
        drop(held);
        assert_eq!(places.taken(), 0);
    }
}
