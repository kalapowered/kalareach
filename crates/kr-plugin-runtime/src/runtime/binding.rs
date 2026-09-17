//! The binding lifecycle a broker works with.
//!
//! A binding is one component instance serving one application binding. It has a thread of its
//! own, because a component call is a blocking call into machine code and a store is a single
//! thread's object. That thread is also the whole of what a slow component can hold up.
//!
//! Everything that runs a component runs on that thread: instantiation, `bind`, every call and
//! every replacement after a fault. Nothing that runs a component runs on a caller's thread.
//!
//! # What never waits
//!
//! [`BindingHandle::enqueue_observation`] pushes onto the bounded queue and returns. It takes no
//! lock a component holds, runs nothing, and cannot fail for want of a component. That is the
//! structural form of section 11's requirement that PTY draining, terminal-query responses and the
//! presentation queues never wait for an observation callback: a caller on the terminal path has
//! no way to end up behind a component even if it tries.
//!
//! Everything else is asynchronous and carries the caller's own deadline, including preparing the
//! binding in the first place. A caller that stops waiting gets [`crate::RuntimeError::CallerDeadline`]
//! and carries on; the component's own bounds still apply on its thread.
//!
//! [`BindingHandle::stop`] is the one exception, and it blocks on purpose: it is how a caller makes
//! sure the thread is gone before it drops what the thread was using. A call already inside the
//! component finishes first, and every call is bounded, so the wait is bounded too.
//!
//! # No instance for an idle shell
//!
//! A [`Runtime`] with no prepared bindings holds an engine, a cache directory and an idle
//! compilation pool. It has no store, no instance, no binding thread and no epoch ticks. The first
//! instance appears when a broker prepares a binding, which is when an application that uses one
//! has actually been matched.
//!
//! # What bounds what
//!
//! | Thing | What bounds it |
//! | --- | --- |
//! | observations waiting for the component | the 4 MiB queue, which evicts and reports a gap |
//! | the binding's command channel | what can enter it: observations go in the queue rather than the channel, and the pump is woken once rather than once per event; every other command is one caller's own request, with a payload the protocol has bounded at a frame and a deadline after which its caller has stopped waiting |
//! | events waiting for the caller | a bounded channel; an overflow drops the presentation, says so, and asks the component to rebuild its document |
//! | one call's output | 1 MiB over the document and the returned value together |
//! | one instance's memory | 64 MiB across every linear memory it has |
//!
//! # What a plugin-host crash costs
//!
//! Every instance, every queue and every compiled artefact in memory. Nothing else: pending
//! requests, dispatch markers and the approval ledger live in the worker's broker, and a worker
//! whose bindings vanished re-registers them. That is why this crate has no durable state of its
//! own beyond the compiled-code cache, which is a cache.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use kr_ipc::clock::{SharedClock, SystemSharedClock};
use kr_plugin_sdk::identity::PluginIdentity;
use kr_protocol::scalars::Uuid;

use crate::runtime::bindings::{
    ActionToken, Binding as WireBinding, DecodedRequest, EffectPlan, EncodedResponse, Fault,
    NamedArgument, RequestSnapshot,
};
use crate::runtime::budget::{CallKind, FUEL_PER_DEADLINE_MS};
use crate::runtime::cache::CompiledCache;
use crate::runtime::compile::{CompileBudget, CompilePool, Compiled};
use crate::runtime::engine::RuntimeEngine;
use crate::runtime::error::{RuntimeError, RuntimeResult};
use crate::runtime::faults::{FaultCounter, FaultVerdict};
use crate::runtime::host::{AttachmentFact, BindingFacts, EmittedNode, ScopedSourceEvent};
use crate::runtime::instance::{CallOutcome, Instance, OutputSize};
use crate::runtime::limits::InstanceLimiter;
use crate::runtime::queue::{Admission, ObservationGap, ObservationQueue};

/// How many observations one pump pass delivers before it looks at its commands again.
///
/// A pass that drained the whole queue would let a burst of observations delay a `prepare-action`
/// a person is waiting on. Sixteen is enough that the per-pass overhead is negligible and few
/// enough that an interactive call is never far behind.
const PUMP_BATCH: usize = 16;

/// How many events a caller may be behind before presentations start being dropped.
///
/// A caller that stops reading must not be able to make this host grow without bound, and a
/// component must not be blocked because a socket is slow. So the channel is bounded, and an
/// overflow drops the presentation, says so, and asks the component to rebuild its document: the
/// same answer a lost observation gets, for the same reason.
pub const DEFAULT_EVENT_QUEUE: usize = 256;

/// How many unanswered calls one binding will hold at once.
///
/// A caller that stopped waiting did not take its request back: the request is still on the
/// binding's thread, holding whatever it carries, until the thread reaches it. Without a bound, a
/// caller that retried every time its deadline ran out would grow that backlog without limit. The
/// figure is generous for a binding a person is interacting with and small enough that the memory
/// a stalled component can hold stays a number.
const MAX_OUTSTANDING_CALLS: usize = 64;

/// How much of a failure is carried in a fault notice.
///
/// A fault detail is text a person reads and a host records, and a component can put a mebibyte of
/// its own words into a declared fault. Three faults disable a binding, so an unbounded detail
/// would put three mebibytes per binding into a queue that must always have room for the notices
/// nothing else can replace. Four kibibytes is more than any failure needs to be legible.
const MAX_FAULT_DETAIL_BYTES: usize = 4 * 1024;

/// How many places in the event channel presentation may not take.
///
/// A fault and a disabled notice have to arrive, and a component drawing documents faster than a
/// caller reads them must not be able to leave no room for one. Three faults disable a binding, so
/// four must-arrive events is the most one binding ever produces; this is twice that, and it is
/// what makes reliable delivery independent of how much presentation is waiting.
const FAULT_RESERVE: usize = 8;

/// How long the binding's thread waits for room to report a fault.
///
/// A fault and a disabled notice are the two a caller cannot infer from anything else, so they are
/// worth waiting for. Waiting without a bound would let a caller that stopped reading hold this
/// thread, and a stop would then wait on a send that waits on the caller. After this long the
/// binding disables itself instead, which is what the notice would have asked for.
const FAULT_DELIVERY_WAIT: core::time::Duration = core::time::Duration::from_secs(2);

/// How long preparing a binding may take before the caller is told it has not finished.
pub const DEFAULT_PREPARE_DEADLINE: core::time::Duration = core::time::Duration::from_secs(10);

/// The identifier of one binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BindingId(Uuid);

impl BindingId {
    /// Wraps a raw identifier.
    #[must_use]
    pub const fn new(value: Uuid) -> Self {
        Self(value)
    }

    /// Returns the raw identifier.
    #[must_use]
    pub const fn get(self) -> Uuid {
        self.0
    }
}

impl core::fmt::Display for BindingId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, formatter)
    }
}

/// What a broker asks for when it prepares a binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingRequest {
    /// The binding this instance serves.
    pub binding_id: BindingId,
    /// Which package, which bytes and which catalogue generation.
    ///
    /// All three, because an identifier alone would let an installed update turn an existing
    /// binding into a different version. What this runtime does with the identity is record it and
    /// report it: whether the package these bytes came from was verified against that hash is the
    /// caller's to establish before it gets here.
    pub identity: PluginIdentity,
    /// The facts the component may read about the binding.
    pub facts: BindingFacts,
    /// The executable path the host matched, as the host observed it.
    pub executable: String,
}

/// Something a binding produced without being asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindingEvent {
    /// The component emitted document nodes.
    Document {
        /// Which export emitted them.
        call: CallKind,
        /// The nodes.
        nodes: Vec<EmittedNode>,
    },
    /// The observation stream has a gap, and a fresh snapshot follows.
    Gap(ObservationGap),
    /// Documents were dropped because the caller was too far behind, and a fresh snapshot follows.
    PresentationDropped {
        /// How many documents went.
        documents: u32,
    },
    /// A call failed, and the binding survived it.
    Fault {
        /// Which export failed.
        call: CallKind,
        /// The failure.
        detail: String,
        /// How many faults are inside the window now.
        faults_in_window: u32,
    },
    /// The binding is disabled and will run nothing more.
    Disabled {
        /// Why, in the words a person is shown.
        reason: String,
    },
}

/// How a runtime is configured.
#[derive(Clone)]
pub struct RuntimeConfig {
    /// Where compiled artefacts are filed.
    pub cache_root: PathBuf,
    /// The bounds a compilation runs under.
    pub compile: CompileBudget,
    /// How many components may compile at once.
    pub compile_threads: usize,
    /// How many components may wait for a compilation thread.
    pub compile_queue: usize,
    /// How much fuel one millisecond of deadline is worth.
    pub fuel_rate: u64,
    /// The clock the fault window is measured on.
    pub clock: Arc<dyn SharedClock>,
}

impl RuntimeConfig {
    /// Builds a configuration with the defaults and a cache directory.
    #[must_use]
    pub fn new(cache_root: impl Into<PathBuf>) -> Self {
        Self {
            cache_root: cache_root.into(),
            compile: CompileBudget::defaults(),
            compile_threads: crate::runtime::compile::COMPILE_THREADS,
            compile_queue: crate::runtime::compile::COMPILE_QUEUE,
            fuel_rate: FUEL_PER_DEADLINE_MS,
            clock: Arc::new(SystemSharedClock),
        }
    }
}

impl core::fmt::Debug for RuntimeConfig {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RuntimeConfig")
            .field("cache_root", &self.cache_root)
            .field("compile", &self.compile)
            .field("compile_threads", &self.compile_threads)
            .field("compile_queue", &self.compile_queue)
            .field("fuel_rate", &self.fuel_rate)
            .finish_non_exhaustive()
    }
}

/// The component runtime: one engine, one cache, one compilation pool, and the live bindings.
#[derive(Debug)]
pub struct Runtime {
    engine: RuntimeEngine,
    cache: CompiledCache,
    pool: CompilePool,
    config: RuntimeConfig,
    bindings: Mutex<HashMap<BindingId, Registration>>,
}

/// Who a binding belongs to.
///
/// One per worker connection, and one per in-process caller that prepares bindings of its own. A
/// binding exists to serve the caller that prepared it, so every lookup and every removal names an
/// owner: a second connection that guessed an identifier finds no binding rather than somebody
/// else's, and a connection that goes takes its own bindings and nobody else's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BindingOwner(u64);

/// The source of owner identifiers, which are never reused inside a process.
static NEXT_OWNER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl BindingOwner {
    /// Takes an owner identifier nothing else in this process holds.
    #[must_use]
    pub fn next() -> Self {
        Self(NEXT_OWNER.fetch_add(1, Ordering::Relaxed))
    }

    /// Returns the raw identifier, for a health report or a record.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl core::fmt::Display for BindingOwner {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, formatter)
    }
}

/// One entry in the registry.
///
/// A binding is reserved before anything is started and becomes live when its instance exists.
/// Reserving first is what makes two registrations of one identifier a refusal rather than a race:
/// without it both could pass a "is it live" check before either had finished starting.
#[derive(Debug)]
struct Registration {
    owner: BindingOwner,
    state: RegistrationState,
}

#[derive(Debug)]
enum RegistrationState {
    /// Somebody is preparing this binding.
    Reserved,
    /// The binding is live.
    Live(Arc<BindingHandle>),
}

impl Runtime {
    /// Builds a runtime.
    ///
    /// Nothing is compiled or instantiated here. The engine is configured, the cache directory is
    /// created owner-only, and the compilation pool's threads start idle at background priority.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::Engine`] when the engine will not build, or
    /// [`RuntimeError::CacheUnusable`] when the cache directory cannot be used.
    pub fn new(config: RuntimeConfig) -> RuntimeResult<Self> {
        let engine = RuntimeEngine::new()?;
        let cache = CompiledCache::open(config.cache_root.clone())?;
        let pool = CompilePool::with_threads(config.compile_threads, config.compile_queue);
        Ok(Self {
            engine,
            cache,
            pool,
            config,
            bindings: Mutex::new(HashMap::new()),
        })
    }

    /// Returns the engine.
    #[must_use]
    pub const fn engine(&self) -> &RuntimeEngine {
        &self.engine
    }

    /// Returns the compiled-code cache.
    #[must_use]
    pub const fn cache(&self) -> &CompiledCache {
        &self.cache
    }

    /// Returns the compilation pool.
    #[must_use]
    pub const fn pool(&self) -> &CompilePool {
        &self.pool
    }

    /// Returns how many bindings are live.
    ///
    /// Zero means no store, no instance and no binding thread exist. A host serving idle shells
    /// stays at zero.
    #[must_use]
    pub fn live_bindings(&self) -> usize {
        self.bindings.lock().map_or(0, |bindings| {
            bindings
                .values()
                .filter(|entry| matches!(entry.state, RegistrationState::Live(_)))
                .count()
        })
    }

    /// Returns how many bindings one owner holds.
    #[must_use]
    pub fn bindings_of(&self, owner: BindingOwner) -> usize {
        self.bindings.lock().map_or(0, |bindings| {
            bindings
                .values()
                .filter(|entry| entry.owner == owner)
                .count()
        })
    }

    /// Returns a live binding of `owner`'s.
    ///
    /// An identifier another owner holds is not found, which is the point: an identifier is not a
    /// capability, and a caller that guessed one gets the same answer as a caller that invented one.
    #[must_use]
    pub fn binding(
        &self,
        owner: BindingOwner,
        binding_id: BindingId,
    ) -> Option<Arc<BindingHandle>> {
        self.bindings
            .lock()
            .ok()
            .and_then(|bindings| match bindings.get(&binding_id) {
                Some(Registration {
                    owner: held,
                    state: RegistrationState::Live(handle),
                }) if *held == owner => Some(Arc::clone(handle)),
                _ => None,
            })
    }

    /// Reserves an identifier for `owner`, or says it is taken.
    ///
    /// Taken under the lock and before anything is started, so two registrations of one identifier
    /// cannot both get past it.
    fn reserve(&self, owner: BindingOwner, binding_id: BindingId) -> RuntimeResult<()> {
        let mut bindings = self
            .bindings
            .lock()
            .map_err(|_| RuntimeError::Instantiation {
                detail: "the binding registry is poisoned".to_owned(),
            })?;
        if bindings.contains_key(&binding_id) {
            return Err(RuntimeError::Instantiation {
                detail: format!("binding {binding_id} is already live"),
            });
        }
        bindings.insert(
            binding_id,
            Registration {
                owner,
                state: RegistrationState::Reserved,
            },
        );
        Ok(())
    }

    /// Gives up a reservation that did not become a binding.
    fn release(&self, owner: BindingOwner, binding_id: BindingId) {
        if let Ok(mut bindings) = self.bindings.lock()
            && matches!(
                bindings.get(&binding_id),
                Some(Registration {
                    owner: held,
                    state: RegistrationState::Reserved,
                }) if *held == owner
            )
        {
            bindings.remove(&binding_id);
        }
    }

    /// Submits a component for compilation, lazily and at background priority.
    ///
    /// Returns as soon as the work is queued. This is the only place a component is compiled, and
    /// it is a separate step from [`Self::instantiate`] so that a caller can see, and a test can
    /// prove, that no call deadline contains a compile.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::ComponentTooLarge`] or [`RuntimeError::CompilationPressure`].
    pub fn compile(&self, wasm: Arc<[u8]>) -> RuntimeResult<Compilation> {
        let wait = self
            .pool
            .submit(&self.engine, &self.cache, wasm, self.config.compile)?;
        Ok(Compilation { wait })
    }

    /// Instantiates a compiled component, calls `bind`, and starts the binding's thread.
    ///
    /// The instantiation and `bind` run on that thread rather than this one, and this call waits
    /// for them with the caller's own deadline. The call budgets in [`crate::runtime::budget`]
    /// start after they have finished, which is what section 11 means by starting a call budget
    /// only once the instance is ready.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::Instantiation`] when the thread cannot start or the instance cannot
    /// be created or bound, [`RuntimeError::CallerDeadline`] when it has not finished by the
    /// deadline, and [`RuntimeError::NoSuchBinding`]'s opposite -- a refusal naming the binding --
    /// when that binding is already live.
    pub async fn instantiate(
        &self,
        owner: BindingOwner,
        request: BindingRequest,
        compiled: &Compiled,
        events: tokio::sync::mpsc::Sender<BindingEvent>,
        within: core::time::Duration,
    ) -> RuntimeResult<Arc<BindingHandle>> {
        let binding_id = request.binding_id;
        // One binding, one instance. Replacing a live binding silently would leave an instance
        // running that nothing could reach and nothing would stop, so the identifier is taken
        // before anything is started rather than checked before anything is awaited.
        self.reserve(owner, binding_id)?;

        let handle = BindingHandle::start(
            request,
            &self.engine,
            &compiled.component,
            self.config.fuel_rate,
            FaultCounter::new(Arc::clone(&self.config.clock)),
            events,
        )
        .inspect_err(|_| self.release(owner, binding_id))?;
        let handle = Arc::new(handle);
        match handle.ready(within).await {
            Ok(()) => {}
            Err(error) => {
                // Signalled rather than joined: this is an asynchronous caller whose deadline has
                // run out, and joining here would hold its thread for as long as the instantiation
                // it gave up on.
                handle.signal_stop();
                self.release(owner, binding_id);
                return Err(error);
            }
        }
        // The reservation is what this replaces. An owner that went away while its instance was
        // starting took its reservation with it, and the instance it no longer has a use for is
        // stopped here rather than left running for nobody.
        let live = self
            .bindings
            .lock()
            .is_ok_and(|mut bindings| match bindings.get(&binding_id) {
                Some(Registration {
                    owner: held,
                    state: RegistrationState::Reserved,
                }) if *held == owner => {
                    bindings.insert(
                        binding_id,
                        Registration {
                            owner,
                            state: RegistrationState::Live(Arc::clone(&handle)),
                        },
                    );
                    true
                }
                _ => false,
            });
        if !live {
            handle.signal_stop();
            return Err(RuntimeError::NoSuchBinding {
                binding: binding_id.to_string(),
            });
        }
        Ok(handle)
    }

    /// Prepares a binding: compile, instantiate, `bind`.
    ///
    /// All three inside one caller deadline, because all three are what a caller is waiting for.
    /// A caller that runs out of patience loses nothing: the compile continues on its pool thread
    /// and files its result, so the next preparation of the same component is quick.
    ///
    /// # Errors
    ///
    /// Returns the compilation, instantiation or `bind` failure, or
    /// [`RuntimeError::CallerDeadline`] when the whole preparation does not finish inside
    /// `deadline`.
    pub async fn prepare(
        &self,
        owner: BindingOwner,
        request: BindingRequest,
        wasm: Arc<[u8]>,
        deadline: core::time::Duration,
        events: tokio::sync::mpsc::Sender<BindingEvent>,
    ) -> RuntimeResult<Arc<BindingHandle>> {
        let started = std::time::Instant::now();
        let compilation = self.compile(wasm)?;
        let compiled = compilation.wait(deadline).await?;
        let remaining = remaining_of(started, deadline)?;
        self.instantiate(owner, request, &compiled, events, remaining)
            .await
    }

    /// Removes a binding and stops its thread.
    ///
    /// Blocks until the thread is gone, so a caller knows the instance is no longer running when
    /// this returns. The component's own state goes with it; nothing a decision depends on was in
    /// there, because pending and dispatch state is the worker broker's.
    pub fn unbind(&self, owner: BindingOwner, binding_id: BindingId) -> bool {
        let entry =
            self.bindings
                .lock()
                .ok()
                .and_then(|mut bindings| match bindings.get(&binding_id) {
                    Some(held) if held.owner == owner => bindings.remove(&binding_id),
                    _ => None,
                });
        match entry {
            Some(Registration {
                state: RegistrationState::Live(handle),
                ..
            }) => {
                handle.stop();
                true
            }
            // A reservation somebody is still preparing. Removing it is the whole of the removal:
            // the preparation will find its reservation gone and give the handle up.
            Some(Registration {
                state: RegistrationState::Reserved,
                ..
            }) => true,
            None => false,
        }
    }

    /// Removes every binding one owner holds, and stops them.
    ///
    /// What a connection's end costs: its own bindings and nothing else. Reservations go too, so a
    /// preparation still running for a caller that has gone finds its reservation removed and stops
    /// the instance it was about to hand over.
    pub fn release_owner(&self, owner: BindingOwner) -> usize {
        let handles: Vec<Arc<BindingHandle>> = self
            .bindings
            .lock()
            .map(|mut bindings| {
                let held: Vec<BindingId> = bindings
                    .iter()
                    .filter(|(_id, entry)| entry.owner == owner)
                    .map(|(id, _entry)| *id)
                    .collect();
                held.into_iter()
                    .filter_map(|id| match bindings.remove(&id) {
                        Some(Registration {
                            state: RegistrationState::Live(handle),
                            ..
                        }) => Some(handle),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let stopped = handles.len();
        for handle in handles {
            handle.stop();
        }
        stopped
    }

    /// Removes every binding and stops every thread. Blocks, as [`Self::unbind`] does.
    pub fn unbind_all(&self) {
        let handles: Vec<Arc<BindingHandle>> = self
            .bindings
            .lock()
            .map(|mut bindings| {
                bindings
                    .drain()
                    .filter_map(|(_id, entry)| match entry.state {
                        RegistrationState::Live(handle) => Some(handle),
                        RegistrationState::Reserved => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        for handle in handles {
            handle.stop();
        }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.unbind_all();
    }
}

/// A compilation that is under way.
#[derive(Debug)]
pub struct Compilation {
    wait: tokio::sync::oneshot::Receiver<RuntimeResult<Compiled>>,
}

impl Compilation {
    /// Waits for the compilation, up to `deadline`.
    ///
    /// A caller that gives up loses nothing: the compile continues on its pool thread and its
    /// result is filed in the cache, so the next preparation of the same component finds it.
    ///
    /// # Errors
    ///
    /// Returns the compilation failure, or [`RuntimeError::CallerDeadline`] when it has not
    /// finished by the deadline.
    pub async fn wait(self, deadline: core::time::Duration) -> RuntimeResult<Compiled> {
        match tokio::time::timeout(deadline, self.wait).await {
            Ok(Ok(outcome)) => outcome,
            // The pool dropped the sender, which means the pool is gone.
            Ok(Err(_)) => Err(RuntimeError::CompilationPressure { queued: 0 }),
            Err(_elapsed) => Err(RuntimeError::CallerDeadline {
                deadline_ms: millis(deadline),
            }),
        }
    }

    /// Returns the result if it is already there.
    ///
    /// # Errors
    ///
    /// Returns the compilation failure when it has finished and failed.
    pub fn poll(&mut self) -> Option<RuntimeResult<Compiled>> {
        match self.wait.try_recv() {
            Ok(outcome) => Some(outcome),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => None,
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                Some(Err(RuntimeError::CompilationPressure { queued: 0 }))
            }
        }
    }
}

/// What a call into a component produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallResult<T> {
    /// What the component answered, or the fault it declared.
    pub answer: Result<T, String>,
    /// The nodes it emitted while answering.
    pub nodes: Vec<EmittedNode>,
}

enum Command {
    Pump,
    Snapshot(Answer<()>),
    PrepareAction {
        token: ActionToken,
        arguments: Vec<NamedArgument>,
        answer: Answer<EffectPlan>,
    },
    DecodeRequest {
        event: ScopedSourceEvent,
        answer: Answer<DecodedRequest>,
    },
    EncodeResponse {
        request: Box<RequestSnapshot>,
        decision: String,
        event: Option<ScopedSourceEvent>,
        answer: Answer<EncodedResponse>,
    },
    Checkpoint(Answer<Vec<u8>>),
    Restore {
        state: Vec<u8>,
        answer: Answer<()>,
    },
    Stop,
}

type Answer<T> = tokio::sync::oneshot::Sender<RuntimeResult<CallResult<T>>>;

/// What a caller has changed and the component has not been told yet.
///
/// A slot rather than a message, so a second change replaces the first instead of queueing behind
/// it: what a component wants to know is the current state, and being told an older one after a
/// newer one would be worse than not being told at all.
#[derive(Debug, Default)]
struct PendingUpdates {
    facts: Mutex<Option<BindingFacts>>,
    attachments: Mutex<Option<Vec<AttachmentFact>>>,
}

/// A live binding.
///
/// Cloneable through an [`Arc`] and usable from several tasks at once: the commands are serialised
/// by the binding's own thread, which is the only thread that ever touches the store.
pub struct BindingHandle {
    request: BindingRequest,
    commands: mpsc::Sender<Command>,
    queue: Arc<Mutex<ObservationQueue>>,
    disabled: Arc<Mutex<Option<String>>>,
    stopping: Arc<AtomicBool>,
    pump_pending: Arc<AtomicBool>,
    pending: Arc<PendingUpdates>,
    outstanding: Arc<AtomicUsize>,
    ready: Mutex<Option<tokio::sync::oneshot::Receiver<RuntimeResult<()>>>>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl core::fmt::Debug for BindingHandle {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BindingHandle")
            .field("binding_id", &self.request.binding_id)
            .field("identity", &self.request.identity.to_string())
            .finish_non_exhaustive()
    }
}

impl BindingHandle {
    /// Starts the binding's thread, which instantiates the component and binds it.
    fn start(
        request: BindingRequest,
        engine: &RuntimeEngine,
        component: &wasmtime::component::Component,
        fuel_rate: u64,
        faults: FaultCounter,
        events: tokio::sync::mpsc::Sender<BindingEvent>,
    ) -> RuntimeResult<Self> {
        let (commands, inbox) = mpsc::channel();
        let (ready, readiness) = tokio::sync::oneshot::channel();
        let queue = Arc::new(Mutex::new(ObservationQueue::new()));
        let disabled = Arc::new(Mutex::new(None));
        let stopping = Arc::new(AtomicBool::new(false));
        let pump_pending = Arc::new(AtomicBool::new(false));
        let pending = Arc::new(PendingUpdates::default());
        let outstanding = Arc::new(AtomicUsize::new(0));

        let target = WireBinding {
            plugin_id: request.identity.plugin_id.as_str().to_owned(),
            binding_revision: request.facts.binding_revision,
            executable: request.executable.clone(),
        };
        let setup = WorkerSetup {
            engine: engine.clone(),
            component: component.clone(),
            facts: request.facts.clone(),
            fuel_rate,
            target,
        };
        let worker = BindingWorker {
            instance: None,
            faults,
            events,
            dropped_documents: 0,
            queue: Arc::clone(&queue),
            disabled: Arc::clone(&disabled),
            stopping: Arc::clone(&stopping),
            pump_pending: Arc::clone(&pump_pending),
            pending: Arc::clone(&pending),
            outstanding: Arc::clone(&outstanding),
            commands: commands.clone(),
            identity: request.identity.clone(),
        };
        let name = format!("kr-plugin-binding-{}", request.binding_id);
        let thread = std::thread::Builder::new()
            .name(name)
            .spawn(move || worker.run(setup, ready, inbox))
            .map_err(|error| RuntimeError::Instantiation {
                detail: format!("the binding's thread could not be started: {error}"),
            })?;

        Ok(Self {
            request,
            commands,
            queue,
            disabled,
            stopping,
            pump_pending,
            pending,
            outstanding,
            ready: Mutex::new(Some(readiness)),
            thread: Mutex::new(Some(thread)),
        })
    }

    /// Waits for the instance to exist and `bind` to have answered.
    ///
    /// # Errors
    ///
    /// Returns the instantiation or `bind` failure, or [`RuntimeError::CallerDeadline`].
    async fn ready(&self, within: core::time::Duration) -> RuntimeResult<()> {
        let readiness = self
            .ready
            .lock()
            .ok()
            .and_then(|mut slot| slot.take())
            .ok_or_else(|| RuntimeError::Instantiation {
                detail: "this binding's readiness was already taken".to_owned(),
            })?;
        match tokio::time::timeout(within, readiness).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(_)) => Err(RuntimeError::Instantiation {
                detail: "the binding's thread ended before it reported itself".to_owned(),
            }),
            Err(_elapsed) => Err(RuntimeError::CallerDeadline {
                deadline_ms: millis(within),
            }),
        }
    }

    /// Returns the binding this instance serves.
    #[must_use]
    pub const fn request(&self) -> &BindingRequest {
        &self.request
    }

    /// Returns the plugin identity the binding is running.
    #[must_use]
    pub const fn identity(&self) -> &PluginIdentity {
        &self.request.identity
    }

    /// Returns the disabled reason, once the binding is disabled.
    #[must_use]
    pub fn disabled_reason(&self) -> Option<String> {
        self.disabled.lock().ok().and_then(|slot| slot.clone())
    }

    /// Returns how many bytes the observation queue holds.
    #[must_use]
    pub fn queued_bytes(&self) -> u64 {
        self.queue.lock().map_or(0, |queue| queue.held_bytes())
    }

    /// Returns true when the component owes a fresh snapshot.
    #[must_use]
    pub fn snapshot_required(&self) -> bool {
        self.queue
            .lock()
            .is_ok_and(|queue| queue.snapshot_required())
    }

    /// Offers one source event to the binding's observation queue.
    ///
    /// Never waits and never runs a component. A caller on the terminal path can call this while
    /// the component is in the middle of an unbounded loop, and it returns at once.
    ///
    /// The pump is woken only when it is not already awake, so a burst of observations adds one
    /// command rather than one per event: the 4 MiB queue is what bounds a burst, and a command
    /// channel that grew with it would be a second, unbounded copy of the same backlog.
    pub fn enqueue_observation(&self, event: ScopedSourceEvent) -> Admission {
        let admission = match self.queue.lock() {
            Ok(mut queue) => queue.push(event),
            // A poisoned queue means a binding thread panicked holding it. Reporting the event as
            // refused is the honest answer: nothing will interpret it.
            Err(_) => Admission::Refused { held_bytes: 0 },
        };
        self.wake();
        admission
    }

    fn wake(&self) {
        if !self.pump_pending.swap(true, Ordering::AcqRel) {
            // A thread that has already stopped makes this fail, which is not a reason to fail the
            // push: the event is in the queue and the queue is going away with the binding.
            if self.commands.send(Command::Pump).is_err() {
                self.pump_pending.store(false, Ordering::Release);
            }
        }
    }

    /// Asks the component for a fresh document.
    ///
    /// # Errors
    ///
    /// Returns the component's failure, or [`RuntimeError::CallerDeadline`].
    pub async fn snapshot(&self, deadline: core::time::Duration) -> RuntimeResult<CallResult<()>> {
        self.dispatch(deadline, Command::Snapshot).await
    }

    /// Turns an invoked control into a proposed effect.
    ///
    /// The component returns a plan. It sends nothing: the broker checks the plan against the
    /// token, the actor's grant, the binding revision and the declared effect class, and then
    /// decides whether anything happens.
    ///
    /// # Errors
    ///
    /// Returns the component's failure, or [`RuntimeError::CallerDeadline`].
    pub async fn prepare_action(
        &self,
        token: ActionToken,
        arguments: Vec<NamedArgument>,
        deadline: core::time::Duration,
    ) -> RuntimeResult<CallResult<EffectPlan>> {
        self.dispatch(deadline, |answer| Command::PrepareAction {
            token,
            arguments,
            answer,
        })
        .await
    }

    /// Interprets an immutable native request.
    ///
    /// # Errors
    ///
    /// Returns the component's failure, or [`RuntimeError::CallerDeadline`].
    pub async fn decode_request(
        &self,
        event: ScopedSourceEvent,
        deadline: core::time::Duration,
    ) -> RuntimeResult<CallResult<DecodedRequest>> {
        self.dispatch(deadline, |answer| Command::DecodeRequest { event, answer })
            .await
    }

    /// Encodes a validated decision as a response to a pending native request.
    ///
    /// # Errors
    ///
    /// Returns the component's failure, or [`RuntimeError::CallerDeadline`].
    pub async fn encode_response(
        &self,
        request: RequestSnapshot,
        decision: String,
        event: Option<ScopedSourceEvent>,
        deadline: core::time::Duration,
    ) -> RuntimeResult<CallResult<EncodedResponse>> {
        self.dispatch(deadline, |answer| Command::EncodeResponse {
            request: Box::new(request),
            decision,
            event,
            answer,
        })
        .await
    }

    /// Takes the component's own resumable state.
    ///
    /// # Errors
    ///
    /// Returns the component's failure, or [`RuntimeError::CallerDeadline`].
    pub async fn checkpoint(
        &self,
        deadline: core::time::Duration,
    ) -> RuntimeResult<CallResult<Vec<u8>>> {
        self.dispatch(deadline, Command::Checkpoint).await
    }

    /// Restores state from a checkpoint this build produced.
    ///
    /// # Errors
    ///
    /// Returns the component's failure, or [`RuntimeError::CallerDeadline`].
    pub async fn restore(
        &self,
        state: Vec<u8>,
        deadline: core::time::Duration,
    ) -> RuntimeResult<CallResult<()>> {
        self.dispatch(deadline, |answer| Command::Restore { state, answer })
            .await
    }

    /// Replaces the facts the component reads about its binding.
    ///
    /// The latest replaces the last rather than queueing behind it: only the current facts are
    /// worth telling a component, and a caller that revised them twice while a call was running
    /// did not mean the component to be told the older set afterwards.
    pub fn set_facts(&self, facts: BindingFacts) {
        if let Ok(mut slot) = self.pending.facts.lock() {
            *slot = Some(facts);
        }
        self.wake();
    }

    /// Replaces the attachments the current draft holds. Coalesced, as the facts are.
    pub fn set_attachments(&self, attachments: Vec<AttachmentFact>) {
        if let Ok(mut slot) = self.pending.attachments.lock() {
            *slot = Some(attachments);
        }
        self.wake();
    }

    /// Stops the binding's thread and waits for it.
    ///
    /// The stop is a flag as well as a command, so it is honoured before the commands already in
    /// the channel rather than after them: a caller that is closing a binding is not waiting for
    /// its backlog. A call already inside the component finishes first, and every call is bounded.
    pub fn stop(&self) {
        self.signal_stop();
        if let Ok(mut slot) = self.thread.lock()
            && let Some(thread) = slot.take()
        {
            let _ = thread.join();
        }
    }

    /// Tells the binding's thread to stop, without waiting for it.
    ///
    /// For the paths that must not block: an asynchronous caller whose deadline ran out, and the
    /// drop of a handle that may be happening on an executor's thread. The thread ends on its own,
    /// after at most one bounded call, and drops the instance with it.
    pub fn signal_stop(&self) {
        self.stopping.store(true, Ordering::Release);
        // The command is what wakes a thread that is blocked waiting for one.
        let _ = self.commands.send(Command::Stop);
    }

    /// Takes one place in the binding's backlog, or says the backlog is full.
    fn admit(&self) -> RuntimeResult<()> {
        self.outstanding
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                (held < MAX_OUTSTANDING_CALLS).then_some(held + 1)
            })
            .map(|_held| ())
            .map_err(|held| RuntimeError::CallBacklog {
                outstanding: held,
                limit: MAX_OUTSTANDING_CALLS,
            })
    }

    /// Returns how many calls are waiting for the binding's thread.
    #[must_use]
    pub fn outstanding_calls(&self) -> usize {
        self.outstanding.load(Ordering::Acquire)
    }

    async fn dispatch<T, F>(
        &self,
        deadline: core::time::Duration,
        build: F,
    ) -> RuntimeResult<CallResult<T>>
    where
        F: FnOnce(Answer<T>) -> Command,
    {
        if let Some(reason) = self.disabled_reason() {
            return Err(RuntimeError::Disabled { reason });
        }
        // Admitted against the backlog before anything is built, because what bounds the backlog
        // is what is allowed into it: a caller whose deadline ran out leaves its request on the
        // thread, and the thread is the only thing that takes one off.
        self.admit()?;
        let (answer, reply) = tokio::sync::oneshot::channel();
        if self.commands.send(build(answer)).is_err() {
            self.outstanding.fetch_sub(1, Ordering::AcqRel);
            return Err(RuntimeError::NoSuchBinding {
                binding: self.request.binding_id.to_string(),
            });
        }
        match tokio::time::timeout(deadline, reply).await {
            Ok(Ok(outcome)) => outcome,
            // The thread dropped the answer, which happens when it stops mid-queue.
            Ok(Err(_)) => Err(RuntimeError::NoSuchBinding {
                binding: self.request.binding_id.to_string(),
            }),
            Err(_elapsed) => Err(RuntimeError::CallerDeadline {
                deadline_ms: millis(deadline),
            }),
        }
    }
}

impl Drop for BindingHandle {
    /// Signals rather than joins.
    ///
    /// A handle can be dropped on an asynchronous executor's thread, and joining there would block
    /// it for as long as the component's current call. [`BindingHandle::stop`] is the joining form,
    /// and [`Runtime::unbind`] is where a caller that wants the instance definitely gone uses it.
    fn drop(&mut self) {
        self.signal_stop();
    }
}

/// What the binding's thread needs to create its instance.
struct WorkerSetup {
    engine: RuntimeEngine,
    component: wasmtime::component::Component,
    facts: BindingFacts,
    fuel_rate: u64,
    target: WireBinding,
}

struct BindingWorker {
    instance: Option<Instance>,
    faults: FaultCounter,
    events: tokio::sync::mpsc::Sender<BindingEvent>,
    dropped_documents: u32,
    queue: Arc<Mutex<ObservationQueue>>,
    disabled: Arc<Mutex<Option<String>>>,
    stopping: Arc<AtomicBool>,
    pump_pending: Arc<AtomicBool>,
    pending: Arc<PendingUpdates>,
    outstanding: Arc<AtomicUsize>,
    commands: mpsc::Sender<Command>,
    identity: PluginIdentity,
}

impl BindingWorker {
    fn run(
        mut self,
        setup: WorkerSetup,
        ready: tokio::sync::oneshot::Sender<RuntimeResult<()>>,
        inbox: mpsc::Receiver<Command>,
    ) {
        // Instantiation and `bind` happen here, on this thread, so nothing a caller is holding is
        // behind them and no caller's thread runs a component.
        let started = Instance::new(
            &setup.engine,
            &setup.component,
            setup.facts,
            InstanceLimiter::defaults(),
            setup.fuel_rate,
        );
        let outcome = match started {
            Ok(mut instance) => {
                let bound = instance.bind(setup.target);
                let nodes = bound.nodes;
                match bound.result {
                    Ok(Ok(())) => {
                        self.instance = Some(instance);
                        // What `bind` drew is presentation like any other. Discarding it would
                        // lose a component's first document for no reason.
                        if !nodes.is_empty() {
                            self.send(BindingEvent::Document {
                                call: CallKind::Bind,
                                nodes,
                            });
                        }
                        Ok(())
                    }
                    Ok(Err(fault)) => Err(RuntimeError::Instantiation {
                        detail: format!("bind declared a fault: {}", fault_text(&fault)),
                    }),
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        };
        let failed = outcome.is_err();
        // A caller that has given up is not an error; the thread ends either way.
        let _ = ready.send(outcome);
        if failed {
            return;
        }

        while let Ok(command) = inbox.recv() {
            if self.stopping.load(Ordering::Acquire) {
                return;
            }
            match command {
                Command::Pump => self.pump(),
                Command::Snapshot(answer) => {
                    if self.abandoned(&answer) {
                        continue;
                    }
                    let owed = self.snapshot_owed();
                    let outcome = self.run_call(CallKind::Snapshot, Instance::snapshot);
                    self.discharge(&outcome, owed);
                    let _ = answer.send(outcome);
                }
                Command::PrepareAction {
                    token,
                    arguments,
                    answer,
                } => {
                    if self.abandoned(&answer) {
                        continue;
                    }
                    let outcome = self.run_call(CallKind::PrepareAction, move |instance| {
                        instance.prepare_action(token, arguments)
                    });
                    let _ = answer.send(outcome);
                }
                Command::DecodeRequest { event, answer } => {
                    if self.abandoned(&answer) {
                        continue;
                    }
                    let outcome = self.run_call(CallKind::DecodeRequest, move |instance| {
                        instance.decode_request(event)
                    });
                    let _ = answer.send(outcome);
                }
                Command::EncodeResponse {
                    request,
                    decision,
                    event,
                    answer,
                } => {
                    if self.abandoned(&answer) {
                        continue;
                    }
                    let outcome = self.run_call(CallKind::EncodeResponse, move |instance| {
                        instance.encode_response(*request, decision, event)
                    });
                    let _ = answer.send(outcome);
                }
                Command::Checkpoint(answer) => {
                    if self.abandoned(&answer) {
                        continue;
                    }
                    let outcome = self.run_call(CallKind::Checkpoint, Instance::checkpoint);
                    let _ = answer.send(outcome);
                }
                Command::Restore { state, answer } => {
                    if self.abandoned(&answer) {
                        continue;
                    }
                    let outcome =
                        self.run_call(CallKind::Restore, move |instance| instance.restore(state));
                    let _ = answer.send(outcome);
                }
                Command::Stop => return,
            }
        }
    }

    /// Releases one call's place in the backlog and says whether its caller is still waiting.
    ///
    /// A caller whose deadline ran out has dropped its receiver. Running the component for it would
    /// spend a call's fuel and elapsed budget on an answer nobody will read, and would put the call
    /// a live caller is waiting for behind it.
    fn abandoned<T>(&self, answer: &Answer<T>) -> bool {
        self.outstanding.fetch_sub(1, Ordering::AcqRel);
        answer.is_closed()
    }

    fn pump(&mut self) {
        // Cleared before the queue is read, so an event that arrives during this pass wakes the
        // next one rather than being left in the queue with nobody coming for it.
        self.pump_pending.store(false, Ordering::Release);
        if self.is_disabled() {
            // A disabled binding interprets nothing. The queue is cleared so a re-registration
            // starts from a snapshot rather than from a backlog nobody read.
            if let Ok(mut queue) = self.queue.lock() {
                queue.clear();
            }
            return;
        }
        self.apply_pending();

        // The gap, then the snapshot it obliges, then the events. Nothing leaves the queue before
        // the component is in a state to interpret it: an event this pass removed and then
        // abandoned would be an event nobody ever accounted for.
        let Some((owed, gap)) = self
            .queue
            .lock()
            .ok()
            .map(|mut queue| (queue.snapshot_owed(), queue.take_gap()))
        else {
            return;
        };
        if let Some(gap) = gap {
            self.send(BindingEvent::Gap(gap));
        }
        if owed != 0 {
            // The component's view is stale: either events were lost, or the instance was replaced
            // after a fault and has no state left. Either way the contract's answer is a fresh
            // snapshot, and it happens here because the component has no way to ask for one. The
            // obligation is discharged by number, so a gap that appeared while this snapshot was
            // running still asks for another.
            let outcome = self.run_call(CallKind::Snapshot, Instance::snapshot);
            if !self.discharge(&outcome, owed) {
                // The snapshot failed, or the component declined it. Either way the obligation
                // stands, and delivering observations against a document that does not exist
                // would interpret them against nothing.
                self.rearm(true);
                return;
            }
        }

        for _ in 0..PUMP_BATCH {
            if self.is_disabled() || self.stopping.load(Ordering::Acquire) {
                return;
            }
            // One at a time, so a fault costs the event that caused it and not the batch.
            let Some(event) = self.take_one() else {
                return;
            };
            let lost = event.clone();
            let outcome = self.run_call(CallKind::Observe, move |instance| instance.observe(event));
            if outcome.is_err() {
                // A faulted instance is replaced and owes a snapshot. The event that faulted is
                // one the component never took in, so it is recorded as lost; the events still in
                // the queue are still in the queue, and the next pass takes the snapshot before it
                // delivers any of them.
                if let Ok(mut queue) = self.queue.lock() {
                    queue.taken_event_was_lost(&lost);
                }
                self.rearm(true);
                return;
            }
        }
        self.rearm(self.queue.lock().is_ok_and(|queue| !queue.is_empty()));
    }

    /// Tells the component what a caller has changed since the last call.
    fn apply_pending(&mut self) {
        let facts = self
            .pending
            .facts
            .lock()
            .ok()
            .and_then(|mut slot| slot.take());
        let attachments = self
            .pending
            .attachments
            .lock()
            .ok()
            .and_then(|mut slot| slot.take());
        if let Some(instance) = self.instance.as_mut() {
            if let Some(facts) = facts {
                instance.set_binding_facts(facts);
            }
            if let Some(attachments) = attachments {
                instance.set_attachments(attachments);
            }
        }
    }

    /// Takes the oldest observation, if there is one.
    fn take_one(&self) -> Option<ScopedSourceEvent> {
        self.queue
            .lock()
            .ok()
            .and_then(|mut queue| queue.take_one())
    }

    /// Wakes the pump again when there is more to do.
    fn rearm(&self, needed: bool) {
        if needed && !self.pump_pending.swap(true, Ordering::AcqRel) {
            let _ = self.commands.send(Command::Pump);
        }
    }

    fn snapshot_owed(&self) -> u64 {
        self.queue.lock().map_or(0, |queue| queue.snapshot_owed())
    }

    /// Clears the snapshot obligation `owed` when the snapshot that answered it succeeded.
    ///
    /// Returns whether it did. A component that declined the snapshot has not rebuilt its view any
    /// more than one whose snapshot faulted, so the obligation stands either way.
    fn discharge<T>(&self, outcome: &RuntimeResult<CallResult<T>>, owed: u64) -> bool {
        let answered = outcome.as_ref().is_ok_and(|result| result.answer.is_ok());
        if answered
            && owed != 0
            && let Ok(mut queue) = self.queue.lock()
        {
            queue.snapshot_taken(owed);
        }
        answered
    }

    fn run_call<T, F>(&mut self, kind: CallKind, invoke: F) -> RuntimeResult<CallResult<T>>
    where
        T: OutputSize,
        F: FnOnce(&mut Instance) -> CallOutcome<T>,
    {
        if let Some(reason) = self.disabled_reason() {
            return Err(RuntimeError::Disabled { reason });
        }
        let Some(instance) = self.instance.as_mut() else {
            return Err(RuntimeError::NoSuchBinding {
                binding: self.identity.plugin_id.as_str().to_owned(),
            });
        };

        // A trapped instance cannot be entered again, so it is replaced first. The replacement has
        // no presentation state, which is why it owes a snapshot.
        if instance.faulted() {
            match instance.replace() {
                Ok(nodes) => {
                    if let Ok(mut queue) = self.queue.lock() {
                        queue.require_snapshot();
                    }
                    if !nodes.is_empty() {
                        self.send(BindingEvent::Document {
                            call: CallKind::Bind,
                            nodes,
                        });
                    }
                }
                Err(error) => {
                    self.record_fault(kind, &error);
                    return Err(error);
                }
            }
        }

        self.apply_pending();
        let Some(instance) = self.instance.as_mut() else {
            return Err(RuntimeError::NoSuchBinding {
                binding: self.identity.plugin_id.as_str().to_owned(),
            });
        };
        let outcome = invoke(instance);
        let nodes = outcome.nodes;
        if !nodes.is_empty() {
            self.send(BindingEvent::Document {
                call: kind,
                nodes: nodes.clone(),
            });
        }
        match outcome.result {
            Ok(answer) => Ok(CallResult {
                answer: answer.map_err(|fault| fault_text(&fault)),
                nodes,
            }),
            Err(error) => {
                self.record_fault(kind, &error);
                Err(error)
            }
        }
    }

    fn record_fault(&mut self, kind: CallKind, error: &RuntimeError) {
        if !error.counts_as_fault() {
            return;
        }
        let detail = clipped(error.to_string(), MAX_FAULT_DETAIL_BYTES);
        match self.faults.record(&detail) {
            FaultVerdict::Continue { faults_in_window } => {
                // The binding survives, and the instance behind it does not: a trap is terminal
                // for a component instance. The replacement has no presentation state, so the
                // component owes a snapshot before anything else is delivered to it.
                if let Ok(mut queue) = self.queue.lock() {
                    queue.require_snapshot();
                }
                self.send(BindingEvent::Fault {
                    call: kind,
                    detail,
                    faults_in_window,
                });
            }
            FaultVerdict::Disabled { reason } => {
                let reason = clipped(
                    format!("{} is disabled: {reason}", self.identity.plugin_id),
                    MAX_FAULT_DETAIL_BYTES,
                );
                if let Ok(mut slot) = self.disabled.lock() {
                    *slot = Some(reason.clone());
                }
                self.send(BindingEvent::Disabled { reason });
            }
        }
    }

    /// Sends one event to the caller, or records that a presentation was dropped.
    ///
    /// The channel is bounded, and this never waits on it: a component must not be blocked because
    /// a caller is slow, and a caller that has stopped reading must not be able to make this host
    /// grow without bound. So a full channel means the document goes, the loss is counted, and the
    /// component is asked to rebuild its view -- the same answer a lost observation gets.
    ///
    /// A fault or a disabled notice is never dropped: those are the two a caller cannot infer from
    /// anything else, so the send waits for room by blocking this thread, which is the binding's
    /// own and nothing else's.
    fn send(&mut self, event: BindingEvent) {
        if self.dropped_documents > 0 {
            let dropped = BindingEvent::PresentationDropped {
                documents: self.dropped_documents,
            };
            if self.events.capacity() > FAULT_RESERVE && self.events.try_send(dropped).is_ok() {
                self.dropped_documents = 0;
            }
        }
        let must_arrive = matches!(
            event,
            BindingEvent::Fault { .. } | BindingEvent::Disabled { .. }
        );
        if !must_arrive {
            // The reserve is not presentation's to take: a document that filled the last places
            // would be a document that left no room for the fault that followed it.
            if self.events.capacity() <= FAULT_RESERVE || self.events.try_send(event).is_err() {
                self.dropped_documents = self.dropped_documents.saturating_add(1);
                if let Ok(mut queue) = self.queue.lock() {
                    queue.require_snapshot();
                }
            }
            return;
        }

        // A fault and a disabled notice are the two a caller cannot infer from anything else, so
        // they are worth waiting for room. Waiting without a bound is not: a caller that has
        // stopped reading would hold this thread for ever, and a stop would then be waiting for a
        // send that is waiting for the caller. So the wait is bounded and gives up.
        let deadline = std::time::Instant::now() + FAULT_DELIVERY_WAIT;
        let mut event = event;
        loop {
            match self.events.try_send(event) {
                Ok(()) => return,
                Err(tokio::sync::mpsc::error::TrySendError::Full(returned)) => event = returned,
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return,
            }
            if self.stopping.load(Ordering::Acquire) || std::time::Instant::now() >= deadline {
                // Nobody is reading, so nobody is going to act on this binding either. Disabling
                // it locally is what stops it running anything more, which is what the notice
                // would have asked for.
                if let Ok(mut slot) = self.disabled.lock()
                    && slot.is_none()
                {
                    *slot = Some(format!(
                        "{} is disabled: its host stopped reading what the binding reported",
                        self.identity.plugin_id
                    ));
                }
                return;
            }
            std::thread::sleep(core::time::Duration::from_millis(5));
        }
    }

    fn disabled_reason(&self) -> Option<String> {
        self.disabled.lock().ok().and_then(|slot| slot.clone())
    }

    fn is_disabled(&self) -> bool {
        self.disabled_reason().is_some()
    }
}

fn millis(duration: core::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Returns `text`, or as much of it as `limit` bytes hold, said plainly.
///
/// Cut at a character boundary, so what a person is shown is still text. The tail is what goes,
/// because the first words of a failure are the ones that say what happened.
fn clipped(text: String, limit: usize) -> String {
    if text.len() <= limit {
        return text;
    }
    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{} (and {} more bytes)", &text[..end], text.len() - end)
}

/// Returns what is left of `deadline` after the time since `started`.
///
/// One deadline across a preparation rather than a fresh one per stage: a caller that allowed
/// thirty seconds meant thirty seconds, not thirty for the compile and thirty more for what
/// follows it.
///
/// # Errors
///
/// Returns [`RuntimeError::CallerDeadline`] when nothing is left.
pub fn remaining_of(
    started: std::time::Instant,
    deadline: core::time::Duration,
) -> RuntimeResult<core::time::Duration> {
    deadline
        .checked_sub(started.elapsed())
        .filter(|left| !left.is_zero())
        .ok_or(RuntimeError::CallerDeadline {
            deadline_ms: millis(deadline),
        })
}

/// Renders a component-declared fault as the text a host records.
#[must_use]
pub fn fault_text(fault: &Fault) -> String {
    match fault {
        Fault::Unreadable(detail) => format!("unreadable: {detail}"),
        Fault::Refused(detail) => format!("refused: {detail}"),
        Fault::NotPermitted(detail) => format!("not permitted: {detail}"),
        Fault::Exhausted(detail) => format!("exhausted: {detail}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_plugin_sdk::digest::PayloadDigest;
    use kr_plugin_sdk::version::PackageVersion;
    use kr_protocol::ids::{PluginId, RepositoryGeneration};

    fn config() -> (tempfile::TempDir, RuntimeConfig) {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let config = RuntimeConfig::new(directory.path().join("plugin-cache"));
        (directory, config)
    }

    #[test]
    fn a_runtime_with_no_bindings_holds_no_instance() {
        let (_directory, config) = config();
        let runtime = Runtime::new(config).expect("a runtime");
        assert_eq!(runtime.live_bindings(), 0);
        // Nothing has been compiled either, so an idle shell costs an engine and a cache directory.
        assert!(runtime.cache().root().exists());
        assert_eq!(runtime.cache().resident(), 0);
    }

    #[test]
    fn unbinding_something_that_is_not_bound_says_so() {
        let (_directory, config) = config();
        let runtime = Runtime::new(config).expect("a runtime");
        let owner = BindingOwner::next();
        assert!(!runtime.unbind(owner, BindingId::new(Uuid::from_bytes([9; 16]))));
        assert_eq!(runtime.bindings_of(owner), 0);
        assert_eq!(runtime.release_owner(owner), 0);
    }

    #[test]
    fn a_binding_identifier_renders_as_its_identifier() {
        let id = BindingId::new(Uuid::from_bytes([1; 16]));
        assert_eq!(id.to_string(), "01010101-0101-0101-0101-010101010101");
        assert_eq!(id.get(), Uuid::from_bytes([1; 16]));
    }

    #[test]
    fn a_declared_fault_renders_with_its_kind() {
        assert_eq!(
            fault_text(&Fault::Refused("not mine".to_owned())),
            "refused: not mine"
        );
        assert_eq!(
            fault_text(&Fault::NotPermitted("no grant".to_owned())),
            "not permitted: no grant"
        );
        assert_eq!(
            fault_text(&Fault::Unreadable("bad json".to_owned())),
            "unreadable: bad json"
        );
        assert_eq!(
            fault_text(&Fault::Exhausted("too deep".to_owned())),
            "exhausted: too deep"
        );
    }

    #[test]
    fn a_binding_request_names_the_bytes_and_the_generation_as_well_as_the_plugin() {
        let request = BindingRequest {
            binding_id: BindingId::new(Uuid::from_bytes([2; 16])),
            identity: PluginIdentity::new(
                PluginId::new("kalareach/example").expect("an identifier"),
                PackageVersion::parse("1.0.0").expect("a version"),
                PayloadDigest::of(b"the package"),
                RepositoryGeneration::new(3),
            ),
            facts: BindingFacts {
                plugin_id: "kalareach/example".to_owned(),
                binding_revision: 1,
                activity: crate::runtime::host::BindingActivity::Idle,
                thread_id: None,
                turn_id: None,
                updated_at_ms: 0,
                held_rights: Vec::new(),
            },
            executable: "/usr/local/bin/example".to_owned(),
        };
        let rendered = request.identity.to_string();
        assert!(rendered.contains("kalareach/example@1.0.0+"));
        assert!(rendered.ends_with("/3"));
    }

    #[test]
    fn the_compilation_origin_distinguishes_a_compile_from_a_cache_load() {
        use crate::runtime::compile::CompileOrigin;
        assert_ne!(CompileOrigin::Compiled, CompileOrigin::Cached);
    }

    #[test]
    fn a_fault_detail_a_component_wrote_is_clipped_to_what_a_person_reads() {
        let short = "the component trapped".to_owned();
        assert_eq!(clipped(short.clone(), MAX_FAULT_DETAIL_BYTES), short);

        let long = "x".repeat(MAX_FAULT_DETAIL_BYTES * 4);
        let cut = clipped(long, MAX_FAULT_DETAIL_BYTES);
        assert!(cut.starts_with(&"x".repeat(MAX_FAULT_DETAIL_BYTES)));
        assert!(cut.ends_with("more bytes)"));

        // Cut at a character boundary, so the result is still text.
        let wide = "\u{2014}".repeat(MAX_FAULT_DETAIL_BYTES);
        let cut = clipped(wide, MAX_FAULT_DETAIL_BYTES);
        assert!(cut.chars().count() > 0);
    }

    #[tokio::test]
    async fn a_fault_has_room_however_much_presentation_is_waiting() {
        // A caller that stopped reading, and a component that kept drawing. The channel fills with
        // documents; what must not happen is that the fault behind them finds no room.
        let (events, mut received) = tokio::sync::mpsc::channel(DEFAULT_EVENT_QUEUE);
        let mut sent = 0;
        while events.capacity() > FAULT_RESERVE {
            events
                .try_send(BindingEvent::Document {
                    call: CallKind::Observe,
                    nodes: Vec::new(),
                })
                .expect("there is room");
            sent += 1;
        }
        assert!(sent > 0);

        // The reserve is what is left, and it is only ever the must-arrive events' to use.
        assert_eq!(events.capacity(), FAULT_RESERVE);
        for index in 0..FAULT_RESERVE {
            events
                .try_send(BindingEvent::Fault {
                    call: CallKind::Observe,
                    detail: format!("fault {index}"),
                    faults_in_window: 1,
                })
                .expect("a fault always has room");
        }
        assert_eq!(events.capacity(), 0);

        // And four is the most one binding ever produces: three faults and the disabling.
        assert!(FAULT_RESERVE >= 2 * (kr_plugin_sdk::limits::FAULTS_BEFORE_DISABLE as usize + 1));
        received.close();
    }

    #[test]
    fn a_preparation_deadline_is_one_deadline_across_its_stages() {
        let started = std::time::Instant::now() - core::time::Duration::from_millis(400);
        let left = remaining_of(started, core::time::Duration::from_millis(1_000))
            .expect("some of the deadline is left");
        assert!(left <= core::time::Duration::from_millis(600));
        // And a stage that overran the whole deadline leaves nothing for the next one.
        let error = remaining_of(started, core::time::Duration::from_millis(100))
            .expect_err("the deadline is spent");
        assert!(matches!(error, RuntimeError::CallerDeadline { .. }));
    }
}
