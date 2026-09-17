//! The binding lifecycle a broker works with.
//!
//! A binding is one component instance serving one application binding. It has a thread of its
//! own, because a component call is a blocking call into machine code and a store is a single
//! thread's object. That thread is also the whole of what a slow component can hold up.
//!
//! # What never waits
//!
//! [`BindingHandle::enqueue_observation`] pushes onto the bounded queue and returns. It takes no
//! lock a component holds, runs nothing, and cannot fail for want of a component. That is the
//! structural form of section 11's requirement that PTY draining, terminal-query responses and the
//! presentation queues never wait for an observation callback: a caller on the terminal path has
//! no way to end up behind a component even if it tries.
//!
//! Everything that does run a component is asynchronous and carries the caller's own deadline. A
//! caller that stops waiting gets [`crate::RuntimeError::CallerDeadline`] and carries on; the
//! component's own bounds still apply on its thread.
//!
//! # No instance for an idle shell
//!
//! A [`Runtime`] with no prepared bindings holds an engine, a cache directory and an idle
//! compilation pool. It has no store, no instance, no binding thread and no epoch ticks. The first
//! instance appears when a broker prepares a binding, which is when an application that uses one
//! has actually been matched.
//!
//! # What a plugin-host crash costs
//!
//! Every instance, every queue and every compiled artefact in memory. Nothing else: pending
//! requests, dispatch markers and the approval ledger live in the worker's broker, and a worker
//! whose bindings vanished re-registers them. That is why this crate has no durable state of its
//! own beyond the compiled-code cache, which is a cache.

use std::collections::HashMap;
use std::path::PathBuf;
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
use crate::runtime::instance::{CallOutcome, Instance};
use crate::runtime::limits::InstanceLimiter;
use crate::runtime::queue::{Admission, ObservationGap, ObservationQueue};

/// How many observations one pump pass delivers before it looks at its commands again.
///
/// A pass that drained the whole queue would let a burst of observations delay a `prepare-action`
/// a person is waiting on. Sixteen is enough that the per-pass overhead is negligible and few
/// enough that an interactive call is never far behind.
const PUMP_BATCH: usize = 16;

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
    /// binding into a different version.
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
    bindings: Mutex<HashMap<BindingId, Arc<BindingHandle>>>,
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
        self.bindings.lock().map_or(0, |bindings| bindings.len())
    }

    /// Returns a live binding.
    #[must_use]
    pub fn binding(&self, binding_id: BindingId) -> Option<Arc<BindingHandle>> {
        self.bindings
            .lock()
            .ok()
            .and_then(|bindings| bindings.get(&binding_id).cloned())
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

    /// Instantiates a compiled component and calls `bind`.
    ///
    /// The call budgets in [`crate::runtime::budget`] start after this returns, which is what
    /// section 11 means by starting a call budget only once the instance is ready.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::Instantiation`] when the instance cannot be created, or the failure
    /// `bind` produced.
    pub fn instantiate(
        &self,
        request: BindingRequest,
        compiled: &Compiled,
        events: tokio::sync::mpsc::UnboundedSender<BindingEvent>,
    ) -> RuntimeResult<Arc<BindingHandle>> {
        let target = WireBinding {
            plugin_id: request.identity.plugin_id.as_str().to_owned(),
            binding_revision: request.facts.binding_revision,
            executable: request.executable.clone(),
        };
        let mut instance = Instance::new(
            &self.engine,
            &compiled.component,
            request.facts.clone(),
            InstanceLimiter::defaults(),
            self.config.fuel_rate,
        )?;
        let bound = instance.bind(target)?;
        if let Err(fault) = bound.answer {
            return Err(RuntimeError::Instantiation {
                detail: format!("bind declared a fault: {}", fault_text(&fault)),
            });
        }

        let handle = BindingHandle::start(
            request.clone(),
            instance,
            FaultCounter::new(Arc::clone(&self.config.clock)),
            events,
        );
        let handle = Arc::new(handle);
        if let Ok(mut bindings) = self.bindings.lock() {
            bindings.insert(request.binding_id, Arc::clone(&handle));
        }
        Ok(handle)
    }

    /// Prepares a binding: compile, instantiate, `bind`.
    ///
    /// This is the convenience that does all three in order and waits for the compile. It is the
    /// shape a broker wants when it has somewhere to await; the three steps are separate above for
    /// when it does not.
    ///
    /// # Errors
    ///
    /// Returns the compilation, instantiation or `bind` failure, or
    /// [`RuntimeError::CallerDeadline`] when the compile does not finish inside `deadline`.
    pub fn prepare(
        &self,
        request: BindingRequest,
        wasm: Arc<[u8]>,
        deadline: core::time::Duration,
        events: tokio::sync::mpsc::UnboundedSender<BindingEvent>,
    ) -> RuntimeResult<Arc<BindingHandle>> {
        let compilation = self.compile(wasm)?;
        let compiled = compilation.wait(deadline)?;
        self.instantiate(request, &compiled, events)
    }

    /// Removes a binding and stops its thread.
    ///
    /// The component's own state goes with it. Nothing a decision depends on was in there: pending
    /// and dispatch state is the worker broker's.
    pub fn unbind(&self, binding_id: BindingId) -> bool {
        let handle = self
            .bindings
            .lock()
            .ok()
            .and_then(|mut bindings| bindings.remove(&binding_id));
        match handle {
            Some(handle) => {
                handle.stop();
                true
            }
            None => false,
        }
    }

    /// Removes every binding and stops every thread.
    pub fn unbind_all(&self) {
        let handles: Vec<Arc<BindingHandle>> = self
            .bindings
            .lock()
            .map(|mut bindings| bindings.drain().map(|(_id, handle)| handle).collect())
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
    wait: mpsc::Receiver<RuntimeResult<Compiled>>,
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
    pub fn wait(self, deadline: core::time::Duration) -> RuntimeResult<Compiled> {
        match self.wait.recv_timeout(deadline) {
            Ok(outcome) => outcome,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(RuntimeError::CallerDeadline {
                deadline_ms: u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX),
            }),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(RuntimeError::CompilationPressure { queued: 0 })
            }
        }
    }

    /// Returns the result if it is already there.
    ///
    /// # Errors
    ///
    /// Returns the compilation failure when it has finished and failed.
    pub fn poll(&self) -> Option<RuntimeResult<Compiled>> {
        match self.wait.try_recv() {
            Ok(outcome) => Some(outcome),
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => {
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
        request: RequestSnapshot,
        decision: String,
        event: Option<ScopedSourceEvent>,
        answer: Answer<EncodedResponse>,
    },
    Checkpoint(Answer<Vec<u8>>),
    Restore {
        state: Vec<u8>,
        answer: Answer<()>,
    },
    SetFacts(BindingFacts),
    SetAttachments(Vec<AttachmentFact>),
    Stop,
}

type Answer<T> = tokio::sync::oneshot::Sender<RuntimeResult<CallResult<T>>>;

/// A live binding.
///
/// Cloneable through an [`Arc`] and usable from several tasks at once: the commands are serialised
/// by the binding's own thread, which is the only thread that ever touches the store.
pub struct BindingHandle {
    request: BindingRequest,
    commands: mpsc::Sender<Command>,
    queue: Arc<Mutex<ObservationQueue>>,
    disabled: Arc<Mutex<Option<String>>>,
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
    fn start(
        request: BindingRequest,
        instance: Instance,
        faults: FaultCounter,
        events: tokio::sync::mpsc::UnboundedSender<BindingEvent>,
    ) -> Self {
        let (commands, inbox) = mpsc::channel();
        let queue = Arc::new(Mutex::new(ObservationQueue::new()));
        let disabled = Arc::new(Mutex::new(None));
        let worker = BindingWorker {
            instance,
            faults,
            events,
            queue: Arc::clone(&queue),
            disabled: Arc::clone(&disabled),
            identity: request.identity.clone(),
        };
        let name = format!("kr-plugin-binding-{}", request.binding_id);
        let thread = std::thread::Builder::new()
            .name(name)
            .spawn(move || worker.run(inbox))
            .ok();
        Self {
            request,
            commands,
            queue,
            disabled,
            thread: Mutex::new(thread),
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

    /// Returns true when the component owes a fresh snapshot after a gap.
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
    pub fn enqueue_observation(&self, event: ScopedSourceEvent) -> Admission {
        let admission = match self.queue.lock() {
            Ok(mut queue) => queue.push(event),
            // A poisoned queue means a binding thread panicked holding it. Reporting the event as
            // refused is the honest answer: nothing will interpret it.
            Err(_) => Admission::Refused { held_bytes: 0 },
        };
        // Waking the pump is a send on an unbounded channel: it allocates and returns. A thread
        // that has already stopped makes this fail, which is not a reason to fail the push.
        let _ = self.commands.send(Command::Pump);
        admission
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
            request,
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
    pub fn set_facts(&self, facts: BindingFacts) {
        let _ = self.commands.send(Command::SetFacts(facts));
    }

    /// Replaces the attachments the current draft holds.
    pub fn set_attachments(&self, attachments: Vec<AttachmentFact>) {
        let _ = self.commands.send(Command::SetAttachments(attachments));
    }

    /// Stops the binding's thread and waits for it.
    ///
    /// A thread in the middle of a component call finishes it first. Every call is bounded, so the
    /// wait is bounded too.
    pub fn stop(&self) {
        let _ = self.commands.send(Command::Stop);
        if let Ok(mut slot) = self.thread.lock()
            && let Some(thread) = slot.take()
        {
            let _ = thread.join();
        }
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
        let (answer, reply) = tokio::sync::oneshot::channel();
        self.commands
            .send(build(answer))
            .map_err(|_| RuntimeError::NoSuchBinding {
                binding: self.request.binding_id.to_string(),
            })?;
        match tokio::time::timeout(deadline, reply).await {
            Ok(Ok(outcome)) => outcome,
            // The thread dropped the answer, which happens when it stops mid-queue.
            Ok(Err(_)) => Err(RuntimeError::NoSuchBinding {
                binding: self.request.binding_id.to_string(),
            }),
            Err(_elapsed) => Err(RuntimeError::CallerDeadline {
                deadline_ms: u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX),
            }),
        }
    }
}

impl Drop for BindingHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

struct BindingWorker {
    instance: Instance,
    faults: FaultCounter,
    events: tokio::sync::mpsc::UnboundedSender<BindingEvent>,
    queue: Arc<Mutex<ObservationQueue>>,
    disabled: Arc<Mutex<Option<String>>>,
    identity: PluginIdentity,
}

impl BindingWorker {
    fn run(mut self, inbox: mpsc::Receiver<Command>) {
        while let Ok(command) = inbox.recv() {
            match command {
                Command::Pump => self.pump(),
                Command::Snapshot(answer) => {
                    let outcome = self.run_call(CallKind::Snapshot, |instance| instance.snapshot());
                    if outcome.as_ref().is_ok_and(|result| result.answer.is_ok())
                        && let Ok(mut queue) = self.queue.lock()
                    {
                        queue.snapshot_taken();
                    }
                    let _ = answer.send(outcome);
                }
                Command::PrepareAction {
                    token,
                    arguments,
                    answer,
                } => {
                    let outcome = self.run_call(CallKind::PrepareAction, move |instance| {
                        instance.prepare_action(token, arguments)
                    });
                    let _ = answer.send(outcome);
                }
                Command::DecodeRequest { event, answer } => {
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
                    let outcome = self.run_call(CallKind::EncodeResponse, move |instance| {
                        instance.encode_response(request, decision, event)
                    });
                    let _ = answer.send(outcome);
                }
                Command::Checkpoint(answer) => {
                    let outcome =
                        self.run_call(CallKind::Checkpoint, |instance| instance.checkpoint());
                    let _ = answer.send(outcome);
                }
                Command::Restore { state, answer } => {
                    let outcome =
                        self.run_call(CallKind::Restore, move |instance| instance.restore(state));
                    let _ = answer.send(outcome);
                }
                Command::SetFacts(facts) => self.instance.set_binding_facts(facts),
                Command::SetAttachments(attachments) => {
                    self.instance.set_attachments(attachments);
                }
                Command::Stop => return,
            }
        }
    }

    fn pump(&mut self) {
        if self.is_disabled() {
            // A disabled binding interprets nothing. The queue is cleared so a re-registration
            // starts from a snapshot rather than from a backlog nobody read.
            if let Ok(mut queue) = self.queue.lock() {
                queue.clear();
            }
            return;
        }
        let (drained, owes_snapshot) = match self.queue.lock() {
            Ok(mut queue) => {
                let owes = queue.snapshot_required();
                (queue.drain(PUMP_BATCH), owes)
            }
            Err(_) => return,
        };
        if let Some(gap) = drained.gap {
            let _ = self.events.send(BindingEvent::Gap(gap));
        }
        if owes_snapshot {
            // The component's view is stale: either events were lost, or the instance was replaced
            // after a fault and has no state left. Either way the contract's answer is a fresh
            // snapshot, and it happens here because the component has no way to ask for one.
            let outcome = self.run_call(CallKind::Snapshot, |instance| instance.snapshot());
            if outcome.is_ok_and(|result| result.answer.is_ok())
                && let Ok(mut queue) = self.queue.lock()
            {
                queue.snapshot_taken();
            }
        }
        for event in drained.events {
            if self.is_disabled() {
                return;
            }
            let _ = self.run_call(CallKind::Observe, move |instance| instance.observe(event));
        }
    }

    fn run_call<T, F>(&mut self, kind: CallKind, invoke: F) -> RuntimeResult<CallResult<T>>
    where
        F: FnOnce(&mut Instance) -> RuntimeResult<CallOutcome<T>>,
    {
        if let Some(reason) = self.disabled_reason() {
            return Err(RuntimeError::Disabled { reason });
        }
        match invoke(&mut self.instance) {
            Ok(outcome) => {
                if !outcome.nodes.is_empty() {
                    let _ = self.events.send(BindingEvent::Document {
                        call: kind,
                        nodes: outcome.nodes.clone(),
                    });
                }
                Ok(CallResult {
                    answer: outcome.answer.map_err(|fault| fault_text(&fault)),
                    nodes: outcome.nodes,
                })
            }
            Err(error) => {
                if error.counts_as_fault() {
                    let detail = error.to_string();
                    match self.faults.record(&detail) {
                        FaultVerdict::Continue { faults_in_window } => {
                            // The binding survives, and the instance behind it does not: a trap is
                            // terminal for a component instance. The replacement has no
                            // presentation state, so the next pump rebuilds it from a snapshot.
                            if let Ok(mut queue) = self.queue.lock() {
                                queue.require_snapshot();
                            }
                            let _ = self.events.send(BindingEvent::Fault {
                                call: kind,
                                detail,
                                faults_in_window,
                            });
                        }
                        FaultVerdict::Disabled { reason } => {
                            let reason =
                                format!("{} is disabled: {reason}", self.identity.plugin_id);
                            if let Ok(mut slot) = self.disabled.lock() {
                                *slot = Some(reason.clone());
                            }
                            let _ = self.events.send(BindingEvent::Disabled { reason });
                        }
                    }
                }
                Err(error)
            }
        }
    }

    fn disabled_reason(&self) -> Option<String> {
        self.disabled.lock().ok().and_then(|slot| slot.clone())
    }

    fn is_disabled(&self) -> bool {
        self.disabled_reason().is_some()
    }
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
    }

    #[test]
    fn unbinding_something_that_is_not_bound_says_so() {
        let (_directory, config) = config();
        let runtime = Runtime::new(config).expect("a runtime");
        assert!(!runtime.unbind(BindingId::new(Uuid::from_bytes([9; 16]))));
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
}
