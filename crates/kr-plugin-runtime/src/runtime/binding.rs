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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use kr_ipc::clock::{SharedClock, SystemSharedClock};
use kr_plugin_sdk::identity::PluginIdentity;
use kr_plugin_service::protocol4::Through;
use kr_plugin_service::vocabulary::{
    Admission, AttachmentFact, BindingFacts, BindingId, ScopedSourceEvent, SourceProvenance,
};
use kr_protocol::ids::SourceEventHandle;

use crate::runtime::bindings::{
    ActionToken, Binding as WireBinding, DecodedRequest, EffectPlan, EncodedResponse, Fault,
    NamedArgument, RequestSnapshot,
};
use crate::runtime::budget::{CallKind, FUEL_PER_DEADLINE_MS};
use crate::runtime::cache::CompiledCache;
use crate::runtime::compile::{CompileBudget, CompilePool, Compiled, Payload};
use crate::runtime::engine::RuntimeEngine;
use crate::runtime::error::{RuntimeError, RuntimeResult};
use crate::runtime::faults::{FaultCounter, FaultVerdict};
use crate::runtime::host::EmittedNode;
use crate::runtime::instance::{CallOutcome, Instance, OutputSize};
use crate::runtime::limits::InstanceLimiter;
use crate::runtime::queue::{ObservationGap, ObservationQueue};

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

/// How long after a failed attempt the binding's thread tries to send an owed report again:
/// nothing wakes the thread when the caller reads and makes room. The time is a deadline that
/// commands do not move, so calls that follow one another closer than this still leave the report
/// its turn.
const OWED_RETRY: core::time::Duration = core::time::Duration::from_millis(50);

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
    /// Whether the caller wants to be told what the instance has consumed
    /// ([`BindingEvent::Consumed`]). A caller that has no use for it asks for none, so the
    /// report does not share the channel with what it does use.
    pub report_consumed: bool,
}

/// Something a binding produced without being asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindingEvent {
    /// The component emitted document nodes.
    Document {
        /// Which export emitted them.
        call: CallKind,
        /// Which of this binding's documents they are, counted from one.
        ///
        /// A caller that made the call can match its answer to the document the call drew, and a
        /// reader that is sent the document in pieces can tell which pieces belong together.
        document: u64,
        /// The nodes.
        nodes: Vec<EmittedNode>,
    },
    /// The observation stream has a gap, and a fresh snapshot follows.
    Gap(ObservationGap),
    /// Documents were dropped because the caller was too far behind, and a fresh snapshot follows.
    ///
    /// A gap is one of the presentations that go, and what it said of the loss is kept here, so the
    /// loss is still bounded when the caller learns of it.
    PresentationDropped {
        /// How many documents went, the gaps among them included.
        documents: u32,
        /// The first event lost, as the oldest gap that went named it.
        first: Option<SourceEventHandle>,
        /// The last event lost, as the newest gap that went named it.
        last: Option<SourceEventHandle>,
    },
    /// A call failed, and the binding survived it.
    Fault {
        /// Which export failed.
        call: CallKind,
        /// The failure.
        detail: String,
        /// How many faults are inside the window now.
        faults_in_window: u32,
        /// The event whose `observe` failed, where the call was one: a trap, an output over its
        /// budget and a replacement that could not be made all name it.
        event: Option<SourceEventHandle>,
        /// The generation the next call runs under: the replacements so far, and one more when
        /// the instance has trapped, for the replacement the next call makes first.
        generation: u32,
    },
    /// The binding is disabled and will run nothing more.
    Disabled {
        /// Why, in the words a person is shown.
        reason: String,
    },
    /// What the instance has consumed, at the end of a pass that returned at least one event.
    ///
    /// Never one of the presentations a slow caller loses: a newer report takes the place of an
    /// older one that has not been delivered, and one that finds no room waits until there is.
    Consumed(Consumed),
}

/// What an instance has consumed, as its binding's thread keeps it.
///
/// An event is consumed when its `observe` call returned, whether the component took it in or
/// declined it. An event that trapped, that the queue dropped or that was refused before it ran is
/// not consumed, and what the instance consumed is then not a prefix of what was offered: `clean`
/// says so from that event on, until a restore that carried the position of a state.
///
/// An event from a terminal scrape is the terminal source's, and any other is the native
/// source's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Consumed {
    /// How many times the instance has been replaced.
    pub generation: u32,
    /// Whether it is a prefix: no event was dropped, trapped or refused since the state it
    /// describes.
    pub clean: bool,
    /// The last native event whose `observe` returned, where one has.
    pub native: Option<SourceEventHandle>,
    /// The last terminal event whose `observe` returned, where one has.
    pub terminal: Option<SourceEventHandle>,
}

impl Consumed {
    const fn start() -> Self {
        Self {
            generation: 0,
            clean: true,
            native: None,
            terminal: None,
        }
    }

    fn returned(&mut self, provenance: SourceProvenance, handle: SourceEventHandle) {
        match provenance {
            SourceProvenance::TerminalScrape => self.terminal = Some(handle),
            SourceProvenance::NativeProtocol | SourceProvenance::MachineOutput => {
                self.native = Some(handle);
            }
        }
    }
}

/// A checkpoint: the component's own resumable state, and what the instance had consumed when it
/// was taken.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    /// The component's own state.
    pub state: Vec<u8>,
    /// What the instance had consumed.
    pub consumed: Consumed,
}

/// What offering an event to a binding's queue came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offered {
    /// What happened to the event.
    pub admission: Admission,
    /// The bytes the queue can still take after this admission.
    pub free_bytes: u64,
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
    #[cfg(any(test, feature = "testing"))]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl core::fmt::Display for BindingOwner {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, formatter)
    }
}

/// Which registration of an identifier a binding is.
///
/// An identifier is registered, removed and registered again, and what was meant for one
/// registration must not reach the next. The caller that starts a registration chooses its
/// incarnation, names it again to remove that registration, and so removes that one and no other:
/// a removal that is left waiting for a thread, or for a caller that has gone, finds the identifier
/// registered again by then and leaves it alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Incarnation(u64);

/// The source of incarnation numbers, which are never reused inside a process.
static NEXT_INCARNATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl Incarnation {
    /// Takes an incarnation number nothing else in this process holds.
    #[must_use]
    pub fn next() -> Self {
        Self(NEXT_INCARNATION.fetch_add(1, Ordering::Relaxed))
    }

    /// Returns the number itself, for a caller that has to name the registration to code that
    /// does not know this type.
    #[must_use]
    pub(crate) const fn number(self) -> u64 {
        self.0
    }
}

/// One entry in the registry.
///
/// A binding is reserved before anything is started and becomes live when its instance exists.
/// Reserving first is what makes two registrations of one identifier a refusal rather than a race:
/// without it both could pass a "is it live" check before either had finished starting.
///
/// The incarnation is the registration's: the entry is found, kept and removed by it, and the
/// identifier alone names nothing once it can be registered again.
#[derive(Debug)]
struct Registration {
    owner: BindingOwner,
    incarnation: Incarnation,
    state: RegistrationState,
}

#[derive(Debug)]
enum RegistrationState {
    /// Somebody is preparing this binding, under the entry's incarnation.
    ///
    /// The incarnation is what makes a reservation one preparation's and not the identifier's.
    /// Without it, a preparation that had lost its reservation -- because the identifier was
    /// unbound while it ran -- could take the reservation a later preparation of the same
    /// identifier had made, and hand that caller an instance it never asked for.
    Reserved,
    /// The binding is live.
    Live(Arc<BindingHandle>),
}

/// What removing a binding found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unbound {
    /// A live binding was removed and its thread stopped.
    Stopped,
    /// A preparation was under way, and its reservation is gone; the preparation gives its
    /// instance up when it finds out.
    Preparing,
    /// The owner holds no such binding.
    Absent,
}

impl Unbound {
    /// Returns whether there was anything to remove.
    #[must_use]
    #[cfg(any(test, feature = "testing"))]
    pub const fn existed(self) -> bool {
        !matches!(self, Self::Absent)
    }
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
        Self::over(config, RuntimeEngine::new()?)
    }

    /// Builds a runtime whose engine's epoch no time advances, for the tests of what a component
    /// does with the calls it is given: a call is stopped by its deadline only when a test
    /// advances the epoch, so a machine that stalls the call for as long as it likes cannot reach
    /// one. See [`RuntimeEngine::with_epoch_held`].
    ///
    /// # Errors
    ///
    /// Returns what [`Self::new`] does.
    #[cfg(feature = "testing")]
    pub fn with_epoch_held(config: RuntimeConfig) -> RuntimeResult<Self> {
        Self::over(config, RuntimeEngine::with_epoch_held()?)
    }

    fn over(config: RuntimeConfig, engine: RuntimeEngine) -> RuntimeResult<Self> {
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

    /// Returns a live binding of `owner`'s.
    ///
    /// An identifier another owner holds is not found, which is the point: an identifier is not a
    /// capability, and a caller that guessed one gets the same answer as a caller that invented one.
    #[must_use]
    #[cfg(any(test, feature = "testing"))]
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
                    ..
                }) if *held == owner => Some(Arc::clone(handle)),
                _ => None,
            })
    }

    /// Stops the next pass over the observation queue of the live binding `binding_id`, whichever
    /// owner holds it, as [`BindingHandle::stop_next_pump`] does: for the tests of a host that
    /// serves a binding to a connection the test cannot name the owner of.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn stop_next_pump(&self, binding_id: BindingId) -> Option<PumpStop> {
        self.bindings
            .lock()
            .ok()
            .and_then(|bindings| match bindings.get(&binding_id) {
                Some(Registration {
                    state: RegistrationState::Live(handle),
                    ..
                }) => Some(handle.stop_next_pump()),
                _ => None,
            })
    }

    /// Takes one preparation's claim on an identifier, or says it is taken.
    ///
    /// The returned guard gives the reservation up if the preparation does not finish, however it
    /// ends: a refusal, a caller's deadline, or a future nobody polled again.
    fn reserve_for(
        self: &Arc<Self>,
        owner: BindingOwner,
        incarnation: Incarnation,
        binding_id: BindingId,
    ) -> RuntimeResult<Reservation> {
        self.reserve(owner, incarnation, binding_id)?;
        Ok(Reservation {
            runtime: Arc::clone(self),
            owner,
            incarnation,
            binding_id,
            kept: false,
        })
    }

    /// Reserves an identifier for `owner`, or says it is taken.
    ///
    /// Taken under the lock and before anything is started, so two registrations of one identifier
    /// cannot both get past it.
    fn reserve(
        &self,
        owner: BindingOwner,
        incarnation: Incarnation,
        binding_id: BindingId,
    ) -> RuntimeResult<()> {
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
                incarnation,
                state: RegistrationState::Reserved,
            },
        );
        Ok(())
    }

    /// Gives up one incarnation's reservation, if it is still that incarnation's.
    fn release(&self, owner: BindingOwner, incarnation: Incarnation, binding_id: BindingId) {
        if let Ok(mut bindings) = self.bindings.lock()
            && matches!(
                bindings.get(&binding_id),
                Some(Registration {
                    owner: held,
                    incarnation: held_incarnation,
                    state: RegistrationState::Reserved,
                }) if *held == owner && *held_incarnation == incarnation
            )
        {
            bindings.remove(&binding_id);
        }
    }

    /// Holds the compilation pool's jobs until the returned hold is dropped, for the tests of what
    /// a caller does while a compile it queued is not done. See [`CompilePool::hold`].
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn hold_compiles(&self) -> crate::runtime::compile::CompileHold {
        self.pool.hold()
    }

    /// Submits a component for compilation, lazily and at background priority.
    ///
    /// Returns as soon as the work is queued. This is the only place a component is compiled, and
    /// it is a separate step from [`Self::instantiate`] so that a caller can see, and a test can
    /// prove, that no call deadline contains a compile. It makes no pass over the component's
    /// bytes: the payload already carries their digest, and making that is the caller's, where
    /// blocking work belongs.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::ComponentTooLarge`] or [`RuntimeError::CompilationPressure`].
    pub fn compile(&self, payload: Payload) -> RuntimeResult<Compilation> {
        let wait = self
            .pool
            .submit(&self.engine, &self.cache, payload, self.config.compile)?;
        Ok(Compilation { wait })
    }

    /// Instantiates a compiled component, calls `bind`, and starts the binding's thread.
    ///
    /// The registration is `incarnation`'s: the caller chose it, and names it to remove this
    /// registration and no other.
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
        self: &Arc<Self>,
        owner: BindingOwner,
        incarnation: Incarnation,
        request: BindingRequest,
        compiled: &Compiled,
        events: tokio::sync::mpsc::Sender<BindingEvent>,
        within: core::time::Duration,
    ) -> RuntimeResult<Arc<BindingHandle>> {
        let binding_id = request.binding_id;
        // One binding, one instance. Replacing a live binding silently would leave an instance
        // running that nothing could reach and nothing would stop, so the identifier is taken
        // before anything is started rather than checked before anything is awaited. The guard
        // gives it up however this ends, including a caller that stopped polling.
        let mut reservation = self.reserve_for(owner, incarnation, binding_id)?;

        let handle = BindingHandle::start(
            request,
            incarnation,
            &self.engine,
            &compiled.component,
            self.config.fuel_rate,
            FaultCounter::new(Arc::clone(&self.config.clock)),
            events,
        )?;
        let handle = Arc::new(handle);
        if let Err(error) = handle.ready(within).await {
            // Signalled rather than joined: this is an asynchronous caller whose deadline has run
            // out, and joining here would hold its thread for as long as the instantiation it gave
            // up on.
            handle.signal_stop();
            return Err(error);
        }
        // The reservation is what this replaces, and only if it is still this incarnation's. An
        // owner that went away while its instance was starting took its reservation with it, and
        // the instance it no longer has a use for is stopped here rather than left running for
        // nobody.
        if !reservation.becomes(&handle) {
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
    /// and, when it is within its budget, files its result, so the next preparation of the same
    /// component is quick. Nothing here hashes the component: [`Payload::new`] does, and a caller
    /// on an executor makes the payload on a blocking thread.
    ///
    /// # Errors
    ///
    /// Returns the compilation, instantiation or `bind` failure, or
    /// [`RuntimeError::CallerDeadline`] when the whole preparation does not finish inside
    /// `deadline`.
    #[cfg(any(test, feature = "testing"))]
    pub async fn prepare(
        self: &Arc<Self>,
        owner: BindingOwner,
        request: BindingRequest,
        payload: Payload,
        deadline: core::time::Duration,
        events: tokio::sync::mpsc::Sender<BindingEvent>,
    ) -> RuntimeResult<Arc<BindingHandle>> {
        let started = std::time::Instant::now();
        let compilation = self.compile(payload)?;
        let compiled = compilation.wait(deadline).await?;
        let remaining = remaining_of(started, deadline)?;
        self.instantiate(
            owner,
            Incarnation::next(),
            request,
            &compiled,
            events,
            remaining,
        )
        .await
    }

    /// Removes one registration of a binding and stops its thread.
    ///
    /// Only `incarnation`'s registration is removed. An identifier that is registered again, by
    /// the same owner, is a registration of another incarnation, and the caller that is removing
    /// the earlier one finds nothing to remove: [`Unbound::Absent`].
    ///
    /// Blocks until the thread is gone, so a caller knows the instance is no longer running when
    /// this returns. The component's own state goes with it; nothing a decision depends on was in
    /// there, because pending and dispatch state is the worker broker's.
    pub fn unbind(
        &self,
        owner: BindingOwner,
        binding_id: BindingId,
        incarnation: Incarnation,
    ) -> Unbound {
        self.remove(owner, binding_id, incarnation, BindingHandle::stop)
    }

    /// Removes one registration of a binding and tells its thread to stop, without waiting for it.
    ///
    /// For a caller that cannot block: the binding is gone from the runtime when this returns, and
    /// its thread ends on its own after at most one bounded call. What [`Self::unbind`] guarantees
    /// about the instance having stopped is not given. As there, only `incarnation`'s registration
    /// is removed.
    pub fn detach(
        &self,
        owner: BindingOwner,
        binding_id: BindingId,
        incarnation: Incarnation,
    ) -> Unbound {
        self.remove(owner, binding_id, incarnation, BindingHandle::signal_stop)
    }

    fn remove(
        &self,
        owner: BindingOwner,
        binding_id: BindingId,
        incarnation: Incarnation,
        stop: impl FnOnce(&BindingHandle),
    ) -> Unbound {
        let entry =
            self.bindings
                .lock()
                .ok()
                .and_then(|mut bindings| match bindings.get(&binding_id) {
                    Some(held) if held.owner == owner && held.incarnation == incarnation => {
                        bindings.remove(&binding_id)
                    }
                    _ => None,
                });
        match entry {
            Some(Registration {
                state: RegistrationState::Live(handle),
                ..
            }) => {
                stop(&handle);
                Unbound::Stopped
            }
            // A reservation somebody is still preparing. Removing it is the whole of the removal:
            // the preparation will find its reservation gone and give the handle up. The caller is
            // told which of the two it was, because the preparation's instance has not been
            // stopped by this removal and is still to go.
            Some(Registration {
                state: RegistrationState::Reserved,
                ..
            }) => Unbound::Preparing,
            None => Unbound::Absent,
        }
    }

    /// Removes every binding one owner holds, and tells their threads to stop, without waiting for
    /// them.
    ///
    /// What a connection's end costs: its own bindings and nothing else, and no thread of a pool
    /// that other work may keep busy, since nothing here waits. Each thread ends on its own after
    /// at most one bounded call, as one that [`Self::detach`] left does. Reservations go too, so a
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
            handle.signal_stop();
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

/// One preparation's claim on an identifier, given up if the preparation does not finish.
///
/// Held across every await a preparation makes, so a caller that stopped polling leaves no
/// reservation behind for an identifier nothing is preparing any more.
struct Reservation {
    runtime: Arc<Runtime>,
    owner: BindingOwner,
    incarnation: Incarnation,
    binding_id: BindingId,
    kept: bool,
}

impl Reservation {
    /// Turns this claim into the live binding, if it is still this incarnation's claim.
    fn becomes(&mut self, handle: &Arc<BindingHandle>) -> bool {
        let Ok(mut bindings) = self.runtime.bindings.lock() else {
            return false;
        };
        let held = matches!(
            bindings.get(&self.binding_id),
            Some(Registration {
                owner,
                incarnation,
                state: RegistrationState::Reserved,
            }) if *owner == self.owner && *incarnation == self.incarnation
        );
        if !held {
            return false;
        }
        bindings.insert(
            self.binding_id,
            Registration {
                owner: self.owner,
                incarnation: self.incarnation,
                state: RegistrationState::Live(Arc::clone(handle)),
            },
        );
        self.kept = true;
        true
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.kept {
            self.runtime
                .release(self.owner, self.incarnation, self.binding_id);
        }
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
    /// A caller that gives up loses nothing: the compile continues on its pool thread and, when it
    /// is within its budget, its result is filed in the cache, so the next preparation of the same
    /// component finds it.
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
    #[cfg(any(test, feature = "testing"))]
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
    /// Which of this binding's documents those nodes are, where the call drew one.
    ///
    /// Nothing for a call that drew nothing, which is how a caller tells an empty document from one
    /// it has not been given yet.
    pub document: Option<u64>,
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
    Checkpoint(Answer<Checkpoint>),
    Restore {
        state: Vec<u8>,
        through: Option<Through>,
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
    incarnation: Incarnation,
    commands: mpsc::Sender<Command>,
    queue: Arc<Mutex<ObservationQueue>>,
    disabled: Arc<Mutex<Option<String>>>,
    stopping: Arc<AtomicBool>,
    pump_pending: Arc<AtomicBool>,
    #[cfg(feature = "testing")]
    pump_stop: Arc<Mutex<Option<PumpStopSide>>>,
    /// Whether the worker owed the caller a report the last time it came to wait.
    #[cfg(feature = "testing")]
    report_owed: Arc<AtomicBool>,
    pending: Arc<PendingUpdates>,
    outstanding: Arc<AtomicUsize>,
    calls: Arc<AtomicU64>,
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
        incarnation: Incarnation,
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
        #[cfg(feature = "testing")]
        let pump_stop = Arc::new(Mutex::new(None));
        #[cfg(feature = "testing")]
        let report_owed = Arc::new(AtomicBool::new(false));
        let pending = Arc::new(PendingUpdates::default());
        let outstanding = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicU64::new(0));

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
            dropped_first: None,
            dropped_last: None,
            documents: 0,
            calls: Arc::clone(&calls),
            queue: Arc::clone(&queue),
            disabled: Arc::clone(&disabled),
            stopping: Arc::clone(&stopping),
            pump_pending: Arc::clone(&pump_pending),
            #[cfg(feature = "testing")]
            pump_stop: Arc::clone(&pump_stop),
            #[cfg(feature = "testing")]
            report_owed: Arc::clone(&report_owed),
            pending: Arc::clone(&pending),
            outstanding: Arc::clone(&outstanding),
            commands: commands.clone(),
            identity: request.identity.clone(),
            consumed: Consumed::start(),
            report_consumed: request.report_consumed,
            observing: None,
            returned_in_pass: false,
            consumed_owed: None,
            owed_due: std::time::Instant::now(),
            consumed_held: false,
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
            incarnation,
            commands,
            queue,
            disabled,
            stopping,
            pump_pending,
            #[cfg(feature = "testing")]
            pump_stop,
            #[cfg(feature = "testing")]
            report_owed,
            pending,
            outstanding,
            calls,
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

    /// Returns which registration of the binding's identifier this instance is.
    #[must_use]
    pub const fn incarnation(&self) -> Incarnation {
        self.incarnation
    }

    /// Returns the plugin identity the binding is running.
    #[must_use]
    #[cfg(any(test, feature = "testing"))]
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
    #[cfg(any(test, feature = "testing"))]
    pub fn queued_bytes(&self) -> u64 {
        self.queue.lock().map_or(0, |queue| queue.held_bytes())
    }

    /// Stops the binding's next pass over its observation queue before it takes anything from it,
    /// for the tests of what the queue does while the component has not yet read it: the
    /// component's speed against the producer's decides nothing once the pass is held.
    ///
    /// Observations offered while the pass stands are held in the queue up to its bound, and the
    /// pass that goes on when the stop is released finds what the queue still holds and the gap
    /// that stands for the rest. Call it before the offer that wakes the pass, and release the
    /// stop before [`Self::stop`], which waits for the pass.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn stop_next_pump(&self) -> PumpStop {
        self.stop_pump_after(0)
    }

    /// As [`Self::stop_next_pump`], and the pass stands after it has taken `events` events and the
    /// component has returned from the last of them, not at its start. Events the host offers while
    /// it stands are held in the queue, and what overflows it is lost between two takes of the pass.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn stop_pump_after(&self, events: usize) -> PumpStop {
        let (reached, acknowledged) = tokio::sync::watch::channel(false);
        let (release, released) = mpsc::channel();
        if let Ok(mut slot) = self.pump_stop.lock() {
            *slot = Some(PumpStopSide {
                after: events,
                reached,
                released,
            });
        }
        PumpStop {
            acknowledged,
            _release: release,
        }
    }

    /// Whether the binding still owes its caller a report of what the instance has consumed, as of
    /// the last time its thread came to wait for a command.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn report_owed(&self) -> bool {
        self.report_owed.load(Ordering::Acquire)
    }

    /// Says the component's view is stale and a fresh snapshot is owed.
    ///
    /// For a caller that lost what the component drew: a document that never reached whoever was
    /// to read it leaves that reader with a stale view, and the answer is the same one a lost
    /// observation gets -- the component draws again.
    pub fn require_snapshot(&self) {
        if let Ok(mut queue) = self.queue.lock() {
            queue.require_snapshot();
        }
        self.wake();
    }

    /// Returns true when the component owes a fresh snapshot.
    #[must_use]
    #[cfg(any(test, feature = "testing"))]
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
    pub fn enqueue_observation(&self, event: ScopedSourceEvent) -> Offered {
        let offered = match self.queue.lock() {
            Ok(mut queue) => {
                let admission = queue.push(event);
                Offered {
                    admission,
                    free_bytes: queue.free_bytes(),
                }
            }
            // A poisoned queue means a binding thread panicked holding it. Reporting the event as
            // refused is the honest answer: nothing will interpret it.
            Err(_) => Offered {
                admission: Admission::Refused { held_bytes: 0 },
                free_bytes: 0,
            },
        };
        self.wake();
        offered
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

    /// Takes the component's own resumable state, and what the instance has consumed.
    ///
    /// # Errors
    ///
    /// Returns the component's failure, or [`RuntimeError::CallerDeadline`].
    pub async fn checkpoint(
        &self,
        deadline: core::time::Duration,
    ) -> RuntimeResult<CallResult<Checkpoint>> {
        self.dispatch(deadline, Command::Checkpoint).await
    }

    /// Restores state from a checkpoint this build produced.
    ///
    /// With `through`, what the instance has consumed becomes what the state was taken at, and is
    /// clean, once the restore has answered. Without it the position stays and is no longer clean:
    /// the state covers events the position cannot name. A restore the component declines changes
    /// nothing.
    ///
    /// # Errors
    ///
    /// Returns the component's failure, or [`RuntimeError::CallerDeadline`].
    pub async fn restore(
        &self,
        state: Vec<u8>,
        through: Option<Through>,
        deadline: core::time::Duration,
    ) -> RuntimeResult<CallResult<()>> {
        self.dispatch(deadline, |answer| Command::Restore {
            state,
            through,
            answer,
        })
        .await
    }

    /// Replaces the facts the component reads about its binding.
    ///
    /// Coalesced: a revision no call has yet seen is replaced by the next, and the component is told
    /// the current facts before its next call, never an older revision after a newer one.
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

    /// Returns how many calls into the component have finished.
    ///
    /// What a caller uses to tell a component that was working during some stretch of time from one
    /// that was merely bound: the count grew, so calls ran.
    #[must_use]
    pub fn completed_calls(&self) -> u64 {
        self.calls.load(Ordering::Acquire)
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

/// A test's stop of a binding's next pump pass, held from [`BindingHandle::stop_next_pump`].
///
/// Dropping it lets the pass go, as [`Self::release`] does.
#[cfg(feature = "testing")]
#[derive(Debug)]
pub struct PumpStop {
    acknowledged: tokio::sync::watch::Receiver<bool>,
    _release: mpsc::Sender<()>,
}

#[cfg(feature = "testing")]
impl PumpStop {
    /// Waits until the pass has stopped, which is the point the stop is acknowledged at: the pass
    /// has been woken, and nothing has left the queue. Says whether a pass stopped: a later stop
    /// that replaced this one before a pass reached it ends the wait with `false`.
    ///
    /// A pass that is never woken, or a binding that ends before it, leaves the wait without an
    /// end, because the binding's handle keeps the stop until it is dropped: a caller that must
    /// not hang bounds the wait.
    pub async fn reached(&mut self) -> bool {
        self.acknowledged.wait_for(|reached| *reached).await.is_ok()
    }

    /// Lets the pass go on.
    pub fn release(self) {}
}

/// The pass's side of a [`PumpStop`].
#[cfg(feature = "testing")]
struct PumpStopSide {
    after: usize,
    reached: tokio::sync::watch::Sender<bool>,
    released: mpsc::Receiver<()>,
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
    /// The first and the last event lost, as the gaps among the dropped presentations named them.
    dropped_first: Option<SourceEventHandle>,
    dropped_last: Option<SourceEventHandle>,
    /// How many documents this binding has drawn, which is what numbers the next one.
    documents: u64,
    /// How many calls into the component have finished, for a caller that wants to know whether
    /// the component was working during some stretch of time rather than merely bound.
    calls: Arc<AtomicU64>,
    queue: Arc<Mutex<ObservationQueue>>,
    disabled: Arc<Mutex<Option<String>>>,
    stopping: Arc<AtomicBool>,
    pump_pending: Arc<AtomicBool>,
    #[cfg(feature = "testing")]
    pump_stop: Arc<Mutex<Option<PumpStopSide>>>,
    #[cfg(feature = "testing")]
    report_owed: Arc<AtomicBool>,
    pending: Arc<PendingUpdates>,
    outstanding: Arc<AtomicUsize>,
    commands: mpsc::Sender<Command>,
    identity: PluginIdentity,
    /// What the instance has consumed. Its generation is the instance's own and is read from it
    /// when a report is made ([`Self::consumed_now`]).
    consumed: Consumed,
    /// Whether the caller asked to be told what the instance has consumed.
    report_consumed: bool,
    /// The event whose `observe` is running, for the fault a trap in it raises.
    observing: Option<SourceEventHandle>,
    /// Whether the pass in hand returned at least one event.
    returned_in_pass: bool,
    /// What the caller has not been given yet. A newer one replaces it.
    consumed_owed: Option<Consumed>,
    /// When the thread next tries to send `consumed_owed`: [`OWED_RETRY`] after the last attempt,
    /// whatever commands come in between.
    owed_due: std::time::Instant,
    /// Whether `consumed_owed` waits for the gap a pass left to be reported first.
    consumed_held: bool,
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
                            self.draw(CallKind::Bind, nodes);
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

        loop {
            // Between two commands, so a run of calls that emit no document cannot keep a report
            // from its turn.
            if self.consumed_owed.is_some() && std::time::Instant::now() >= self.owed_due {
                self.flush_consumed();
            }
            #[cfg(feature = "testing")]
            self.report_owed
                .store(self.consumed_owed.is_some(), Ordering::Release);
            let received = match self.owed_wait() {
                Some(wait) => inbox.recv_timeout(wait),
                None => inbox
                    .recv()
                    .map_err(|_| mpsc::RecvTimeoutError::Disconnected),
            };
            let command = match received {
                Ok(command) => command,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            };
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
                    let consumed = self.consumed_now();
                    let _ = answer.send(outcome.map(|result| CallResult {
                        answer: result.answer.map(|state| Checkpoint { state, consumed }),
                        nodes: result.nodes,
                        document: result.document,
                    }));
                }
                Command::Restore {
                    state,
                    through,
                    answer,
                } => {
                    if self.abandoned(&answer) {
                        continue;
                    }
                    let outcome =
                        self.run_call(CallKind::Restore, move |instance| instance.restore(state));
                    if outcome.as_ref().is_ok_and(|result| result.answer.is_ok()) {
                        // The state was replaced, and what was owed described the one it replaced:
                        // the answer to the restore is what the caller reads now.
                        self.consumed_owed = None;
                        match through {
                            Some(through) => {
                                self.consumed.native = through.native;
                                self.consumed.terminal = through.terminal;
                                self.consumed.clean = true;
                            }
                            // The state covers events the position cannot name.
                            None => self.consumed.clean = false,
                        }
                    }
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
        self.returned_in_pass = false;
        self.pump_pass();
        if self.is_disabled() {
            // A disabled binding runs no pass that would report a gap, so nothing it owes is ever
            // read: its caller has the notice that says why.
            self.consumed_owed = None;
            self.consumed_held = false;
            return;
        }
        // After the gap and the fault the pass raised, so the caller reads them first. A gap the pass
        // left in the queue, which a trap or a loss during the pass does, is reported by the next
        // pass, and what is owed waits for it.
        if self.returned_in_pass && self.report_consumed {
            self.consumed_owed = Some(self.consumed_now());
        }
        self.consumed_held = self.queue.lock().is_ok_and(|queue| queue.gap_pending());
        self.flush_consumed();
    }

    /// How long the thread waits for a command: until the owed report is due, or without end when
    /// nothing is owed.
    fn owed_wait(&self) -> Option<core::time::Duration> {
        self.consumed_owed.is_some().then(|| {
            self.owed_due
                .saturating_duration_since(std::time::Instant::now())
        })
    }

    /// How many times the instance has been replaced after a trap.
    fn replacements(&self) -> u32 {
        self.instance.as_ref().map_or(0, |instance| {
            u32::try_from(instance.replacements()).unwrap_or(u32::MAX)
        })
    }

    /// The generation the next call runs under: the replacements so far, and one for the
    /// replacement that call makes first when the instance has trapped.
    fn next_generation(&self) -> u32 {
        self.instance.as_ref().map_or(0, |instance| {
            u32::try_from(instance.replacements())
                .unwrap_or(u32::MAX)
                .saturating_add(u32::from(instance.faulted()))
        })
    }

    /// What the instance has consumed, at the generation it runs under now.
    fn consumed_now(&self) -> Consumed {
        Consumed {
            generation: self.replacements(),
            ..self.consumed.clone()
        }
    }

    /// Gives the caller what it is owed, if the channel has room for it.
    ///
    /// The places the reserve keeps for a fault are not this report's, and a full channel leaves it
    /// owed for the next pass or the next report, which a newer one then replaces.
    fn flush_consumed(&mut self) {
        if self.consumed_held {
            self.owed_due = std::time::Instant::now() + OWED_RETRY;
            return;
        }
        let Some(owed) = self.consumed_owed.take() else {
            return;
        };
        if self.events.is_closed() {
            // Nobody reads the channel any more, so nobody is owed anything.
            return;
        }
        // What the binding said before the report is told first: a loss that a full channel kept
        // from the caller comes with the positions it bounds.
        self.flush_dropped();
        if self.dropped_documents == 0
            && self.events.capacity() > FAULT_RESERVE
            && self
                .events
                .try_send(BindingEvent::Consumed(owed.clone()))
                .is_ok()
        {
            return;
        }
        self.consumed_owed = Some(owed);
        self.owed_due = std::time::Instant::now() + OWED_RETRY;
    }

    fn pump_pass(&mut self) {
        #[cfg(feature = "testing")]
        self.stand_when_stopped(0);
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
            // Events were lost: what the instance consumed is no longer all that came before it.
            self.consumed.clean = false;
            self.send(BindingEvent::Gap(gap));
            self.consumed_held = false;
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
                //
                // Only a failure asks for another pass now. A failure is a fault, and three faults
                // in a minute disable the binding, so retrying is bounded. A component that
                // *declined* the snapshot has broken no bound and has not been counted, so asking
                // it again immediately would be an unbounded loop of calls nothing asked for: its
                // obligation waits for the next thing that happens to the binding instead.
                let failed = outcome.is_err();
                self.rearm(failed);
                return;
            }
        }

        for taken in 0..PUMP_BATCH {
            // Read by the stop a test sets between two takes.
            let _ = taken;
            if self.is_disabled() || self.stopping.load(Ordering::Acquire) {
                return;
            }
            // One at a time, so a fault costs the event that caused it and not the batch.
            let Some((event, lost_before)) = self.take_one() else {
                return;
            };
            if lost_before {
                // An event before this one was lost or refused after the pass began: what the
                // instance consumes from here on does not follow it.
                self.consumed.clean = false;
            }
            let lost = event.clone();
            self.observing = Some(lost.handle.clone());
            let outcome = self.run_call(CallKind::Observe, move |instance| instance.observe(event));
            self.observing = None;
            if outcome.is_ok() {
                // The call returned: the component took the event in or declined it, and either
                // way it will not be offered again.
                self.consumed.returned(lost.provenance, lost.handle.clone());
                self.returned_in_pass = true;
            }
            #[cfg(feature = "testing")]
            self.stand_when_stopped(taken + 1);
            if outcome.is_err() {
                // A faulted instance is replaced and owes a snapshot. The event that faulted is
                // one the component never took in, so it is recorded as lost; the events still in
                // the queue are still in the queue, and the next pass takes the snapshot before it
                // delivers any of them.
                self.consumed.clean = false;
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
    fn take_one(&self) -> Option<(ScopedSourceEvent, bool)> {
        let mut queue = self.queue.lock().ok()?;
        let event = queue.take_one()?;
        let lost_before = queue.take_loss_before_taken();
        Some((event, lost_before))
    }

    /// Stands at the start of a pass a test has stopped, until the test lets it go.
    ///
    /// The stop is taken, so it holds one pass and the next runs freely. The pass is acknowledged
    /// before it waits, and nothing has left the queue by then.
    #[cfg(feature = "testing")]
    fn stand_when_stopped(&self, taken: usize) {
        let Some(stop) = self.pump_stop.lock().ok().and_then(|mut slot| {
            if slot.as_ref().is_some_and(|stop| stop.after == taken) {
                slot.take()
            } else {
                None
            }
        }) else {
            return;
        };
        stop.reached.send_replace(true);
        // Ends when the test releases the pass, or drops its side without having released it.
        let _ = stop.released.recv();
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
                        self.draw(CallKind::Bind, nodes);
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
        self.calls.fetch_add(1, Ordering::AcqRel);
        let nodes = outcome.nodes;
        let document = (!nodes.is_empty()).then(|| self.draw(kind, nodes.clone()));
        match outcome.result {
            Ok(answer) => Ok(CallResult {
                answer: answer.map_err(|fault| fault_text(&fault)),
                nodes,
                document,
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
        // A trapped instance is not a state anything consumed describes.
        self.consumed.clean = false;
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
                    event: self.observing.clone(),
                    generation: self.next_generation(),
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

    /// Sends one document and returns the number it was given.
    fn draw(&mut self, call: CallKind, nodes: Vec<EmittedNode>) -> u64 {
        self.documents = self.documents.saturating_add(1);
        let document = self.documents;
        self.send(BindingEvent::Document {
            call,
            document,
            nodes,
        });
        document
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
        self.flush_dropped();
        self.flush_consumed();
        let must_arrive = matches!(
            event,
            BindingEvent::Fault { .. } | BindingEvent::Disabled { .. }
        );
        if !must_arrive {
            // The reserve is not presentation's to take: a document that filled the last places
            // would be a document that left no room for the fault that followed it.
            let refused = if self.events.capacity() <= FAULT_RESERVE {
                Some(event)
            } else {
                self.events
                    .try_send(event)
                    .err()
                    .map(tokio::sync::mpsc::error::TrySendError::into_inner)
            };
            if let Some(refused) = refused {
                self.drop_presentation(&refused);
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

    /// Tells the caller what presentation went for want of room, once the channel has room.
    fn flush_dropped(&mut self) {
        if self.dropped_documents == 0 || self.events.capacity() <= FAULT_RESERVE {
            return;
        }
        let dropped = BindingEvent::PresentationDropped {
            documents: self.dropped_documents,
            first: self.dropped_first.clone(),
            last: self.dropped_last.clone(),
        };
        if self.events.try_send(dropped).is_ok() {
            self.dropped_documents = 0;
            self.dropped_first = None;
            self.dropped_last = None;
        }
    }

    /// Records that a presentation went for want of room, and that the component owes a snapshot.
    ///
    /// A gap that goes leaves its positions in the record, which the caller is told of with the
    /// documents that went.
    fn drop_presentation(&mut self, event: &BindingEvent) {
        self.dropped_documents = self.dropped_documents.saturating_add(1);
        if let BindingEvent::Gap(gap) = event {
            if self.dropped_first.is_none() {
                self.dropped_first.clone_from(&gap.first);
            }
            if gap.last.is_some() {
                self.dropped_last.clone_from(&gap.last);
            }
        }
        if let Ok(mut queue) = self.queue.lock() {
            queue.require_snapshot();
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
    use kr_protocol::scalars::Uuid;

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
        assert_eq!(
            runtime.unbind(
                owner,
                BindingId::new(Uuid::from_bytes([9; 16])),
                Incarnation::next()
            ),
            Unbound::Absent
        );
        assert!(!Unbound::Absent.existed());
        assert!(Unbound::Stopped.existed());
        assert!(Unbound::Preparing.existed());
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
                activity: kr_plugin_service::vocabulary::BindingActivity::Idle,
                thread_id: None,
                turn_id: None,
                updated_at_ms: 0,
                held_rights: Vec::new(),
            },
            executable: "/usr/local/bin/example".to_owned(),
            report_consumed: true,
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
                    document: 1,
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
                    event: None,
                    generation: 1,
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
