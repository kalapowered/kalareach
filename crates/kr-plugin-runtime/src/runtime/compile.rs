//! Compiling a component: lazily, at binding preparation, on its own threads.
//!
//! Section 11 is specific about when this happens and what it must not affect. Compilation happens
//! **at binding preparation**, under its own bounded budget, at background priority. It is not part
//! of any call deadline, it cannot block PTY draining, and a slow compile is never counted as a
//! repeated observation fault.
//!
//! All three follow from the same structure: the compile runs on a pool thread, the caller hands
//! over the bytes and gets a handle, and the call budgets in [`crate::runtime::budget`] start only
//! once an instance exists. Nothing on the terminal path is on the other end of a compile.
//!
//! # The budget
//!
//! Two bounds, both checked rather than hoped for:
//!
//! * **Size.** A component larger than [`MAX_COMPONENT_BYTES`] is refused before any work starts.
//!   Machine code is a multiple of its input, so bounding the input is what bounds the memory a
//!   compile can take.
//! * **Time.** A compile that finishes outside [`CompileBudget::deadline_ms`] has its result
//!   discarded and reports how long it took. Cranelift cannot be interrupted part way, so this is
//!   a threshold on accepting a result rather than a cap on the work: an over-budget compile is
//!   not used and not cached, and the caller is told the figure. What bounds the resources already
//!   spent is the size bound above and the pool below.
//!
//! The caller has a deadline of its own on top of both, and it is the one that matters to anything
//! waiting: [`crate::runtime::binding::Runtime::prepare`] bounds the whole preparation -- the
//! compile, the instantiation and `bind` -- and answers when that runs out, whatever the pool is
//! still doing.
//!
//! The pool itself is the third bound. It has a fixed number of threads and a bounded queue, so a
//! host that is asked to prepare a hundred bindings at once compiles a few at a time and refuses
//! the rest with [`crate::runtime::error::RuntimeError::CompilationPressure`] instead of starting
//! a hundred compiles.
//!
//! # Background priority
//!
//! Each pool thread lowers its own scheduling priority when it starts. What that means is the
//! platform's answer rather than this crate's:
//!
//! | Platform | What a pool thread does |
//! | --- | --- |
//! | Apple and other Unix | takes the lowest priority its scheduling policy allows, through `pthread_setschedparam` |
//! | Linux | takes the lowest niceness the thread scheduler allows |
//! | Windows | takes the lowest thread priority |
//!
//! A platform that refuses is not a failure: the compile still runs off the hot path, which is the
//! property that matters, and [`CompilePool::background_priority`] reports what was achieved
//! rather than what was asked for. Lowering a thread's priority is best effort on every one of
//! them, so nothing here depends on it having worked.

use std::sync::mpsc;
use std::sync::{Arc, Mutex};
#[cfg(feature = "testing")]
use std::sync::{Condvar, PoisonError};

use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_service::vocabulary::COMPILE_DEADLINE_MS;

use crate::runtime::cache::{CacheKey, CompiledCache};
use crate::runtime::engine::RuntimeEngine;
use crate::runtime::error::{RuntimeError, RuntimeResult};
use crate::runtime::imports;

/// The largest component this host will compile.
///
/// A package is bounded at 64 MiB in total and a component is one payload inside it. Compiling
/// 16 MiB of Wasm is already a second or more of work; past that the sensible answer is that the
/// package is not one this host runs.
pub const MAX_COMPONENT_BYTES: u64 = 16 * 1024 * 1024;

/// How many components may be compiling at once.
pub const COMPILE_THREADS: usize = 2;

/// How many components may be waiting for a compilation thread.
pub const COMPILE_QUEUE: usize = 8;

/// The bounds a compilation runs under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompileBudget {
    /// The largest component that will be compiled at all.
    pub max_bytes: u64,
    /// How long a compile may take before its result is discarded.
    pub deadline_ms: u64,
}

impl CompileBudget {
    /// The defaults.
    #[must_use]
    pub const fn defaults() -> Self {
        Self {
            max_bytes: MAX_COMPONENT_BYTES,
            deadline_ms: COMPILE_DEADLINE_MS,
        }
    }
}

impl Default for CompileBudget {
    fn default() -> Self {
        Self::defaults()
    }
}

/// What a compilation produced, and where it came from.
#[derive(Debug)]
pub struct Compiled {
    /// The compiled component.
    pub component: wasmtime::component::Component,
    /// How the host obtained it.
    pub origin: CompileOrigin,
    /// How long obtaining it took, in milliseconds.
    pub elapsed_ms: u64,
    /// The key it is filed under.
    pub key: CacheKey,
}

/// Where a compiled component came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompileOrigin {
    /// Compiled in this process from validated Wasm.
    Compiled,
    /// Loaded from an artefact this host compiled earlier.
    Cached,
}

/// What thread priority a pool thread achieved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackgroundPriority {
    /// The platform lowered the thread's priority.
    Lowered,
    /// The platform declined, and the compile runs off the hot path regardless.
    Declined,
}

/// The background compilation pool.
///
/// One pool per runtime. It holds no engine of its own: the engine is passed with each request, so
/// a request compiled for one engine is never handed to another.
#[derive(Debug)]
pub struct CompilePool {
    sender: mpsc::SyncSender<Job>,
    priority: Arc<Mutex<Option<BackgroundPriority>>>,
    threads: usize,
    #[cfg(feature = "testing")]
    hold: Arc<HoldState>,
}

/// How many holds tests have on the pool's jobs, and what a held job waits on.
#[cfg(feature = "testing")]
#[derive(Debug, Default)]
struct HoldState {
    holds: Mutex<usize>,
    released: Condvar,
}

#[cfg(feature = "testing")]
impl HoldState {
    fn take(&self) {
        *self.holds.lock().unwrap_or_else(PoisonError::into_inner) += 1;
    }

    fn release(&self) {
        let mut holds = self.holds.lock().unwrap_or_else(PoisonError::into_inner);
        *holds = holds.saturating_sub(1);
        if *holds == 0 {
            self.released.notify_all();
        }
    }

    fn is_held(&self) -> bool {
        *self.holds.lock().unwrap_or_else(PoisonError::into_inner) > 0
    }

    fn wait_until_released(&self) {
        let mut holds = self.holds.lock().unwrap_or_else(PoisonError::into_inner);
        while *holds > 0 {
            holds = self
                .released
                .wait(holds)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

/// A test's hold on the compilation pool, taken with [`CompilePool::hold`].
///
/// Every job the pool takes while a hold stands waits before it compiles anything, so a caller
/// that was told its compile was queued can be shown a compile that is not done and cannot be done.
/// Dropping a hold lets the jobs go once no other hold stands.
#[cfg(feature = "testing")]
#[derive(Debug)]
pub struct CompileHold {
    state: Arc<HoldState>,
}

#[cfg(feature = "testing")]
impl Drop for CompileHold {
    fn drop(&mut self) {
        self.state.release();
    }
}

type JobWork = Box<dyn FnOnce() + Send + 'static>;

struct Job(JobWork);

impl CompilePool {
    /// Starts a pool with the default thread and queue bounds.
    #[must_use]
    pub fn new() -> Self {
        Self::with_threads(COMPILE_THREADS, COMPILE_QUEUE)
    }

    /// Starts a pool with the given bounds.
    #[must_use]
    pub fn with_threads(threads: usize, queue: usize) -> Self {
        let threads = threads.max(1);
        let (sender, receiver) = mpsc::sync_channel::<Job>(queue);
        let receiver = Arc::new(Mutex::new(receiver));
        let priority = Arc::new(Mutex::new(None));
        #[cfg(feature = "testing")]
        let hold = Arc::new(HoldState::default());
        for index in 0..threads {
            let receiver = Arc::clone(&receiver);
            let priority = Arc::clone(&priority);
            let spawned = std::thread::Builder::new()
                .name(format!("kr-plugin-compile-{index}"))
                .spawn(move || {
                    let achieved = lower_priority();
                    if let Ok(mut slot) = priority.lock() {
                        *slot = Some(achieved);
                    }
                    loop {
                        let job = {
                            let Ok(guard) = receiver.lock() else {
                                return;
                            };
                            guard.recv()
                        };
                        match job {
                            Ok(Job(work)) => work(),
                            // Every sender is gone, so the pool is shutting down.
                            Err(_) => return,
                        }
                    }
                });
            if spawned.is_err() {
                break;
            }
        }
        Self {
            sender,
            priority,
            threads,
            #[cfg(feature = "testing")]
            hold,
        }
    }

    /// Holds every job the pool takes until the returned hold, and every other hold taken meanwhile,
    /// is dropped.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn hold(&self) -> CompileHold {
        self.hold.take();
        CompileHold {
            state: Arc::clone(&self.hold),
        }
    }

    /// Whether a hold on the pool's jobs stands.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn is_held(&self) -> bool {
        self.hold.is_held()
    }

    /// Returns how many threads the pool was built with.
    #[must_use]
    pub const fn threads(&self) -> usize {
        self.threads
    }

    /// Returns what priority the pool's threads achieved, once one has started.
    #[must_use]
    pub fn background_priority(&self) -> Option<BackgroundPriority> {
        self.priority.lock().ok().and_then(|slot| *slot)
    }

    /// Submits a compilation and returns a receiver for its result.
    ///
    /// The call returns as soon as the work is queued. Nothing here waits for a compile, which is
    /// what keeps a caller on the terminal path from ever being behind one.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::ComponentTooLarge`] when the component is past the budget's size
    /// bound, or [`RuntimeError::CompilationPressure`] when every thread is busy and the queue is
    /// full.
    pub fn submit(
        &self,
        engine: &RuntimeEngine,
        cache: &CompiledCache,
        wasm: Arc<[u8]>,
        budget: CompileBudget,
    ) -> RuntimeResult<tokio::sync::oneshot::Receiver<RuntimeResult<Compiled>>> {
        let bytes = wasm.len() as u64;
        if bytes > budget.max_bytes {
            return Err(RuntimeError::ComponentTooLarge {
                bytes,
                limit: budget.max_bytes,
            });
        }
        let engine = engine.clone();
        let cache = cache.clone();
        self.submit_work(move || compile_or_load(&engine, &cache, &wasm, budget))
    }

    /// Queues one piece of work for a pool thread and returns a receiver for what it comes to.
    fn submit_work(
        &self,
        work: impl FnOnce() -> RuntimeResult<Compiled> + Send + 'static,
    ) -> RuntimeResult<tokio::sync::oneshot::Receiver<RuntimeResult<Compiled>>> {
        // A channel a caller can await rather than block on, so nothing that is waiting for a
        // compile is holding a thread while it waits.
        let (answer, wait) = tokio::sync::oneshot::channel();
        #[cfg(feature = "testing")]
        let hold = Arc::clone(&self.hold);
        let job = Job(Box::new(move || {
            #[cfg(feature = "testing")]
            hold.wait_until_released();
            // A compiler that panics on a component refuses that component. It does not end the
            // pool thread it ran on, which would be lost for good and take a share of the pool
            // with it, and it does not leave the caller told that the pool is gone.
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
                .unwrap_or_else(|panic| {
                    let message = panic
                        .downcast_ref::<&str>()
                        .map(|text| (*text).to_owned())
                        .or_else(|| panic.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "without a message".to_owned());
                    Err(RuntimeError::InvalidComponent {
                        detail: format!("the compiler panicked: {message}"),
                    })
                });
            // A caller that has given up on the compile is not an error: the result is cached, so
            // the next preparation finds it.
            let _ = answer.send(outcome);
        }));
        self.sender.try_send(job).map_err(|error| match error {
            mpsc::TrySendError::Full(_) => RuntimeError::CompilationPressure {
                queued: COMPILE_QUEUE,
            },
            mpsc::TrySendError::Disconnected(_) => RuntimeError::CompilationPressure { queued: 0 },
        })?;
        Ok(wait)
    }
}

impl Default for CompilePool {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns the cache key for one component under one engine.
#[must_use]
pub fn key_for(engine: &RuntimeEngine, wasm: &[u8]) -> CacheKey {
    CacheKey {
        wasm_digest: PayloadDigest::of(wasm),
        wasm_bytes: wasm.len() as u64,
        engine_compatibility: engine.compatibility().to_owned(),
        engine_version: engine.version().to_owned(),
        target: engine.target().to_owned(),
    }
}

/// Compiles a component in this process, or loads one this process compiled earlier.
///
/// # Errors
///
/// Returns the compilation, cache or import failure. A cache entry that fails its checks is
/// removed and the component is compiled again, because a refused entry is a reason to recompile
/// rather than a reason to refuse the binding.
pub fn compile_or_load(
    engine: &RuntimeEngine,
    cache: &CompiledCache,
    wasm: &[u8],
    budget: CompileBudget,
) -> RuntimeResult<Compiled> {
    let bytes = wasm.len() as u64;
    if bytes > budget.max_bytes {
        return Err(RuntimeError::ComponentTooLarge {
            bytes,
            limit: budget.max_bytes,
        });
    }
    let key = key_for(engine, wasm);
    let started = std::time::Instant::now();

    match cache.load(engine.engine(), &key) {
        Ok(Some(component)) => {
            imports::check(&component, engine.engine())?;
            let elapsed_ms = elapsed_ms(started);
            // The budget covers obtaining a component, not only compiling one. A load that took
            // longer than a compile is allowed to take is a load this host does not accept either.
            if elapsed_ms > budget.deadline_ms {
                return Err(RuntimeError::CompilationTooSlow {
                    elapsed_ms,
                    budget_ms: budget.deadline_ms,
                });
            }
            return Ok(Compiled {
                component,
                origin: CompileOrigin::Cached,
                elapsed_ms,
                key,
            });
        }
        Ok(None) => {}
        Err(refusal) => {
            // A refused entry is removed so that the next preparation is a clean miss rather than
            // the same refusal again. The refusal itself is not the binding's failure: this host
            // still has the validated Wasm and can compile it.
            let _ = cache.remove(&key);
            let _ = refusal;
        }
    }

    // The only way machine code enters this host: compiling validated Wasm in this process. The
    // refusal carries the engine's whole account of why, every cause and not only the outermost:
    // "failed to compile" names the function and says nothing of what was wrong with it.
    let component =
        wasmtime::component::Component::new(engine.engine(), wasm).map_err(|error| {
            RuntimeError::InvalidComponent {
                detail: format!("{error:#}"),
            }
        })?;
    let elapsed_ms = elapsed_ms(started);
    if elapsed_ms > budget.deadline_ms {
        return Err(RuntimeError::CompilationTooSlow {
            elapsed_ms,
            budget_ms: budget.deadline_ms,
        });
    }
    imports::check(&component, engine.engine())?;
    // Filing the artefact is a convenience for the next preparation, and a failure to file it is
    // not a failure to prepare this binding. It also keeps the component in this process's memory,
    // so a second binding of the same package neither compiles nor reads a file.
    let _ = cache.store(&key, &component);
    Ok(Compiled {
        component,
        origin: CompileOrigin::Compiled,
        elapsed_ms,
        key,
    })
}

fn elapsed_ms(since: std::time::Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn lower_priority() -> BackgroundPriority {
    use thread_priority::{ThreadPriority, set_current_thread_priority};

    if set_current_thread_priority(ThreadPriority::Min).is_ok() {
        BackgroundPriority::Lowered
    } else {
        BackgroundPriority::Declined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_size_bound_refuses_an_oversized_component_before_any_work() {
        let pool = CompilePool::with_threads(1, 1);
        let engine = RuntimeEngine::new().expect("an engine");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let cache = CompiledCache::open(directory.path().join("cache")).expect("a cache");
        let oversized: Arc<[u8]> =
            vec![0_u8; usize::try_from(MAX_COMPONENT_BYTES + 1).expect("a usize")].into();
        let error = pool
            .submit(&engine, &cache, oversized, CompileBudget::defaults())
            .expect_err("an oversized component is refused");
        assert!(matches!(error, RuntimeError::ComponentTooLarge { .. }));
    }

    /// The nice value the kernel holds for the calling thread, from its own record of the thread.
    #[cfg(target_os = "linux")]
    fn nice_of_this_thread() -> i64 {
        let stat = std::fs::read_to_string("/proc/thread-self/stat").expect("the thread's record");
        // The command name sits in parentheses and may hold spaces; what follows its closing one is
        // plain fields, the state first. The nice value is the nineteenth field of the record.
        let after_the_name = stat.rsplit_once(')').expect("the name is closed").1;
        after_the_name
            .split_whitespace()
            .nth(16)
            .expect("the nice field")
            .parse()
            .expect("a number")
    }

    // KR-REQ-11.41: a compile runs on a pool thread that the kernel holds at the lowest ordinary
    // priority, and not only one that reports that it asked.
    //
    // The work is queued on the pool and reads the nice value of the thread it runs on, so a pool
    // whose threads asked for nothing, or whose request was made on another thread, fails here.
    // A sandbox that refuses a thread the change of its own priority makes the pool report
    // `Declined`, which the pool allows; this case is for a host that does not refuse it.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_compile_runs_on_a_pool_thread_the_kernel_holds_at_the_lowest_ordinary_priority() {
        let pool = CompilePool::with_threads(1, 1);
        let (reply, nice) = mpsc::channel();
        pool.sender
            .try_send(Job(Box::new(move || {
                let _ = reply.send(nice_of_this_thread());
            })))
            .expect("the job is queued");
        let held_at = nice
            .recv_timeout(core::time::Duration::from_secs(60))
            .expect("the pool thread ran the job");
        assert_eq!(
            pool.background_priority(),
            Some(BackgroundPriority::Lowered),
            "the pool thread's request was declined, which a sandbox that refuses a thread the \
             change of its own priority does"
        );
        assert_eq!(
            held_at, 19,
            "the kernel holds the pool thread at nice {held_at}"
        );
    }

    // KR-REQ-11.41: a pool thread reports the priority its request for background priority came to.
    #[test]
    fn a_pool_thread_asks_for_background_priority() {
        let pool = CompilePool::with_threads(1, 1);
        let deadline = std::time::Instant::now() + core::time::Duration::from_secs(5);
        while pool.background_priority().is_none() {
            assert!(
                std::time::Instant::now() < deadline,
                "no pool thread reported its priority"
            );
            std::thread::sleep(core::time::Duration::from_millis(5));
        }
        // What the platform gave is the platform's answer; that it was asked for is this crate's.
        assert!(matches!(
            pool.background_priority(),
            Some(BackgroundPriority::Lowered | BackgroundPriority::Declined)
        ));
    }

    // KR-REQ-11.41: the jobs a held pool takes wait until the last hold is let go, however the
    // holds are taken and dropped, so a compile cannot be released by a hold that was dropped
    // early.
    #[cfg(feature = "testing")]
    #[test]
    fn a_pool_stays_held_until_the_last_hold_is_dropped() {
        let pool = CompilePool::with_threads(1, 1);
        assert!(!pool.is_held());
        let first = pool.hold();
        let second = pool.hold();
        drop(first);
        assert!(pool.is_held(), "the first hold's drop freed the second's");
        drop(second);
        assert!(!pool.is_held());
    }

    #[test]
    fn the_key_changes_with_the_component_and_with_the_engine() {
        let engine = RuntimeEngine::new().expect("an engine");
        let first = key_for(&engine, b"one component");
        let second = key_for(&engine, b"another component");
        assert_ne!(first.wasm_digest, second.wasm_digest);
        assert_eq!(first.engine_compatibility, second.engine_compatibility);

        let mut foreign = first.clone();
        foreign.engine_compatibility = "an engine from another build".to_owned();
        assert_ne!(first.engine_directory(), foreign.engine_directory());
    }

    #[test]
    fn a_component_that_is_not_wasm_is_refused_as_invalid_rather_than_compiled() {
        let engine = RuntimeEngine::new().expect("an engine");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let cache = CompiledCache::open(directory.path().join("cache")).expect("a cache");
        let error = compile_or_load(
            &engine,
            &cache,
            b"not wasm at all",
            CompileBudget::defaults(),
        )
        .expect_err("text is not a component");
        assert!(matches!(error, RuntimeError::InvalidComponent { .. }));
    }

    #[test]
    fn a_compile_that_panics_is_refused_and_leaves_the_pool_serving_the_next_one() {
        let pool = CompilePool::with_threads(1, 2);
        let panicked = pool
            .submit_work(|| panic!("the compiler fell over"))
            .expect("the work is queued");
        // Behind it on the pool's only thread: it runs only if that thread is still there. The wait
        // is a bound so that a lost thread fails the case rather than holding it.
        let (ran, next) = mpsc::channel::<()>();
        pool.sender
            .try_send(Job(Box::new(move || {
                let _ = ran.send(());
            })))
            .expect("the next job is queued");
        next.recv_timeout(core::time::Duration::from_secs(5))
            .expect("the pool thread survived the panic");
        match panicked.blocking_recv().expect("the caller is answered") {
            Err(RuntimeError::InvalidComponent { detail }) => {
                assert!(detail.contains("the compiler fell over"), "{detail}");
            }
            other => panic!("the caller was told {other:?}"),
        }
    }

    #[test]
    fn the_queue_is_bounded_so_a_flood_is_refused_rather_than_queued() {
        // One thread and a queue of one. The jobs below report when they start and then block, so
        // the test can wait until the thread is definitely inside one before it fills the queue;
        // otherwise the thread might take a queued job between the fill and the submission and the
        // answer would depend on timing.
        let pool = CompilePool::with_threads(1, 1);
        let (release, held) = mpsc::channel::<()>();
        let held = Arc::new(Mutex::new(held));
        let (started, running) = mpsc::channel::<()>();

        let fill = || {
            loop {
                let held = Arc::clone(&held);
                let started = started.clone();
                let job = Job(Box::new(move || {
                    let _ = started.send(());
                    if let Ok(guard) = held.lock() {
                        let _ = guard.recv();
                    }
                }));
                if pool.sender.try_send(job).is_err() {
                    return;
                }
            }
        };

        fill();
        running
            .recv_timeout(core::time::Duration::from_secs(5))
            .expect("the pool thread starts a job");
        // The thread is now blocked in that job and will take no other. Filling again leaves the
        // queue full with nothing to drain it.
        fill();

        let engine = RuntimeEngine::new().expect("an engine");
        let directory = tempfile::tempdir().expect("a temporary directory");
        let cache = CompiledCache::open(directory.path().join("cache")).expect("a cache");
        let outcome = pool.submit(
            &engine,
            &cache,
            Arc::from(&b"\0asm\x0d\0\x01\0"[..]),
            CompileBudget::defaults(),
        );
        assert!(
            matches!(outcome, Err(RuntimeError::CompilationPressure { .. })),
            "a full pool answered {outcome:?}"
        );
        drop(release);
    }
}
