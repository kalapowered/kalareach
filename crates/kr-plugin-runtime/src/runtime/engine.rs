//! The component engine, and the thread that makes its deadlines real.
//!
//! # Configuration
//!
//! Only the component model is on. `wasmtime-wasi` is not linked at all, so there is no ambient
//! filesystem, network, process, environment, clock or random import to grant; the only interfaces
//! in the linker are the four in the SDK's WIT package.
//!
//! Fuel and epoch interruption are both on, because section 11 asks for both: fuel bounds the work
//! a call may do, and the epoch deadline bounds the elapsed time. Neither substitutes for the
//! other, and neither is reported as the other.
//!
//! # The epoch ticker
//!
//! Epoch interruption works by a counter the engine compares against each store's deadline. Someone
//! has to advance the counter, and this module owns that: one thread per engine.
//!
//! The counter tracks **elapsed time**, not wakeups. Each pass reads the monotonic clock and
//! advances the epoch by however many milliseconds have actually gone by, so a thread the scheduler
//! kept waiting does not leave a call with more time than its deadline allows. A late thread makes
//! a deadline fire late by the length of its own delay and never by more.
//!
//! It advances the counter only while a call is in flight. An engine hosting no calls needs no
//! ticks, and a host with an idle shell should not have a thread waking a thousand times a second
//! on its behalf. A call registers before it enters the component and deregisters when it returns.
//!
//! # Shutting it down
//!
//! The thread holds a strong reference to the ticker for its whole life, because a thread waiting
//! on a condition variable has to own what it is waiting on. So what ends it is not the ticker's
//! own drop: [`RuntimeEngine`] holds a separate guard, shared by its clones, whose drop sets the
//! stop flag and wakes the thread. When the last clone of an engine goes, the thread wakes, sees
//! the flag and returns, and the ticker goes with it.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use crate::runtime::error::{RuntimeError, RuntimeResult};

/// How often the epoch advances, in milliseconds.
///
/// One millisecond is a tenth of the shortest deadline in section 11, so a 10 ms observation
/// deadline is enforced to within a tick of its length. Finer ticking would cost more than the
/// precision is worth; coarser would round the shortest deadline away.
pub const EPOCH_TICK_MS: u64 = 1;

/// The version of the engine this host is built against.
pub const ENGINE_VERSION: &str = "48.0.2";

/// The target this host compiles machine code for.
pub const TARGET: &str = env!("KR_PLUGIN_TARGET");

/// The most ticks one pass advances the epoch by.
///
/// A pass that was delayed for a minute would otherwise advance the epoch sixty thousand times in
/// one go, which costs more than it settles: every deadline in section 11 is already long past at
/// a hundredth of that.
const MAX_ADVANCE: u64 = 1_000;

/// How many epoch threads are running.
///
/// One per live engine. A test that creates and drops engines checks this rather than assuming the
/// threads went with them.
static LIVE_TICKERS: AtomicUsize = AtomicUsize::new(0);

/// Returns how many epoch threads are running.
#[must_use]
pub fn live_tickers() -> usize {
    LIVE_TICKERS.load(Ordering::Relaxed)
}

/// Returns the engine's compatibility identity as a stable hexadecimal string.
///
/// The engine hands out an opaque hashable value covering its version and every compilation
/// setting that decides whether one build's artefact can be loaded by another. Feeding it through
/// SHA-256 rather than the standard library's default hasher keeps the written form stable across
/// compiler releases, so a host that is rebuilt does not lose its cache for no reason.
fn compatibility_of(engine: &wasmtime::Engine) -> String {
    use core::hash::{Hash as _, Hasher};
    use sha2::Digest as _;

    struct Sha256Hasher(sha2::Sha256);

    impl Hasher for Sha256Hasher {
        fn write(&mut self, bytes: &[u8]) {
            self.0.update(bytes);
        }

        fn finish(&self) -> u64 {
            let digest = self.0.clone().finalize();
            let mut head = [0_u8; 8];
            head.copy_from_slice(&digest[..8]);
            u64::from_be_bytes(head)
        }
    }

    let mut hasher = Sha256Hasher(sha2::Sha256::new());
    engine.precompile_compatibility_hash().hash(&mut hasher);
    let digest = hasher.0.finalize();
    let mut text = String::with_capacity(digest.len() * 2);
    for byte in digest {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

/// The engine, its ticker and the identity its compiled artefacts are filed under.
#[derive(Clone, Debug)]
pub struct RuntimeEngine {
    engine: wasmtime::Engine,
    ticker: Arc<EpochTicker>,
    /// Dropped when the last clone of this engine goes, which is what stops the ticker's thread.
    shutdown: Arc<TickerShutdown>,
    compatibility: String,
}

impl RuntimeEngine {
    /// Builds the engine with the section 11 configuration.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::Engine`] when the engine will not accept the configuration, which
    /// on a supported host means the build is missing a compiler backend.
    pub fn new() -> RuntimeResult<Self> {
        let mut config = wasmtime::Config::new();
        config.wasm_component_model(true);
        // Both bounds, as section 11 requires. Fuel is a work allowance; the epoch is elapsed time.
        config.consume_fuel(true);
        config.epoch_interruption(true);
        // A trap that says where it happened is the difference between a usable disabled reason and
        // "the component trapped".
        config.wasm_backtrace_max_frames(core::num::NonZeroUsize::new(16));
        config.wasm_backtrace_details(wasmtime::WasmBacktraceDetails::Disable);
        config.cranelift_opt_level(wasmtime::OptLevel::Speed);
        // The limiter is what bounds an instance's memory. Reserving the bound up front means a
        // component that grows to it never moves its memory, and one that asks past it is refused
        // by the limiter rather than by an allocation failure.
        config.memory_reservation(kr_plugin_sdk::limits::INSTANCE_MEMORY_BYTES);
        config.memory_may_move(false);

        let engine = wasmtime::Engine::new(&config).map_err(RuntimeError::engine)?;
        let compatibility = compatibility_of(&engine);
        let ticker = EpochTicker::start(&engine);
        Ok(Self {
            engine,
            ticker: Arc::clone(&ticker),
            shutdown: Arc::new(TickerShutdown(ticker)),
            compatibility,
        })
    }

    /// Returns the engine.
    #[must_use]
    pub const fn engine(&self) -> &wasmtime::Engine {
        &self.engine
    }

    /// Returns the engine's compatibility hash: its version and compilation settings together.
    ///
    /// This is the part of a cache key that is not the component. Two engines that would produce
    /// interchangeable machine code share it; two that would not, do not.
    #[must_use]
    pub fn compatibility(&self) -> &str {
        &self.compatibility
    }

    /// Returns the target this engine compiles machine code for.
    ///
    /// The compatibility hash already covers the instruction-set features a compile was made
    /// with; this is the part a person reading the cache directory needs.
    #[must_use]
    pub const fn target(&self) -> &'static str {
        TARGET
    }

    /// Returns the engine version.
    #[must_use]
    pub const fn version(&self) -> &'static str {
        ENGINE_VERSION
    }

    /// Registers a call as in flight, so the epoch advances while it runs.
    ///
    /// The returned guard deregisters on drop, including when the call unwinds.
    #[must_use]
    pub fn in_flight(&self) -> InFlight {
        self.ticker.enter();
        InFlight {
            ticker: Arc::clone(&self.ticker),
        }
    }

    /// Returns how many times the epoch has advanced.
    ///
    /// For the tests that need to know the ticker is doing its job rather than assume it.
    #[must_use]
    pub fn ticks(&self) -> u64 {
        self.ticker.ticks.load(Ordering::Relaxed)
    }

    /// Advances the epoch once, without the ticker.
    ///
    /// For the tests that need a deadline to expire at a moment they choose.
    pub fn advance_epoch(&self) {
        self.engine.increment_epoch();
        self.ticker.ticks.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns true when the epoch ticker is running.
    ///
    /// A host that could not start the ticker cannot enforce an elapsed deadline, and says so
    /// rather than running a component as though it could.
    #[must_use]
    pub fn deadlines_enforceable(&self) -> bool {
        let _ = &self.shutdown;
        self.ticker.running()
    }

    /// Returns a flag that becomes true when this engine's epoch thread has ended.
    ///
    /// A test holds it across dropping the engine, which is exactly the moment the thread has to
    /// end and nothing else can observe. Counting threads across a process would tell a test about
    /// every other engine in it as well.
    #[must_use]
    pub fn ticker_ended(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.ticker.ended)
    }
}

/// A call that is in flight.
#[derive(Debug)]
pub struct InFlight {
    ticker: Arc<EpochTicker>,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.ticker.leave();
    }
}

/// What ends the ticker's thread.
///
/// Held by [`RuntimeEngine`] behind an [`Arc`] that its clones share, so the flag is set and the
/// thread woken exactly when the last engine goes. The thread's own strong reference to the ticker
/// is therefore not what keeps it alive.
#[derive(Debug)]
struct TickerShutdown(Arc<EpochTicker>);

impl Drop for TickerShutdown {
    fn drop(&mut self) {
        self.0.stopping.store(true, Ordering::Release);
        // Taken under the lock, so a thread between checking the flag and waiting cannot miss it.
        if let Ok(_state) = self.0.state.lock() {
            self.0.wake.notify_all();
        } else {
            self.0.wake.notify_all();
        }
    }
}

#[derive(Debug)]
struct EpochTicker {
    state: Mutex<TickerState>,
    wake: Condvar,
    ticks: AtomicU64,
    stopping: AtomicBool,
    /// Set when the thread has returned. A test holds this rather than counting threads.
    ended: Arc<AtomicBool>,
}

#[derive(Debug, Default)]
struct TickerState {
    in_flight: usize,
}

impl EpochTicker {
    fn start(engine: &wasmtime::Engine) -> Arc<Self> {
        let ticker = Arc::new(Self {
            state: Mutex::new(TickerState::default()),
            wake: Condvar::new(),
            ticks: AtomicU64::new(0),
            stopping: AtomicBool::new(false),
            ended: Arc::new(AtomicBool::new(false)),
        });
        let held = Arc::clone(&ticker);
        // A weak reference to the engine, so the thread does not keep it alive; the engine's own
        // shutdown guard is what ends the thread.
        let engine = engine.weak();
        LIVE_TICKERS.fetch_add(1, Ordering::Relaxed);
        let spawned = std::thread::Builder::new()
            .name("kr-plugin-epoch".to_owned())
            .spawn(move || {
                let tick = core::time::Duration::from_millis(EPOCH_TICK_MS);
                // The epoch tracks elapsed time rather than the number of times this thread woke
                // up. Each pass advances it to where the clock says it should be, counted from the
                // moment the current run of in-flight calls began, so a sleep that overshoots and
                // a scheduler that is late cost nothing: the next pass makes up the difference
                // rather than losing it.
                let mut anchor = std::time::Instant::now();
                let mut advanced = 0_u64;
                loop {
                    if held.stopping.load(Ordering::Acquire) {
                        break;
                    }
                    {
                        let Ok(mut state) = held.state.lock() else {
                            break;
                        };
                        let mut idle = state.in_flight == 0;
                        let was_idle = idle;
                        while idle {
                            if held.stopping.load(Ordering::Acquire) {
                                held.ended.store(true, Ordering::Release);
                                LIVE_TICKERS.fetch_sub(1, Ordering::Relaxed);
                                return;
                            }
                            let (guard, _timeout) = held
                                .wake
                                .wait_timeout(state, core::time::Duration::from_millis(50))
                                .unwrap_or_else(|error| error.into_inner());
                            state = guard;
                            idle = state.in_flight == 0;
                        }
                        if was_idle {
                            // Time nothing was running is time no call spent, so the count starts
                            // again from the moment a call appeared.
                            anchor = std::time::Instant::now();
                            advanced = 0;
                        }
                    }
                    let owed =
                        u64::try_from(anchor.elapsed().as_millis() / u128::from(EPOCH_TICK_MS))
                            .unwrap_or(u64::MAX);
                    let advance = owed.saturating_sub(advanced).clamp(1, MAX_ADVANCE);
                    let Some(engine) = engine.upgrade() else {
                        break;
                    };
                    for _ in 0..advance {
                        engine.increment_epoch();
                    }
                    drop(engine);
                    advanced = advanced.saturating_add(advance);
                    held.ticks.fetch_add(advance, Ordering::Relaxed);
                    std::thread::sleep(tick);
                }
                held.ended.store(true, Ordering::Release);
                LIVE_TICKERS.fetch_sub(1, Ordering::Relaxed);
            });
        if spawned.is_err() {
            // A host that cannot start a thread cannot enforce an elapsed deadline by epoch.
            // `deadlines_enforceable` reports it and `Instance::call` refuses to run a deadlined
            // call rather than running one it cannot bound.
            LIVE_TICKERS.fetch_sub(1, Ordering::Relaxed);
            ticker.stopping.store(true, Ordering::Release);
            ticker.ended.store(true, Ordering::Release);
        }
        ticker
    }

    fn enter(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.in_flight += 1;
            self.wake.notify_all();
        }
    }

    fn leave(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.in_flight = state.in_flight.saturating_sub(1);
        }
    }

    fn running(&self) -> bool {
        !self.stopping.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Waits until `condition` holds, or fails with `whatever` if it does not.
    fn until(whatever: &str, condition: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + core::time::Duration::from_secs(10);
        while !condition() {
            assert!(std::time::Instant::now() < deadline, "{whatever}");
            std::thread::sleep(core::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn the_engine_carries_its_identity_for_the_cache_key() {
        let engine = RuntimeEngine::new().expect("an engine");
        assert!(!engine.compatibility().is_empty());
        assert!(!engine.target().is_empty());
        assert_eq!(engine.version(), ENGINE_VERSION);
        assert!(engine.deadlines_enforceable());
    }

    #[test]
    fn the_epoch_advances_while_a_call_is_in_flight() {
        let engine = RuntimeEngine::new().expect("an engine");
        let before = engine.ticks();
        let guard = engine.in_flight();
        until(
            "the epoch did not advance while a call was in flight",
            || engine.ticks() >= before + 5,
        );
        drop(guard);
    }

    #[test]
    fn the_epoch_advances_by_the_time_that_passed_rather_than_by_the_number_of_wakeups() {
        let engine = RuntimeEngine::new().expect("an engine");
        let guard = engine.in_flight();
        // One pass has to have happened before the measurement, so that `last` is anchored inside
        // the in-flight window rather than at the moment it opened.
        std::thread::sleep(core::time::Duration::from_millis(20));
        let before = engine.ticks();
        let started = std::time::Instant::now();
        std::thread::sleep(core::time::Duration::from_millis(200));
        let advanced = engine.ticks() - before;
        let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        drop(guard);
        // At least as many ticks as milliseconds went by, less the pass in progress. A thread that
        // counted only its own wakeups would fall behind under any load at all.
        assert!(
            advanced + 4 >= elapsed,
            "{elapsed} ms passed and the epoch advanced {advanced} times"
        );
    }

    #[test]
    fn the_epoch_stops_advancing_once_nothing_is_in_flight() {
        let engine = RuntimeEngine::new().expect("an engine");
        {
            let _guard = engine.in_flight();
            std::thread::sleep(core::time::Duration::from_millis(20));
        }
        // One more pass may already be under way when the guard drops, so settle before reading.
        std::thread::sleep(core::time::Duration::from_millis(60));
        let idle = engine.ticks();
        std::thread::sleep(core::time::Duration::from_millis(120));
        assert_eq!(
            engine.ticks(),
            idle,
            "the epoch kept advancing with no call in flight"
        );
    }

    #[test]
    fn an_engine_dropped_while_idle_takes_its_thread_with_it() {
        // Every one of these is idle: nothing has ever been in flight, which is the state a thread
        // that held its own ticker alive would wait in for ever.
        let engines: Vec<RuntimeEngine> = (0..4)
            .map(|_| RuntimeEngine::new().expect("an engine"))
            .collect();
        assert!(live_tickers() >= 4);
        let ended: Vec<Arc<AtomicBool>> = engines.iter().map(RuntimeEngine::ticker_ended).collect();
        assert!(ended.iter().all(|flag| !flag.load(Ordering::Acquire)));
        drop(engines);
        until("epoch threads outlived their engines", || {
            ended.iter().all(|flag| flag.load(Ordering::Acquire))
        });
    }

    #[test]
    fn a_clone_keeps_the_ticker_and_the_last_one_ends_it() {
        let engine = RuntimeEngine::new().expect("an engine");
        let ended = engine.ticker_ended();
        let clone = engine.clone();
        drop(engine);
        std::thread::sleep(core::time::Duration::from_millis(120));
        assert!(
            clone.deadlines_enforceable(),
            "dropping one clone stopped the ticker the other still needs"
        );
        assert!(
            !ended.load(Ordering::Acquire),
            "dropping one clone ended the thread the other still needs"
        );
        drop(clone);
        until("the epoch thread outlived the last engine", || {
            ended.load(Ordering::Acquire)
        });
    }

    #[test]
    fn two_engines_of_one_build_agree_on_their_compatibility() {
        let first = RuntimeEngine::new().expect("an engine");
        let second = RuntimeEngine::new().expect("an engine");
        assert_eq!(first.compatibility(), second.compatibility());
        assert_eq!(first.target(), second.target());
    }
}
