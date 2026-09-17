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
//! has to advance the counter, and this module owns that: one thread per engine, advancing it once
//! a millisecond.
//!
//! It advances the counter only while a call is in flight. An engine hosting no calls needs no
//! ticks, and a host with an idle shell should not have a thread waking a thousand times a second
//! on its behalf. A call registers before it enters the component and deregisters when it returns,
//! and the ticker sleeps on a condition variable in between.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use crate::runtime::error::{RuntimeError, RuntimeResult};

/// How often the epoch advances, in milliseconds.
///
/// One millisecond is the granularity of the shortest deadline in section 11 divided by ten, so a
/// 10 ms observation deadline is enforced to within a tick. Finer ticking would cost more than the
/// precision is worth; coarser would round the shortest deadline away.
pub const EPOCH_TICK_MS: u64 = 1;

/// The version of the engine this host is built against.
pub const ENGINE_VERSION: &str = "48.0.2";

/// The target this host compiles machine code for.
pub const TARGET: &str = env!("KR_PLUGIN_TARGET");

/// Returns the engine's compatibility identity as a stable hexadecimal string.
///
/// The engine hands out an opaque hashable value covering its version and every compilation
/// setting that decides whether one build's artefact can be loaded by another. Feeding it through
/// SHA-256 rather than the standard library's default hasher keeps the written form stable across
/// compiler releases, so a host that is rebuilt does not lose its cache for no reason.
fn compatibility_of(engine: &wasmtime::Engine) -> String {
    use core::hash::{Hash as _, Hasher};

    struct Sha256Hasher(sha2::Sha256);

    impl Hasher for Sha256Hasher {
        fn write(&mut self, bytes: &[u8]) {
            use sha2::Digest as _;
            self.0.update(bytes);
        }

        fn finish(&self) -> u64 {
            use sha2::Digest as _;
            let digest = self.0.clone().finalize();
            let mut head = [0_u8; 8];
            head.copy_from_slice(&digest[..8]);
            u64::from_be_bytes(head)
        }
    }

    let mut hasher = Sha256Hasher(sha2::Sha256::new());
    engine.precompile_compatibility_hash().hash(&mut hasher);
    use sha2::Digest as _;
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
            ticker,
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

#[derive(Debug)]
struct EpochTicker {
    state: Mutex<TickerState>,
    wake: Condvar,
    ticks: AtomicU64,
    stopping: AtomicBool,
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
        });
        // The thread holds a weak reference, so the engine and the ticker can be dropped and the
        // thread notices rather than keeping them alive.
        let weak = Arc::downgrade(&ticker);
        let engine = engine.weak();
        let spawned = std::thread::Builder::new()
            .name("kr-plugin-epoch".to_owned())
            .spawn(move || {
                let tick = core::time::Duration::from_millis(EPOCH_TICK_MS);
                loop {
                    let Some(ticker) = weak.upgrade() else {
                        return;
                    };
                    if ticker.stopping.load(Ordering::Acquire) {
                        return;
                    }
                    {
                        let Ok(mut state) = ticker.state.lock() else {
                            return;
                        };
                        while state.in_flight == 0 {
                            if ticker.stopping.load(Ordering::Acquire) {
                                return;
                            }
                            // Waiting with a timeout rather than indefinitely, so a stop that
                            // happens while nothing is in flight is noticed without the stopper
                            // having to hold the lock to notify.
                            let (guard, _timeout) = ticker
                                .wake
                                .wait_timeout(state, core::time::Duration::from_millis(50))
                                .unwrap_or_else(|error| error.into_inner());
                            state = guard;
                        }
                    }
                    let Some(engine) = engine.upgrade() else {
                        return;
                    };
                    engine.increment_epoch();
                    ticker.ticks.fetch_add(1, Ordering::Relaxed);
                    drop(engine);
                    drop(ticker);
                    std::thread::sleep(tick);
                }
            });
        if spawned.is_err() {
            // A host that cannot start a thread cannot enforce an elapsed deadline by epoch. The
            // engine still refuses to run anything past its fuel, and `Runtime::call` treats a
            // ticker that is not advancing as a reason to stop rather than as permission to run
            // unbounded: see `Runtime::guard_deadline`.
            ticker.stopping.store(true, Ordering::Release);
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

impl RuntimeEngine {
    /// Returns true when the epoch ticker is running.
    ///
    /// A host that could not start the ticker cannot enforce an elapsed deadline, and says so
    /// rather than running a component as though it could.
    #[must_use]
    pub fn deadlines_enforceable(&self) -> bool {
        self.ticker.running()
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        self.wake.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let deadline = std::time::Instant::now() + core::time::Duration::from_secs(5);
        while engine.ticks() < before + 5 {
            assert!(
                std::time::Instant::now() < deadline,
                "the epoch did not advance while a call was in flight"
            );
            std::thread::sleep(core::time::Duration::from_millis(2));
        }
        drop(guard);
    }

    #[test]
    fn the_epoch_stops_advancing_once_nothing_is_in_flight() {
        let engine = RuntimeEngine::new().expect("an engine");
        {
            let _guard = engine.in_flight();
            std::thread::sleep(core::time::Duration::from_millis(20));
        }
        // One more tick may already be under way when the guard drops, so settle before reading.
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
    fn two_engines_of_one_build_agree_on_their_compatibility() {
        let first = RuntimeEngine::new().expect("an engine");
        let second = RuntimeEngine::new().expect("an engine");
        assert_eq!(first.compatibility(), second.compatibility());
        assert_eq!(first.target(), second.target());
    }
}
