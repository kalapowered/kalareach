//! Measures KR-PERF-009 against real weights.
//!
//! This binary never downloads anything. `scripts/bench-descriptions.sh` fetches the selected
//! profile's assets once into a cache on local storage and this verifies them, which keeps the two
//! responsibilities apart: the script knows how to fetch, and the product knows what a correct file
//! is. An asset whose size or digest is not the one the profile records stops the run, because a
//! figure measured against weights nobody qualified is not a figure about this product.
//!
//! Every number printed says what it was measured on. Section 27's reference-host conditions are a
//! property of the machine, so a latency with no hardware beside it cannot be compared with the
//! next one.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use kr_describe::budget::{Budgets, ResidentCost};
use kr_describe::context::{ContextBinding, ContextSignal};
use kr_describe::environment::{EnvironmentKind, ExecutionEnvironment};
use kr_describe::metadata::RepositoryFacts;
use kr_describe::metrics::{Distribution, LatencyLedger, PUBLISHED_SESSION_COUNTS};
use kr_describe::priority::Cancellation;
use kr_describe::profile::catalogue::{Catalogue, MetGates};
use kr_describe::profile::{Asset, ModelProfile};
use kr_describe::queue::Priority;
use kr_describe::resource::{ResourceSettings, platform};
use kr_describe::runtime::LoadOutcome;
use kr_describe::service::{DescriptionService, HostPlacement, RuntimeFactory, Tick};
use kr_describe::store::DescriptionStore;
use kr_describe::time::Reading;
use kr_protocol::ids::{EnvironmentId, SessionEpoch, SessionId};
use kr_protocol::scalars::Uuid;
use vtparse::{CsiParam, VTActor, VTParser};

/// The largest number of sessions the benchmark drives.
const MAX_SESSIONS: u32 = 50;

/// Background terminal actor that absorbs escape sequences without allocating.
struct BenchTerminalActor;

impl VTActor for BenchTerminalActor {
    fn print(&mut self, _b: char) {}
    fn execute_c0_or_c1(&mut self, _b: u8) {}
    fn dcs_hook(&mut self, _byte: u8, _params: &[i64], _intermediates: &[u8], _ignored: bool) {}
    fn dcs_put(&mut self, _byte: u8) {}
    fn dcs_unhook(&mut self) {}
    fn osc_dispatch(&mut self, _params: &[&[u8]]) {}
    fn csi_dispatch(&mut self, _params: &[CsiParam], _ignored: bool, _c: u8) {}
    fn esc_dispatch(&mut self, _params: &[i64], _intermediates: &[u8], _ignored: bool, _byte: u8) {}
    fn apc_dispatch(&mut self, _data: Vec<u8>) {}
}

const ANSI_TERMINAL_STREAM: &[u8] = b"\x1b[?25l\x1b[2J\x1b[H\x1b[32m\xe2\x9c\x93\x1b[0m Compiling kr-describe v0.1.0\r\n\x1b[1;34m-->\x1b[0m crates/kr-describe/src/service.rs:42:1\r\n\x1b[33mwarning\x1b[0m: benchmarking terminal stream\r\n\x1b[38;2;255;128;64m[kalareach]\x1b[0m status line updated\r\n\x1b[?25h";

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let mode = arguments.first().map(String::as_str).unwrap_or("--run");
    let profile = match selected_profile(&arguments) {
        Ok(profile) => profile,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::FAILURE;
        }
    };
    match mode {
        "--manifest" => {
            for asset in profile.assets() {
                println!(
                    "{}\t{}\t{}\t{}",
                    asset.file_name, asset.url, asset.bytes, asset.sha256
                );
            }
            ExitCode::SUCCESS
        }
        "--run" => match run(&profile, &cache_directory(&arguments)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(message) => {
                eprintln!("{message}");
                ExitCode::FAILURE
            }
        },
        other => {
            eprintln!(
                "usage: kr-describe-bench [--manifest|--run] [--profile <id>] [--cache <dir>]"
            );
            eprintln!("unknown mode {other}");
            ExitCode::FAILURE
        }
    }
}

/// Reads `--profile`, defaulting to the catalogue's default.
fn selected_profile(arguments: &[String]) -> Result<ModelProfile, String> {
    let catalogue = Catalogue::builtin().map_err(|error| error.to_string())?;
    let Some(wanted) = flag(arguments, "--profile") else {
        return Ok(catalogue.default_profile().clone());
    };
    catalogue
        .profile(&wanted)
        .cloned()
        .ok_or_else(|| format!("this build ships no profile called {wanted}"))
}

/// Reads `--cache`, defaulting to the platform's own cache directory on local storage.
fn cache_directory(arguments: &[String]) -> PathBuf {
    if let Some(given) = flag(arguments, "--cache") {
        return PathBuf::from(given);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_owned());
    if cfg!(target_os = "macos") {
        PathBuf::from(home)
            .join("Library/Caches")
            .join("kalareach-describe")
    } else {
        PathBuf::from(home)
            .join(".cache")
            .join("kalareach-describe")
    }
}

fn flag(arguments: &[String], name: &str) -> Option<String> {
    arguments
        .iter()
        .position(|argument| argument == name)
        .and_then(|index| arguments.get(index + 1))
        .cloned()
}

/// What machine this run happened on, which every figure below is about.
fn hardware() -> String {
    let mut system = sysinfo::System::new_all();
    system.refresh_all();
    format!(
        "{} {} | {} physical cores | {:.1} GiB RAM",
        std::env::consts::OS,
        std::env::consts::ARCH,
        system
            .physical_core_count()
            .map_or_else(|| "unknown".to_owned(), |cores| cores.to_string()),
        system.total_memory() as f64 / (1024.0 * 1024.0 * 1024.0),
    )
}

/// Samples this process's peak processor use over a window, in hundredths of one core.
///
/// `None` is a window that produced no reading, which is not the same as a process that used
/// nothing: `sysinfo` computes processor use from the interval between two refreshes of one view,
/// so the first refresh of a fresh one carries a nought that nobody measured. A refresh taken any
/// sooner than `MINIMUM_CPU_UPDATE_INTERVAL` is arithmetic over a gap the operating system never
/// reported, so the window is spent rather than slept through.
fn peak_process_cpu_centis(window: std::time::Duration) -> Option<u64> {
    let pid = sysinfo::Pid::from_u32(std::process::id());
    let mut system = sysinfo::System::new();
    let until = Instant::now() + window;
    let mut peak = None;
    let mut refreshes = 0_u32;
    loop {
        system.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
        if let Some(process) = system.process(pid) {
            refreshes += 1;
            if refreshes >= 2 {
                let centis = process.cpu_usage().round() as u64;
                peak = Some(peak.map_or(centis, |held: u64| held.max(centis)));
            }
        }
        if Instant::now() >= until {
            return peak;
        }
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    }
}

/// A figure, or the fact that nothing measured it.
fn measured(figure: Option<u64>) -> String {
    figure.map_or_else(|| "not measured".to_owned(), |value| value.to_string())
}

/// Reads this process's own resident set.
fn process_rss_bytes() -> u64 {
    let pid = sysinfo::Pid::from_u32(std::process::id());
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
    system.process(pid).map_or(0, sysinfo::Process::memory)
}

#[allow(clippy::too_many_lines)]
fn run(profile: &ModelProfile, cache: &Path) -> Result<(), String> {
    let machine = hardware();
    println!("# KR-PERF-009: local session descriptions");
    println!("hardware: {machine}");
    println!(
        "profile: {} revision {}",
        profile.profile_id(),
        profile.revision().get()
    );
    println!(
        "runtime: {} {} over llama.cpp {}",
        profile.runtime().binding,
        profile.runtime().binding_version,
        profile.runtime().llama_cpp_revision
    );
    println!("gpu_layers: {}", profile.execution().gpu_layers);

    // Every asset, verified before anything is loaded. A mismatch stops the run.
    let mut weights = PathBuf::new();
    for asset in profile.assets() {
        let path = cache.join(&asset.file_name);
        let started = Instant::now();
        verify(asset, &path)?;
        println!(
            "asset {}: {} bytes, digest verified in {:.1} s [{machine}]",
            asset.file_name,
            asset.bytes,
            started.elapsed().as_secs_f64()
        );
        if asset.role == "weights" {
            weights = path;
        }
    }
    if weights.as_os_str().is_empty() {
        return Err("the profile names no weights asset".to_owned());
    }

    // What this process costs before the model is in it. Both baselines are what the separated
    // figures are separated by: whatever the process held and burned without a model is not the
    // model's, and the report says so rather than attributing the harness to the runtime.
    let baseline_rss = process_rss_bytes();
    let baseline_cpu = peak_process_cpu_centis(3 * sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    let peak_load_rss = Arc::new(AtomicU64::new(baseline_rss));
    let peak_load_cpu = Arc::new(AtomicU64::new(0));
    let load_cpu_samples = Arc::new(AtomicU64::new(0));
    let load_sampling = Arc::new(AtomicBool::new(true));

    let peak_rss_clone = peak_load_rss.clone();
    let peak_cpu_clone = peak_load_cpu.clone();
    let load_cpu_samples_clone = load_cpu_samples.clone();
    let load_sampling_clone = load_sampling.clone();
    let load_sampler_thread = std::thread::spawn(move || {
        let pid = sysinfo::Pid::from_u32(std::process::id());
        let mut system = sysinfo::System::new();
        let mut refreshes = 0_u64;
        while load_sampling_clone.load(Ordering::Relaxed) {
            system.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
            if let Some(p) = system.process(pid) {
                refreshes += 1;
                let current_rss = p.memory();
                peak_rss_clone.fetch_max(current_rss, Ordering::Relaxed);
                // The first refresh of a fresh view carries a processor nought nobody measured, so
                // it is counted as a refresh and not as a reading.
                if refreshes >= 2 {
                    let current_cpu = p.cpu_usage().round() as u64;
                    peak_cpu_clone.fetch_max(current_cpu, Ordering::Relaxed);
                    load_cpu_samples_clone.fetch_add(1, Ordering::Relaxed);
                }
            }
            // The cadence is the shortest one `sysinfo` computes processor use over. A faster loop
            // reports memory sooner and processor use that means nothing.
            std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        }
    });

    let cold = Instant::now();
    let budgets = Budgets::DEFAULTS;
    let initial_cancellation = Cancellation::new();
    let load_outcome = kr_describe::llama::LlamaRuntime::load(
        profile,
        &weights,
        &initial_cancellation,
        budgets.execution_deadline_ms,
    )
    .map_err(|error| error.to_string())?;
    let runtime = match load_outcome {
        LoadOutcome::Loaded(runtime) => runtime,
        other => return Err(format!("model load did not succeed: {other:?}")),
    };
    let load_ms = cold.elapsed().as_millis() as u64;

    load_sampling.store(false, Ordering::Release);
    let _ = load_sampler_thread.join();
    let loaded_rss = process_rss_bytes();
    let peak_rss_during_load = peak_load_rss.load(Ordering::Acquire).max(loaded_rss);
    let model_cpu = (load_cpu_samples.load(Ordering::Acquire) > 0)
        .then(|| peak_load_cpu.load(Ordering::Acquire));
    println!("cold_start_load_ms: {load_ms} [{machine}]");
    let applied = runtime
        .priority()
        .ok_or_else(|| "the runtime did not say what class it applied".to_owned())?;
    println!(
        "background priority: {} (cpu {}, io {}){} [{machine}]",
        applied.mechanism.as_str(),
        applied.cpu,
        applied.io,
        applied
            .why
            .map(|why| format!(" - {why}"))
            .unwrap_or_default()
    );

    let declared: ResidentCost = profile.execution().resident_estimate;
    println!(
        "declared_resident_bytes: {} (weights {}, beyond the weights {}) [{machine}]",
        declared.total(),
        declared.weights_bytes,
        declared.beyond_the_weights()
    );
    // Every figure below is of this one process, and it is named that way. The model and runtime
    // share is the growth over the baseline taken before the load, which is an estimate rather than
    // a measurement of the runtime on its own: the harness, its samplers and later the terminal
    // workload are in the same process and no per-thread accounting separates them. Calling the
    // difference a measurement is how a benchmark comes to publish its own cost as the product's.
    println!(
        "baseline_before_load: rss {baseline_rss} bytes, cpu {} centis, benchmark process [{machine}]",
        measured(baseline_cpu)
    );
    println!(
        "measured_load_rss_bytes: benchmark process {peak_rss_during_load}, over the baseline {} (estimate of the model and its runtime) [{machine}]",
        peak_rss_during_load.saturating_sub(baseline_rss)
    );
    println!(
        "measured_load_cpu_centis: benchmark process {}, over the baseline {} (estimate of the model and its runtime) [{machine}]",
        measured(model_cpu),
        measured(model_cpu.map(|peak| peak.saturating_sub(baseline_cpu.unwrap_or(0))))
    );
    println!(
        "whole_product_rss_cpu: not measured by this run, which is one process; the controller, \
         the workers and the shared services are not running beside it [{machine}]"
    );
    // A breached budget is a failed qualification target and the run says so at the end, having
    // measured everything it can still measure. Stopping here would answer the memory question by
    // withholding the latency ones, and section 27 asks for both.
    let mut unmet: Vec<String> = Vec::new();
    let ceiling_held = peak_rss_during_load <= budgets.process_memory_ceiling_bytes;
    println!(
        "process_ceiling_bytes: {} held: {} [{machine}]",
        budgets.process_memory_ceiling_bytes, ceiling_held
    );
    if !ceiling_held {
        unmet.push(format!(
            "the {} byte process ceiling was breached during model load: {peak_rss_during_load} bytes",
            budgets.process_memory_ceiling_bytes
        ));
    }

    // One service, one runtime, the real weights. The runtime is moved into the factory, so the
    // first mapping takes it and a second would be a fault rather than a second set of weights.
    let held = std::cell::RefCell::new(Some(runtime));
    let factory: RuntimeFactory = Box::new(
        move |_profile: &ModelProfile, _cancellation: &Cancellation, _deadline_ms: u64| {
            held.borrow_mut()
                .take()
                .map(LoadOutcome::Loaded)
                .ok_or_else(|| kr_describe::DescribeError::Runtime {
                    detail: "this benchmark maps one model once".to_owned(),
                })
        },
    );
    let mut service = DescriptionService::new(
        HostPlacement {
            environment: ExecutionEnvironment::new(
                EnvironmentId::new(Uuid::from_bytes([9; 16])),
                EnvironmentKind::Native,
            ),
            data_access: None,
            target: current_target().to_owned(),
        },
        Catalogue::builtin().map_err(|error| error.to_string())?,
        MetGates::default(),
        ResourceSettings {
            // The benchmark runs on mains or on a machine whose power this build cannot read, and
            // the point of the run is the model, so inference on battery is enabled for it. Every
            // other budget is the product's own.
            on_battery: true,
            ..ResourceSettings::default()
        },
        DescriptionStore::open(&cache.join("bench-store")).map_err(|error| error.to_string())?,
        factory,
    );

    // The service selects for itself, from the catalogue and the gates this host has met. A
    // benchmark that loaded one profile and handed it to a service that selected another would be
    // attributing every figure below to the wrong model, so it refuses instead.
    let selected = service
        .selection()
        .profile()
        .map(|selected| selected.profile_id().to_owned());
    if selected.as_deref() != Some(profile.profile_id()) {
        return Err(format!(
            "this host selects {} and {} was asked for; a profile is measured only where it is the \
             one the host would run",
            selected.as_deref().unwrap_or("no profile"),
            profile.profile_id()
        ));
    }

    let conditions = platform::read_conditions();
    let mut ledger = LatencyLedger::new();
    let mut published = BTreeMap::new();

    let stop_workload = Arc::new(AtomicBool::new(false));
    let stop_clone = stop_workload.clone();
    let workload_thread = std::thread::Builder::new()
        .name("bench-terminal-workload".to_owned())
        .spawn(move || {
            let mut parser = VTParser::new();
            let mut actor = BenchTerminalActor;
            while !stop_clone.load(Ordering::Relaxed) {
                for _ in 0..50 {
                    parser.parse(ANSI_TERMINAL_STREAM, &mut actor);
                }
                std::thread::yield_now();
            }
        })
        .map_err(|error| error.to_string())?;

    // The terminal workload is this run's contention, and it runs in this process. What it costs on
    // its own, before a single job is admitted, is what the active figures below take out of the
    // model and runtime share: a report that called the workload's processor use the model's would
    // be measuring the harness and publishing it as the product.
    let workload_cpu_centis = peak_process_cpu_centis(4 * sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    println!(
        "terminal_workload_cpu_centis: {} (measured with the workload running and no job admitted) [{machine}]",
        measured(workload_cpu_centis)
    );

    // Both accumulators start empty, so the active figures are of the passes and of nothing else.
    // Seeding them with the load's peaks would have republished the load as a measurement of
    // inference under contention, which is the one thing this pass exists to measure. Empty also
    // has to stay distinguishable from nought: a pass that refuses every job can be over before the
    // sampler has two refreshes to compute processor use from, and a nought printed then would be a
    // measurement nobody took.
    let bench_sampling = Arc::new(AtomicBool::new(true));
    let bench_sampling_clone = bench_sampling.clone();
    let peak_bench_rss = Arc::new(AtomicU64::new(0));
    let peak_bench_rss_clone = peak_bench_rss.clone();
    let peak_bench_cpu = Arc::new(AtomicU64::new(0));
    let peak_bench_cpu_clone = peak_bench_cpu.clone();
    let bench_cpu_samples = Arc::new(AtomicU64::new(0));
    let bench_cpu_samples_clone = bench_cpu_samples.clone();
    let bench_sampler_thread = std::thread::spawn(move || {
        let pid = sysinfo::Pid::from_u32(std::process::id());
        let mut system = sysinfo::System::new();
        let mut refreshes = 0_u64;
        while bench_sampling_clone.load(Ordering::Relaxed) {
            system.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
            if let Some(p) = system.process(pid) {
                refreshes += 1;
                let current_rss = p.memory();
                peak_bench_rss_clone.fetch_max(current_rss, Ordering::Relaxed);
                if refreshes >= 2 {
                    let current_cpu = p.cpu_usage().round() as u64;
                    peak_bench_cpu_clone.fetch_max(current_cpu, Ordering::Relaxed);
                    bench_cpu_samples_clone.fetch_add(1, Ordering::Relaxed);
                }
            }
            std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        }
    });

    let bench_start = Instant::now();
    let reading_now = || {
        let elapsed = bench_start.elapsed().as_millis() as u64;
        Reading::new(elapsed, elapsed)
    };

    for sessions in PUBLISHED_SESSION_COUNTS {
        if sessions > MAX_SESSIONS {
            continue;
        }
        let mut described = 0_u32;
        let mut deadline_exceeded = 0_u32;
        let mut rejected = 0_u32;
        let mut session_ids = Vec::with_capacity(sessions as usize);
        for seed in 0..sessions {
            let session_id = SessionId::new(Uuid::from_bytes([
                sessions as u8,
                seed as u8,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ]));
            session_ids.push(session_id);
            service.session_opened(session_id, SessionEpoch::V1, ContextBinding::new("bench"));
            let now = reading_now();
            service.observe(
                &session_id,
                ContextSignal::WorkingDirectory {
                    directory: "kalareach".to_owned(),
                    repository: Some(RepositoryFacts {
                        name: "kalareach".to_owned(),
                        branch: Some("main".to_owned()),
                    }),
                },
                now,
            );
            service.observe(
                &session_id,
                ContextSignal::TaskIntent(format!("check the pairing flow for host {seed}")),
                now,
            );
            service.settle(&session_id, Priority::Ordinary, now.after_ms(2_000));
        }
        for _ in 0..sessions {
            let started = Instant::now();
            let now = reading_now();
            let tick = service
                .tick(&conditions, now)
                .map_err(|error| error.to_string())?;
            let elapsed_ms = started.elapsed().as_millis() as u64;
            match tick {
                Tick::Published { queue_wait_ms, .. } => {
                    described += 1;
                    ledger.record(sessions, queue_wait_ms, elapsed_ms);
                }
                Tick::DeadlineExceeded { .. } => deadline_exceeded += 1,
                Tick::Rejected { rejection, .. } => {
                    rejected += 1;
                    eprintln!("rejected at {sessions} sessions: {}", rejection.as_str());
                }
                Tick::ResourcePaused { reason, .. } => {
                    println!(
                        "resource_paused at {sessions} sessions: {} [{machine}]",
                        reason.as_str()
                    );
                }
                other => eprintln!("unexpected tick at {sessions} sessions: {other:?}"),
            }
        }
        for session_id in &session_ids {
            service.session_closed(session_id, reading_now());
        }
        published.insert(sessions, (described, deadline_exceeded, rejected));
    }

    bench_sampling.store(false, Ordering::Release);
    let _ = bench_sampler_thread.join();
    stop_workload.store(true, Ordering::Release);
    let _ = workload_thread.join();

    // The resident set is read once more here, so the passes always leave one reading behind even
    // when they were over before the sampler's second refresh. Processor use has no such reading:
    // it exists only between two refreshes, and a pass too short for them is reported as unmeasured
    // rather than as nought.
    let active_rss = peak_bench_rss
        .load(Ordering::Acquire)
        .max(process_rss_bytes());
    let active_cpu = (bench_cpu_samples.load(Ordering::Acquire) > 0)
        .then(|| peak_bench_cpu.load(Ordering::Acquire));
    println!(
        "measured_active_inference_rss_bytes: benchmark process {active_rss}, over the baseline {} (estimate of the model, its runtime and the work of the passes) [{machine}]",
        active_rss.saturating_sub(baseline_rss)
    );
    println!(
        "measured_active_inference_cpu_centis: benchmark process {}, over the terminal workload {} (estimate; the workload's own figure above was measured with no job admitted, and a peak taken under contention is not the workload's share of this one) [{machine}]",
        measured(active_cpu),
        measured(active_cpu.map(|peak| {
            peak.saturating_sub(
                workload_cpu_centis
                    .unwrap_or(0)
                    .max(baseline_cpu.unwrap_or(0)),
            )
        }))
    );
    let active_ceiling_held = active_rss <= budgets.process_memory_ceiling_bytes;
    println!(
        "active_inference_process_ceiling_bytes: {} held: {} [{machine}]",
        budgets.process_memory_ceiling_bytes, active_ceiling_held
    );
    if !active_ceiling_held {
        unmet.push(format!(
            "the {} byte process ceiling was breached during active inference: {active_rss} bytes",
            budgets.process_memory_ceiling_bytes
        ));
    }

    for reading in ledger.published() {
        report(
            "queue_wait",
            reading.sessions,
            &reading.queue_wait,
            &machine,
        );
        report("execution", reading.sessions, &reading.execution, &machine);
        let (described, deadline_exceeded, rejected) = published
            .get(&reading.sessions)
            .copied()
            .unwrap_or((0, 0, 0));
        println!(
            "sessions {}: described {described}, past the deadline {deadline_exceeded}, refused {rejected} [{machine}]",
            reading.sessions
        );
    }
    for unmeasured in ledger.unmeasured() {
        println!("sessions {unmeasured}: not measured on this run [{machine}]");
    }

    // The honest resource-paused case, on the same host that has just been publishing: an owner
    // reserve larger than this machine's free memory pauses inference, and the deterministic titles
    // are unaffected.
    println!("--- resource pause, on the same host, with inference otherwise admitted ---");
    let mut strict = DescriptionService::new(
        HostPlacement {
            environment: ExecutionEnvironment::new(
                EnvironmentId::new(Uuid::from_bytes([10; 16])),
                EnvironmentKind::Native,
            ),
            data_access: None,
            target: current_target().to_owned(),
        },
        Catalogue::builtin().map_err(|error| error.to_string())?,
        MetGates::default(),
        ResourceSettings {
            on_battery: true,
            owner_reserve_bytes: Some(u64::MAX / 2),
            ..ResourceSettings::default()
        },
        DescriptionStore::in_memory().map_err(|error| error.to_string())?,
        Box::new(
            |_profile: &ModelProfile, _cancellation: &Cancellation, _deadline_ms: u64| {
                Err(kr_describe::DescribeError::Runtime {
                    detail: "the paused case never maps a model".to_owned(),
                })
            },
        ),
    );
    let session_id = SessionId::new(Uuid::from_bytes([11; 16]));
    let now = reading_now();
    strict.session_opened(session_id, SessionEpoch::V1, ContextBinding::new("bench"));
    strict.observe(
        &session_id,
        ContextSignal::WorkingDirectory {
            directory: "kalareach".to_owned(),
            repository: None,
        },
        now,
    );
    strict.settle(&session_id, Priority::Ordinary, now.after_ms(2_000));
    let paused = strict
        .tick(&conditions, now.after_ms(3_000))
        .map_err(|error| error.to_string())?;
    println!("paused_tick: {paused:?} [{machine}]");
    let label = strict
        .label(
            &session_id,
            &kr_describe::metadata::SessionFacts {
                directory: Some("kalareach".to_owned()),
                ..kr_describe::metadata::SessionFacts::default()
            },
            kr_describe::metadata::VerifiedStatus::Running,
        )
        .map_err(|error| error.to_string())?;
    println!(
        "paused_label: \"{}\" from {} [{machine}]",
        label.title,
        label.source.as_str()
    );
    if !matches!(paused, Tick::ResourcePaused { .. }) {
        unmet.push(format!("the resource-pause case did not pause: {paused:?}"));
    }

    let total: u32 = published.values().map(|(described, _, _)| described).sum();
    if total == 0 {
        unmet.push("no description was produced, so nothing here is a measurement".to_owned());
    } else {
        println!("--- {total} descriptions produced against real weights on {machine} ---");
    }

    if unmet.is_empty() {
        return Ok(());
    }
    for target in &unmet {
        println!("qualification_target_not_met: {target} [{machine}]");
    }
    Err(format!(
        "{} qualification target(s) were not met on {machine}; the figures above are the run",
        unmet.len()
    ))
}

fn verify(asset: &Asset, path: &Path) -> Result<(), String> {
    asset.verify_file(path).map_err(|error| {
        format!(
            "{}: {error}\nthe benchmark refuses to run against weights this profile does not name",
            path.display()
        )
    })
}

fn report(kind: &str, sessions: u32, distribution: &Distribution, machine: &str) {
    println!(
        "{kind}_ms at {sessions} sessions: p50 {} p95 {} p99 {} max {} over {} samples [{machine}]",
        distribution.p50_ms,
        distribution.p95_ms,
        distribution.p99_ms,
        distribution.max_ms,
        distribution.samples
    );
}

/// The target triple this build runs on, which a profile has to list.
const fn current_target() -> &'static str {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "aarch64-apple-darwin"
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "x86_64-apple-darwin"
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        "aarch64-unknown-linux-gnu"
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "x86_64-unknown-linux-gnu"
    } else {
        "x86_64-pc-windows-msvc"
    }
}
