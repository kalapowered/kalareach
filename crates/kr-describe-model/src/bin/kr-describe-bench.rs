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
//!
//! `--run` drives the product's own description process (`--inference` names its program) the way
//! the control daemon does, through the same driver, and keeps the terminal workload it measures
//! that process beside in this process. The process puts itself in the background class; this one
//! never does. On macOS and Windows the class is a whole process's, so a workload in the model's
//! process would run in the class with the model, and the figures would be of a terminal at
//! background priority.

#[path = "kr-describe-bench/outputs.rs"]
mod outputs;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use kr_describe::budget::{Budgets, ResidentCost};
use kr_describe::context::{ContextBinding, ContextSignal};
use kr_describe::environment::{EnvironmentKind, ExecutionEnvironment, build_target};
use kr_describe::metadata::RepositoryFacts;
use kr_describe::metrics::{Distribution, LatencyLedger, PUBLISHED_SESSION_COUNTS};
use kr_describe::priority::{Cancellation, enter_background};
use kr_describe::profile::catalogue::{Catalogue, MetGates};
use kr_describe::profile::{Asset, ModelProfile};
use kr_describe::queue::Priority;
use kr_describe::resource::{
    HostConditions, PauseReason, ResourceSettings, ResourceState, platform,
};
use kr_describe::service::{
    DescriptionService, HostPlacement, LOAD_DEADLINE_MS, Outcome, ProcessEnd, UnloadReason,
};
use kr_describe::store::DescriptionStore;
use kr_describe::supervise::{Driver, Launch, Report};
use kr_describe::time::Reading;
use kr_describe_model::llama::{Llama, LlamaRuntime};
use kr_protocol::ids::{EnvironmentId, SessionEpoch, SessionId};
use kr_protocol::scalars::Uuid;
use vtparse::{CsiParam, VTActor, VTParser};

/// The largest number of sessions the benchmark drives.
const MAX_SESSIONS: u32 = 50;

/// The longest the benchmark waits for the driver between its turns. The driver wakes sooner when
/// the process says something.
const TURN_WAIT: Duration = Duration::from_millis(100);

/// The longest the benchmark waits for queued work that the service holds back to a time it sets,
/// as it does for the wait after a job that missed its deadline, which doubles up to five minutes.
const QUEUED_WAIT_BOUND: Duration = Duration::from_secs(6 * 60);

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
        "--run" => {
            let Some(program) = flag(&arguments, "--inference") else {
                eprintln!(
                    "--run takes --inference <path>: the kr-describe-inference program it \
                     drives, the process the product runs the model in"
                );
                return ExitCode::FAILURE;
            };
            match run(
                &profile,
                &cache_directory(&arguments),
                &PathBuf::from(program),
            ) {
                Ok(()) => ExitCode::SUCCESS,
                Err(message) => {
                    eprintln!("{message}");
                    ExitCode::FAILURE
                }
            }
        }
        "--outputs" => {
            let rounds = match flag(&arguments, "--rounds") {
                None if arguments.iter().any(|argument| argument == "--rounds") => {
                    eprintln!("--rounds takes a whole number of at least one");
                    return ExitCode::FAILURE;
                }
                None => 1,
                Some(given) => match given.parse::<u32>() {
                    Ok(rounds) if rounds > 0 => rounds,
                    _ => {
                        eprintln!("--rounds takes a whole number of at least one, not {given}");
                        return ExitCode::FAILURE;
                    }
                },
            };
            match run_outputs(&profile, &cache_directory(&arguments), rounds) {
                Ok(true) => ExitCode::SUCCESS,
                Ok(false) => ExitCode::FAILURE,
                Err(message) => {
                    eprintln!("{message}");
                    ExitCode::FAILURE
                }
            }
        }
        other => {
            eprintln!(
                "usage: kr-describe-bench [--manifest|--run --inference <path>|--outputs [--rounds <n>]] [--profile <id>] [--cache <dir>]"
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

/// Reads a process's resident set, when the operating system answers for it.
///
/// `None` is a lookup that found no process to read, which is not a process holding nothing.
fn process_rss_bytes(pid: u32) -> Option<u64> {
    let pid = sysinfo::Pid::from_u32(pid);
    let mut system = sysinfo::System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::Some(&[pid]), true);
    system.process(pid).map(sysinfo::Process::memory)
}

/// The peaks of a process's resident set and processor use between two takes, read from outside the
/// process.
///
/// It reads the process on the benchmark's own turns and no oftener than `sysinfo` computes
/// processor use over: a faster loop reports memory sooner and processor use that means nothing. The
/// first refresh of a view of a process carries a processor nought nobody measured, so it counts as
/// a refresh and not as a reading, and a process that is started again is another view.
struct Sampler {
    system: sysinfo::System,
    pid: Option<u32>,
    refreshed: Option<Instant>,
    refreshes: u32,
    resident: Option<u64>,
    processor: Option<u64>,
}

impl Sampler {
    fn new() -> Self {
        Self {
            system: sysinfo::System::new(),
            pid: None,
            refreshed: None,
            refreshes: 0,
            resident: None,
            processor: None,
        }
    }

    /// Reads the process `pid` if the shortest interval processor use is computed over has passed
    /// since the last read of it.
    fn sample(&mut self, pid: Option<u32>) {
        let Some(pid) = pid else {
            return;
        };
        if self.pid != Some(pid) {
            self.pid = Some(pid);
            self.refreshed = None;
            self.refreshes = 0;
        }
        if self
            .refreshed
            .is_some_and(|at| at.elapsed() < sysinfo::MINIMUM_CPU_UPDATE_INTERVAL)
        {
            return;
        }
        let process_id = sysinfo::Pid::from_u32(pid);
        self.system
            .refresh_processes(sysinfo::ProcessesToUpdate::Some(&[process_id]), true);
        self.refreshed = Some(Instant::now());
        let Some(process) = self.system.process(process_id) else {
            return;
        };
        self.refreshes += 1;
        let resident = process.memory();
        self.resident = Some(self.resident.map_or(resident, |held| held.max(resident)));
        if self.refreshes >= 2 {
            let centis = process.cpu_usage().round() as u64;
            self.processor = Some(self.processor.map_or(centis, |held| held.max(centis)));
        }
    }

    /// Returns the peaks since the last take, resident set first, and starts a new window. The
    /// first read of the new window is a refresh and not a reading, so that the processor use of
    /// the new window never covers time from the one before.
    fn take(&mut self) -> (Option<u64>, Option<u64>) {
        self.refreshes = 0;
        (self.resident.take(), self.processor.take())
    }
}

/// The largest of the readings that exist, or `None` when none of them does.
fn largest(readings: [Option<u64>; 2]) -> Option<u64> {
    readings.into_iter().flatten().max()
}

/// Reports one phase's process ceiling, and records a breach or an absent measurement as unmet.
///
/// A ceiling nothing was measured against is not a ceiling that held. Printing `held: true` over an
/// absent reading is how a budget comes to be passed by not being checked.
fn report_ceiling(
    line: &str,
    resident: Option<u64>,
    ceiling: u64,
    phase: &str,
    machine: &str,
    unmet: &mut Vec<String>,
) {
    let held = resident.map(|bytes| bytes <= ceiling);
    println!(
        "{line}: {ceiling} held: {} [{machine}]",
        held.map_or_else(|| "not measured".to_owned(), |held| held.to_string())
    );
    match (held, resident) {
        (Some(true), _) => {}
        (Some(false), Some(bytes)) => unmet.push(format!(
            "the {ceiling} byte process ceiling was breached during {phase}: {bytes} bytes"
        )),
        _ => unmet.push(format!(
            "the {ceiling} byte process ceiling was not measured during {phase}"
        )),
    }
}

/// Describes the fixed sessions of [`outputs::fixtures`] with the real weights and counts what
/// comes back: each answer through llama.cpp's grammar and this product's validation, and each job
/// against the product's deadline. Returns whether every one held.
fn run_outputs(profile: &ModelProfile, cache: &Path, rounds: u32) -> Result<bool, String> {
    let machine = hardware();
    println!("# KR-REQ-22.18: grammar-constrained descriptions from the real model");
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
    let mut weights = PathBuf::new();
    for asset in profile.assets() {
        let path = cache.join(&asset.file_name);
        verify(asset, &path)?;
        println!(
            "asset {}: {} bytes, digest verified",
            asset.file_name, asset.bytes
        );
        if asset.role == "weights" {
            weights = path;
        }
    }
    if weights.as_os_str().is_empty() {
        return Err("the profile names no weights asset".to_owned());
    }
    let applied = enter_background();
    println!(
        "background priority: {} (cpu {}, io {}) [{machine}]",
        applied.mechanism.as_str(),
        applied.cpu,
        applied.io
    );
    let cold = Instant::now();
    let runtime = LlamaRuntime::load(
        profile,
        &weights,
        &Cancellation::new(),
        Instant::now() + Duration::from_millis(LOAD_DEADLINE_MS),
    )
    .map_err(|(why, detail)| {
        format!(
            "model load did not succeed: {}{}",
            why.as_str(),
            detail
                .map(|detail| format!(": {detail}"))
                .unwrap_or_default()
        )
    })?;
    println!(
        "cold_start_load_ms: {} [{machine}]",
        cold.elapsed().as_millis()
    );
    let limits = Budgets::DEFAULTS.bounds(profile.execution());
    let fixtures = outputs::fixtures();
    println!(
        "limits: {} threads, {} tokens in, {} out, {} ms per job, {} sessions fixed [{machine}]",
        limits.cpu_threads,
        limits.context_tokens,
        limits.max_output_tokens,
        limits.deadline_ms,
        fixtures.len()
    );
    let mut model = Llama::loaded(runtime);
    let records = outputs::run(&mut model, profile, limits, &fixtures, rounds, |record| {
        println!("{}", outputs::job_line(record));
    });
    for line in outputs::report(&records, limits.deadline_ms, limits.prompt_tokens, &machine) {
        println!("{line}");
    }
    Ok(outputs::count(&records, limits.deadline_ms).all_held())
}

/// Links the profile's assets where the description process looks for them, as the daemon places
/// them: `<models>/<profile>/<revision>/<file>`. The files stay where the benchmark verified them.
fn place_assets(profile: &ModelProfile, cache: &Path, models: &Path) -> Result<(), String> {
    let directory = models
        .join(profile.profile_id())
        .join(profile.revision().get().to_string());
    std::fs::create_dir_all(&directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?;
    for asset in profile.assets() {
        let placed = directory.join(&asset.file_name);
        match std::fs::remove_file(&placed) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("{}: {error}", placed.display())),
        }
        let verified = std::fs::canonicalize(cache.join(&asset.file_name))
            .map_err(|error| format!("{}: {error}", asset.file_name))?;
        link(&verified, &placed).map_err(|error| format!("{}: {error}", placed.display()))?;
    }
    Ok(())
}

#[cfg(unix)]
fn link(original: &Path, placed: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(original, placed)
}

#[cfg(not(unix))]
fn link(original: &Path, placed: &Path) -> std::io::Result<()> {
    std::fs::hard_link(original, placed)
}

/// Opens a session whose directory and task are known and settles it into a queued job.
fn queue_session(
    service: &mut DescriptionService,
    session_id: SessionId,
    intent: String,
    now: Reading,
) {
    service.session_opened(session_id, SessionEpoch::V1, ContextBinding::new("bench"));
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
    service.observe(&session_id, ContextSignal::TaskIntent(intent), now);
    service.settle(&session_id, Priority::Ordinary, now.after_ms(2_000));
}

/// What the benchmark reads of the description process while it drives it: the class the process
/// reports, and the process's own resident set and processor use from outside it.
struct Watch<'a> {
    machine: &'a str,
    sampler: Sampler,
    /// The resident ceiling the process is held to.
    ceiling_bytes: u64,
    /// Whether the class the process reported has been printed.
    class_printed: bool,
    /// Whether a load has been seen to end with a model.
    loaded: bool,
    /// Whether the passes have begun, from which a process's peaks are the passes'.
    passes_begun: bool,
    /// The peaks of the processes that went before the one running, in the passes, resident set
    /// first.
    earlier: (Option<u64>, Option<u64>),
    /// The targets this run missed.
    unmet: Vec<String>,
}

impl Watch<'_> {
    /// Prints the class the process says it runs the model in, once it has said it.
    fn note_class(&mut self, driver: &Driver) {
        if self.class_printed {
            return;
        }
        let Some(applied) = driver.background() else {
            return;
        };
        self.class_printed = true;
        println!(
            "background priority: {} (cpu {}, io {}){}, as the description process reports it [{}]",
            applied.mechanism,
            applied.cpu,
            applied.io,
            applied
                .why
                .0
                .as_ref()
                .map(|why| format!(" - {why}"))
                .unwrap_or_default(),
            self.machine
        );
    }

    /// Notes a process that was started. In the passes, what was read so far is of the process
    /// before it, and is kept apart from the new one's.
    fn note_started(&mut self, pid: u32) {
        println!("description_process: pid {pid} [{}]", self.machine);
        if self.passes_begun {
            let (resident, processor) = self.sampler.take();
            self.earlier = (
                largest([self.earlier.0, resident]),
                largest([self.earlier.1, processor]),
            );
        }
    }

    /// Begins the passes: nothing read before them is theirs.
    fn begin_passes(&mut self) {
        self.sampler.take();
        self.passes_begun = true;
    }

    /// Returns the peaks of the passes over every process they ran in, resident set first.
    fn passes_peaks(&mut self) -> (Option<u64>, Option<u64>) {
        let (resident, processor) = self.sampler.take();
        (
            largest([self.earlier.0, resident]),
            largest([self.earlier.1, processor]),
        )
    }

    /// Prints what the load came to, with the process's peaks over it.
    fn note_load(&mut self, pid: Option<u32>, cold_start_ms: u64) {
        self.loaded = true;
        let (resident, processor) = self.sampler.take();
        let resident = largest([resident, pid.and_then(process_rss_bytes)]);
        let machine = self.machine;
        println!(
            "cold_start_load_ms: {cold_start_ms} (the service's account, from its request for the \
             load to the answer: the start of the process, its handshake and its check of the \
             weights' digest are in it) [{machine}]"
        );
        println!(
            "measured_load_rss_bytes: description process {} (the model and its runtime) [{machine}]",
            measured(resident)
        );
        println!(
            "measured_load_cpu_centis: description process {} (peak over the load) [{machine}]",
            measured(processor)
        );
        report_ceiling(
            "process_ceiling_bytes",
            resident,
            self.ceiling_bytes,
            "model load",
            machine,
            &mut self.unmet,
        );
    }

    /// Prints a report that the process ended or was unloaded, and records as a missed target the
    /// ones a memory budget causes. The ceiling is read from outside at intervals, and the service
    /// ends or unloads the process on the process's own figure, so a breach is as likely to be
    /// seen here as in the samples.
    fn note_end(&mut self, ended: &Turn) {
        let machine = self.machine;
        match ended {
            Turn::Outcome(Outcome::ProcessEnded { why }) => {
                println!("description_process_ended: {} [{machine}]", why.as_str());
                if *why == ProcessEnd::MemoryCeiling {
                    self.unmet.push(format!(
                        "the description process passed the {} byte process ceiling and was ended",
                        self.ceiling_bytes
                    ));
                }
            }
            Turn::Outcome(Outcome::Dropped { id }) => {
                println!("answer_dropped: {id}, work nobody was waiting for [{machine}]");
            }
            Turn::Unloaded(why) => {
                println!("description_process_unloaded: {why:?} [{machine}]");
                if matches!(why, UnloadReason::Paused(PauseReason::MemoryPressure)) {
                    self.unmet.push(format!(
                        "the service unloaded the model for memory pressure, as it does for a \
                         process past its {} byte ceiling",
                        self.ceiling_bytes
                    ));
                }
            }
            _ => {}
        }
    }
}

/// What one turn of the benchmark's driver came to.
#[derive(Debug)]
enum Turn {
    /// An answer, and what it came to.
    Outcome(Outcome),
    /// Inference is paused, and the model was not loaded.
    Paused(PauseReason),
    /// The service had the process ended.
    Unloaded(UnloadReason),
    /// Nothing was queued, or nothing came due within the longest wait the service sets.
    Idle,
}

impl Turn {
    /// Which of the reports of one driver turn the turn is returned as: the end of a job before the
    /// end of a process, an answer nobody waited for, or an unload.
    const fn rank(&self) -> u8 {
        match self {
            Self::Outcome(Outcome::ProcessEnded { .. } | Outcome::Dropped { .. }) => 1,
            Self::Unloaded(_) => 2,
            _ => 0,
        }
    }
}

/// Drives the service through the daemon's driver until it has an answer's outcome, a pause or
/// nothing queued, with each job running in the description process. Work that waits for a time
/// the service sets, as it does after a job that missed its deadline, is waited for, as the daemon
/// waits for it.
fn turn(
    driver: &mut Driver,
    watch: &mut Watch,
    conditions: &HostConditions,
    reading_now: &dyn Fn() -> Reading,
) -> Result<Turn, String> {
    let mut idle_since: Option<Instant> = None;
    loop {
        let reports = driver
            .turn(conditions, reading_now())
            .map_err(|error| error.to_string())?;
        watch.sampler.sample(driver.pid());
        watch.note_class(driver);
        let mut ended: Vec<Turn> = Vec::new();
        for report in reports {
            match report {
                Report::Started { pid } => watch.note_started(pid),
                Report::Outcome(Outcome::Loaded { cold_start_ms }) => {
                    watch.note_load(driver.pid(), cold_start_ms);
                }
                Report::Outcome(outcome) => ended.push(Turn::Outcome(outcome)),
                Report::Unloaded { why } => ended.push(Turn::Unloaded(why)),
                Report::Checked { .. } => {}
            }
        }
        for each in &ended {
            watch.note_end(each);
        }
        if let Some(first) = ended.into_iter().min_by_key(Turn::rank) {
            return Ok(first);
        }
        let service = driver.service();
        if service.in_flight() == 0 && !service.is_loading() {
            if let ResourceState::ResourcePaused { reason, .. } = service.resource_state() {
                return Ok(Turn::Paused(reason));
            }
            let since = *idle_since.get_or_insert_with(Instant::now);
            if service.scheduler().queued() == 0 || since.elapsed() >= QUEUED_WAIT_BOUND {
                return Ok(Turn::Idle);
            }
        } else {
            idle_since = None;
        }
        driver.wait(TURN_WAIT);
        watch.sampler.sample(driver.pid());
    }
}

#[allow(clippy::too_many_lines)]
fn run(profile: &ModelProfile, cache: &Path, program: &Path) -> Result<(), String> {
    // The description process runs in a directory of its own, so every path it is given, or finds
    // its files by, is absolute.
    let cache =
        &std::path::absolute(cache).map_err(|error| format!("{}: {error}", cache.display()))?;
    let program =
        &std::path::absolute(program).map_err(|error| format!("{}: {error}", program.display()))?;
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
    }
    if !profile.assets().iter().any(|asset| asset.role == "weights") {
        return Err("the profile names no weights asset".to_owned());
    }

    // The model runs in the description process, which the driver starts as the daemon does. Its
    // files and its runtime directory are the benchmark's own, on the same local storage as the
    // cache.
    let process_directory = cache.join("bench-process");
    let models = process_directory.join("models");
    let runtime = process_directory.join("runtime");
    place_assets(profile, cache, &models)?;
    std::fs::create_dir_all(&runtime).map_err(|error| format!("{}: {error}", runtime.display()))?;
    let launch = Launch {
        program: program.to_path_buf(),
        arguments: vec!["--runtime-dir".into(), runtime.clone().into_os_string()],
        working_directory: runtime,
        environment: Vec::new(),
        models,
        system_memory_limit: true,
    };
    let build = format!("kr-describe-bench/{}", kr_describe::wire::RELEASE);

    let budgets = Budgets::DEFAULTS;
    let declared: ResidentCost = profile.execution().resident_estimate;
    println!(
        "declared_resident_bytes: {} (weights {}, beyond the weights {}) [{machine}]",
        declared.total(),
        declared.weights_bytes,
        declared.beyond_the_weights()
    );
    // Every figure of the model's memory and processor use below is of the description process
    // alone, which holds the runtime and the model and nothing of this harness, and it is named
    // that way. They are read from outside it, at the cadence `sysinfo` computes processor use
    // over. The cold start is the service's own account of the load.
    println!(
        "whole_product_rss_cpu: not measured by this run, which drives one description process \
         beside the benchmark's own; the controller, the workers and the shared services are not \
         running beside them [{machine}]"
    );

    // One service, driven as the daemon drives it, over the real weights in the description process.
    let service = DescriptionService::new(
        HostPlacement {
            environment: ExecutionEnvironment::new(
                EnvironmentId::new(Uuid::from_bytes([9; 16])),
                EnvironmentKind::Native,
            ),
            data_access: None,
            target: build_target().to_owned(),
            processor: kr_describe::processor::Features::running(),
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
    let mut driver = Driver::new(service, launch.clone(), build.clone());

    let conditions = platform::read_conditions();
    let mut ledger = LatencyLedger::new();
    let mut outcomes = BTreeMap::new();
    let mut watch = Watch {
        machine: &machine,
        sampler: Sampler::new(),
        ceiling_bytes: budgets.process_memory_ceiling_bytes,
        class_printed: false,
        loaded: false,
        passes_begun: false,
        earlier: (None, None),
        unmet: Vec::new(),
    };

    // The terminal workload is this run's contention, and it runs in this process, which the
    // benchmark puts in no class: the description process puts itself in the background class, and
    // this one never does. Its own cost is read first, with the process not yet started, so that it
    // is never taken for the model's.
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
    let workload_cpu_centis = peak_process_cpu_centis(4 * sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    println!(
        "terminal_workload_cpu_centis: {} (the benchmark's process, measured with the workload running and the description process not started) [{machine}]",
        measured(workload_cpu_centis)
    );

    let bench_start = Instant::now();
    let reading_now = || {
        let elapsed = bench_start.elapsed().as_millis() as u64;
        Reading::new(elapsed, elapsed)
    };

    // The first job loads the model, as the first job of the product does. It is a warm-up whose
    // job is not recorded, so that the figures of the passes are of a loaded model and the cold
    // start is reported apart, as the load's figures are.
    let warm_up = SessionId::new(Uuid::from_bytes([0xFE; 16]));
    queue_session(
        driver.service_mut(),
        warm_up,
        "warm up the model".to_owned(),
        reading_now(),
    );
    let warmed = turn(&mut driver, &mut watch, &conditions, &reading_now)?;
    driver.service_mut().session_closed(&warm_up, reading_now());
    println!("warm_up_job: {warmed:?} [{machine}]");
    if !watch.loaded {
        return Err(match warmed {
            Turn::Outcome(Outcome::LoadEnded { why, detail }) => format!(
                "model load did not succeed: {}{}",
                why.as_str(),
                detail
                    .map(|detail| format!(": {detail}"))
                    .unwrap_or_default()
            ),
            Turn::Paused(reason) | Turn::Unloaded(UnloadReason::Paused(reason)) => format!(
                "this host pauses inference ({}), so the model is not loaded and nothing is \
                 measured",
                reason.as_str()
            ),
            other => format!("the description process did not load the model: {other:?}"),
        });
    }

    // Both windows start empty, so the active figures are of the passes and of nothing else.
    // Seeding them with the load's peaks would have republished the load as a measurement of
    // inference under contention, which is the one thing this pass exists to measure. Empty also
    // has to stay distinguishable from nought: a pass that refuses every job can be over before the
    // sampler has two refreshes to compute processor use from, and a nought printed then would be a
    // measurement nobody took.
    watch.begin_passes();

    for sessions in PUBLISHED_SESSION_COUNTS {
        if sessions > MAX_SESSIONS {
            continue;
        }
        let mut ended = Outcomes::default();
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
            queue_session(
                driver.service_mut(),
                session_id,
                format!("check the pairing flow for host {seed}"),
                reading_now(),
            );
        }
        for _ in 0..sessions {
            let turned = turn(&mut driver, &mut watch, &conditions, &reading_now)?;
            match turned {
                // The service's own account of the two waits: from the job's queueing to its
                // dispatch, and from its dispatch to its publication.
                Turn::Outcome(Outcome::Published {
                    queue_wait_ms,
                    execution_ms,
                    ..
                }) => {
                    ended.described += 1;
                    ledger.record(sessions, queue_wait_ms, execution_ms);
                }
                Turn::Outcome(Outcome::DeadlineExceeded { .. }) => ended.past_deadline += 1,
                Turn::Outcome(Outcome::Rejected { rejection, .. }) => {
                    ended.refused += 1;
                    eprintln!("rejected at {sessions} sessions: {}", rejection.as_str());
                }
                Turn::Paused(reason) | Turn::Unloaded(UnloadReason::Paused(reason)) => {
                    ended.paused += 1;
                    println!(
                        "resource_paused at {sessions} sessions: {} [{machine}]",
                        reason.as_str()
                    );
                }
                other => {
                    ended.other += 1;
                    eprintln!("unexpected turn at {sessions} sessions: {other:?}");
                }
            }
        }
        for session_id in &session_ids {
            driver
                .service_mut()
                .session_closed(session_id, reading_now());
        }
        outcomes.insert(sessions, ended);
    }

    stop_workload.store(true, Ordering::Release);
    let _ = workload_thread.join();

    // The resident set is read once more here, so the passes always leave one reading behind even
    // when they were over before the sampler's second refresh. Processor use has no such reading:
    // it exists only between two refreshes, and a pass too short for them is reported as unmeasured
    // rather than as nought.
    let (peak_resident, active_cpu) = watch.passes_peaks();
    let active_rss = largest([peak_resident, driver.pid().and_then(process_rss_bytes)]);
    println!(
        "measured_active_inference_rss_bytes: description process {} (the model, its runtime and the work of the passes) [{machine}]",
        measured(active_rss)
    );
    println!(
        "measured_active_inference_cpu_centis: description process {} (peak over the passes, with the terminal workload running in the benchmark's process) [{machine}]",
        measured(active_cpu)
    );
    report_ceiling(
        "active_inference_process_ceiling_bytes",
        active_rss,
        budgets.process_memory_ceiling_bytes,
        "active inference",
        &machine,
        &mut watch.unmet,
    );

    for line in session_lines(&ledger, &outcomes, &machine) {
        println!("{line}");
    }

    // The honest resource-paused case, on the same host that has just been publishing: an owner
    // reserve larger than this machine's free memory pauses inference, and the deterministic titles
    // are unaffected.
    println!("--- resource pause, on the same host, with inference otherwise admitted ---");
    let strict = DescriptionService::new(
        HostPlacement {
            environment: ExecutionEnvironment::new(
                EnvironmentId::new(Uuid::from_bytes([10; 16])),
                EnvironmentKind::Native,
            ),
            data_access: None,
            target: build_target().to_owned(),
            processor: kr_describe::processor::Features::running(),
        },
        Catalogue::builtin().map_err(|error| error.to_string())?,
        MetGates::default(),
        ResourceSettings {
            on_battery: true,
            owner_reserve_bytes: Some(u64::MAX / 2),
            ..ResourceSettings::default()
        },
        DescriptionStore::in_memory().map_err(|error| error.to_string())?,
    );
    // This driver starts no process: the service pauses before it asks for a load.
    let mut strict = Driver::new(strict, launch, build);
    let session_id = SessionId::new(Uuid::from_bytes([11; 16]));
    let now = reading_now();
    strict
        .service_mut()
        .session_opened(session_id, SessionEpoch::V1, ContextBinding::new("bench"));
    strict.service_mut().observe(
        &session_id,
        ContextSignal::WorkingDirectory {
            directory: "kalareach".to_owned(),
            repository: None,
        },
        now,
    );
    strict
        .service_mut()
        .settle(&session_id, Priority::Ordinary, now.after_ms(2_000));
    let paused = turn(&mut strict, &mut watch, &conditions, &|| {
        now.after_ms(3_000)
    })?;
    println!("paused_turn: {paused:?} [{machine}]");
    let label = strict
        .service()
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
    if !matches!(paused, Turn::Paused(_)) {
        watch
            .unmet
            .push(format!("the resource-pause case did not pause: {paused:?}"));
    }

    let total: u32 = outcomes.values().map(|ended| ended.described).sum();
    if total == 0 {
        watch
            .unmet
            .push("no description was produced, so nothing here is a measurement".to_owned());
    } else {
        println!(
            "--- {total} descriptions produced in the passes against real weights on {machine} ---"
        );
    }

    if watch.unmet.is_empty() {
        return Ok(());
    }
    for target in &watch.unmet {
        println!("qualification_target_not_met: {target} [{machine}]");
    }
    Err(format!(
        "{} qualification target(s) were not met on {machine}; the figures above are the run",
        watch.unmet.len()
    ))
}

fn verify(asset: &Asset, path: &Path) -> Result<(), String> {
    kr_describe_model::assets::verify_file(asset, path).map_err(|error| {
        format!(
            "{}: {error}\nthe benchmark refuses to run against weights this profile does not name",
            path.display()
        )
    })
}

/// How the ticks of one session count's pass ended.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Outcomes {
    /// A description was produced and published.
    described: u32,
    /// The job passed its deadline.
    past_deadline: u32,
    /// The job ran and its result was refused.
    refused: u32,
    /// The tick ended in the resource pause: before a job ran, or after one when the process had
    /// passed its memory ceiling and the model was unloaded.
    paused: u32,
    /// Anything else a tick can end in.
    other: u32,
}

impl std::fmt::Display for Outcomes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "described {}, past the deadline {}, refused {}, paused {}, other {}",
            self.described, self.past_deadline, self.refused, self.paused, self.other
        )
    }
}

/// What each of section 22's session counts did, in the order it names them: the two latencies
/// where a description was published, and in every case how its ticks ended. A count that
/// published nothing says so with those counts beside it, so a record of it says why nothing was
/// measured: every job past its deadline, refused, or held by the resource pause.
fn session_lines(
    ledger: &LatencyLedger,
    outcomes: &BTreeMap<u32, Outcomes>,
    machine: &str,
) -> Vec<String> {
    let mut lines = Vec::new();
    for sessions in PUBLISHED_SESSION_COUNTS {
        let ended = outcomes.get(&sessions).copied().unwrap_or_default();
        match ledger.reading(sessions) {
            Some(reading) => {
                lines.push(distribution_line(
                    "queue_wait",
                    sessions,
                    &reading.queue_wait,
                    machine,
                ));
                lines.push(distribution_line(
                    "execution",
                    sessions,
                    &reading.execution,
                    machine,
                ));
                lines.push(format!("sessions {sessions}: {ended} [{machine}]"));
            }
            None => lines.push(format!(
                "sessions {sessions}: not measured on this run: {ended} [{machine}]"
            )),
        }
    }
    lines
}

fn distribution_line(
    kind: &str,
    sessions: u32,
    distribution: &Distribution,
    machine: &str,
) -> String {
    format!(
        "{kind}_ms at {sessions} sessions: p50 {} p95 {} p99 {} max {} over {} samples [{machine}]",
        distribution.p50_ms,
        distribution.p95_ms,
        distribution.p99_ms,
        distribution.max_ms,
        distribution.samples
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use kr_describe::metrics::LatencyLedger;

    use super::{Outcomes, session_lines};

    #[test]
    fn a_count_that_published_nothing_says_how_its_jobs_ended() {
        let outcomes = BTreeMap::from([(
            1,
            Outcomes {
                past_deadline: 1,
                ..Outcomes::default()
            },
        )]);
        let lines = session_lines(&LatencyLedger::new(), &outcomes, "a host");
        assert!(
            lines.contains(
                &"sessions 1: not measured on this run: described 0, past the deadline 1, refused \
                  0, paused 0, other 0 [a host]"
                    .to_owned()
            ),
            "{lines:#?}"
        );
    }

    #[test]
    fn a_count_that_published_prints_its_latencies_as_before() {
        let mut ledger = LatencyLedger::new();
        ledger.record(5, 12, 340);
        let outcomes = BTreeMap::from([(
            5,
            Outcomes {
                described: 1,
                paused: 2,
                ..Outcomes::default()
            },
        )]);
        let lines = session_lines(&ledger, &outcomes, "a host");
        let at_five: Vec<&str> = lines
            .iter()
            .map(String::as_str)
            .filter(|line| line.contains(" 5 sessions") || line.starts_with("sessions 5:"))
            .collect();
        assert_eq!(
            at_five,
            [
                "queue_wait_ms at 5 sessions: p50 12 p95 12 p99 12 max 12 over 1 samples [a host]",
                "execution_ms at 5 sessions: p50 340 p95 340 p99 340 max 340 over 1 samples \
                 [a host]",
                "sessions 5: described 1, past the deadline 0, refused 0, paused 2, other 0 [a host]",
            ],
        );
    }

    #[test]
    fn every_published_count_has_a_line_in_order() {
        let lines = session_lines(&LatencyLedger::new(), &BTreeMap::new(), "a host");
        assert_eq!(
            lines,
            [1, 5, 20, 50]
                .map(|sessions| format!(
                    "sessions {sessions}: not measured on this run: described 0, past the \
                     deadline 0, refused 0, paused 0, other 0 [a host]"
                ))
                .to_vec(),
        );
    }
}
