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
use std::time::Instant;

use kr_describe::budget::{Budgets, ProcessFigures, ResidentCost};
use kr_describe::context::{ContextBinding, ContextSignal};
use kr_describe::environment::{EnvironmentKind, ExecutionEnvironment};
use kr_describe::metadata::RepositoryFacts;
use kr_describe::metrics::{Distribution, LatencyLedger, PUBLISHED_SESSION_COUNTS};
use kr_describe::profile::catalogue::{Catalogue, MetGates};
use kr_describe::profile::{Asset, ModelProfile};
use kr_describe::queue::Priority;
use kr_describe::resource::{ResourceSettings, platform};
use kr_describe::runtime::InferenceRuntime;
use kr_describe::service::{DescriptionService, HostPlacement, RuntimeFactory, Tick};
use kr_describe::store::DescriptionStore;
use kr_describe::time::Reading;
use kr_protocol::ids::{EnvironmentId, SessionEpoch, SessionId};
use kr_protocol::scalars::Uuid;

/// The largest number of sessions the benchmark drives.
const MAX_SESSIONS: u32 = 50;

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
        "{} {} | {} logical processors | {:.1} GiB RAM",
        std::env::consts::OS,
        std::env::consts::ARCH,
        system
            .physical_core_count()
            .map_or_else(|| "unknown".to_owned(), |cores| cores.to_string()),
        system.total_memory() as f64 / (1024.0 * 1024.0 * 1024.0),
    )
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

    let baseline_rss = process_rss_bytes();
    let cold = Instant::now();
    let runtime = kr_describe::llama::LlamaRuntime::load(profile, &weights)
        .map_err(|error| error.to_string())?;
    let load_ms = cold.elapsed().as_millis() as u64;
    let loaded_rss = process_rss_bytes();
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

    let budgets = Budgets::DEFAULTS;
    let declared: ResidentCost = profile.execution().resident_estimate;
    println!(
        "declared_resident_bytes: {} (weights {}, beyond the weights {}) [{machine}]",
        declared.total(),
        declared.weights_bytes,
        declared.beyond_the_weights()
    );
    let figures = ProcessFigures {
        whole_product_rss_bytes: loaded_rss,
        model_rss_bytes: loaded_rss.saturating_sub(baseline_rss),
        whole_product_cpu_centis: 0,
        model_cpu_centis: 0,
    };
    println!(
        "measured_rss_bytes: whole process {}, model and runtime {}, process without the model {} [{machine}]",
        figures.whole_product_rss_bytes,
        figures.model_rss_bytes,
        figures.product_without_model_rss_bytes()
    );
    println!(
        "process_ceiling_bytes: {} held: {} [{machine}]",
        budgets.process_memory_ceiling_bytes,
        figures.whole_product_rss_bytes <= budgets.process_memory_ceiling_bytes
    );

    // One service, one runtime, the real weights. The runtime is moved into the factory, so the
    // first mapping takes it and a second would be a fault rather than a second set of weights.
    let held = std::cell::RefCell::new(Some(Box::new(runtime) as Box<dyn InferenceRuntime>));
    let factory: RuntimeFactory = Box::new(move |_profile: &ModelProfile| {
        held.borrow_mut()
            .take()
            .ok_or_else(|| kr_describe::DescribeError::Runtime {
                detail: "this benchmark maps one model once".to_owned(),
            })
    });
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
    let mut clock = 0_u64;
    for sessions in PUBLISHED_SESSION_COUNTS {
        if sessions > MAX_SESSIONS {
            continue;
        }
        let mut described = 0_u32;
        let mut deadline_exceeded = 0_u32;
        let mut rejected = 0_u32;
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
                Reading::new(clock, clock),
            );
            service.observe(
                &session_id,
                ContextSignal::TaskIntent(format!("check the pairing flow for host {seed}")),
                Reading::new(clock, clock),
            );
            clock += 2_000;
            service.settle(&session_id, Priority::Ordinary, Reading::new(clock, clock));
        }
        for _ in 0..sessions {
            let started = Instant::now();
            clock += 1;
            let tick = service
                .tick(&conditions, Reading::new(clock, clock))
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
            // Every session is past its cooldown for the next pass.
            clock += budgets.session_cooldown_ms + 1;
        }
        published.insert(sessions, (described, deadline_exceeded, rejected));
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
        Box::new(|_profile: &ModelProfile| {
            Err(kr_describe::DescribeError::Runtime {
                detail: "the paused case never maps a model".to_owned(),
            })
        }),
    );
    let session_id = SessionId::new(Uuid::from_bytes([11; 16]));
    strict.session_opened(session_id, SessionEpoch::V1, ContextBinding::new("bench"));
    strict.observe(
        &session_id,
        ContextSignal::WorkingDirectory {
            directory: "kalareach".to_owned(),
            repository: None,
        },
        Reading::new(0, 0),
    );
    strict.settle(&session_id, Priority::Ordinary, Reading::new(2_000, 2_000));
    let paused = strict
        .tick(&conditions, Reading::new(3_000, 3_000))
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
        return Err("the paused case did not pause".to_owned());
    }

    let total: u32 = published.values().map(|(described, _, _)| described).sum();
    if total == 0 {
        return Err("no description was produced, so nothing here is a measurement".to_owned());
    }
    println!("--- {total} descriptions produced against real weights on {machine} ---");
    Ok(())
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
