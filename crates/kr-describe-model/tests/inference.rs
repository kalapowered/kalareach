//! The description process with the real weights, where this host has them: the daemon's driver
//! starts `kr-describe-inference`, which checks the file against the profile, loads it, answers a
//! job under the grammar and its deadline, and stops a job it is told to cancel.
//!
//! The weights are the selected profile's, read from the cache `scripts/bench-descriptions.sh`
//! fills, and never written. A host without them says so and runs nothing.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use kr_describe::budget::GIB;
use kr_describe::context::{ContextBinding, ContextSignal};
use kr_describe::environment::{EnvironmentKind, ExecutionEnvironment, build_target};
use kr_describe::metadata::RepositoryFacts;
use kr_describe::profile::catalogue::{Catalogue, MetGates};
use kr_describe::queue::Priority;
use kr_describe::resource::{HostConditions, PowerSource, ResourceSettings, ThermalState};
use kr_describe::service::{DescriptionService, HostPlacement, Outcome};
use kr_describe::store::DescriptionStore;
use kr_describe::supervise::{Driver, Launch, Report};
use kr_describe::time::Reading;
use kr_protocol::ids::{EnvironmentId, SessionEpoch, SessionId};
use kr_protocol::scalars::Uuid;

/// Where the benchmark keeps the weights on this platform, or where this run is told they are.
fn cache_directory() -> Option<PathBuf> {
    if let Some(given) = std::env::var_os("KR_DESCRIBE_MODEL_CACHE") {
        return Some(PathBuf::from(given));
    }
    let home = PathBuf::from(std::env::var_os("HOME")?);
    Some(if cfg!(target_os = "macos") {
        home.join("Library/Caches/kalareach-describe")
    } else {
        home.join(".cache/kalareach-describe")
    })
}

fn session(seed: u8) -> SessionId {
    SessionId::new(Uuid::from_bytes([seed; 16]))
}

/// A host with room for the model, so the policy admits it and the test is about the process.
fn roomy() -> HostConditions {
    HostConditions::measured(
        64 * GIB,
        48 * GIB,
        PowerSource::Mains,
        ThermalState::Nominal,
    )
}

/// Opens a session with a repository and an intent, settled into a queued job.
fn queue(service: &mut DescriptionService, session_id: SessionId, intent: &str) {
    service.session_opened(session_id, SessionEpoch::V1, ContextBinding::new("tests"));
    let start = Reading::new(0, 0);
    service.observe(
        &session_id,
        ContextSignal::WorkingDirectory {
            directory: "kalareach".to_owned(),
            repository: Some(RepositoryFacts {
                name: "kalareach".to_owned(),
                branch: Some("main".to_owned()),
            }),
        },
        start,
    );
    service.observe(
        &session_id,
        ContextSignal::TaskIntent(intent.to_owned()),
        start,
    );
    assert!(
        service
            .settle(&session_id, Priority::Foreground, start.after_ms(2_000))
            .is_some()
    );
}

/// The real model loads, describes a session inside its deadline or ends the job at it, and stops
/// a job it is told to cancel; the process is never ended to do any of it.
#[test]
fn the_description_process_runs_the_real_model() {
    let catalogue = Catalogue::builtin().expect("this build's profiles");
    let profile = catalogue.default_profile().clone();
    let weights = profile
        .assets()
        .iter()
        .find(|asset| asset.role == "weights")
        .expect("the profile names its weights")
        .clone();
    let Some(cached) = cache_directory().map(|cache| cache.join(&weights.file_name)) else {
        eprintln!("the real-weights test did not run: this host has no home directory");
        return;
    };
    if std::fs::metadata(&cached).map(|about| about.len()).ok() != Some(weights.bytes) {
        eprintln!(
            "the real-weights test did not run: {} is not on this host",
            cached.display()
        );
        return;
    }
    let directory = tempfile::tempdir().expect("a directory on the internal disk");
    let program = directory.path().join(format!(
        "kr-describe-inference{}",
        std::env::consts::EXE_SUFFIX
    ));
    kr_ipc::testing::place_program(
        Path::new(env!("CARGO_BIN_EXE_kr-describe-inference")),
        &program,
    );
    let models = directory.path().join("models");
    let placed = models
        .join(profile.profile_id())
        .join(profile.revision().get().to_string());
    std::fs::create_dir_all(&placed).expect("the model directory");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&cached, placed.join(&weights.file_name)).expect("the weights");
    #[cfg(not(unix))]
    std::fs::hard_link(&cached, placed.join(&weights.file_name)).expect("the weights");
    let runtime = directory.path().join("runtime");
    std::fs::create_dir_all(&runtime).expect("the runtime directory");

    let service = DescriptionService::new(
        HostPlacement {
            environment: ExecutionEnvironment::new(
                EnvironmentId::new(Uuid::from_bytes([0x81; 16])),
                EnvironmentKind::Native,
            ),
            data_access: None,
            target: build_target().to_owned(),
        },
        catalogue,
        MetGates::default(),
        ResourceSettings::default(),
        DescriptionStore::in_memory().expect("a store"),
    );
    let mut driver = Driver::new(
        service,
        Launch {
            program,
            arguments: vec!["--runtime-dir".into(), runtime.clone().into()],
            working_directory: runtime,
            environment: Vec::new(),
            models,
        },
        "kr-describe-tests/0".to_owned(),
    );
    let started = Instant::now();
    let now = || {
        let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let wall = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |since| u64::try_from(since.as_millis()).unwrap_or(0));
        Reading::new(2_000 + elapsed, wall)
    };

    queue(driver.service_mut(), session(1), "check the pairing flow");
    let reports = run_until(
        &mut driver,
        &now,
        "the first job",
        Duration::from_secs(400),
        |reports, _| a_job_ended(reports),
    );
    eprintln!("the real model's first job: {reports:?}");
    assert!(
        !the_process_ended(&reports),
        "the process was ended: {reports:?}"
    );
    assert!(
        reports
            .iter()
            .any(|report| matches!(report, Report::Outcome(Outcome::Loaded { .. }))),
        "{reports:?}"
    );
    assert!(
        reports.iter().any(|report| matches!(
            report,
            Report::Outcome(Outcome::Published { .. } | Outcome::DeadlineExceeded { .. })
        )),
        "the job is described, or ended at its deadline: {reports:?}"
    );

    // A job told to cancel while the model reads its prompt or decodes stops, and the process
    // answers the cancellation itself rather than being ended for it.
    queue(driver.service_mut(), session(2), "fix the release workflow");
    run_until(
        &mut driver,
        &now,
        "the second job is sent",
        Duration::from_secs(60),
        |_, driver| driver.service().in_flight() == 1,
    );
    std::thread::sleep(Duration::from_millis(500));
    driver.service().cancel_running(&session(2));
    let asked = Instant::now();
    let reports = run_until(
        &mut driver,
        &now,
        "the cancellation",
        Duration::from_secs(60),
        |reports, _| a_job_ended(reports),
    );
    eprintln!(
        "the real model answered its cancellation in {:?}: {reports:?}",
        asked.elapsed()
    );
    assert!(
        !the_process_ended(&reports),
        "the process was ended: {reports:?}"
    );
    assert!(
        reports.contains(&Report::Outcome(Outcome::Cancelled {
            session_id: session(2)
        })),
        "{reports:?}"
    );
}

/// Turns at the real clock until `done` holds, waiting for the process between turns.
fn run_until(
    driver: &mut Driver,
    now: &dyn Fn() -> Reading,
    what: &str,
    limit: Duration,
    done: impl Fn(&[Report], &Driver) -> bool,
) -> Vec<Report> {
    let mut reports = Vec::new();
    let give_up = Instant::now() + limit;
    loop {
        reports.extend(driver.turn(&roomy(), now()).expect("a turn"));
        if done(&reports, driver) {
            return reports;
        }
        assert!(
            Instant::now() < give_up,
            "{what} did not happen: {reports:?}"
        );
        driver.wait(Duration::from_millis(100));
    }
}

/// Returns whether a job's outcome is among some reports.
fn a_job_ended(reports: &[Report]) -> bool {
    reports.iter().any(|report| {
        matches!(
            report,
            Report::Outcome(
                Outcome::Published { .. }
                    | Outcome::Rejected { .. }
                    | Outcome::Cancelled { .. }
                    | Outcome::DeadlineExceeded { .. }
                    | Outcome::Requeued { .. }
                    | Outcome::Failed { .. }
            )
        )
    })
}

/// Returns whether the process ended among some reports.
fn the_process_ended(reports: &[Report]) -> bool {
    reports
        .iter()
        .any(|report| matches!(report, Report::Outcome(Outcome::ProcessEnded { .. })))
}
