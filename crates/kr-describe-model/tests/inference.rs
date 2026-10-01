//! The description process with the real weights, where this host has them: the daemon's driver
//! starts `kr-describe-inference`, which checks the file against the profile, loads it, answers a
//! job under the grammar and its deadline, and stops a job it is told to cancel.
//!
//! The weights are the selected profile's, read from the cache `scripts/bench-descriptions.sh`
//! fills, and never written. A host without them says so and runs nothing.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use kr_describe::budget::GIB;
use kr_describe::context::{ContextBinding, ContextBuilder, ContextRevision, ContextSignal};
use kr_describe::environment::{EnvironmentKind, ExecutionEnvironment, build_target};
use kr_describe::metadata::RepositoryFacts;
use kr_describe::output::{DESCRIPTION_GRAMMAR, prompt};
use kr_describe::profile::ModelProfile;
use kr_describe::profile::catalogue::{Catalogue, MetGates};
use kr_describe::queue::Priority;
use kr_describe::resource::{HostConditions, PowerSource, ResourceSettings, ThermalState};
use kr_describe::service::{DescriptionService, HostPlacement, Outcome};
use kr_describe::store::DescriptionStore;
use kr_describe::supervise::{Driver, Launch, Report};
use kr_describe::time::Reading;
use kr_describe::wire::{
    Answer, AssetFile, JobEnd, JobLimits, LoadEnd, Request, VerifyResult, WIRE_VERSION, frame_of,
    read_message,
};
use kr_protocol::ids::{EnvironmentId, SessionEpoch, SessionId};
use kr_protocol::scalars::{U64, Uuid};

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

/// The executable and the real weights, placed in a directory of the test's own on the internal
/// disk as the daemon places them: `<models>/<profile>/<revision>/<file>`.
struct Placed {
    _directory: tempfile::TempDir,
    program: PathBuf,
    models: PathBuf,
    runtime: PathBuf,
    profile: ModelProfile,
}

impl Placed {
    /// Places the process and the weights, or says why this host cannot and returns nothing.
    fn real_weights() -> Option<Self> {
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
            return None;
        };
        if std::fs::metadata(&cached).map(|about| about.len()).ok() != Some(weights.bytes) {
            eprintln!(
                "the real-weights test did not run: {} is not on this host",
                cached.display()
            );
            return None;
        }
        Some(Self::with_weights(|placed| {
            #[cfg(unix)]
            std::os::unix::fs::symlink(&cached, placed).expect("the weights");
            #[cfg(not(unix))]
            std::fs::hard_link(&cached, placed).expect("the weights");
        }))
    }

    /// Places the process with a file at the weights' path that is not the profile's, small enough
    /// to need no weights on this host.
    fn wrong_weights() -> Self {
        Self::with_weights(|placed| {
            std::fs::write(placed, b"not the weights the profile records").expect("a file");
        })
    }

    /// Places the process and the model directory, and has `put` make the file at the weights'
    /// path.
    fn with_weights(put: impl FnOnce(&Path)) -> Self {
        let catalogue = Catalogue::builtin().expect("this build's profiles");
        let profile = catalogue.default_profile().clone();
        let weights = profile
            .assets()
            .iter()
            .find(|asset| asset.role == "weights")
            .expect("the profile names its weights")
            .clone();
        let directory = tempfile::tempdir().expect("a directory on the internal disk");
        let program = directory.path().join(format!(
            "kr-describe-inference{}",
            std::env::consts::EXE_SUFFIX
        ));
        // Started once and let end, so the operating system's check of a new executable is paid
        // before the test times anything.
        kr_ipc::testing::place_and_start_once(
            Path::new(env!("CARGO_BIN_EXE_kr-describe-inference")),
            &program,
            &["--version"],
        );
        let models = directory.path().join("models");
        let placed = models
            .join(profile.profile_id())
            .join(profile.revision().get().to_string());
        std::fs::create_dir_all(&placed).expect("the model directory");
        put(&placed.join(&weights.file_name));
        let runtime = directory.path().join("runtime");
        std::fs::create_dir_all(&runtime).expect("the runtime directory");
        Self {
            _directory: directory,
            program,
            models,
            runtime,
            profile,
        }
    }
}

/// The real model loads, describes a session inside its deadline or ends the job at it, and stops
/// a job it is told to cancel; the process is never ended to do any of it.
#[test]
fn the_description_process_runs_the_real_model() {
    let Some(placed) = Placed::real_weights() else {
        return;
    };
    let catalogue = Catalogue::builtin().expect("this build's profiles");
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
            program: placed.program.clone(),
            arguments: vec!["--runtime-dir".into(), placed.runtime.clone().into()],
            working_directory: placed.runtime.clone(),
            environment: Vec::new(),
            models: placed.models.clone(),
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

/// The real model stops a job it is told to cancel, between chunks of its prompt or tokens of its
/// output, and the process answers that job `ended` as cancelled. A model that ran the job to its
/// end would answer `produced`: the daemon's outcome would still be a cancellation, because the
/// daemon's own token is cancelled, so only the process's answer tells the two apart. Spoken to
/// over its own pipes, as the daemon's driver speaks to it.
#[test]
fn the_real_model_stops_a_job_it_is_told_to_cancel() {
    let Some(placed) = Placed::real_weights() else {
        return;
    };
    let mut child = Command::new(&placed.program)
        .arg("--runtime-dir")
        .arg(&placed.runtime)
        .current_dir(&placed.runtime)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("the description process starts");
    let mut input = child.stdin.take().expect("its input");
    let mut output = child.stdout.take().expect("its output");
    let (tell, answers) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        while let Ok(Some(answer)) = read_message::<Answer>(&mut output) {
            if tell.send(answer).is_err() {
                return;
            }
        }
    });
    let mut send = |request: &Request| {
        let frame = frame_of(request).expect("a request frames");
        input
            .write_all(&frame)
            .and_then(|()| input.flush())
            .expect("the request is written");
    };

    send(&Request::Hello {
        build: "kr-describe-tests/0".to_owned(),
        wire: U64::new(WIRE_VERSION),
    });
    let ready = answers.recv_timeout(Duration::from_secs(120));
    assert!(
        matches!(ready, Ok(Answer::Ready { .. })),
        "waited 120 s for ready after hello, and saw {ready:?}"
    );
    let profile = &placed.profile;
    let directory = placed
        .models
        .join(profile.profile_id())
        .join(profile.revision().get().to_string());
    send(&Request::Load {
        id: U64::new(1),
        profile_id: profile.profile_id().to_owned(),
        revision: U64::new(profile.revision().get()),
        assets: profile
            .assets()
            .iter()
            .map(|asset| AssetFile {
                file_name: asset.file_name.clone(),
                path: directory
                    .join(&asset.file_name)
                    .to_string_lossy()
                    .into_owned(),
            })
            .collect(),
        deadline_ms: U64::new(400_000),
    });
    let loaded = answers.recv_timeout(Duration::from_secs(400));
    assert!(
        matches!(&loaded, Ok(Answer::Loaded { id, .. }) if id.get() == 1),
        "{loaded:?}"
    );

    let context = ContextBuilder::new(
        EnvironmentId::new(Uuid::from_bytes([0x81; 16])),
        session(3),
        SessionEpoch::V1,
        ContextBinding::new("tests"),
        ContextRevision::new(1),
    )
    .directory("kalareach")
    .intent("check the pairing flow and the host approval screen")
    .build();
    send(&Request::Generate {
        id: U64::new(2),
        prompt: prompt(&context),
        grammar: DESCRIPTION_GRAMMAR.to_owned(),
        limits: JobLimits {
            context_tokens: U64::new(4_096),
            max_output_tokens: U64::new(128),
            cpu_threads: U64::new(4),
        },
        deadline_ms: U64::new(30_000),
        ceiling_bytes: U64::new(4 * GIB),
    });
    // Long enough for the model thread to be inside the job, well short of the job's end.
    std::thread::sleep(Duration::from_millis(500));
    send(&Request::Cancel { id: U64::new(2) });
    let asked = Instant::now();
    // The control thread says it has read the cancellation before it cancels, and the model thread
    // answers the job after it has forgotten it, so the acknowledgement is the first frame.
    let mut acknowledged_in = None;
    let answer = loop {
        let answer = answers.recv_timeout(Duration::from_secs(30));
        if matches!(&answer, Ok(Answer::Cancelling { id }) if id.get() == 2) {
            acknowledged_in = Some(asked.elapsed());
            continue;
        }
        break answer;
    };
    eprintln!(
        "the real model acknowledged its cancellation in {acknowledged_in:?} and answered it in \
         {:?}: {answer:?}",
        asked.elapsed()
    );
    assert!(
        acknowledged_in.is_some(),
        "the control thread said it had read the cancellation"
    );
    assert!(
        matches!(
            &answer,
            Ok(Answer::Ended { id, why: JobEnd::Cancelled, .. }) if id.get() == 2
        ),
        "the model stopped the job itself: {answer:?}"
    );

    // Its input ends, and so does it.
    drop(input);
    let give_up = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().expect("its status") {
            break status;
        }
        assert!(Instant::now() < give_up, "the process outlived its input");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(status.success(), "{status:?}");
}

/// The real process, with no weights on this host at all, says what background class and memory
/// ceiling it runs under, and refuses a file that is not the profile's as its own kind of answer:
/// a check of it comes back as a mismatch and a load of it ends as a refusal of its files, which
/// is no failure of the runtime. A check of a file that is not there is unreadable. The control is
/// the same process answering a request for a profile its catalogue does not hold, which is a
/// refusal of another kind. Spoken to over its own pipes, as the daemon's driver speaks to it.
#[test]
fn the_real_process_names_its_class_and_refuses_a_file_that_is_not_the_profiles() {
    let placed = Placed::wrong_weights();
    let mut child = Command::new(&placed.program)
        .arg("--runtime-dir")
        .arg(&placed.runtime)
        .current_dir(&placed.runtime)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("the description process starts");
    let mut input = child.stdin.take().expect("its input");
    let mut output = child.stdout.take().expect("its output");
    let (tell, answers) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        while let Ok(Some(answer)) = read_message::<Answer>(&mut output) {
            if tell.send(answer).is_err() {
                return;
            }
        }
    });
    let mut send = |request: &Request| {
        let frame = frame_of(request).expect("a request frames");
        input
            .write_all(&frame)
            .and_then(|()| input.flush())
            .expect("the request is written");
    };

    send(&Request::Hello {
        build: "kr-describe-tests/0".to_owned(),
        wire: U64::new(WIRE_VERSION),
    });
    let ready = answers.recv_timeout(Duration::from_secs(120));
    let Ok(Answer::Ready {
        background,
        ceiling,
        target,
        ..
    }) = ready
    else {
        panic!("waited 120 s for ready after hello, and saw {ready:?}");
    };
    assert_eq!(target, build_target());
    assert!(!background.mechanism.is_empty(), "{background:?}");
    assert!(!ceiling.is_empty());

    let profile = &placed.profile;
    let weights = profile
        .assets()
        .iter()
        .find(|asset| asset.role == "weights")
        .expect("the profile names its weights");
    let directory = placed
        .models
        .join(profile.profile_id())
        .join(profile.revision().get().to_string());
    let path = directory.join(&weights.file_name);

    send(&Request::Verify {
        id: U64::new(1),
        profile_id: profile.profile_id().to_owned(),
        revision: U64::new(profile.revision().get()),
        file_name: weights.file_name.clone(),
        path: path.to_string_lossy().into_owned(),
        deadline_ms: U64::new(60_000),
    });
    let checked = answers.recv_timeout(Duration::from_secs(60));
    assert!(
        matches!(
            &checked,
            Ok(Answer::Verified { id, result: VerifyResult::Mismatch, .. }) if id.get() == 1
        ),
        "a file that is not the profile's is a mismatch: {checked:?}"
    );
    send(&Request::Verify {
        id: U64::new(2),
        profile_id: profile.profile_id().to_owned(),
        revision: U64::new(profile.revision().get()),
        file_name: weights.file_name.clone(),
        path: directory.join("absent.gguf").to_string_lossy().into_owned(),
        deadline_ms: U64::new(60_000),
    });
    let absent = answers.recv_timeout(Duration::from_secs(60));
    assert!(
        matches!(
            &absent,
            Ok(Answer::Verified { id, result: VerifyResult::Unreadable, .. }) if id.get() == 2
        ),
        "a file that is not there cannot be read: {absent:?}"
    );

    let load = |id: u64, profile_id: &str| Request::Load {
        id: U64::new(id),
        profile_id: profile_id.to_owned(),
        revision: U64::new(profile.revision().get()),
        assets: profile
            .assets()
            .iter()
            .map(|asset| AssetFile {
                file_name: asset.file_name.clone(),
                path: directory
                    .join(&asset.file_name)
                    .to_string_lossy()
                    .into_owned(),
            })
            .collect(),
        deadline_ms: U64::new(60_000),
    };
    send(&load(3, profile.profile_id()));
    let loaded = answers.recv_timeout(Duration::from_secs(60));
    assert!(
        matches!(
            &loaded,
            Ok(Answer::LoadEnded { id, why: LoadEnd::Assets, .. }) if id.get() == 3
        ),
        "a load of a file that is not the profile's is refused for its files: {loaded:?}"
    );
    send(&load(4, "a-profile-this-catalogue-does-not-hold"));
    let unknown = answers.recv_timeout(Duration::from_secs(60));
    assert!(
        matches!(
            &unknown,
            Ok(Answer::LoadEnded { id, why: LoadEnd::Refused, .. }) if id.get() == 4
        ),
        "a profile it does not hold is another kind of refusal: {unknown:?}"
    );

    drop(input);
    let give_up = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().expect("its status") {
            break status;
        }
        assert!(Instant::now() < give_up, "the process outlived its input");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(status.success(), "{status:?}");
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
