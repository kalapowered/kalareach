//! The description process on its own: the stub executable, spoken to over its real standard input
//! and output, answering, cancelling, ending with its daemon, ending itself when it is stuck, and
//! holding its environment's lock.

mod stub;
mod support;

use std::io::Read;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kr_describe::context::ContextRevision;
use kr_describe::output::{Expectation, ProducedUnder, validate};
use kr_describe::priority::Cancellation;
use kr_describe::profile::catalogue::Catalogue;
use kr_describe::serve::{
    CONTROL_BOUND_MS, Exit, Generating, Job, LoadWork, Loading, Model, OVERDUE_GRACE_MS, Options,
};
use kr_describe::testing::Script;
use kr_describe::wire::{Answer, JobEnd, LoadEnd, Request, WIRE_VERSION, frame_of};
use kr_protocol::ids::SessionEpoch;
use kr_protocol::scalars::U64;
use kr_worker::privacy::PrivacyGeneration;

use stub::{Placed, Process, generate, load};
use support::{binding, default_profile};

const SOON: Duration = Duration::from_secs(10);

/// What the job built by [`generate`] was produced under.
fn produced_under(revision: u64) -> ProducedUnder {
    let profile = default_profile();
    ProducedUnder {
        session_epoch: SessionEpoch::V1,
        binding: binding(),
        context_revision: ContextRevision::new(revision),
        cursor: kr_describe::context::CursorInterval::default(),
        profile_id: profile.profile_id().to_owned(),
        profile_revision: profile.revision(),
        generation: PrivacyGeneration::INITIAL,
    }
}

fn expectation(revision: u64) -> Expectation {
    let profile = default_profile();
    Expectation {
        session_epoch: SessionEpoch::V1,
        revision: ContextRevision::new(revision),
        binding: binding(),
        profile_id: profile.profile_id().to_owned(),
        profile_revision: profile.revision(),
        generation: PrivacyGeneration::INITIAL,
        name_pinned: false,
    }
}

/// A process says what it is, loads the profile its own catalogue holds, and answers a job with
/// bytes that validate as a description of that job.
#[test]
fn the_process_says_what_it_is_loads_and_describes() {
    let placed = Placed::stub();
    let runtime = placed.directory("runtime");
    let mut process = Process::start(&placed, &Script::default(), &runtime);
    let Answer::Ready {
        build,
        wire,
        target,
        identity,
        ..
    } = process.hello()
    else {
        panic!("the first answer is ready");
    };
    assert!(kr_describe::wire::same_release(&build), "{build}");
    assert_eq!(wire.get(), WIRE_VERSION);
    assert_eq!(target, kr_describe::environment::build_target());
    if let Some(identity) = identity.0 {
        assert_eq!(identity.pid.get(), u64::from(process.pid()));
    }

    process.send(&load(1, &default_profile(), 300_000));
    assert!(matches!(
        process.expect_answer(SOON, "the load"),
        Answer::Loaded { id, .. } if id.get() == 1
    ));
    assert!(
        runtime.join(kr_describe::serve::LOCK_FILE).exists(),
        "the process took its environment's lock"
    );
    process.send(&generate(2, 3, 30_000));
    let Answer::Produced { id, bytes, .. } = process.expect_answer(SOON, "the job") else {
        panic!("the job produced");
    };
    assert_eq!(id.get(), 2);
    let description = validate(bytes.as_slice(), &produced_under(3), &expectation(3))
        .expect("the answer is a description of the job");
    assert_eq!(description.title.as_str(), "kalareach");
}

/// A load or a job for a profile this build does not ship at that revision is refused, and a
/// second load in a process that has a model is refused rather than served beside it.
#[test]
fn a_load_the_process_does_not_hold_is_refused() {
    let placed = Placed::stub();
    let runtime = placed.directory("runtime");
    let mut process = Process::start(&placed, &Script::default(), &runtime);
    process.hello();
    let Request::Load {
        id,
        profile_id,
        revision,
        assets,
        deadline_ms,
    } = load(1, &default_profile(), 300_000)
    else {
        unreachable!()
    };
    process.send(&Request::Load {
        id,
        profile_id: "a-profile-nobody-signed".to_owned(),
        revision,
        assets: assets.clone(),
        deadline_ms,
    });
    assert!(matches!(
        process.expect_answer(SOON, "the refusal"),
        Answer::LoadEnded {
            why: LoadEnd::Refused,
            ..
        }
    ));
    process.send(&Request::Load {
        id: U64::new(2),
        profile_id: profile_id.clone(),
        revision: U64::new(revision.get() + 1),
        assets: assets.clone(),
        deadline_ms,
    });
    assert!(matches!(
        process.expect_answer(SOON, "the refusal"),
        Answer::LoadEnded {
            why: LoadEnd::Refused,
            ..
        }
    ));
    process.send(&generate(3, 1, 30_000));
    assert!(matches!(
        process.expect_answer(SOON, "the job"),
        Answer::Ended {
            why: JobEnd::NotLoaded,
            ..
        }
    ));

    // The control: the profile this build ships, at its revision, loads; a second does not.
    process.send(&load(4, &default_profile(), 300_000));
    assert!(matches!(
        process.expect_answer(SOON, "the load"),
        Answer::Loaded { .. }
    ));
    process.send(&load(5, &default_profile(), 300_000));
    assert!(matches!(
        process.expect_answer(SOON, "the second load"),
        Answer::LoadEnded {
            why: LoadEnd::Refused,
            ..
        }
    ));
}

/// A cancellation reaches a load and a job while they run, and each answers at once that it was
/// cancelled; the control is the same work left alone, which finishes.
#[test]
fn a_cancellation_reaches_a_load_and_a_job_while_they_run() {
    let placed = Placed::stub();

    let runtime = placed.directory("loading");
    let script = Script {
        load_until_cancelled: true,
        ..Script::default()
    };
    let mut process = Process::start(&placed, &script, &runtime);
    process.hello();
    process.send(&load(1, &default_profile(), 300_000));
    assert!(
        process.answer(Duration::from_millis(300)).is_none(),
        "the load is still running"
    );
    let asked = Instant::now();
    process.send(&Request::Cancel { id: U64::new(1) });
    assert!(matches!(
        process.expect_answer(SOON, "the cancelled load"),
        Answer::LoadEnded { id, why: LoadEnd::Cancelled, .. } if id.get() == 1
    ));
    assert!(
        asked.elapsed() < Duration::from_secs(1),
        "{:?}",
        asked.elapsed()
    );

    let runtime = placed.directory("decoding");
    let script = Script {
        generate_until_cancelled: true,
        ..Script::default()
    };
    let mut process = Process::start(&placed, &script, &runtime);
    process.hello();
    process.send(&load(1, &default_profile(), 300_000));
    process.expect_answer(SOON, "the load");
    process.send(&generate(2, 1, 30_000));
    assert!(
        process.answer(Duration::from_millis(300)).is_none(),
        "the job is still running"
    );
    let asked = Instant::now();
    process.send(&Request::Cancel { id: U64::new(2) });
    assert!(matches!(
        process.expect_answer(SOON, "the cancelled job"),
        Answer::Ended { id, why: JobEnd::Cancelled, .. } if id.get() == 2
    ));
    assert!(
        asked.elapsed() < Duration::from_secs(1),
        "{:?}",
        asked.elapsed()
    );

    // The control: the same work, taking a moment and left alone, finishes.
    let runtime = placed.directory("finishing");
    let script = Script {
        load_ms: 200,
        generate_ms: 200,
        ..Script::default()
    };
    let mut process = Process::start(&placed, &script, &runtime);
    process.hello();
    process.send(&load(1, &default_profile(), 300_000));
    assert!(matches!(
        process.expect_answer(SOON, "the load"),
        Answer::Loaded { .. }
    ));
    process.send(&generate(2, 1, 30_000));
    assert!(matches!(
        process.expect_answer(SOON, "the job"),
        Answer::Produced { .. }
    ));
}

/// A process whose input ends - its daemon closed it or went away - cancels the job it is inside
/// and ends; the control is the same process with its input open, which goes on running.
#[test]
fn a_process_ends_when_its_input_ends_even_inside_a_job() {
    let placed = Placed::stub();
    let runtime = placed.directory("runtime");
    let script = Script {
        generate_until_cancelled: true,
        ..Script::default()
    };
    let mut process = Process::start(&placed, &script, &runtime);
    process.hello();
    process.send(&load(1, &default_profile(), 300_000));
    process.expect_answer(SOON, "the load");
    process.send(&generate(2, 1, 30_000));
    assert!(
        process.exit_within(Duration::from_millis(500)).is_none(),
        "with its input open, the process runs on"
    );
    process.close_input();
    let status = process
        .exit_within(Duration::from_secs(5))
        .expect("the process ends when its input ends");
    assert_eq!(status.code(), Some(Exit::Ended.code()));
}

/// A process whose control thread is stuck writing to a daemon that does not read ends itself;
/// the control is the same process with its output read, which answers and runs on.
#[test]
fn a_process_whose_control_thread_is_stuck_ends_itself() {
    let placed = Placed::stub();
    let runtime = placed.directory("stuck");
    let script = Script {
        wedge_output_from: Some(1),
        ..Script::default()
    };
    let mut process = Process::start(&placed, &script, &runtime);
    let asked = Instant::now();
    process.send(&Request::Hello {
        build: "kr-describe-tests/0".to_owned(),
        wire: U64::new(WIRE_VERSION),
    });
    let status = process
        .exit_within(Duration::from_millis(CONTROL_BOUND_MS) * 5)
        .expect("the stuck process ends itself");
    assert_eq!(status.code(), Some(Exit::ControlStalled.code()));
    assert!(asked.elapsed() >= Duration::from_millis(CONTROL_BOUND_MS));

    let runtime = placed.directory("reading");
    let mut process = Process::start(&placed, &Script::default(), &runtime);
    assert!(matches!(process.hello(), Answer::Ready { .. }));
    assert!(
        process
            .exit_within(Duration::from_millis(CONTROL_BOUND_MS * 2))
            .is_none(),
        "a control thread that is not stuck is left alone"
    );
}

/// A process whose job runs past its deadline without stopping ends itself; the control is a job
/// that stops inside its deadline, which is answered.
#[test]
fn a_process_whose_job_does_not_stop_ends_itself() {
    let placed = Placed::stub();
    let runtime = placed.directory("overdue");
    let script = Script {
        ignore_token_ms: 60_000,
        ..Script::default()
    };
    let mut process = Process::start(&placed, &script, &runtime);
    process.hello();
    process.send(&load(1, &default_profile(), 300_000));
    process.expect_answer(SOON, "the load");
    let asked = Instant::now();
    process.send(&generate(2, 1, 200));
    let status = process
        .exit_within(Duration::from_millis(200 + OVERDUE_GRACE_MS) * 5)
        .expect("the process ends itself");
    assert_eq!(status.code(), Some(Exit::Overdue.code()));
    assert!(asked.elapsed() >= Duration::from_millis(200 + OVERDUE_GRACE_MS));

    let runtime = placed.directory("in-time");
    let script = Script {
        ignore_token_ms: 100,
        ..Script::default()
    };
    let mut process = Process::start(&placed, &script, &runtime);
    process.hello();
    process.send(&load(1, &default_profile(), 300_000));
    process.expect_answer(SOON, "the load");
    process.send(&generate(2, 1, 5_000));
    assert!(matches!(
        process.expect_answer(SOON, "the job"),
        Answer::Produced { .. }
    ));
    assert!(process.exit_within(Duration::from_millis(500)).is_none());
}

/// A second process in the same environment loads nothing until the first has gone, and loads at
/// once when it has; the control is a process in another environment, which loads beside it.
#[test]
fn a_second_process_loads_nothing_until_the_first_has_gone() {
    let placed = Placed::stub();
    let shared = placed.directory("environment");
    let mut first = Process::start(&placed, &Script::default(), &shared);
    first.hello();
    first.send(&load(1, &default_profile(), 300_000));
    assert!(matches!(
        first.expect_answer(SOON, "the first load"),
        Answer::Loaded { .. }
    ));

    let mut second = Process::start(&placed, &Script::default(), &shared);
    assert!(
        matches!(second.hello(), Answer::Ready { .. }),
        "the control thread answers while the lock is held"
    );
    second.send(&load(1, &default_profile(), 300));
    assert!(matches!(
        second.expect_answer(SOON, "the load that waited"),
        Answer::LoadEnded {
            why: LoadEnd::LockHeld,
            ..
        }
    ));
    second.send(&load(2, &default_profile(), 300_000));
    assert!(
        second.answer(Duration::from_millis(500)).is_none(),
        "nothing loads while the first process holds the lock"
    );
    first.kill();
    assert!(matches!(
        second.expect_answer(SOON, "the load once the first has gone"),
        Answer::Loaded { id, .. } if id.get() == 2
    ));

    // The control: another environment's process loads while this one holds its lock.
    let other = placed.directory("another-environment");
    let mut third = Process::start(&placed, &Script::default(), &other);
    third.hello();
    third.send(&load(1, &default_profile(), 300_000));
    assert!(matches!(
        third.expect_answer(SOON, "the other environment's load"),
        Answer::Loaded { .. }
    ));
}

/// Input a test writes frames into, which ends when the test says.
struct Input(Receiver<Vec<u8>>, Vec<u8>);

impl Read for Input {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.1.is_empty() {
            match self.0.recv() {
                Ok(bytes) => self.1 = bytes,
                Err(_) => return Ok(0),
            }
        }
        let count = buffer.len().min(self.1.len());
        buffer[..count].copy_from_slice(&self.1[..count]);
        self.1.drain(..count);
        Ok(count)
    }
}

/// What one job asked a model for.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Asked {
    context_tokens: u32,
    max_output_tokens: u32,
    cpu_threads: u32,
    sampler: kr_describe::profile::SamplerSettings,
    ceiling_bytes: u64,
}

/// A model that records what it was asked for.
#[derive(Clone, Default)]
struct Recording(Arc<Mutex<Vec<Asked>>>);

impl Model for Recording {
    fn load(&mut self, _work: &LoadWork<'_>, _token: &Cancellation, _deadline: Instant) -> Loading {
        Loading::Loaded
    }

    fn generate(&mut self, job: &Job<'_>, _token: &Cancellation, _deadline: Instant) -> Generating {
        self.0.lock().expect("the record").push(Asked {
            context_tokens: job.context_tokens,
            max_output_tokens: job.max_output_tokens,
            cpu_threads: job.cpu_threads,
            sampler: *job.sampler,
            ceiling_bytes: job.ceiling_bytes,
        });
        Generating::Ended {
            why: JobEnd::Failed,
            detail: None,
        }
    }
}

/// KR-REQ-22.10: a job runs with the thread count and bounds it was sent and with the sampler of
/// the profile the process loaded.
#[test]
fn a_job_runs_with_the_limits_sent_and_the_loaded_profiles_sampler() {
    let (write, read): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = std::sync::mpsc::channel();
    let output = Arc::new(Mutex::new(Vec::<u8>::new()));
    struct Shared(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Shared {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("the output").extend_from_slice(buffer);
            Ok(buffer.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let recording = Recording::default();
    let runtime = tempfile::tempdir().expect("a directory on the internal disk");
    let serving = {
        let recording = recording.clone();
        let output = Shared(output.clone());
        let runtime = runtime.path().to_path_buf();
        std::thread::spawn(move || {
            kr_describe::serve::run(
                Options {
                    build: "kr-describe-tests/0".to_owned(),
                    runtime_dir: runtime,
                    catalogue: Catalogue::builtin().expect("the catalogue"),
                },
                recording,
                Input(read, Vec::new()),
                output,
            )
        })
    };
    let profile = default_profile();
    for request in [load(1, &profile, 300_000), generate(2, 1, 30_000)] {
        write
            .send(frame_of(&request).expect("a frame"))
            .expect("sent");
    }
    let until = Instant::now() + SOON;
    while recording.0.lock().expect("the record").is_empty() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(write);
    assert_eq!(serving.join().expect("the serving thread"), Exit::Ended);
    let recorded = recording.0.lock().expect("the record").clone();
    assert_eq!(
        recorded,
        vec![Asked {
            context_tokens: 4_096,
            max_output_tokens: 128,
            cpu_threads: 4,
            sampler: *profile.sampler(),
            ceiling_bytes: 4 << 30,
        }],
        "the job ran with what it was sent and with the loaded profile's sampler"
    );
}
