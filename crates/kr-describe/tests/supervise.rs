//! The daemon's side over the stub executable's real pipes: the driver starts the description
//! process from the internal disk, speaks the wire to it, holds it to its deadlines and ends it,
//! while the service judges every answer against the state in force when it arrives.
//!
//! Every turn takes a reading the test chooses, as the host's thread passes its own, so a thirty
//! second deadline or a ten second handshake is crossed by the reading rather than waited out. The
//! process answers in real time, and the tests wait for its answers in real time.

mod stub;
mod support;

use std::io::BufRead;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use kr_describe::budget::{Budgets, GIB};
use kr_describe::context::{ContextBinding, ContextSignal};
use kr_describe::metadata::{RepositoryFacts, Title};
use kr_describe::output::Rejection;
use kr_describe::profile::catalogue::MetGates;
use kr_describe::queue::{PRIORITY_RUN_LIMIT, Priority};
use kr_describe::resource::{
    HostConditions, PauseReason, PowerSource, ResourceSettings, ResourceState, ThermalState,
};
use kr_describe::service::{DescriptionService, HostPlacement, Outcome, ProcessEnd, UnloadReason};
use kr_describe::store::DescriptionStore;
use kr_describe::supervise::{ANSWER_GRACE_MS, CANCEL_MS, Driver, HANDSHAKE_MS, Launch, Report};
use kr_describe::testing::{Raw, SCRIPT_VARIABLE, Script};
use kr_describe::time::Reading;
use kr_describe::wire::LoadEnd;
use kr_protocol::ids::{SessionEpoch, SessionId};
use kr_worker::privacy::{PrivacyGeneration, PrivacySubsystem};

use stub::Placed;
use support::{MAC, a_pin_not_yet_committed, at, binding, built_in, native, roomy, session};

/// How long a test waits for the process in real time before it gives up.
const REAL: Duration = Duration::from_secs(20);

/// The execution deadline, from dequeue.
const DEADLINE_MS: u64 = Budgets::DEFAULTS.execution_deadline_ms;

/// One description process, driven over its real pipes, with the store in a directory of the
/// test's own on the internal disk.
struct Rig {
    placed: Placed,
    driver: Driver,
}

impl Rig {
    fn new(script: &Script) -> Self {
        Self::with(script, ResourceSettings::default())
    }

    fn with(script: &Script, settings: ResourceSettings) -> Self {
        let placed = Placed::stub();
        let runtime = placed.directory("runtime");
        let store = DescriptionStore::open(&placed.directory("state")).expect("a store");
        let service = DescriptionService::new(
            HostPlacement {
                environment: native(1),
                data_access: None,
                target: MAC.to_owned(),
            },
            built_in(),
            MetGates::default(),
            settings,
            store,
        );
        let launch = Launch {
            program: placed.program().to_path_buf(),
            arguments: vec!["--runtime-dir".into(), runtime.clone().into()],
            working_directory: runtime,
            environment: vec![(SCRIPT_VARIABLE.into(), script.to_env().into())],
            models: placed.directory("models"),
        };
        let driver = Driver::new(service, launch, "kr-describe-tests/0".to_owned());
        Self { placed, driver }
    }

    /// The directory the service's store is in.
    fn state(&self) -> PathBuf {
        self.placed.directory("state")
    }

    /// Turns at `now` until `done` holds, waiting for the process in real time between turns.
    fn until(
        &mut self,
        conditions: &HostConditions,
        now: Reading,
        what: &str,
        done: impl Fn(&[Report], &Driver) -> bool,
    ) -> Vec<Report> {
        let mut reports = Vec::new();
        let give_up = Instant::now() + REAL;
        loop {
            reports.extend(self.driver.turn(conditions, now).expect("a turn"));
            if done(&reports, &self.driver) {
                return reports;
            }
            assert!(
                Instant::now() < give_up,
                "{what} did not happen within {REAL:?}: {reports:?}"
            );
            self.driver.wait(Duration::from_millis(20));
        }
    }

    /// Turns at `now` until the service's job is in the process.
    fn job_sent(&mut self, now: Reading) -> Vec<Report> {
        self.until(&roomy(), now, "the job is sent", |_, driver| {
            driver.service().in_flight() == 1
        })
    }

    /// Waits in real time until an answer has arrived, without handling it.
    fn answer_arrives(&mut self) {
        assert!(self.driver.wait(REAL), "an answer arrived");
    }

    fn service(&mut self) -> &mut DescriptionService {
        self.driver.service_mut()
    }
}

/// Opens a session and settles one change into a queued job.
fn queue(
    service: &mut DescriptionService,
    session_id: &SessionId,
    priority: Priority,
    now: Reading,
) {
    service.session_opened(*session_id, SessionEpoch::V1, binding());
    change(service, session_id, "kalareach", now);
    assert!(
        service
            .settle(session_id, priority, now.after_ms(2_000))
            .is_some()
    );
}

/// Records one change in a session's directory.
fn change(service: &mut DescriptionService, session_id: &SessionId, directory: &str, now: Reading) {
    service.observe(
        session_id,
        ContextSignal::WorkingDirectory {
            directory: directory.to_owned(),
            repository: Some(RepositoryFacts {
                name: directory.to_owned(),
                branch: None,
            }),
        },
        now,
    );
}

/// Returns the outcomes among some reports.
fn outcomes(reports: &[Report]) -> Vec<&Outcome> {
    reports
        .iter()
        .filter_map(|report| match report {
            Report::Outcome(outcome) => Some(outcome),
            Report::Started { .. } | Report::Unloaded { .. } => None,
        })
        .collect()
}

/// Returns whether a job's outcome is among some reports.
fn a_job_ended(reports: &[Report]) -> bool {
    outcomes(reports).iter().any(|outcome| {
        matches!(
            outcome,
            Outcome::Published { .. }
                | Outcome::Rejected { .. }
                | Outcome::Cancelled { .. }
                | Outcome::DeadlineExceeded { .. }
                | Outcome::Requeued { .. }
                | Outcome::Failed { .. }
        )
    })
}

/// Returns whether a process end is among some reports.
fn the_process_ended(reports: &[Report]) -> bool {
    outcomes(reports)
        .iter()
        .any(|outcome| matches!(outcome, Outcome::ProcessEnded { .. }))
}

/// A description is published through the process: the driver starts it, says hello, loads the
/// profile and sends the job, and the answer is published.
#[test]
fn a_description_is_published_through_the_process() {
    let mut rig = Rig::new(&Script::default());
    queue(rig.service(), &session(1), Priority::Ordinary, at(0));
    let reports = rig.until(&roomy(), at(3_000), "the description", |reports, _| {
        a_job_ended(reports)
    });
    assert!(matches!(reports[0], Report::Started { .. }), "{reports:?}");
    assert!(
        outcomes(&reports)
            .iter()
            .any(|outcome| matches!(outcome, Outcome::Loaded { .. })),
        "{reports:?}"
    );
    assert!(
        outcomes(&reports).iter().any(
            |outcome| matches!(outcome, Outcome::Published { session_id, .. } if *session_id == session(1))
        ),
        "{reports:?}"
    );
    assert_eq!(rig.driver.started(), 1);
    assert!(rig.driver.background().is_some());
    if let Some(identity) = rig.driver.identity() {
        assert_eq!(
            identity.pid.get(),
            u64::from(rig.driver.pid().expect("a pid"))
        );
    }
    assert!(
        rig.driver
            .service()
            .store()
            .generated(&session(1))
            .expect("a read")
            .is_some()
    );
}

/// What changes while a job is in the process.
#[derive(Clone, Copy, Debug)]
enum Change {
    NewDirectory,
    Closed,
    NewEpoch,
    NewBinding,
    Pinned,
    Fenced,
    NewGeneration,
    Disabled,
    Cancelled,
}

/// KR-REQ-22.19: each change the host applies while a job is in the process refuses the result that
/// comes back: a new directory that has settled, a closed session, a new epoch, a new binding, a
/// pin, privacy mode's fence, a new privacy generation, descriptions turned off, and a
/// cancellation. The control is the same job with nothing changed, which is published.
#[test]
fn each_change_while_a_job_is_in_the_process_refuses_its_result() {
    for change in [
        Change::NewDirectory,
        Change::Closed,
        Change::NewEpoch,
        Change::NewBinding,
        Change::Pinned,
        Change::Fenced,
        Change::NewGeneration,
        Change::Disabled,
        Change::Cancelled,
    ] {
        let mut rig = Rig::new(&Script::default());
        queue(rig.service(), &session(1), Priority::Ordinary, at(0));
        rig.job_sent(at(3_000));
        rig.answer_arrives();
        let state = rig.state();
        let service = rig.service();
        match change {
            Change::NewDirectory => {
                self::change(service, &session(1), "crates", at(3_100));
                assert!(
                    service
                        .settle(&session(1), Priority::Ordinary, at(5_100))
                        .is_some()
                );
            }
            Change::Closed => service.session_closed(&session(1), at(3_100)),
            Change::NewEpoch => {
                service.session_opened(session(1), SessionEpoch::new(2), binding());
            }
            Change::NewBinding => service.session_opened(
                session(1),
                SessionEpoch::V1,
                ContextBinding::new("desktop-2/terminal/epoch-1"),
            ),
            Change::Pinned => DescriptionStore::open(&state)
                .expect("a second connection")
                .pin(
                    &session(1),
                    &Title::new("Release prep").expect("a title"),
                    "local:501",
                    1_700_000_000_000,
                )
                .expect("a pin"),
            Change::Fenced => {
                service
                    .privacy(session(1))
                    .fence(PrivacyGeneration::new(1))
                    .expect("the fence");
            }
            Change::NewGeneration => {
                service.set_privacy_generation(session(1), PrivacyGeneration::new(1));
            }
            Change::Disabled => service.set_enabled(false),
            Change::Cancelled => assert!(service.cancel_running(&session(1))),
        }
        let reports = rig.until(&roomy(), at(5_200), "the answer", |reports, _| {
            a_job_ended(reports)
        });
        let ended: Vec<&Outcome> = outcomes(&reports)
            .into_iter()
            .filter(|outcome| !matches!(outcome, Outcome::ProcessEnded { .. }))
            .collect();
        let refused = match (change, ended.as_slice()) {
            (Change::NewDirectory, [Outcome::Rejected { rejection, .. }]) => {
                matches!(rejection, Rejection::ChangedContext { .. })
            }
            (Change::Closed, [Outcome::Rejected { rejection, .. }]) => {
                *rejection == Rejection::SessionClosed
            }
            (Change::NewEpoch, [Outcome::Rejected { rejection, .. }]) => {
                matches!(rejection, Rejection::WrongSessionEpoch { .. })
            }
            (Change::NewBinding, [Outcome::Rejected { rejection, .. }]) => {
                matches!(rejection, Rejection::ChangedBinding { .. })
            }
            (Change::Pinned, [Outcome::Rejected { rejection, .. }]) => {
                *rejection == Rejection::NamePinned
            }
            (Change::Fenced | Change::NewGeneration, [Outcome::Rejected { rejection, .. }]) => {
                matches!(rejection, Rejection::LateGeneration { .. })
            }
            (Change::Disabled, [Outcome::Requeued { .. }]) => true,
            (Change::Cancelled, [Outcome::Cancelled { .. }]) => true,
            _ => false,
        };
        assert!(refused, "{change:?} gave {ended:?}");
        assert!(
            rig.driver
                .service()
                .store()
                .generated(&session(1))
                .expect("a read")
                .is_none(),
            "{change:?} left a description"
        );
        assert_eq!(rig.driver.service().counts().published, 0, "{change:?}");
    }

    // The control: nothing changes, and the same answer is published.
    let mut rig = Rig::new(&Script::default());
    queue(rig.service(), &session(1), Priority::Ordinary, at(0));
    rig.job_sent(at(3_000));
    rig.answer_arrives();
    let reports = rig.until(&roomy(), at(5_200), "the answer", |reports, _| {
        a_job_ended(reports)
    });
    assert!(
        matches!(outcomes(&reports)[..], [Outcome::Published { .. }]),
        "{reports:?}"
    );
}

/// KR-REQ-22.19: a pin committed through another connection while a result is being published
/// stops it: the publication waits for the pin's transaction and then records nothing, and no
/// success is counted.
#[test]
fn a_pin_that_races_a_result_over_two_connections_wins() {
    let mut rig = Rig::new(&Script::default());
    queue(rig.service(), &session(1), Priority::Ordinary, at(0));
    rig.job_sent(at(3_000));
    rig.answer_arrives();
    let other = a_pin_not_yet_committed(&rig.state(), &session(1));
    let committing = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        other.execute_batch("COMMIT").expect("the pin is committed");
    });
    let reports = rig.driver.turn(&roomy(), at(3_100)).expect("a turn");
    committing.join().expect("the committing thread");
    assert!(
        matches!(
            outcomes(&reports)[..],
            [Outcome::Rejected {
                rejection: Rejection::NamePinned,
                ..
            }]
        ),
        "{reports:?}"
    );
    assert!(
        rig.driver
            .service()
            .store()
            .generated(&session(1))
            .expect("a read")
            .is_none()
    );
    assert_eq!(
        rig.driver
            .service()
            .standing(&session(1), at(3_100))
            .last_success_wall_ms,
        None
    );
}

/// A frame cut short ends the process: when the process exits after half a frame, its job is
/// queued again with its position; when it goes quiet after half a frame, the job's deadline ends
/// it and not a moment before. The control is a process that sends whole frames.
#[test]
fn a_frame_cut_short_ends_the_process() {
    let mut rig = Rig::new(&Script {
        raw: Some(Raw::PartialFrameThenExit),
        ..Script::default()
    });
    queue(rig.service(), &session(1), Priority::Ordinary, at(0));
    let reports = rig.until(&roomy(), at(3_000), "the end", |reports, _| {
        the_process_ended(reports)
    });
    let ended = outcomes(&reports);
    assert!(
        ended.contains(&&Outcome::Requeued {
            session_id: session(1)
        }),
        "{reports:?}"
    );
    assert!(
        ended.contains(&&Outcome::ProcessEnded {
            why: ProcessEnd::BrokenWire
        }),
        "{reports:?}"
    );
    assert_eq!(rig.driver.pid(), None);
    assert_eq!(rig.driver.service().scheduler().queued(), 1);

    let mut rig = Rig::new(&Script {
        raw: Some(Raw::PartialFrameThenHang),
        ..Script::default()
    });
    queue(rig.service(), &session(1), Priority::Ordinary, at(0));
    rig.job_sent(at(3_000));
    std::thread::sleep(Duration::from_millis(300));
    let due = 3_000 + DEADLINE_MS + ANSWER_GRACE_MS;
    let reports = rig.driver.turn(&roomy(), at(due - 1)).expect("a turn");
    assert!(outcomes(&reports).is_empty(), "{reports:?}");
    assert!(
        rig.driver.pid().is_some(),
        "not a moment before its deadline"
    );
    let reports = rig.driver.turn(&roomy(), at(due)).expect("a turn");
    let ended = outcomes(&reports);
    assert!(
        ended.contains(&&Outcome::DeadlineExceeded {
            session_id: session(1)
        }),
        "{reports:?}"
    );
    assert!(
        ended.contains(&&Outcome::ProcessEnded {
            why: ProcessEnd::PastDeadline
        }),
        "{reports:?}"
    );
    assert_eq!(rig.driver.pid(), None);

    // The control: whole frames are read and published.
    let mut rig = Rig::new(&Script::default());
    queue(rig.service(), &session(1), Priority::Ordinary, at(0));
    let reports = rig.until(&roomy(), at(3_000), "the description", |reports, _| {
        a_job_ended(reports)
    });
    assert!(
        outcomes(&reports)
            .iter()
            .any(|outcome| matches!(outcome, Outcome::Published { .. })),
        "{reports:?}"
    );
}

/// A process that never answers the handshake is ended at its deadline and not before, and the
/// load it was sent ends with it. The control is a process that answers.
#[test]
fn a_silent_process_is_ended_at_the_handshake_deadline() {
    let mut rig = Rig::new(&Script {
        raw: Some(Raw::Silent),
        ..Script::default()
    });
    queue(rig.service(), &session(1), Priority::Ordinary, at(0));
    let reports = rig.driver.turn(&roomy(), at(3_000)).expect("a turn");
    assert!(
        matches!(reports[..], [Report::Started { .. }]),
        "{reports:?}"
    );
    std::thread::sleep(Duration::from_millis(300));
    let reports = rig
        .driver
        .turn(&roomy(), at(3_000 + HANDSHAKE_MS - 1))
        .expect("a turn");
    assert!(reports.is_empty(), "{reports:?}");
    assert!(
        rig.driver.pid().is_some(),
        "not a moment before the deadline"
    );
    let reports = rig
        .driver
        .turn(&roomy(), at(3_000 + HANDSHAKE_MS))
        .expect("a turn");
    let ended = outcomes(&reports);
    assert!(
        ended.contains(&&Outcome::ProcessEnded {
            why: ProcessEnd::SilentAtStart
        }),
        "{reports:?}"
    );
    assert!(
        ended.iter().any(|outcome| matches!(
            outcome,
            Outcome::LoadEnded {
                why: LoadEnd::Failed,
                ..
            }
        )),
        "{reports:?}"
    );
    assert_eq!(rig.driver.pid(), None);
    assert_eq!(rig.driver.service().inference_restarts(), 1);

    // The control: a process that answers is not ended at the same reading.
    let mut rig = Rig::new(&Script::default());
    queue(rig.service(), &session(1), Priority::Ordinary, at(0));
    rig.until(&roomy(), at(3_000), "the description", |reports, _| {
        a_job_ended(reports)
    });
    let pid = rig.driver.pid();
    let reports = rig
        .driver
        .turn(&roomy(), at(3_000 + HANDSHAKE_MS))
        .expect("a turn");
    assert!(!the_process_ended(&reports), "{reports:?}");
    assert_eq!(rig.driver.pid(), pid);
}

/// A process whose control thread has stopped reading is ended when a cancellation goes
/// unanswered past its bound, and not before; its job ends cancelled. The control is a process
/// that reads the cancellation and answers it.
#[test]
fn a_process_whose_control_thread_is_wedged_is_ended_when_a_cancel_goes_unanswered() {
    let mut rig = Rig::new(&Script {
        generate_until_cancelled: true,
        wedge_input_after: Some(3),
        ..Script::default()
    });
    queue(rig.service(), &session(1), Priority::Ordinary, at(0));
    rig.job_sent(at(3_000));
    assert!(rig.driver.service().cancel_running(&session(1)));
    let reports = rig.driver.turn(&roomy(), at(4_000)).expect("a turn");
    assert!(reports.is_empty(), "{reports:?}");
    std::thread::sleep(Duration::from_millis(300));
    let reports = rig
        .driver
        .turn(&roomy(), at(4_000 + CANCEL_MS - 1))
        .expect("a turn");
    assert!(reports.is_empty(), "{reports:?}");
    assert!(rig.driver.pid().is_some(), "not a moment before the bound");
    let reports = rig
        .driver
        .turn(&roomy(), at(4_000 + CANCEL_MS))
        .expect("a turn");
    let ended = outcomes(&reports);
    assert!(
        ended.contains(&&Outcome::Cancelled {
            session_id: session(1)
        }),
        "{reports:?}"
    );
    assert!(
        ended.contains(&&Outcome::ProcessEnded {
            why: ProcessEnd::CancelUnanswered
        }),
        "{reports:?}"
    );
    assert_eq!(rig.driver.pid(), None);

    // The control: the cancellation is read and answered, and the process goes on.
    let mut rig = Rig::new(&Script {
        generate_until_cancelled: true,
        ..Script::default()
    });
    queue(rig.service(), &session(1), Priority::Ordinary, at(0));
    rig.job_sent(at(3_000));
    let pid = rig.driver.pid();
    assert!(rig.driver.service().cancel_running(&session(1)));
    let reports = rig.until(&roomy(), at(4_000), "the cancellation", |reports, _| {
        a_job_ended(reports)
    });
    assert!(
        matches!(outcomes(&reports)[..], [Outcome::Cancelled { .. }]),
        "{reports:?}"
    );
    let reports = rig
        .driver
        .turn(&roomy(), at(4_000 + CANCEL_MS))
        .expect("a turn");
    assert!(!the_process_ended(&reports), "{reports:?}");
    assert_eq!(rig.driver.pid(), pid);
}

/// A cancellation reaches the process during a load and during a decode, and each ends at once
/// with the process still running. The control is the same work left alone, which finishes.
#[test]
fn a_cancellation_reaches_the_process_during_a_load_and_a_decode() {
    let mut rig = Rig::new(&Script {
        load_until_cancelled: true,
        ..Script::default()
    });
    queue(rig.service(), &session(1), Priority::Ordinary, at(0));
    let reports = rig.driver.turn(&roomy(), at(3_000)).expect("a turn");
    assert!(
        matches!(reports[..], [Report::Started { .. }]),
        "{reports:?}"
    );
    let pid = rig.driver.pid();
    // The process has started and said hello before its load is cancelled, so what is timed is
    // the cancellation rather than the start of a process.
    rig.until(&roomy(), at(3_050), "the handshake", |_, driver| {
        driver.background().is_some()
    });
    rig.service().set_enabled(false);
    let asked = Instant::now();
    let reports = rig.until(&roomy(), at(3_100), "the cancelled load", |reports, _| {
        outcomes(reports)
            .iter()
            .any(|outcome| matches!(outcome, Outcome::LoadEnded { .. }))
    });
    assert!(
        outcomes(&reports).contains(&&Outcome::LoadEnded {
            why: LoadEnd::Cancelled,
            detail: None
        }),
        "{reports:?}"
    );
    assert!(
        asked.elapsed() < Duration::from_secs(2),
        "{:?}",
        asked.elapsed()
    );
    assert_eq!(
        rig.driver.pid(),
        pid,
        "the process was not ended to stop its load"
    );

    let mut rig = Rig::new(&Script {
        generate_until_cancelled: true,
        ..Script::default()
    });
    queue(rig.service(), &session(1), Priority::Ordinary, at(0));
    rig.job_sent(at(3_000));
    let pid = rig.driver.pid();
    assert!(rig.driver.service().cancel_running(&session(1)));
    let asked = Instant::now();
    let reports = rig.until(&roomy(), at(3_100), "the cancelled job", |reports, _| {
        a_job_ended(reports)
    });
    assert!(
        matches!(outcomes(&reports)[..], [Outcome::Cancelled { .. }]),
        "{reports:?}"
    );
    assert!(
        asked.elapsed() < Duration::from_secs(2),
        "{:?}",
        asked.elapsed()
    );
    assert_eq!(
        rig.driver.pid(),
        pid,
        "the process was not ended to stop its job"
    );

    // The control: a load and a job that take a moment, left alone, finish.
    let mut rig = Rig::new(&Script {
        load_ms: 200,
        generate_ms: 200,
        ..Script::default()
    });
    queue(rig.service(), &session(1), Priority::Ordinary, at(0));
    let reports = rig.until(&roomy(), at(3_000), "the description", |reports, _| {
        a_job_ended(reports)
    });
    assert!(
        outcomes(&reports)
            .iter()
            .any(|outcome| matches!(outcome, Outcome::Published { .. })),
        "{reports:?}"
    );
}

/// KR-REQ-22.21: the description process goes when its daemon dies, with a job inside it: its
/// input ends, and it ends. The control is the same process while its daemon lives.
#[test]
fn the_process_goes_when_its_daemon_dies() {
    let placed = Placed::stub();
    let runtime = placed.directory("runtime");
    let mut daemon = std::process::Command::new(placed.program())
        .arg("--daemon")
        .arg("--runtime-dir")
        .arg(&runtime)
        .current_dir(&runtime)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .expect("the stub daemon starts");
    let output = daemon.stdout.take().expect("the daemon's output");
    let (tell, heard) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = std::io::BufReader::new(output).read_line(&mut line);
        let _ = tell.send(line);
    });
    let line = heard.recv_timeout(REAL).expect("the child's identity");
    let identity: kr_protocol::identity::ProcessStartIdentity =
        serde_json::from_str(line.trim()).expect("an identity");

    // The control: while the daemon lives, its description process runs.
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        kr_ipc::identity::process_state(&identity),
        kr_ipc::identity::ProcessState::Running
    );

    daemon.kill().expect("the daemon is ended");
    daemon.wait().expect("the daemon is collected");
    let give_up = Instant::now() + Duration::from_secs(10);
    while kr_ipc::identity::process_state(&identity) != kr_ipc::identity::ProcessState::Ended {
        assert!(
            Instant::now() < give_up,
            "the description process outlived its daemon: {identity:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// An answer for work nobody is waiting for is dropped and counted: the second answer to a job,
/// and an answer for an identifier nobody sent. The one description is published once. The
/// control is a process that answers once.
#[test]
fn a_late_answer_is_dropped_and_counted() {
    let mut rig = Rig::new(&Script {
        raw: Some(Raw::AnswerTwice),
        ..Script::default()
    });
    queue(rig.service(), &session(1), Priority::Ordinary, at(0));
    let reports = rig.until(&roomy(), at(3_000), "both late answers", |_, driver| {
        driver.service().counts().dropped_answers == 2
    });
    let ended = outcomes(&reports);
    assert_eq!(
        ended
            .iter()
            .filter(|outcome| matches!(outcome, Outcome::Published { .. }))
            .count(),
        1,
        "{reports:?}"
    );
    assert_eq!(
        ended
            .iter()
            .filter(|outcome| matches!(outcome, Outcome::Dropped { .. }))
            .count(),
        2,
        "{reports:?}"
    );
    assert_eq!(rig.driver.service().counts().published, 1);
    assert_eq!(
        rig.driver
            .service()
            .store()
            .generated_count()
            .expect("a count"),
        1
    );

    // The control: a process that answers once has nothing dropped.
    let mut rig = Rig::new(&Script::default());
    queue(rig.service(), &session(1), Priority::Ordinary, at(0));
    rig.until(&roomy(), at(3_000), "the description", |reports, _| {
        a_job_ended(reports)
    });
    std::thread::sleep(Duration::from_millis(300));
    rig.driver.turn(&roomy(), at(3_000)).expect("a turn");
    assert_eq!(rig.driver.service().counts().dropped_answers, 0);
}

/// A load that takes more than a job's thirty seconds happens before the job is dequeued: the cold
/// start is reported apart, and the job then has its whole deadline and is published. The control
/// is a job whose answer arrives past that deadline, which is refused.
#[test]
fn a_load_over_thirty_seconds_is_followed_by_a_published_job() {
    let mut rig = Rig::new(&Script {
        load_ms: 2_000,
        ..Script::default()
    });
    queue(rig.service(), &session(1), Priority::Ordinary, at(0));
    // The process says it is ready at once; its load takes two seconds of real time, which is
    // what keeps the load's answer for the reading after this one.
    rig.until(&roomy(), at(3_000), "the handshake", |_, driver| {
        driver.background().is_some()
    });
    let loaded_at = 3_000 + DEADLINE_MS + 1_000;
    let reports = rig.until(&roomy(), at(loaded_at), "the load", |reports, _| {
        outcomes(reports)
            .iter()
            .any(|outcome| matches!(outcome, Outcome::Loaded { .. }))
    });
    assert!(
        outcomes(&reports).contains(&&Outcome::Loaded {
            cold_start_ms: loaded_at - 3_000
        }),
        "{reports:?}"
    );
    assert!(
        !the_process_ended(&reports),
        "a long load is not a job past its deadline"
    );
    rig.answer_arrives();
    let reports = rig.until(
        &roomy(),
        at(loaded_at + 500),
        "the description",
        |reports, _| a_job_ended(reports),
    );
    assert!(
        outcomes(&reports).contains(&&Outcome::Published {
            session_id: session(1),
            queue_wait_ms: loaded_at - 2_000,
            execution_ms: 500,
        }),
        "{reports:?}"
    );

    // The control: a job whose answer arrives past its deadline from dequeue is refused.
    let next = loaded_at + 40_000;
    queue(
        rig.service(),
        &session(2),
        Priority::Ordinary,
        at(next - 3_000),
    );
    rig.job_sent(at(next));
    rig.answer_arrives();
    let reports = rig.until(
        &roomy(),
        at(next + DEADLINE_MS + 1),
        "the late answer",
        |reports, _| a_job_ended(reports),
    );
    assert!(
        outcomes(&reports).contains(&&Outcome::DeadlineExceeded {
            session_id: session(2)
        }),
        "{reports:?}"
    );
}

/// KR-REQ-22.14: under mixed demand through the process, an ordinary session is described again
/// only once the measured cadence has passed, a priority session once the cooldown has, and an
/// ordinary job that is due waits behind at most three priority jobs.
///
/// One ordinary session and ten foreground sessions change without pause, and each answer is taken
/// ten seconds after its job was sent, which is the service time the queue measures. A queue gated
/// by the cooldown alone serves the ordinary session every fourth job, forty seconds apart.
#[test]
fn the_cadence_holds_under_mixed_demand_through_the_process() {
    let mut rig = Rig::new(&Script::default());
    let ordinary = session(1);
    let foreground: Vec<SessionId> = (2..=11_u8).map(session).collect();
    queue(rig.service(), &ordinary, Priority::Ordinary, at(0));
    for session_id in &foreground {
        queue(rig.service(), session_id, Priority::Foreground, at(0));
    }
    let cooldown_ms = Budgets::DEFAULTS.session_cooldown_ms;
    let service_ms = 10_000;
    let running = |driver: &Driver| {
        std::iter::once(ordinary)
            .chain(foreground.iter().copied())
            .find(|session_id| driver.service().running_job().is_running(session_id))
    };
    // What the queue stood at just before each dispatch: the next job is sent in the same turn
    // that takes the answer before it, so this is read at that turn's reading, before it.
    let standing = |driver: &Driver, now: u64| {
        let scheduler = driver.service().scheduler();
        (
            scheduler.cadence_ms(at(now)),
            scheduler.is_eligible(&ordinary, at(now)),
        )
    };
    let mut now = 3_000;
    let mut before = standing(&rig.driver, now);
    rig.job_sent(at(now));
    let mut dispatched_at = now;
    let mut last: std::collections::BTreeMap<SessionId, u64> = std::collections::BTreeMap::new();
    let mut ordinary_gaps = Vec::new();
    let mut priority_jobs_while_due = 0;
    for change in 0..60_u64 {
        let sent = running(&rig.driver).expect("a job is in the process");
        let (cadence, due) = before;
        if let Some(previous) = last.insert(sent, dispatched_at) {
            let gap = dispatched_at - previous;
            if sent == ordinary {
                assert!(
                    gap >= cadence,
                    "an ordinary gap of {gap} ms inside a cadence of {cadence} ms"
                );
                ordinary_gaps.push(gap);
            } else {
                assert!(
                    gap >= cooldown_ms,
                    "a priority gap of {gap} ms inside the cooldown"
                );
            }
        }
        if sent == ordinary {
            priority_jobs_while_due = 0;
        } else if due {
            priority_jobs_while_due += 1;
            assert!(
                priority_jobs_while_due <= PRIORITY_RUN_LIMIT,
                "a due ordinary job waited behind more than {PRIORITY_RUN_LIMIT} priority jobs"
            );
        }
        // The answer is taken one service time after its job was sent, and the next job, when one
        // is due, is sent in the same turn.
        now = dispatched_at + service_ms;
        before = standing(&rig.driver, now);
        let reports = rig.until(&roomy(), at(now), "the answer", |reports, _| {
            a_job_ended(reports)
        });
        assert!(
            outcomes(&reports).iter().any(
                |outcome| matches!(outcome, Outcome::Published { session_id, .. } if *session_id == sent)
            ),
            "{reports:?}"
        );
        // The session that was described changes again at once.
        change_and_settle(rig.service(), &sent, change, now);
        while rig.driver.service().in_flight() == 0 {
            now += 1_000;
            before = standing(&rig.driver, now);
            rig.driver.turn(&roomy(), at(now)).expect("a turn");
        }
        dispatched_at = now;
    }
    assert!(
        ordinary_gaps.len() >= 3,
        "the ordinary session is described: {ordinary_gaps:?}"
    );
    assert!(
        ordinary_gaps
            .iter()
            .all(|gap| *gap > cooldown_ms + service_ms),
        "every ordinary gap is longer than a cooldown-only queue's forty seconds: {ordinary_gaps:?}"
    );
}

/// Records a change to a session that settles at once, as a debounce that began two seconds ago.
fn change_and_settle(
    service: &mut DescriptionService,
    session_id: &SessionId,
    change: u64,
    now: u64,
) {
    let priority = if *session_id == session(1) {
        Priority::Ordinary
    } else {
        Priority::Foreground
    };
    service.observe(
        session_id,
        ContextSignal::TaskIntent(format!("change {change}")),
        at(now.saturating_sub(2_000)),
    );
    assert!(service.settle(session_id, priority, at(now)).is_some());
}

/// Notes item 77: a description whose job took the process past its ceiling is published, with its
/// latency recorded, and the process is ended and inference paused after it. The control is a job
/// under the ceiling, after which the same process serves on.
#[test]
fn a_publication_past_the_ceiling_stands_and_the_pause_follows_through_the_process() {
    let ceiling = Budgets::DEFAULTS.process_memory_ceiling_bytes;
    let mut rig = Rig::new(&Script {
        peak_rss_bytes: Some(ceiling + GIB),
        ..Script::default()
    });
    queue(rig.service(), &session(1), Priority::Ordinary, at(0));
    let reports = rig.until(&roomy(), at(3_000), "the description", |reports, _| {
        a_job_ended(reports)
    });
    assert!(
        outcomes(&reports)
            .iter()
            .any(|outcome| matches!(outcome, Outcome::Published { session_id, .. } if *session_id == session(1))),
        "{reports:?}"
    );
    assert!(
        reports.contains(&Report::Unloaded {
            why: UnloadReason::Paused(PauseReason::MemoryPressure)
        }),
        "{reports:?}"
    );
    assert_eq!(rig.driver.pid(), None);
    assert!(
        rig.driver
            .service()
            .store()
            .generated(&session(1))
            .expect("a read")
            .is_some()
    );
    assert_eq!(
        rig.driver.service().resource_state(),
        ResourceState::ResourcePaused {
            reason: PauseReason::MemoryPressure,
            unloaded: true
        }
    );
    assert_eq!(
        rig.driver
            .service()
            .latency()
            .reading(1)
            .expect("measured")
            .execution
            .samples,
        1
    );

    // The control: under the ceiling the process stays and serves the next job.
    let mut rig = Rig::new(&Script {
        peak_rss_bytes: Some(GIB),
        ..Script::default()
    });
    queue(rig.service(), &session(1), Priority::Ordinary, at(0));
    let reports = rig.until(&roomy(), at(3_000), "the description", |reports, _| {
        a_job_ended(reports)
    });
    assert!(
        !reports
            .iter()
            .any(|report| matches!(report, Report::Unloaded { .. }))
    );
    let pid = rig.driver.pid();
    queue(rig.service(), &session(2), Priority::Ordinary, at(10_000));
    rig.until(
        &roomy(),
        at(13_000),
        "the next description",
        |reports, _| a_job_ended(reports),
    );
    assert_eq!(rig.driver.pid(), pid);
    assert_eq!(rig.driver.started(), 1);
}

/// A process that ends inside a job is restarted after the restart delay, and the job is queued
/// again once: when the next process ends inside it too, it is not retried.
#[test]
fn a_process_that_ends_inside_a_job_is_restarted_and_the_job_retried_once() {
    let mut rig = Rig::new(&Script {
        crash_in_generate: true,
        ..Script::default()
    });
    queue(rig.service(), &session(1), Priority::Ordinary, at(0));
    let reports = rig.until(&roomy(), at(3_000), "the first end", |reports, _| {
        the_process_ended(reports)
    });
    assert!(
        outcomes(&reports).contains(&&Outcome::Requeued {
            session_id: session(1)
        }),
        "{reports:?}"
    );
    let reports = rig.driver.turn(&roomy(), at(3_500)).expect("a turn");
    assert!(
        reports.is_empty(),
        "nothing starts inside the restart delay: {reports:?}"
    );
    let reports = rig.until(&roomy(), at(4_000), "the second end", |reports, _| {
        the_process_ended(reports)
    });
    assert!(
        matches!(reports[0], Report::Started { .. }),
        "a new process: {reports:?}"
    );
    assert!(
        outcomes(&reports)
            .iter()
            .any(|outcome| matches!(outcome, Outcome::Failed { session_id, .. } if *session_id == session(1))),
        "{reports:?}"
    );
    assert_eq!(rig.driver.started(), 2);
    assert_eq!(rig.driver.service().inference_restarts(), 2);
    assert_eq!(rig.driver.service().scheduler().queued(), 0);
}

/// A resource pause while a job is in the process cancels it, keeps its place in the queue and
/// ends the process; when the pause clears the job is described. Thermal pressure is the pause.
#[test]
fn a_pause_while_a_job_runs_cancels_it_and_keeps_its_place() {
    let hot = HostConditions::measured(
        16 * GIB,
        12 * GIB,
        PowerSource::Mains,
        ThermalState::Critical,
    );
    let mut rig = Rig::new(&Script {
        generate_ms: 3_000,
        ..Script::default()
    });
    queue(rig.service(), &session(1), Priority::Ordinary, at(0));
    rig.job_sent(at(3_000));
    let reports = rig.until(&hot, at(3_100), "the pause", |reports, _| {
        reports
            .iter()
            .any(|report| matches!(report, Report::Unloaded { .. }))
    });
    assert!(
        outcomes(&reports).contains(&&Outcome::Requeued {
            session_id: session(1)
        }),
        "{reports:?}"
    );
    assert!(
        reports.contains(&Report::Unloaded {
            why: UnloadReason::Paused(PauseReason::Thermal)
        }),
        "{reports:?}"
    );
    assert_eq!(rig.driver.service().scheduler().queued(), 1);
    assert_eq!(
        rig.driver.service().inference_restarts(),
        0,
        "a pause is no failure"
    );
    let reports = rig.until(&roomy(), at(10_000), "the description", |reports, _| {
        a_job_ended(reports)
    });
    assert!(
        outcomes(&reports)
            .iter()
            .any(|outcome| matches!(outcome, Outcome::Published { session_id, .. } if *session_id == session(1))),
        "{reports:?}"
    );
    assert_eq!(rig.driver.started(), 2);
}

/// KR-REQ-22.16: a change that settles while a job is in the process would refuse its result, so
/// the service cancels the job there at once rather than wait for an answer it would refuse. The
/// process stays, and the new revision is described once the session's cooldown has passed. The
/// control is a change still inside its debounce, which leaves the job to publish.
#[test]
fn a_change_that_settles_while_a_job_runs_cancels_it_in_the_process() {
    let mut rig = Rig::new(&Script {
        generate_ms: 2_000,
        ..Script::default()
    });
    queue(rig.service(), &session(1), Priority::Ordinary, at(0));
    rig.job_sent(at(3_000));
    let pid = rig.driver.pid();
    change(rig.service(), &session(1), "crates", at(3_100));
    assert!(
        rig.service()
            .settle(&session(1), Priority::Ordinary, at(5_100))
            .is_some()
    );
    let reports = rig.until(&roomy(), at(5_100), "the cancelled job", |reports, _| {
        a_job_ended(reports)
    });
    // The process answered the cancellation: an answer that finished the job would have been
    // refused as a changed context instead.
    assert_eq!(
        outcomes(&reports),
        vec![&Outcome::Cancelled {
            session_id: session(1)
        }]
    );
    assert_eq!(rig.driver.pid(), pid, "the process was not ended");
    let next = 3_000 + Budgets::DEFAULTS.session_cooldown_ms;
    let reports = rig.until(&roomy(), at(next), "the new revision", |reports, _| {
        a_job_ended(reports)
    });
    assert!(
        outcomes(&reports).iter().any(
            |outcome| matches!(outcome, Outcome::Published { session_id, .. } if *session_id == session(1))
        ),
        "{reports:?}"
    );
    assert_eq!(
        rig.driver
            .service()
            .store()
            .generated(&session(1))
            .expect("a read")
            .expect("a description")
            .revision,
        kr_describe::context::ContextRevision::new(2)
    );
    assert_eq!(rig.driver.pid(), pid);

    // The control: a change inside its debounce leaves the job to publish.
    let mut rig = Rig::new(&Script {
        generate_ms: 300,
        ..Script::default()
    });
    queue(rig.service(), &session(1), Priority::Ordinary, at(0));
    rig.job_sent(at(3_000));
    change(rig.service(), &session(1), "crates", at(3_100));
    assert_eq!(
        rig.service()
            .settle(&session(1), Priority::Ordinary, at(4_000)),
        None
    );
    let reports = rig.until(&roomy(), at(4_000), "the description", |reports, _| {
        a_job_ended(reports)
    });
    assert!(
        matches!(outcomes(&reports)[..], [Outcome::Published { .. }]),
        "{reports:?}"
    );
}
