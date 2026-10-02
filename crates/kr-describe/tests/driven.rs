//! The driven service on its own: what it tells its host to do, and what it makes of each answer
//! and of the process ending, with no process at all.

mod support;

use std::time::Duration;

use kr_describe::budget::{Budgets, GIB};
use kr_describe::context::{
    ContextRevision, ContextSignal, ProjectText, SemanticEvent, SemanticEventKind,
};
use kr_describe::metadata::RepositoryFacts;
use kr_describe::output::Rejection;
use kr_describe::profile::catalogue::MetGates;
use kr_describe::queue::Priority;
use kr_describe::resource::{
    HostConditions, PauseReason, PowerSource, ResourceSettings, ResourceState, ThermalState,
};
use kr_describe::service::{
    Answered, DescriptionService, DownloadProgress, Handles, HostPlacement, Instruction, Outcome,
    ProcessEnd, RESTART_FIRST_MS, RESTART_MOST_MS, UnloadReason, Work,
};
use kr_describe::store::DescriptionStore;
use kr_describe::testing::{Output, answer_of, at_next_decision};
use kr_describe::time::Reading;
use kr_describe::wire::{JobEnd, LoadEnd, Phases};
use kr_protocol::ids::{SessionEpoch, SessionId};

use support::{MAC, at, binding, built_in, native, roomy, session};

fn service() -> DescriptionService {
    service_over(DescriptionStore::in_memory().expect("a store in memory"))
}

/// Opens a session and settles one change in its directory into a queued job.
fn queue(service: &mut DescriptionService, session_id: &SessionId, directory: &str, now: Reading) {
    service.session_opened(*session_id, SessionEpoch::V1, binding());
    change(service, session_id, directory, now);
    assert!(
        service
            .settle(session_id, Priority::Ordinary, now.after_ms(2_000))
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

/// Answers a load, and returns the next instruction.
fn loaded(service: &mut DescriptionService, now: Reading) -> Instruction {
    let Instruction::Load { id, .. } = service.next(&roomy(), now).expect("an instruction") else {
        panic!("a load comes first");
    };
    assert!(matches!(
        service
            .finished(
                id,
                Answered::Loaded {
                    load_ms: 0,
                    rss_bytes: 0
                },
                now
            )
            .expect("an answer"),
        Outcome::Loaded { .. }
    ));
    service.next(&roomy(), now).expect("an instruction")
}

/// The answer a job gets from a model that produced a description of its prompt.
fn produced(prompt: &str, peak_rss_bytes: u64) -> Answered {
    Answered::Produced {
        bytes: answer_of(prompt, &Output::WellFormed),
        phases: Phases::default(),
        peak_rss_bytes,
    }
}

/// KR-REQ-22.16: a change that settles while its session's job is in the process moves the
/// revision, so the job's result, which describes the session as it was, is refused as a changed
/// context, and the job is cancelled at once rather than left to finish; the new revision is
/// described next. The control is a change still inside its debounce when the answer arrives, which
/// leaves the result standing.
#[test]
fn a_change_that_settles_while_its_job_runs_refuses_the_result() {
    let mut service = service();
    queue(&mut service, &session(1), "kalareach", at(0));
    let Instruction::Generate { id, request, .. } = loaded(&mut service, at(3_000)) else {
        panic!("the job is sent");
    };
    change(&mut service, &session(1), "crates", at(3_100));
    assert!(
        service
            .settle(&session(1), Priority::Ordinary, at(5_100))
            .is_some(),
        "the change settles once its debounce has passed, job or no job"
    );
    assert_eq!(service.revision(&session(1)), Some(ContextRevision::new(2)));
    assert_eq!(
        service.next(&roomy(), at(5_100)).expect("an instruction"),
        Instruction::Cancel {
            id,
            work: Work::Job
        },
        "the job is cancelled at once"
    );
    let outcome = service
        .finished(id, produced(&request.prompt, 0), at(5_200))
        .expect("the answer");
    assert_eq!(
        outcome,
        Outcome::Rejected {
            session_id: session(1),
            rejection: Rejection::ChangedContext {
                expected: ContextRevision::new(2),
                found: ContextRevision::new(1)
            }
        }
    );
    assert!(
        service
            .store()
            .generated(&session(1))
            .expect("a read")
            .is_none()
    );

    // The new revision is described once the session's cooldown has passed.
    let next = at(3_000 + Budgets::DEFAULTS.session_cooldown_ms);
    let Instruction::Generate { id, request, .. } = service.next(&roomy(), next).expect("a job")
    else {
        panic!("the new revision's job is sent");
    };
    assert!(matches!(
        service
            .finished(id, produced(&request.prompt, 0), next.after_ms(500))
            .expect("the answer"),
        Outcome::Published { .. }
    ));
    assert_eq!(
        service
            .store()
            .generated(&session(1))
            .expect("a read")
            .expect("a description")
            .revision,
        ContextRevision::new(2)
    );

    // The control: a change still inside its debounce when the answer arrives leaves the result
    // standing, and settles after it.
    let mut service = self::service();
    queue(&mut service, &session(1), "kalareach", at(0));
    let Instruction::Generate { id, request, .. } = loaded(&mut service, at(3_000)) else {
        panic!("the job is sent");
    };
    change(&mut service, &session(1), "crates", at(3_100));
    assert_eq!(
        service.settle(&session(1), Priority::Ordinary, at(4_000)),
        None,
        "not before the debounce"
    );
    assert!(matches!(
        service.next(&roomy(), at(4_000)).expect("an instruction"),
        Instruction::Wait { .. }
    ));
    assert!(matches!(
        service
            .finished(id, produced(&request.prompt, 0), at(4_000))
            .expect("the answer"),
        Outcome::Published { .. }
    ));
    assert!(
        service
            .settle(&session(1), Priority::Ordinary, at(5_100))
            .is_some()
    );
}

/// KR-REQ-22.21: a job whose process ends under it is queued again once, with its aging position,
/// and a second failure is not retried.
#[test]
fn a_job_whose_process_fails_is_queued_again_once() {
    let mut service = service();
    queue(&mut service, &session(1), "kalareach", at(0));
    assert!(matches!(
        loaded(&mut service, at(3_000)),
        Instruction::Generate { .. }
    ));
    let first = service
        .process_ended(ProcessEnd::Exited, at(3_500))
        .expect("the end");
    assert_eq!(
        first,
        vec![
            Outcome::Requeued {
                session_id: session(1)
            },
            Outcome::ProcessEnded {
                why: ProcessEnd::Exited
            }
        ]
    );
    let queued = service.scheduler().jobs()[0].queued_at_ms;
    assert_eq!(queued, 2_000, "the job keeps its aging position");
    assert_eq!(service.inference_restarts(), 1);

    let later = at(3_500 + RESTART_FIRST_MS);
    assert!(matches!(
        loaded(&mut service, later),
        Instruction::Generate { .. }
    ));
    let second = service
        .process_ended(ProcessEnd::Exited, later.after_ms(100))
        .expect("the end");
    assert!(
        matches!(second[0], Outcome::Failed { session_id, .. } if session_id == session(1)),
        "{second:?}"
    );
    assert_eq!(service.scheduler().queued(), 0);
    assert_eq!(service.counts().requeued, 1);
    assert_eq!(service.counts().failed, 1);
}

/// KR-REQ-22.21: after a failure the next load waits a second, doubling to five minutes while
/// failures repeat, and a published description resets the wait.
#[test]
fn the_restart_delay_doubles_to_five_minutes_and_a_publication_resets_it() {
    let mut service = service();
    queue(&mut service, &session(1), "kalareach", at(0));
    let mut now = at(3_000);
    let mut expected = RESTART_FIRST_MS;
    for _ in 0..12 {
        assert!(matches!(
            service.next(&roomy(), now).expect("an instruction"),
            Instruction::Load { .. }
        ));
        service
            .process_ended(ProcessEnd::Exited, now)
            .expect("the end");
        assert_eq!(
            service.restart_not_before_ms(),
            Some(now.monotonic_ms() + expected)
        );
        assert!(
            matches!(
                service.next(&roomy(), now.after_ms(expected - 1)).expect("an instruction"),
                Instruction::Wait { until_ms: Some(until) } if until == now.monotonic_ms() + expected
            ),
            "no load before the delay has passed"
        );
        now = now.after_ms(expected);
        expected = (expected * 2).min(RESTART_MOST_MS);
    }
    assert_eq!(expected, RESTART_MOST_MS, "the delay stops at five minutes");

    let Instruction::Generate { id, request, .. } = loaded(&mut service, now) else {
        panic!("the job is sent");
    };
    assert!(matches!(
        service
            .finished(id, produced(&request.prompt, 0), now.after_ms(10))
            .expect("the answer"),
        Outcome::Published { .. }
    ));
    assert_eq!(service.restart_not_before_ms(), None);
}

/// Notes item 77: a description whose job took the process past its memory ceiling stays
/// published, with its latency recorded; the model is unloaded and inference pauses after it. The
/// control is the same job under the ceiling, which leaves the model loaded.
#[test]
fn a_publication_past_the_ceiling_stands_and_the_pause_follows() {
    let ceiling = Budgets::DEFAULTS.process_memory_ceiling_bytes;
    let mut service = service();
    queue(&mut service, &session(1), "kalareach", at(0));
    let Instruction::Generate { id, request, .. } = loaded(&mut service, at(3_000)) else {
        panic!("the job is sent");
    };
    assert!(matches!(
        service
            .finished(id, produced(&request.prompt, ceiling + GIB), at(4_000))
            .expect("the answer"),
        Outcome::Published { session_id, execution_ms: 1_000, .. } if session_id == session(1)
    ));
    assert!(
        service
            .store()
            .generated(&session(1))
            .expect("a read")
            .is_some(),
        "the description stays"
    );
    assert_eq!(
        service
            .latency()
            .reading(1)
            .expect("measured")
            .execution
            .samples,
        1
    );
    assert_eq!(
        service.next(&roomy(), at(4_000)).expect("an instruction"),
        Instruction::Unload {
            why: UnloadReason::Paused(PauseReason::MemoryPressure)
        }
    );
    assert_eq!(
        service.resource_state(),
        ResourceState::ResourcePaused {
            reason: PauseReason::MemoryPressure,
            unloaded: true
        }
    );
    assert!(!service.is_mapped());

    // The control: under the ceiling the model stays and the next job is sent.
    let mut service = self::service();
    queue(&mut service, &session(1), "kalareach", at(0));
    let Instruction::Generate { id, request, .. } = loaded(&mut service, at(3_000)) else {
        panic!("the job is sent");
    };
    assert!(matches!(
        service
            .finished(id, produced(&request.prompt, ceiling - GIB), at(4_000))
            .expect("the answer"),
        Outcome::Published { .. }
    ));
    assert!(service.is_mapped());
    assert!(matches!(
        service.next(&roomy(), at(4_000)).expect("an instruction"),
        Instruction::Wait { .. }
    ));
}

/// A load is cancelled when the reason for it goes: inference turned off, paused, another profile
/// selected, or no work left; each is sent once. The control is a load with its reason intact.
#[test]
fn a_load_is_cancelled_when_its_reason_goes() {
    let hot = HostConditions::measured(
        16 * GIB,
        12 * GIB,
        PowerSource::Mains,
        ThermalState::Critical,
    );
    for case in ["disabled", "paused", "no work"] {
        let mut service = service();
        queue(&mut service, &session(1), "kalareach", at(0));
        let Instruction::Load { id, .. } = service.next(&roomy(), at(3_000)).expect("a load")
        else {
            panic!("a load comes first");
        };
        let conditions = match case {
            "disabled" => {
                service.set_enabled(false);
                roomy()
            }
            "paused" => hot,
            _ => {
                service.session_closed(&session(1), at(3_100));
                roomy()
            }
        };
        assert_eq!(
            service
                .next(&conditions, at(3_200))
                .expect("an instruction"),
            Instruction::Cancel {
                id,
                work: Work::Load
            },
            "{case}"
        );
        assert_eq!(
            service
                .next(&conditions, at(3_300))
                .expect("an instruction"),
            Instruction::Wait { until_ms: None },
            "{case}: the cancellation is sent once"
        );
        assert_eq!(
            service
                .finished(
                    id,
                    Answered::LoadEnded {
                        why: LoadEnd::Cancelled,
                        detail: None
                    },
                    at(3_400)
                )
                .expect("the answer"),
            Outcome::LoadEnded {
                why: LoadEnd::Cancelled,
                detail: None
            }
        );
        assert_eq!(
            service.restart_not_before_ms(),
            None,
            "{case}: a cancel is no failure"
        );
    }

    // The control: a load whose reason stays is waited for.
    let mut service = service();
    queue(&mut service, &session(1), "kalareach", at(0));
    assert!(matches!(
        service.next(&roomy(), at(3_000)).expect("a load"),
        Instruction::Load { .. }
    ));
    assert_eq!(
        service.next(&roomy(), at(60_000)).expect("an instruction"),
        Instruction::Wait { until_ms: None }
    );
}

/// An answer for work that is not in flight is dropped and counted, and changes nothing; so is a
/// second answer to work that has been answered.
#[test]
fn an_answer_for_work_not_in_flight_is_dropped_and_counted() {
    let mut service = service();
    queue(&mut service, &session(1), "kalareach", at(0));
    let Instruction::Generate { id, request, .. } = loaded(&mut service, at(3_000)) else {
        panic!("the job is sent");
    };
    assert_eq!(
        service
            .finished(id + 100, produced(&request.prompt, 0), at(3_100))
            .expect("an answer"),
        Outcome::Dropped { id: id + 100 }
    );
    assert!(matches!(
        service
            .finished(id, produced(&request.prompt, 0), at(3_200))
            .expect("the answer"),
        Outcome::Published { .. }
    ));
    assert_eq!(
        service
            .finished(
                id,
                Answered::Ended {
                    why: JobEnd::Failed,
                    detail: None
                },
                at(3_300)
            )
            .expect("an answer"),
        Outcome::Dropped { id }
    );
    assert_eq!(service.counts().dropped_answers, 2);
    assert_eq!(service.counts().published, 1);
    assert_eq!(service.inference_restarts(), 0);
}

/// KR-REQ-22.21: a job whose token was cancelled is not queued again when its process ends before
/// the service has acted on the cancellation. It ends cancelled: queued again, it would run with a
/// new token that nobody had cancelled. The controls are the same end with nothing cancelled, which
/// queues the job again once, and a pause, which keeps the job's place.
#[test]
fn a_job_cancelled_before_its_process_ends_is_not_retried() {
    let mut cancelled = service();
    queue(&mut cancelled, &session(1), "kalareach", at(0));
    assert!(matches!(
        loaded(&mut cancelled, at(3_000)),
        Instruction::Generate { .. }
    ));
    assert!(cancelled.cancel_running(&session(1)));
    assert_eq!(
        cancelled
            .process_ended(ProcessEnd::Exited, at(3_100))
            .expect("the end"),
        vec![
            Outcome::Cancelled {
                session_id: session(1)
            },
            Outcome::ProcessEnded {
                why: ProcessEnd::Exited
            }
        ]
    );
    assert_eq!(cancelled.scheduler().queued(), 0);
    assert_eq!(cancelled.counts().requeued, 0);
    assert_eq!(cancelled.counts().cancelled, 1);

    // The control: nothing cancelled, and the job is queued again.
    let mut failed = service();
    queue(&mut failed, &session(1), "kalareach", at(0));
    assert!(matches!(
        loaded(&mut failed, at(3_000)),
        Instruction::Generate { .. }
    ));
    assert_eq!(
        failed
            .process_ended(ProcessEnd::Exited, at(3_100))
            .expect("the end")[0],
        Outcome::Requeued {
            session_id: session(1)
        }
    );
    assert_eq!(failed.scheduler().queued(), 1);

    // The control: a pause cancels the job's token too, and the job keeps its place.
    let hot = HostConditions::measured(
        16 * GIB,
        12 * GIB,
        PowerSource::Mains,
        ThermalState::Critical,
    );
    let mut paused = service();
    queue(&mut paused, &session(1), "kalareach", at(0));
    let Instruction::Generate { id, .. } = loaded(&mut paused, at(3_000)) else {
        panic!("the job is sent");
    };
    assert_eq!(
        paused.next(&hot, at(3_050)).expect("an instruction"),
        Instruction::Cancel {
            id,
            work: Work::Job
        }
    );
    assert_eq!(
        paused
            .process_ended(ProcessEnd::Exited, at(3_100))
            .expect("the end")[0],
        Outcome::Requeued {
            session_id: session(1)
        }
    );
    assert_eq!(paused.scheduler().queued(), 1);
    assert_eq!(paused.counts().cancelled, 0);
}

/// KR-PERF-009: every attempt is measured once, however it ends. Its queue wait and execution go
/// into the latency ledger, and its execution into the service time the cadence is worked out
/// from: a job past its deadline, a cancelled job and a job whose process ended count as a
/// published one does. The control is an answer for work not in flight, which measures nothing.
#[test]
fn every_attempt_is_measured_however_it_ends() {
    let deadline = Budgets::DEFAULTS.execution_deadline_ms;
    let cooldown = Budgets::DEFAULTS.session_cooldown_ms;
    let mut service = service();
    let measured = |service: &DescriptionService| {
        let reading = service.latency().reading(1).expect("measured");
        assert_eq!(reading.queue_wait.samples, reading.execution.samples);
        (
            reading.execution.samples,
            reading.execution.max_ms,
            service.scheduler().service_time().samples(),
        )
    };

    // Past its deadline.
    queue(&mut service, &session(1), "kalareach", at(0));
    let Instruction::Generate { id, .. } = loaded(&mut service, at(3_000)) else {
        panic!("the job is sent");
    };
    assert_eq!(
        service
            .finished(
                id,
                Answered::Ended {
                    why: JobEnd::DeadlineExceeded,
                    detail: None
                },
                at(3_000 + deadline)
            )
            .expect("the answer"),
        Outcome::DeadlineExceeded {
            session_id: session(1)
        }
    );
    assert_eq!(measured(&service), (1, deadline, 1));
    assert_eq!(
        service.scheduler().service_time().mean_ms(),
        Some(deadline),
        "the cadence is worked out from what the process was busy for"
    );

    // Cancelled.
    let second = 3_000 + deadline + cooldown;
    change(&mut service, &session(1), "crates", at(second - 2_000));
    assert!(
        service
            .settle(&session(1), Priority::Ordinary, at(second))
            .is_some()
    );
    let Instruction::Generate { id, .. } = service.next(&roomy(), at(second)).expect("a job")
    else {
        panic!("the job is sent");
    };
    assert!(service.cancel_running(&session(1)));
    assert_eq!(
        service
            .finished(
                id,
                Answered::Ended {
                    why: JobEnd::Cancelled,
                    detail: None
                },
                at(second + 700)
            )
            .expect("the answer"),
        Outcome::Cancelled {
            session_id: session(1)
        }
    );
    assert_eq!(measured(&service).0, 2);
    assert_eq!(measured(&service).2, 2);

    // Its process ended.
    let third = second + deadline + cooldown;
    change(&mut service, &session(1), "docs", at(third - 2_000));
    assert!(
        service
            .settle(&session(1), Priority::Ordinary, at(third))
            .is_some()
    );
    assert!(matches!(
        service.next(&roomy(), at(third)).expect("a job"),
        Instruction::Generate { .. }
    ));
    assert_eq!(
        service
            .process_ended(ProcessEnd::Exited, at(third + 400))
            .expect("the end")[0],
        Outcome::Requeued {
            session_id: session(1)
        }
    );
    assert_eq!(measured(&service).0, 3);
    assert_eq!(measured(&service).2, 3);

    // The control: an answer for work not in flight measures nothing.
    assert_eq!(
        service
            .finished(
                id,
                Answered::Ended {
                    why: JobEnd::Failed,
                    detail: None
                },
                at(third + 500)
            )
            .expect("an answer"),
        Outcome::Dropped { id }
    );
    assert_eq!(measured(&service).0, 3);
    assert_eq!(measured(&service).2, 3);
}

/// KR-REQ-22.19: a job stays running until its description is in the store. While its publication
/// waits for the store, a thread holding the running job's handle sees it running, and a
/// cancellation from there either stops the description reaching the store or is told it came too
/// late only once the description is there. A publication the store refuses ends the job with the
/// error, and only then. The control is the handle once each outcome is complete, which has
/// nothing running and nothing in flight.
#[test]
fn a_job_stays_running_until_its_description_is_in_the_store() {
    let root = tempfile::tempdir().expect("a directory");
    let path = root.path().to_path_buf();
    let mut service = service_over(DescriptionStore::open(&path).expect("a store"));
    queue(&mut service, &session(1), "kalareach", at(0));
    let Instruction::Generate { id, request, .. } = loaded(&mut service, at(3_000)) else {
        panic!("the job is sent");
    };
    let other = write_lock(&path);
    let running = service.running_job().clone();
    let watching = {
        let path = path.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            let while_waiting = running.is_running(&session(1));
            let stopped = running.cancel(&session(1));
            let stored = DescriptionStore::open(&path)
                .expect("a third connection")
                .generated(&session(1))
                .expect("a read")
                .is_some();
            (while_waiting, stopped, stored)
        })
    };
    let committing = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(900));
        other
            .execute_batch("COMMIT")
            .expect("the write lock is released");
    });
    let outcome = service
        .finished(id, produced(&request.prompt, 0), at(3_500))
        .expect("the answer");
    committing.join().expect("the committing thread");
    let (while_waiting, stopped, stored) = watching.join().expect("the watching thread");
    assert!(while_waiting, "the job runs while its publication waits");
    if stopped {
        assert_eq!(
            outcome,
            Outcome::Cancelled {
                session_id: session(1)
            }
        );
        assert!(!stored, "a cancellation in time stops the write");
    } else {
        assert!(matches!(outcome, Outcome::Published { .. }), "{outcome:?}");
        assert!(stored, "too late only once the description is in the store");
    }
    // The control: with the outcome complete, nothing is running or in flight.
    assert!(!service.running_job().is_running(&session(1)));
    assert_eq!(service.in_flight(), 0);

    // A publication the store refuses: the job runs until the store gives up, and then ends.
    change(&mut service, &session(1), "crates", at(40_000));
    assert!(
        service
            .settle(&session(1), Priority::Ordinary, at(42_000))
            .is_some()
    );
    let Instruction::Generate { id, request, .. } =
        service.next(&roomy(), at(42_000)).expect("a job")
    else {
        panic!("the job is sent");
    };
    let other = write_lock(&path);
    let running = service.running_job().clone();
    let watching = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        running.is_running(&session(1))
    });
    let refused = service.finished(id, produced(&request.prompt, 0), at(42_500));
    other
        .execute_batch("ROLLBACK")
        .expect("the write lock is released");
    assert!(refused.is_err(), "{refused:?}");
    assert!(
        watching.join().expect("the watching thread"),
        "the job runs while the store is waited for"
    );
    assert!(!service.running_job().is_running(&session(1)));
    assert_eq!(service.in_flight(), 0);
}

/// KR-REQ-22.16: a long active turn still gets text. A session's intent changes every tenth of a
/// second for four minutes, and each job takes five seconds, longer than the debounce. A job whose
/// change settles under it is refused and cancelled, but the job after it runs to its end while the
/// changes wait for it, so descriptions are published all through the turn, one for each job
/// superseded. The control is the same session changing once, whose job is never superseded.
#[test]
fn a_long_active_turn_is_described_while_it_keeps_changing() {
    let (published, superseded) = active_turn(5_000, true);
    assert!(
        published >= 3,
        "{published} published and {superseded} superseded in four minutes"
    );
    assert!(
        superseded >= 3,
        "a job whose change settled under it is still refused: {superseded}"
    );
    assert!(
        published.abs_diff(superseded) <= 1,
        "the job after a superseded one publishes: {published} published, {superseded} superseded"
    );

    // The control: a session that changes once is described once, and nothing is superseded.
    assert_eq!(active_turn(5_000, false), (1, 0));
}

/// Drives one session for four minutes, whose intent changes every 100 ms when `changing` and only
/// at the start otherwise, with a process that answers each job `job_ms` after it is sent and a
/// cancellation at once, and counts the jobs published and the jobs superseded.
fn active_turn(job_ms: u64, changing: bool) -> (u32, u32) {
    let mut service = service();
    service.session_opened(session(1), SessionEpoch::V1, binding());
    // The job in the process: its identifier, when it was sent, its prompt, and whether it was
    // told to cancel.
    let mut running: Option<(u64, u64, String, bool)> = None;
    let (mut published, mut superseded) = (0, 0);
    for step in 0..2_400_u64 {
        let now = at(step * 100);
        if changing || step == 0 {
            service.observe(
                &session(1),
                ContextSignal::TaskIntent(format!("step {step} of the turn")),
                now,
            );
        }
        let _ = service.settle(&session(1), Priority::Foreground, now);
        let answer = match &running {
            Some((_, _, _, true)) => Some(Answered::Ended {
                why: JobEnd::Cancelled,
                detail: None,
            }),
            Some((_, sent_at, prompt, false)) if now.monotonic_ms() >= sent_at + job_ms => {
                Some(produced(prompt, 0))
            }
            _ => None,
        };
        if let (Some(answer), Some((id, ..))) = (answer, running.clone()) {
            running = None;
            match service.finished(id, answer, now).expect("the answer") {
                Outcome::Published { .. } => published += 1,
                Outcome::Cancelled { .. }
                | Outcome::Rejected {
                    rejection: Rejection::ChangedContext { .. },
                    ..
                } => superseded += 1,
                other => panic!("a job in the turn ended {other:?}"),
            }
        }
        loop {
            match service.next(&roomy(), now).expect("an instruction") {
                Instruction::Load { id, .. } => {
                    service
                        .finished(
                            id,
                            Answered::Loaded {
                                load_ms: 0,
                                rss_bytes: 0,
                            },
                            now,
                        )
                        .expect("the load");
                }
                Instruction::Generate { id, request, .. } => {
                    running = Some((id, now.monotonic_ms(), request.prompt, false));
                }
                Instruction::Cancel { id, .. } => {
                    let job = running.as_mut().expect("the job being cancelled");
                    assert_eq!(job.0, id);
                    job.3 = true;
                }
                Instruction::Wait { .. } => break,
                Instruction::Unload { why } => panic!("the model was unloaded: {why:?}"),
            }
        }
    }
    (published, superseded)
}

/// KR-REQ-22.21: a cancellation is honoured or refused, never both. The service closes the running
/// job's handle at the moment it decides what a job that did not finish comes to, so a caller that
/// cancels after that moment is told nothing was running, and the job it could not reach is queued
/// again. The control is a caller that cancels before it, which is honoured: the job ends
/// cancelled and is not queued again.
#[test]
fn a_cancellation_is_honoured_or_refused_at_the_moment_a_job_is_decided() {
    let mut service = service();
    queue(&mut service, &session(1), "kalareach", at(0));
    assert!(matches!(
        loaded(&mut service, at(3_000)),
        Instruction::Generate { .. }
    ));
    let told = std::rc::Rc::new(std::cell::Cell::new(None));
    {
        let told = std::rc::Rc::clone(&told);
        let running = service.running_job().clone();
        at_next_decision(move || told.set(Some(running.cancel(&session(1)))));
    }
    let ended = service
        .process_ended(ProcessEnd::Exited, at(3_100))
        .expect("the end");
    assert_eq!(
        told.get(),
        Some(false),
        "a cancellation after the decision finds nothing running"
    );
    assert_eq!(
        ended[0],
        Outcome::Requeued {
            session_id: session(1)
        }
    );
    assert_eq!(service.scheduler().queued(), 1);

    // The control: a cancellation before the decision is honoured.
    let mut service = self::service();
    queue(&mut service, &session(1), "kalareach", at(0));
    assert!(matches!(
        loaded(&mut service, at(3_000)),
        Instruction::Generate { .. }
    ));
    assert!(service.cancel_running(&session(1)));
    assert_eq!(
        service
            .process_ended(ProcessEnd::Exited, at(3_100))
            .expect("the end")[0],
        Outcome::Cancelled {
            session_id: session(1)
        }
    );
    assert_eq!(service.scheduler().queued(), 0);
}

/// KR-REQ-22.21: a caller's cancellation outlasts a pause. A job a pause has already stopped, which
/// a caller then cancels, ends cancelled rather than going back in the queue, whether its process
/// answers the cancellation or ends first, and nothing is described when the pause clears. The
/// control is the same pause with no caller: the job keeps its place and is described after.
#[test]
fn a_caller_cancellation_outlasts_a_pause() {
    let hot = HostConditions::measured(
        16 * GIB,
        12 * GIB,
        PowerSource::Mains,
        ThermalState::Critical,
    );
    for crash in [false, true] {
        let mut service = service();
        queue(&mut service, &session(1), "kalareach", at(0));
        let Instruction::Generate { id, .. } = loaded(&mut service, at(3_000)) else {
            panic!("the job is sent");
        };
        assert_eq!(
            service.next(&hot, at(3_050)).expect("an instruction"),
            Instruction::Cancel {
                id,
                work: Work::Job
            }
        );
        assert!(
            service.cancel_running(&session(1)),
            "the caller is told it stopped the job"
        );
        let outcome = if crash {
            service
                .process_ended(ProcessEnd::Exited, at(3_100))
                .expect("the end")
                .remove(0)
        } else {
            service
                .finished(
                    id,
                    Answered::Ended {
                        why: JobEnd::Cancelled,
                        detail: None,
                    },
                    at(3_100),
                )
                .expect("the answer")
        };
        assert_eq!(
            outcome,
            Outcome::Cancelled {
                session_id: session(1)
            },
            "crash {crash}"
        );
        assert_eq!(service.scheduler().queued(), 0, "crash {crash}");
        // The pause clears, and nothing is described.
        let later = service.next(&roomy(), at(40_000)).expect("an instruction");
        assert!(
            !matches!(
                later,
                Instruction::Load { .. } | Instruction::Generate { .. }
            ),
            "crash {crash}: {later:?}"
        );
        assert_eq!(service.counts().published, 0);
    }

    // The control: a pause alone keeps the job's place, and it is described when the pause clears.
    let mut service = service();
    queue(&mut service, &session(1), "kalareach", at(0));
    let Instruction::Generate { id, .. } = loaded(&mut service, at(3_000)) else {
        panic!("the job is sent");
    };
    assert!(matches!(
        service.next(&hot, at(3_050)).expect("an instruction"),
        Instruction::Cancel { .. }
    ));
    assert_eq!(
        service
            .finished(
                id,
                Answered::Ended {
                    why: JobEnd::Cancelled,
                    detail: None,
                },
                at(3_100),
            )
            .expect("the answer"),
        Outcome::Requeued {
            session_id: session(1)
        }
    );
    let (now, id, request) = next_job(&mut service, at(40_000));
    assert!(matches!(
        service
            .finished(id, produced(&request.prompt, 0), now.after_ms(500))
            .expect("the answer"),
        Outcome::Published { .. }
    ));
}

/// Does what the service says, loading when it asks and letting time pass when it waits, until it
/// sends a job, and returns when, with the job.
fn next_job(
    service: &mut DescriptionService,
    from: Reading,
) -> (Reading, u64, kr_describe::service::GenerationRequest) {
    let mut now = from;
    loop {
        match service.next(&roomy(), now).expect("an instruction") {
            Instruction::Load { id, .. } => {
                service
                    .finished(
                        id,
                        Answered::Loaded {
                            load_ms: 0,
                            rss_bytes: 0,
                        },
                        now,
                    )
                    .expect("the load");
            }
            Instruction::Generate { id, request, .. } => return (now, id, request),
            Instruction::Unload { .. } | Instruction::Cancel { .. } => {}
            Instruction::Wait { .. } => {
                assert!(
                    now.monotonic_ms() < from.monotonic_ms() + 400_000,
                    "no job was sent"
                );
                now = now.after_ms(1_000);
            }
        }
    }
}

/// A superseded job whose session closes, or opens again, before its answer arrives leaves no
/// mark on the session there now, and a session opened again after it owes it nothing: the first
/// job of the session there now is superseded by a change that settles under it, as any job is.
/// The control is the same session left open, whose job after a superseded one runs to its end
/// while the change waits for it.
#[test]
fn a_superseded_job_that_outlives_its_session_leaves_no_mark() {
    let cooldown = Budgets::DEFAULTS.session_cooldown_ms;
    for case in ["closed", "opened again", "replaced", "left open"] {
        let mut service = service();
        queue(&mut service, &session(1), "kalareach", at(0));
        let Instruction::Generate { id, .. } = loaded(&mut service, at(3_000)) else {
            panic!("the job is sent");
        };
        change(&mut service, &session(1), "crates", at(3_100));
        assert!(
            service
                .settle(&session(1), Priority::Ordinary, at(5_100))
                .is_some()
        );
        assert_eq!(
            service.next(&roomy(), at(5_100)).expect("an instruction"),
            Instruction::Cancel {
                id,
                work: Work::Job
            },
            "{case}"
        );
        if matches!(case, "closed" | "opened again") {
            service.session_closed(&session(1), at(5_150));
        }
        if case == "opened again" {
            queue(&mut service, &session(1), "docs", at(5_200));
        }
        service
            .finished(
                id,
                Answered::Ended {
                    why: JobEnd::Cancelled,
                    detail: None,
                },
                at(7_300),
            )
            .expect("the answer");
        match case {
            "closed" => queue(&mut service, &session(1), "docs", at(7_400)),
            "replaced" => {
                service.session_opened(session(1), SessionEpoch::new(2), binding());
                change(&mut service, &session(1), "docs", at(7_400));
                assert!(
                    service
                        .settle(&session(1), Priority::Ordinary, at(9_400))
                        .is_some()
                );
            }
            _ => {}
        }
        // A closed session's queue position went with it; the others wait out the cooldown.
        let next = if matches!(case, "closed" | "opened again") {
            at(9_400)
        } else {
            at(3_000 + cooldown)
        };
        let Instruction::Generate { id, .. } = service.next(&roomy(), next).expect("a job") else {
            panic!("{case}: the next job is sent");
        };
        change(&mut service, &session(1), "tests", next.after_ms(100));
        let settled = service.settle(&session(1), Priority::Ordinary, next.after_ms(2_100));
        let instruction = service
            .next(&roomy(), next.after_ms(2_100))
            .expect("an instruction");
        if case == "left open" {
            assert_eq!(
                settled, None,
                "{case}: the change waits for the job after a superseded one"
            );
            assert!(
                matches!(instruction, Instruction::Wait { .. }),
                "{case}: {instruction:?}"
            );
        } else {
            assert!(
                settled.is_some(),
                "{case}: the session there now owes nothing to the old job"
            );
            assert_eq!(
                instruction,
                Instruction::Cancel {
                    id,
                    work: Work::Job
                },
                "{case}"
            );
        }
    }
}

/// A job that outlived its session publishes nothing and never comes back, however the session
/// there now is identified. Its answer, arriving after the session closed and opened again under
/// the same epoch and binding with a new directory already at revision 1, is refused; a crash after
/// the session opened again under a new epoch ends it rather than queueing it, and the session
/// there now is not protected by it; a job a pause stopped, whose session then closed or opened
/// again, is not queued again. The controls are the same answer and the same crash with the session left alone,
/// which publish and queue the job again.
#[test]
fn an_outlived_job_neither_publishes_nor_comes_back() {
    // The answer, after the session closed and opened again.
    for reopened in [true, false] {
        let mut service = service();
        queue(&mut service, &session(1), "kalareach", at(0));
        let Instruction::Generate { id, request, .. } = loaded(&mut service, at(3_000)) else {
            panic!("the job is sent");
        };
        if reopened {
            service.session_closed(&session(1), at(3_100));
            queue(&mut service, &session(1), "docs", at(3_200));
            assert_eq!(service.revision(&session(1)), Some(ContextRevision::new(1)));
        }
        let outcome = service
            .finished(id, produced(&request.prompt, 0), at(5_300))
            .expect("the answer");
        if reopened {
            assert_eq!(
                outcome,
                Outcome::Rejected {
                    session_id: session(1),
                    rejection: Rejection::SessionClosed
                }
            );
            assert!(
                service
                    .store()
                    .generated(&session(1))
                    .expect("a read")
                    .is_none()
            );
        } else {
            assert!(matches!(outcome, Outcome::Published { .. }), "{outcome:?}");
        }
    }

    // A crash, after the session opened again under a new epoch.
    for reopened in [true, false] {
        let mut service = service();
        queue(&mut service, &session(1), "kalareach", at(0));
        assert!(matches!(
            loaded(&mut service, at(3_000)),
            Instruction::Generate { .. }
        ));
        if reopened {
            service.session_opened(session(1), SessionEpoch::new(2), binding());
        }
        let ended = service
            .process_ended(ProcessEnd::Exited, at(3_100))
            .expect("the end");
        if !reopened {
            assert_eq!(
                ended[0],
                Outcome::Requeued {
                    session_id: session(1)
                }
            );
            continue;
        }
        assert_eq!(
            ended[0],
            Outcome::Cancelled {
                session_id: session(1)
            }
        );
        assert_eq!(
            service.scheduler().queued(),
            0,
            "the old job is not queued again"
        );
        // The session there now: its first job is superseded by a change that settles under it.
        change(&mut service, &session(1), "docs", at(3_200));
        assert!(
            service
                .settle(&session(1), Priority::Ordinary, at(5_200))
                .is_some()
        );
        // The identifier's cooldown still runs from the old job's dispatch.
        let now = at(3_000 + Budgets::DEFAULTS.session_cooldown_ms);
        let Instruction::Generate { id, .. } = loaded(&mut service, now) else {
            panic!("the session's first job is sent");
        };
        change(&mut service, &session(1), "tests", now.after_ms(100));
        assert!(
            service
                .settle(&session(1), Priority::Ordinary, now.after_ms(2_100))
                .is_some(),
            "nothing the old job went through protects this one"
        );
        assert_eq!(
            service
                .next(&roomy(), now.after_ms(2_100))
                .expect("an instruction"),
            Instruction::Cancel {
                id,
                work: Work::Job
            }
        );
    }

    // A pause, then the session closes, or opens again.
    let hot = HostConditions::measured(
        16 * GIB,
        12 * GIB,
        PowerSource::Mains,
        ThermalState::Critical,
    );
    for closed in [true, false] {
        let mut service = service();
        queue(&mut service, &session(1), "kalareach", at(0));
        let Instruction::Generate { id, .. } = loaded(&mut service, at(3_000)) else {
            panic!("the job is sent");
        };
        assert!(matches!(
            service.next(&hot, at(3_050)).expect("an instruction"),
            Instruction::Cancel { .. }
        ));
        if closed {
            service.session_closed(&session(1), at(3_060));
        } else {
            service.session_opened(session(1), SessionEpoch::new(2), binding());
        }
        assert_eq!(
            service
                .finished(
                    id,
                    Answered::Ended {
                        why: JobEnd::Cancelled,
                        detail: None,
                    },
                    at(3_100),
                )
                .expect("the answer"),
            Outcome::Cancelled {
                session_id: session(1)
            },
            "closed {closed}"
        );
        assert_eq!(service.scheduler().queued(), 0, "closed {closed}");
    }
}

/// KR-REQ-22.19: a session opened again before its queued job is sent starts afresh. The job built
/// from its earlier context is dropped rather than sent, so a change that then settles as the same
/// revision number is described from what the session is now, and nothing of the earlier context is
/// published. The control is the same queued job with the session left alone, which is sent and
/// describes its directory.
#[test]
fn a_session_opened_again_before_its_job_is_sent_drops_that_job() {
    for reopened in [true, false] {
        let mut service = service();
        queue(&mut service, &session(1), "kalareach", at(0));
        if reopened {
            service.session_opened(session(1), SessionEpoch::V1, binding());
            assert!(
                matches!(
                    service.next(&roomy(), at(2_100)).expect("an instruction"),
                    Instruction::Wait { .. }
                ),
                "nothing from the earlier context is sent"
            );
            change(&mut service, &session(1), "docs", at(2_200));
            assert!(
                service
                    .settle(&session(1), Priority::Ordinary, at(4_200))
                    .is_some()
            );
            assert_eq!(service.revision(&session(1)), Some(ContextRevision::new(1)));
        }
        let (now, id, request) = next_job(&mut service, at(5_000));
        assert!(matches!(
            service
                .finished(id, produced(&request.prompt, 0), now.after_ms(500))
                .expect("the answer"),
            Outcome::Published { .. }
        ));
        let described = service
            .store()
            .generated(&session(1))
            .expect("a read")
            .expect("a description");
        assert_eq!(
            described.title.as_str(),
            if reopened { "docs" } else { "kalareach" },
            "reopened {reopened}"
        );
    }
}

/// KR-REQ-22.21: a session opened again owes nothing to an earlier failure: the retry its old
/// job was queued for is dropped with that job, and its own first job, when its process fails, is
/// queued again once like any other. The control is the same failure with the session left alone,
/// whose retry fails for good.
#[test]
fn a_session_opened_again_owes_nothing_to_an_earlier_failure() {
    for reopened in [true, false] {
        let mut service = service();
        queue(&mut service, &session(1), "kalareach", at(0));
        assert!(matches!(
            loaded(&mut service, at(3_000)),
            Instruction::Generate { .. }
        ));
        assert_eq!(
            service
                .process_ended(ProcessEnd::Exited, at(3_100))
                .expect("the end")[0],
            Outcome::Requeued {
                session_id: session(1)
            }
        );
        if reopened {
            service.session_opened(session(1), SessionEpoch::new(2), binding());
            assert_eq!(
                service.scheduler().queued(),
                0,
                "the retry goes with its job"
            );
            change(&mut service, &session(1), "docs", at(3_200));
            assert!(
                service
                    .settle(&session(1), Priority::Ordinary, at(5_200))
                    .is_some()
            );
        }
        let from = if reopened {
            at(3_000 + Budgets::DEFAULTS.session_cooldown_ms)
        } else {
            at(3_100 + RESTART_FIRST_MS)
        };
        let (now, _, _) = next_job(&mut service, from);
        let ended = service
            .process_ended(ProcessEnd::Exited, now.after_ms(100))
            .expect("the end");
        if reopened {
            assert_eq!(
                ended[0],
                Outcome::Requeued {
                    session_id: session(1)
                },
                "the session's own first failure is retried"
            );
        } else {
            assert!(
                matches!(ended[0], Outcome::Failed { .. }),
                "the retry fails for good: {ended:?}"
            );
        }
    }
}

/// KR-REQ-22.21: a job is retried once after a failure, however many pauses come between. A job
/// that failed, was sent again, was stopped by a pause and sent once more after it, ends failed
/// when its process fails a second time. The control is its first failure, which queues it again.
#[test]
fn a_pause_between_a_failure_and_its_retry_keeps_the_retry_used() {
    let hot = HostConditions::measured(
        16 * GIB,
        12 * GIB,
        PowerSource::Mains,
        ThermalState::Critical,
    );
    let mut service = service();
    queue(&mut service, &session(1), "kalareach", at(0));
    assert!(matches!(
        loaded(&mut service, at(3_000)),
        Instruction::Generate { .. }
    ));
    // The control: the first failure queues the job again.
    assert_eq!(
        service
            .process_ended(ProcessEnd::Exited, at(3_100))
            .expect("the end")[0],
        Outcome::Requeued {
            session_id: session(1)
        }
    );
    // The retry is sent, and a pause stops it.
    let (now, id, _) = next_job(&mut service, at(3_100 + RESTART_FIRST_MS));
    assert_eq!(
        service
            .next(&hot, now.after_ms(50))
            .expect("an instruction"),
        Instruction::Cancel {
            id,
            work: Work::Job
        }
    );
    assert_eq!(
        service
            .finished(
                id,
                Answered::Ended {
                    why: JobEnd::Cancelled,
                    detail: None,
                },
                now.after_ms(100),
            )
            .expect("the answer"),
        Outcome::Requeued {
            session_id: session(1)
        }
    );
    // The pause clears, the job is sent once more, and its process fails again.
    let (now, _, _) = next_job(&mut service, now.after_ms(60_000));
    let ended = service
        .process_ended(ProcessEnd::Exited, now.after_ms(100))
        .expect("the end");
    assert!(
        matches!(ended[0], Outcome::Failed { session_id, .. } if session_id == session(1)),
        "{ended:?}"
    );
    assert_eq!(service.scheduler().queued(), 0);
}

/// KR-REQ-24.11: a job that was dispatched while a fence was being raised is stopped at the next
/// look. A fence raised from another thread cancels the running job's token, and a job whose token
/// is not registered yet has none to cancel; so the service stops a running job whose session is
/// fenced itself. The control is the same job with no fence, which runs on.
#[test]
fn a_job_whose_session_was_fenced_as_it_was_dispatched_is_cancelled_at_the_next_look() {
    for fenced in [false, true] {
        let mut service = service();
        queue(&mut service, &session(1), "kalareach", at(0));
        let (sent, id, _) = next_job(&mut service, at(3_000));
        if fenced {
            // Raised without the cancellation that would have found the job's token.
            service
                .fence()
                .raise(session(1), kr_worker::privacy::PrivacyGeneration::new(1));
        }
        let next = service
            .next(&roomy(), sent.after_ms(10))
            .expect("an instruction");
        if fenced {
            assert_eq!(
                next,
                Instruction::Cancel {
                    id,
                    work: Work::Job
                }
            );
            assert_eq!(
                service.next(&roomy(), sent.after_ms(20)).expect("a wait"),
                Instruction::Wait { until_ms: None },
                "the cancellation is sent once"
            );
        } else {
            assert_eq!(next, Instruction::Wait { until_ms: None }, "left alone");
        }
    }
}

/// KR-REQ-22.16: a semantic event is a change of the context. One that arrives with nothing else
/// moved starts the debounce, and a job follows it; the same event again is the event already
/// held, and starts nothing.
#[test]
fn a_new_semantic_event_starts_the_debounce_and_the_same_one_again_does_not() {
    let event = |cursor: u64| SemanticEvent {
        cursor,
        kind: SemanticEventKind::CommandAccepted,
        summary: ProjectText::new("cargo").expect("a summary"),
    };
    let mut service = service();
    service.session_opened(session(1), SessionEpoch::V1, binding());
    change(&mut service, &session(1), "docs", at(0));
    assert!(
        service
            .settle(&session(1), Priority::Ordinary, at(2_000))
            .is_some()
    );
    assert_eq!(service.settle_due_ms(), None, "nothing waits");

    assert!(service.note_event(&session(1), event(1), at(10_000)));
    assert_eq!(
        service.settle_due_ms(),
        Some(10_000 + 2_000),
        "the event waits out the debounce"
    );
    assert!(
        service
            .settle(&session(1), Priority::Ordinary, at(12_000))
            .is_some()
    );

    assert!(service.note_event(&session(1), event(1), at(20_000)));
    assert_eq!(
        service.settle_due_ms(),
        None,
        "the control: an event already held"
    );
}

/// KR-REQ-22.16: a session opened again starts with no semantic events of its earlier self. An
/// event recorded before the session is opened again, without a close between, reaches no prompt
/// of the session there now. The control is the same session left alone, whose next prompt
/// carries the event.
#[test]
fn a_session_opened_again_carries_no_earlier_events() {
    for reopened in [true, false] {
        let mut service = service();
        service.session_opened(session(1), SessionEpoch::V1, binding());
        assert!(service.note_event(
            &session(1),
            SemanticEvent {
                cursor: 1,
                kind: SemanticEventKind::CommandAccepted,
                summary:
                    ProjectText::new("cargo publish from the earlier session").expect("a summary"),
            },
            at(0),
        ));
        if reopened {
            service.session_opened(session(1), SessionEpoch::V1, binding());
        }
        change(&mut service, &session(1), "docs", at(0));
        assert!(
            service
                .settle(&session(1), Priority::Ordinary, at(2_000))
                .is_some()
        );
        let (_, _, request) = next_job(&mut service, at(3_000));
        assert_eq!(
            request
                .prompt
                .contains("cargo publish from the earlier session"),
            !reopened,
            "reopened {reopened}: {}",
            request.prompt
        );
        assert!(request.prompt.contains("docs"), "{}", request.prompt);
    }
}

/// A host that fetches its files says they are not held until they have been checked: nothing is
/// loaded and the state says `not_downloaded`, and a model that is loaded when they go is let go.
/// The control is the same service with its files held, which loads.
#[test]
fn without_the_files_nothing_loads_and_the_state_says_why() {
    let mut service = service();
    service.set_assets_held(false);
    queue(&mut service, &session(1), "kalareach", at(0));
    assert_eq!(
        service.next(&roomy(), at(3_000)).expect("an instruction"),
        Instruction::Wait { until_ms: None }
    );
    assert_eq!(
        service.resource_state(),
        ResourceState::ResourcePaused {
            reason: PauseReason::NotDownloaded,
            unloaded: false
        }
    );
    assert!(!service.is_loading());

    // Held, the same queue loads.
    service.set_assets_held(true);
    let Instruction::Load { id, .. } = service.next(&roomy(), at(3_000)).expect("an instruction")
    else {
        panic!("a load comes first once the files are held");
    };
    assert!(service.is_loading(), "the load is in the process");
    service
        .finished(
            id,
            Answered::Loaded {
                load_ms: 0,
                rss_bytes: 0,
            },
            at(3_000),
        )
        .expect("the load");
    assert!(!service.is_loading(), "the load is over");

    // A model that is loaded when the files go is let go, and the state says why.
    service.set_assets_held(false);
    assert_eq!(
        service.next(&roomy(), at(3_100)).expect("an instruction"),
        Instruction::Unload {
            why: UnloadReason::Paused(PauseReason::NotDownloaded)
        }
    );
    assert_eq!(
        service.resource_state(),
        ResourceState::ResourcePaused {
            reason: PauseReason::NotDownloaded,
            unloaded: true
        }
    );
}

/// Three failures in a row, none followed by a publication, leave inference failed while the
/// restart delay runs: three jobs that failed here, and two do not. A description published starts
/// the count again. The control is the state after two, and the fourth failure with no
/// publication in between, which shows it at once.
#[test]
fn three_failures_in_a_row_leave_inference_failed_until_a_description_is_published() {
    let failed = |service: &DescriptionService| {
        matches!(
            service.resource_state(),
            ResourceState::ResourcePaused {
                reason: PauseReason::InferenceFailed,
                ..
            }
        )
    };
    let mut service = service();
    queue(&mut service, &session(1), "kalareach", at(0));
    queue(&mut service, &session(2), "crates", at(0));
    let mut now = at(3_000);
    for failures in 1..=2 {
        let (sent, id, _) = next_job(&mut service, now);
        now = sent;
        service
            .finished(
                id,
                Answered::Ended {
                    why: JobEnd::Failed,
                    detail: None,
                },
                now,
            )
            .expect("the answer");
        service.next(&roomy(), now).expect("the unload");
        service.next(&roomy(), now).expect("the wait");
        assert!(!failed(&service), "after {failures} failures");
    }
    let (sent, id, _) = next_job(&mut service, now);
    now = sent;
    service
        .finished(
            id,
            Answered::Ended {
                why: JobEnd::Failed,
                detail: None,
            },
            now,
        )
        .expect("the answer");
    service.next(&roomy(), now).expect("the unload");
    service.next(&roomy(), now).expect("the wait");
    assert!(failed(&service), "after three");

    // The delay passes and a description is published: the count starts again, so one more
    // failure does not show it, and neither do two; a third does.
    let (sent, id, request) = next_job(&mut service, now);
    now = sent;
    assert!(matches!(
        service
            .finished(id, produced(&request.prompt, 0), now)
            .expect("the answer"),
        Outcome::Published { .. }
    ));
    for failures in 1..=3_u8 {
        queue(&mut service, &session(10 + failures), "again", now);
        let (sent, id, _) = next_job(&mut service, now);
        now = sent;
        service
            .finished(
                id,
                Answered::Ended {
                    why: JobEnd::Failed,
                    detail: None,
                },
                now,
            )
            .expect("the answer");
        service.next(&roomy(), now).expect("the unload");
        service.next(&roomy(), now).expect("the wait");
        assert_eq!(
            failed(&service),
            failures == 3,
            "{failures} failures after the publication"
        );
    }
}

/// The control for the count a publication starts again: with no publication between, the fourth
/// failure in a row shows inference failed at once.
#[test]
fn without_a_publication_the_fourth_failure_in_a_row_shows_inference_failed_at_once() {
    let mut service = service();
    let mut now = at(3_000);
    for session_number in 1..=4_u8 {
        queue(&mut service, &session(session_number), "kalareach", now);
        let (sent, id, _) = next_job(&mut service, now);
        now = sent;
        service
            .finished(
                id,
                Answered::Ended {
                    why: JobEnd::Failed,
                    detail: None,
                },
                now,
            )
            .expect("the answer");
        service.next(&roomy(), now).expect("the unload");
        service.next(&roomy(), now).expect("the wait");
    }
    assert!(inference_failed(&service), "after four");
}

/// An end the daemon causes to stop work it called off is no failure of inference, and one that
/// shows the process failing is: a load that was told to stop, said it had read it and did not stop
/// is ended without a failure, and the next load waits a moment; a check of a file that ran past
/// its deadline is no failure and delays nothing; a cancellation nothing acknowledged, and a
/// process that ended by itself, are failures. Three ends of the first two kinds in a row leave
/// inference not failed, where three of either of the others do.
#[test]
fn an_end_the_daemon_causes_to_stop_called_off_work_is_no_failure_of_inference() {
    let failed = |service: &DescriptionService| {
        matches!(
            service.resource_state(),
            ResourceState::ResourcePaused {
                reason: PauseReason::InferenceFailed,
                ..
            }
        )
    };
    // The end, whether a load was told to stop first, whether it is a failure of inference, and
    // whether the next load is delayed by it.
    for (why, load, failure, delayed) in [
        (ProcessEnd::StopOverdue, true, false, true),
        (ProcessEnd::CheckOverdue, false, false, false),
        (ProcessEnd::CancelUnanswered, true, true, true),
        (ProcessEnd::Exited, true, true, true),
    ] {
        let mut service = service();
        queue(&mut service, &session(1), "kalareach", at(0));
        let mut now = at(3_000);
        for round in 1..=3_u32 {
            if load {
                let Instruction::Load { id, .. } = service.next(&roomy(), now).expect("a step")
                else {
                    panic!("{why:?}: a load comes first, round {round}");
                };
                service.set_enabled(false);
                assert_eq!(
                    service.next(&roomy(), now.after_ms(100)).expect("a step"),
                    Instruction::Cancel {
                        id,
                        work: Work::Load
                    }
                );
            }
            let ended = now.after_ms(200);
            let outcomes = service.process_ended(why, ended).expect("the end");
            if load {
                assert!(
                    outcomes.contains(&Outcome::LoadEnded {
                        why: if why == ProcessEnd::Exited {
                            LoadEnd::Failed
                        } else {
                            LoadEnd::Cancelled
                        },
                        detail: Some(format!("the description process ended: {}", why.as_str())),
                    }),
                    "{why:?}: {outcomes:?}"
                );
            }
            assert!(!service.is_loading(), "{why:?}");
            assert_eq!(
                service.inference_restarts(),
                u64::from(failure) * u64::from(round),
                "{why:?}, round {round}"
            );
            if round == 1 {
                assert_eq!(
                    service.restart_not_before_ms(),
                    delayed.then_some(ended.monotonic_ms() + RESTART_FIRST_MS),
                    "{why:?}: the next load's delay"
                );
            }
            service.set_enabled(true);
            if load {
                // Inside the delay nothing is loaded, and the state says whether inference failed.
                assert!(
                    matches!(
                        service.next(&roomy(), ended.after_ms(1)).expect("a step"),
                        Instruction::Wait { until_ms: Some(_) }
                    ),
                    "{why:?}, round {round}: the next load waits"
                );
            }
            assert_eq!(
                failed(&service),
                failure && round == 3,
                "{why:?}: inference_failed after {round}"
            );
            // Past the delay, whatever it was.
            now = ended.after_ms(10 * 60 * 1_000);
        }
    }
}

/// What a test holds publications under: it admits them or it does not, and says whether the write
/// ran inside it.
struct Gate {
    admits: bool,
    /// Whether it admits a job's registration; a test of publications leaves it on.
    dispatches: bool,
    ran: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// The service's own records of work in flight, which the gate reads to say where a job is
    /// registered.
    handles: kr_describe::service::Handles,
}

impl kr_describe::service::PublicationGate for Gate {
    fn admit_dispatch(
        &self,
        _generation: kr_worker::privacy::PrivacyGeneration,
        register: &mut dyn FnMut(),
    ) {
        if self.dispatches {
            assert_eq!(
                self.handles.in_flight.total(),
                0,
                "no job is registered before the gate runs the registration"
            );
            register();
            // Inside the gate, where privacy mode's change waits for it: the job is in flight and
            // has the token that cancels it.
            assert_eq!(
                self.handles.in_flight.total(),
                1,
                "registered inside the gate"
            );
            assert!(
                self.handles.running.is_running(&session(1)),
                "the job has its cancellation token inside the gate"
            );
        }
    }

    fn hold(
        &self,
        _generation: kr_worker::privacy::PrivacyGeneration,
        publish: &mut dyn FnMut() -> kr_describe::Result<kr_describe::privacy::PublishGate>,
    ) -> Option<kr_describe::Result<kr_describe::privacy::PublishGate>> {
        self.admits.then(|| {
            self.ran.store(true, std::sync::atomic::Ordering::SeqCst);
            publish()
        })
    }
}

/// KR-REQ-24.11: a job is registered as in flight inside the gate, and not at all when the gate
/// admits none: the job is dropped from the queue and counted as cancelled, nothing is sent and
/// nothing is in flight, so no job starts once privacy mode is published. The control is a
/// service with no gate, and one whose gate admits, which send the job.
#[test]
fn a_job_is_registered_inside_its_gate_and_never_sent_when_none_admits_it() {
    for case in ["no gate", "admitting", "refusing"] {
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut service = service();
        if case != "no gate" {
            service.set_publication_gate(Box::new(Gate {
                admits: true,
                dispatches: case == "admitting",
                ran: ran.clone(),
                handles: service.handles(),
            }));
        }
        queue(&mut service, &session(1), "kalareach", at(0));
        let next = loaded(&mut service, at(3_000));
        if case == "refusing" {
            assert!(
                matches!(next, Instruction::Wait { .. }),
                "nothing is sent: {next:?}"
            );
            assert_eq!(service.in_flight(), 0, "{case}");
            assert_eq!(service.counts().cancelled, 1, "{case}");
        } else {
            assert!(
                matches!(next, Instruction::Generate { .. }),
                "{case}: {next:?}"
            );
            assert_eq!(service.in_flight(), 1, "{case}");
            assert_eq!(service.counts().cancelled, 0, "{case}");
        }
    }
}

/// A publication is written inside the gate the host holds it under, and not at all when the gate
/// admits none: the description is not stored and the result is refused as not admitted. The
/// control is a service with no gate, which publishes.
#[test]
fn a_publication_is_written_inside_its_gate_and_refused_when_none_admits_it() {
    for case in ["no gate", "admitting", "refusing"] {
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut service = service();
        match case {
            "admitting" | "refusing" => service.set_publication_gate(Box::new(Gate {
                admits: case == "admitting",
                dispatches: true,
                ran: ran.clone(),
                handles: service.handles(),
            })),
            _ => {}
        }
        queue(&mut service, &session(1), "kalareach", at(0));
        let (now, id, request) = next_job(&mut service, at(3_000));
        let outcome = service
            .finished(id, produced(&request.prompt, 0), now)
            .expect("the answer");
        let stored = service
            .store()
            .generated(&session(1))
            .expect("a read")
            .is_some();
        match case {
            "refusing" => {
                assert!(
                    matches!(
                        outcome,
                        Outcome::Rejected {
                            rejection: Rejection::NotAdmitted { .. },
                            ..
                        }
                    ),
                    "{outcome:?}"
                );
                assert!(!stored, "nothing was stored");
                assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
                assert_eq!(service.counts().refused, 1);
            }
            _ => {
                assert!(matches!(outcome, Outcome::Published { .. }), "{outcome:?}");
                assert!(stored, "the description was stored");
                assert_eq!(
                    ran.load(std::sync::atomic::Ordering::SeqCst),
                    case == "admitting",
                    "the write ran inside the gate: {case}"
                );
            }
        }
    }
}

/// Builds a service over a store of the test's own.
fn service_over(store: DescriptionStore) -> DescriptionService {
    DescriptionService::new(
        HostPlacement {
            environment: native(1),
            data_access: None,
            target: MAC.to_owned(),
            processor: kr_describe::processor::Features::running(),
        },
        built_in(),
        MetGates::default(),
        ResourceSettings::default(),
        store,
    )
}

/// Opens a second connection to a store on disk that holds its write lock, taken before anything
/// else could write.
fn write_lock(root: &std::path::Path) -> rusqlite::Connection {
    let other = rusqlite::Connection::open(root.join("descriptions.sqlite3"))
        .expect("a second connection to the same store");
    other
        .execute_batch("BEGIN IMMEDIATE")
        .expect("the second connection takes the write lock");
    other
}

/// How a job that ran past its deadline can end: the process says so, the process answers late
/// with bytes, or the daemon ends the process for it.
#[derive(Clone, Copy, Debug)]
enum Overran {
    /// The process answers that the job passed its deadline.
    Said,
    /// The process answers with a description after the job's deadline.
    AnsweredLate,
    /// The daemon ends the process at the job's deadline.
    Ended,
}

/// Runs one job to the end in the way a case says, and returns when it ended.
fn overrun(service: &mut DescriptionService, from: Reading, how: Overran) -> Reading {
    let (sent, id, request) = next_job(service, from);
    let deadline = Budgets::DEFAULTS.execution_deadline_ms;
    match how {
        Overran::Said => {
            let now = sent.after_ms(deadline);
            assert!(matches!(
                service
                    .finished(
                        id,
                        Answered::Ended {
                            why: JobEnd::DeadlineExceeded,
                            detail: None
                        },
                        now
                    )
                    .expect("the answer"),
                Outcome::DeadlineExceeded { .. }
            ));
            now
        }
        Overran::AnsweredLate => {
            let now = sent.after_ms(deadline + 1);
            assert!(matches!(
                service
                    .finished(id, produced(&request.prompt, 0), now)
                    .expect("the answer"),
                Outcome::DeadlineExceeded { .. }
            ));
            now
        }
        Overran::Ended => {
            let now = sent.after_ms(deadline + 2_000);
            let outcomes = service
                .process_ended(ProcessEnd::PastDeadline, now)
                .expect("the end");
            assert!(
                outcomes
                    .iter()
                    .any(|outcome| matches!(outcome, Outcome::DeadlineExceeded { .. })),
                "{outcomes:?}"
            );
            now
        }
    }
}

/// Three jobs in a row that overran their deadline leave inference failed while the restart delay
/// runs, whichever way each one was found out, and the model that answered them is still in the
/// process, so the state does not say it was unloaded. The control is two.
#[test]
fn three_deadlines_in_a_row_leave_inference_failed_whichever_way_each_was_found() {
    let paused = |service: &DescriptionService| match service.resource_state() {
        ResourceState::ResourcePaused {
            reason: PauseReason::InferenceFailed,
            unloaded,
        } => Some(unloaded),
        _ => None,
    };
    for forms in [
        [Overran::Said, Overran::AnsweredLate, Overran::Said],
        [
            Overran::AnsweredLate,
            Overran::AnsweredLate,
            Overran::AnsweredLate,
        ],
        [Overran::Said, Overran::Said, Overran::Said],
        [Overran::Ended, Overran::AnsweredLate, Overran::Said],
    ] {
        let mut service = service();
        let mut now = at(3_000);
        for (index, how) in forms.into_iter().enumerate() {
            queue(&mut service, &session(1 + index as u8), "kalareach", now);
            now = overrun(&mut service, now, how);
            service.next(&roomy(), now).expect("an instruction");
            match (index, paused(&service)) {
                (0 | 1, shown) => assert_eq!(shown, None, "{forms:?}: after {}", index + 1),
                (_, shown) => assert_eq!(
                    shown,
                    Some(false),
                    "{forms:?}: after three, the model is still in the process"
                ),
            }
        }
    }
}

/// A session whose changes wait for its job to end reports no time to settle at, so a host that
/// sleeps until the earliest one does not wake at once, find nothing to do and wake again for the
/// whole of the job. The control is a session that is idle, whose pending change settles a
/// debounce after it was seen.
#[test]
fn a_session_whose_changes_wait_for_its_job_reports_no_time_to_settle_at() {
    let mut service = service();
    service.session_opened(session(1), SessionEpoch::V1, binding());
    assert_eq!(service.settle_due_ms(), None);
    // The control.
    change(&mut service, &session(1), "kalareach", at(1_000));
    assert_eq!(service.settle_due_ms(), Some(1_000 + 2_000));
    assert!(
        service
            .settle(&session(1), Priority::Ordinary, at(3_000))
            .is_some()
    );
    assert_eq!(service.settle_due_ms(), None, "settled");

    // A job runs, a change settles under it and supersedes it, and the job after it runs to its
    // end while the next change waits.
    let (sent, id, _) = next_job(&mut service, at(3_000));
    change(&mut service, &session(1), "crates", sent);
    assert!(
        service
            .settle(&session(1), Priority::Ordinary, sent.after_ms(2_000))
            .is_some()
    );
    assert!(matches!(
        service
            .next(&roomy(), sent.after_ms(2_000))
            .expect("an instruction"),
        Instruction::Cancel { .. }
    ));
    service
        .finished(
            id,
            Answered::Ended {
                why: JobEnd::Cancelled,
                detail: None,
            },
            sent.after_ms(2_100),
        )
        .expect("the answer");
    let (second, id, request) = next_job(&mut service, sent.after_ms(2_100));
    change(&mut service, &session(1), "tests", second);
    assert_eq!(
        service.settle_due_ms(),
        Some(second.monotonic_ms() + 2_000),
        "a change is pending, and the host will ask at its time"
    );
    assert!(
        service
            .settle(&session(1), Priority::Ordinary, second.after_ms(2_000))
            .is_none(),
        "it waits for the job"
    );
    assert_eq!(
        service.settle_due_ms(),
        None,
        "nothing settles until the job ends, so there is nothing to wake for"
    );
    // The job ends, and the change that waited settles at once.
    service
        .finished(id, produced(&request.prompt, 0), second.after_ms(3_000))
        .expect("the answer");
    assert_eq!(service.settle_due_ms(), None);
    assert_eq!(
        service.scheduler().queued(),
        1,
        "the waiting change is queued"
    );

    // A fenced session's pending change is not waited for either.
    service.session_opened(session(2), SessionEpoch::V1, binding());
    change(
        &mut service,
        &session(2),
        "kalareach",
        second.after_ms(4_000),
    );
    assert!(service.settle_due_ms().is_some());
    service
        .fence()
        .raise(session(2), kr_worker::privacy::PrivacyGeneration::INITIAL);
    assert_eq!(service.settle_due_ms(), None, "fenced");
}

/// A load in the process is stopped when the files it reads stop being held, as it is when
/// descriptions are turned off. The control is the same load with its files held, which is left
/// alone.
#[test]
fn a_load_is_cancelled_when_the_files_stop_being_held() {
    let mut service = service();
    queue(&mut service, &session(1), "kalareach", at(0));
    let Instruction::Load { id, .. } = service.next(&roomy(), at(3_000)).expect("an instruction")
    else {
        panic!("a load comes first");
    };
    assert_eq!(
        service.next(&roomy(), at(3_100)).expect("an instruction"),
        Instruction::Wait { until_ms: None },
        "held: the load is left alone"
    );
    service.set_assets_held(false);
    assert_eq!(
        service.next(&roomy(), at(3_200)).expect("an instruction"),
        Instruction::Cancel {
            id,
            work: Work::Load
        }
    );
}

/// Builds a service over records of work in flight that the test holds clones of.
fn sharing(handles: &Handles) -> DescriptionService {
    DescriptionService::sharing(
        HostPlacement {
            environment: native(1),
            data_access: None,
            target: MAC.to_owned(),
            processor: kr_describe::processor::Features::running(),
        },
        built_in(),
        MetGates::default(),
        ResourceSettings::default(),
        DescriptionStore::in_memory().expect("a store in memory"),
        handles.clone(),
    )
}

/// What a service that goes away leaves behind: a job in the process, a load, and the shared
/// records of both. Whoever holds a clone of the records sees what the service did until then and
/// reads nought outstanding once it is gone.
#[test]
fn a_service_that_goes_leaves_nothing_outstanding_in_the_records_it_shared() {
    use std::sync::atomic::Ordering;

    let handles = Handles::default();
    let mut service = sharing(&handles);
    queue(&mut service, &session(1), "kalareach", at(0));
    queue(&mut service, &session(2), "crates", at(0));
    assert_eq!(service.live_session_ids(), vec![session(1), session(2)]);
    let Instruction::Load { id, .. } = service.next(&roomy(), at(3_000)).expect("an instruction")
    else {
        panic!("a load comes first");
    };
    assert_eq!(handles.loading.load(Ordering::Acquire), 1);
    service
        .finished(
            id,
            Answered::Loaded {
                load_ms: 0,
                rss_bytes: 0,
            },
            at(3_000),
        )
        .expect("the load");
    assert_eq!(handles.loading.load(Ordering::Acquire), 0);
    assert!(matches!(
        service.next(&roomy(), at(3_000)).expect("an instruction"),
        Instruction::Generate { .. }
    ));
    assert_eq!(handles.in_flight.total(), 1, "in flight, for every holder");
    assert_eq!(service.in_flight(), 1);
    handles
        .fence
        .raise(session(2), kr_worker::privacy::PrivacyGeneration::INITIAL);
    assert!(
        service.fence().is_fenced(&session(2)),
        "one fence, for every holder"
    );
    drop(service);
    assert_eq!(handles.in_flight.total(), 0, "nothing is in flight now");
    assert!(!handles.running.is_running(&session(1)));
    assert_eq!(handles.loading.load(Ordering::Acquire), 0);

    // A load in flight when the service goes is not left counted either.
    let handles = Handles::default();
    let mut service = sharing(&handles);
    queue(&mut service, &session(1), "kalareach", at(0));
    assert!(matches!(
        service.next(&roomy(), at(3_000)).expect("an instruction"),
        Instruction::Load { .. }
    ));
    assert_eq!(handles.loading.load(Ordering::Acquire), 1);
    drop(service);
    assert_eq!(handles.loading.load(Ordering::Acquire), 0);
}

/// A load that failed, a crash and a job that failed are three failures in a row, whichever kind
/// each is.
#[test]
fn a_failed_load_a_crash_and_a_failed_job_are_three_failures_in_a_row() {
    let mut service = service();
    queue(&mut service, &session(1), "kalareach", at(0));
    let mut now = at(3_000);

    // A load that failed.
    let Instruction::Load { id, .. } = service.next(&roomy(), now).expect("an instruction") else {
        panic!("a load comes first");
    };
    service
        .finished(
            id,
            Answered::LoadEnded {
                why: LoadEnd::Failed,
                detail: None,
            },
            now,
        )
        .expect("the answer");
    service.next(&roomy(), now.after_ms(10)).expect("a wait");
    assert!(!inference_failed(&service), "one");

    // A process that ended on its own during the next load.
    now = now.after_ms(10 * 60 * 1_000);
    assert!(matches!(
        service.next(&roomy(), now).expect("an instruction"),
        Instruction::Load { .. }
    ));
    service
        .process_ended(ProcessEnd::Exited, now.after_ms(10))
        .expect("the end");
    service.next(&roomy(), now.after_ms(20)).expect("a wait");
    assert!(!inference_failed(&service), "two");

    // A job that failed.
    now = now.after_ms(10 * 60 * 1_000);
    let (sent, id, _) = next_job(&mut service, now);
    service
        .finished(
            id,
            Answered::Ended {
                why: JobEnd::Failed,
                detail: None,
            },
            sent,
        )
        .expect("the answer");
    service.next(&roomy(), sent).expect("the unload");
    service.next(&roomy(), sent).expect("the wait");
    assert!(inference_failed(&service), "three");
}

/// A load the process refused because a file is not the profile's counts for nothing against
/// inference however often it happens: no restart delay and no pause for failures. The service
/// holds nothing as downloaded afterwards and asks for no load until it is told the files are held
/// again, and the same answer for any other ending of a load is the control that counts.
#[test]
fn a_load_refused_for_its_files_is_no_failure_and_nothing_loads_until_they_are_held_again() {
    let mut service = service();
    queue(&mut service, &session(1), "kalareach", at(0));
    let mut now = at(3_000);
    for round in 1..=4_u64 {
        let Instruction::Load { id, .. } = service.next(&roomy(), now).expect("an instruction")
        else {
            panic!("round {round}: a load comes first");
        };
        let outcome = service
            .finished(
                id,
                Answered::LoadEnded {
                    why: LoadEnd::Assets,
                    detail: Some("tiny.gguf is not the file the profile records".to_owned()),
                },
                now,
            )
            .expect("the answer");
        assert!(matches!(
            outcome,
            Outcome::LoadEnded {
                why: LoadEnd::Assets,
                ..
            }
        ));
        assert!(!service.assets_held(), "round {round}");
        assert_eq!(
            service.setup_state().progress,
            DownloadProgress::NotStarted,
            "round {round}"
        );
        assert_eq!(service.inference_restarts(), 0, "round {round}");
        assert_eq!(service.restart_not_before_ms(), None, "round {round}");
        assert!(!inference_failed(&service), "round {round}");
        // The process holds no model and has nothing to do, so it is ended; then nothing is asked
        // for while the files are not held.
        assert!(
            matches!(
                service.next(&roomy(), now.after_ms(10)).expect("an unload"),
                Instruction::Unload {
                    why: UnloadReason::Assets
                }
            ),
            "round {round}"
        );
        assert!(
            matches!(
                service.next(&roomy(), now.after_ms(20)).expect("a wait"),
                Instruction::Wait { .. }
            ),
            "round {round}"
        );
        service.set_assets_held(true);
        now = now.after_ms(1_000);
    }

    // The control: the same ending for another reason is a failure, and three are a pause.
    let mut service = self::service();
    queue(&mut service, &session(1), "kalareach", at(0));
    let mut now = at(3_000);
    for _ in 0..3 {
        let Instruction::Load { id, .. } = service.next(&roomy(), now).expect("an instruction")
        else {
            panic!("a load comes first");
        };
        service
            .finished(
                id,
                Answered::LoadEnded {
                    why: LoadEnd::Refused,
                    detail: None,
                },
                now,
            )
            .expect("the answer");
        service.next(&roomy(), now.after_ms(10)).expect("a wait");
        now = now.after_ms(10 * 60 * 1_000);
    }
    assert!(inference_failed(&service));
}

/// Whether the service is paused for repeated failures.
fn inference_failed(service: &DescriptionService) -> bool {
    matches!(
        service.resource_state(),
        ResourceState::ResourcePaused {
            reason: PauseReason::InferenceFailed,
            ..
        }
    )
}

/// What privacy mode has the service forget, with nothing in the store touched: every queued job,
/// every retained context and event, and what waits behind a job, for every session. The service
/// goes on working afterwards: a change captured after it is described as any is. The control is a
/// description already in the store, which stays, because removing a row is the store's own step.
#[test]
fn forgetting_content_clears_the_queue_and_the_contexts_and_leaves_the_store_alone() {
    let mut service = service();
    queue(&mut service, &session(1), "kalareach", at(0));
    queue(&mut service, &session(2), "crates", at(0));
    service.session_opened(session(3), SessionEpoch::V1, binding());
    change(&mut service, &session(3), "tests", at(0));
    assert!(service.settle_due_ms().is_some(), "a change is pending");
    assert_eq!(service.scheduler().queued(), 2);

    // A published description is the control.
    let (now, id, request) = next_job(&mut service, at(3_000));
    assert!(matches!(
        service
            .finished(id, produced(&request.prompt, 0), now)
            .expect("the answer"),
        Outcome::Published { .. }
    ));
    let published = [session(1), session(2)]
        .iter()
        .filter(|session_id| {
            service
                .store()
                .generated(session_id)
                .expect("a read")
                .is_some()
        })
        .count();
    assert_eq!(published, 1, "one job ran");

    let forgotten = service.forget_content();
    assert_eq!(forgotten, 2, "the queued job and the pending change");
    assert_eq!(service.scheduler().queued(), 0);
    assert_eq!(service.settle_due_ms(), None);
    let still = [session(1), session(2)]
        .iter()
        .filter(|session_id| {
            service
                .store()
                .generated(session_id)
                .expect("a read")
                .is_some()
        })
        .count();
    assert_eq!(still, 1, "the store is not touched");

    // Still working: a change after it is described.
    change(&mut service, &session(3), "after", at(10_000));
    assert!(
        service
            .settle(&session(3), Priority::Ordinary, at(12_000))
            .is_some()
    );
    assert_eq!(service.scheduler().queued(), 1);
}

/// Inference on battery is the owner's setting, off until it is turned on, and it applies at the
/// next turn: a host on battery pauses with the battery's reason and loads nothing, turning the
/// setting on lets the same queue load, and turning it off again lets a model that is loaded go.
#[test]
fn inference_on_battery_follows_the_owners_setting_at_the_next_turn() {
    let on_battery = HostConditions::measured(
        16 * GIB,
        12 * GIB,
        PowerSource::Battery,
        ThermalState::Nominal,
    );
    let mut service = service();
    queue(&mut service, &session(1), "kalareach", at(0));
    assert!(matches!(
        service
            .next(&on_battery, at(3_000))
            .expect("an instruction"),
        Instruction::Wait { .. }
    ));
    assert_eq!(
        service.resource_state(),
        ResourceState::ResourcePaused {
            reason: PauseReason::Battery,
            unloaded: false
        }
    );
    service.set_on_battery(true);
    let Instruction::Load { id, .. } = service
        .next(&on_battery, at(3_100))
        .expect("an instruction")
    else {
        panic!("allowed on battery, the queue loads");
    };
    service
        .finished(
            id,
            Answered::Loaded {
                load_ms: 0,
                rss_bytes: 0,
            },
            at(3_100),
        )
        .expect("the load");
    service.set_on_battery(false);
    assert_eq!(
        service
            .next(&on_battery, at(3_200))
            .expect("an instruction"),
        Instruction::Unload {
            why: UnloadReason::Paused(PauseReason::Battery)
        },
        "a model that was allowed is let go when the setting goes"
    );
}
