//! The driven service on its own: what it tells its host to do, and what it makes of each answer
//! and of the process ending, with no process at all.

mod support;

use kr_describe::budget::{Budgets, GIB};
use kr_describe::context::{ContextRevision, ContextSignal};
use kr_describe::metadata::RepositoryFacts;
use kr_describe::output::Rejection;
use kr_describe::profile::catalogue::MetGates;
use kr_describe::queue::Priority;
use kr_describe::resource::{
    HostConditions, PauseReason, PowerSource, ResourceSettings, ResourceState, ThermalState,
};
use kr_describe::service::{
    Answered, DescriptionService, HostPlacement, Instruction, Outcome, ProcessEnd,
    RESTART_FIRST_MS, RESTART_MOST_MS, UnloadReason, Work,
};
use kr_describe::store::DescriptionStore;
use kr_describe::testing::{Output, answer_of};
use kr_describe::time::Reading;
use kr_describe::wire::{JobEnd, LoadEnd, Phases};
use kr_protocol::ids::{SessionEpoch, SessionId};

use support::{MAC, at, binding, built_in, native, roomy, session};

fn service() -> DescriptionService {
    DescriptionService::new(
        HostPlacement {
            environment: native(1),
            data_access: None,
            target: MAC.to_owned(),
        },
        built_in(),
        MetGates::default(),
        ResourceSettings::default(),
        DescriptionStore::in_memory().expect("a store in memory"),
    )
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
