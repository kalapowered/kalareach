//! The description process on its own: the stub executable, spoken to over its real standard input
//! and output, answering, cancelling, ending with its daemon, ending itself when it is stuck, and
//! holding its environment's lock.

mod stub;
mod support;

use std::io::Read;
use std::path::Path;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use kr_describe::context::ContextRevision;
use kr_describe::output::{Expectation, ProducedUnder, validate};
use kr_describe::priority::Cancellation;
use kr_describe::profile::catalogue::Catalogue;
use kr_describe::serve::{
    CONTROL_BOUND_MS, Exit, Generating, Job, LoadWork, Loading, Model, OVERDUE_GRACE_MS, Options,
    Verifying,
};
use kr_describe::supervise::STOP_BOUND_MS;
use kr_describe::testing::{
    Script, TokenRead, acknowledging_state, bound_held_after_the_answer, bound_held_at_the_answer,
    bound_held_at_the_forgetting, job_bounds, job_token_as_read, release_held_watchdog,
    release_held_work, token_cancelled_at_the_look, watchdog_found, watchdog_has_spared,
};
use kr_describe::wire::{Answer, JobEnd, LoadEnd, Request, WIRE_VERSION, frame_of};
use kr_protocol::ids::SessionEpoch;
use kr_protocol::scalars::U64;
use kr_worker::privacy::PrivacyGeneration;

use stub::{
    Placed, Process, began, generate, load, wait_for, wait_until_began, wait_until_started,
};
use support::{binding, default_profile};

const SOON: Duration = Duration::from_secs(10);

/// The deadline of a job that a case tells to stop, in milliseconds. The control thread has to read
/// the stop before the deadline and the grace after it have passed, or the process ends as overdue
/// before it can acknowledge, so a case that sends the stop after the job began leaves the process
/// a margin of this and the grace, which is the time anything here is given to arrive.
const STOP_DEADLINE_MS: u64 = 8_000;
const _: () = assert!(STOP_DEADLINE_MS + OVERDUE_GRACE_MS == SOON.as_secs() * 1_000);

/// How long past its deadline the guide gives work that its process has not been told to stop, and
/// a job whose stop its control thread has read, written out so that a case that counts in them
/// fails when either changes.
const GUIDE_GRACE_MS: u64 = 2_000;
const GUIDE_STOP_BOUND_MS: u64 = 30_000;

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

/// KR-REQ-22.11: a cancellation reaches a load and a job once the model thread has begun them, and
/// each answers that it was cancelled; the control is the same work left alone, which finishes.
#[test]
fn a_cancellation_reaches_a_load_and_a_job_while_they_run() {
    let placed = Placed::stub();

    let runtime = placed.directory("loading");
    let script = Script {
        load_until_cancelled: true,
        mark_work: true,
        ..Script::default()
    };
    let mut process = Process::start(&placed, &script, &runtime);
    process.hello();
    process.send(&load(1, &default_profile(), 300_000));
    wait_until_began(&runtime, "load");
    process.send(&Request::Cancel { id: U64::new(1) });
    assert!(matches!(
        process.expect_terminal(SOON, "the cancelled load"),
        Answer::LoadEnded { id, why: LoadEnd::Cancelled, .. } if id.get() == 1
    ));

    let runtime = placed.directory("decoding");
    let script = Script {
        generate_until_cancelled: true,
        mark_work: true,
        ..Script::default()
    };
    let mut process = Process::start(&placed, &script, &runtime);
    process.hello();
    process.send(&load(1, &default_profile(), 300_000));
    process.expect_answer(SOON, "the load");
    process.send(&generate(2, 1, 30_000));
    wait_until_began(&runtime, "job");
    process.send(&Request::Cancel { id: U64::new(2) });
    assert!(matches!(
        process.expect_terminal(SOON, "the cancelled job"),
        Answer::Ended { id, why: JobEnd::Cancelled, .. } if id.get() == 2
    ));

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

/// A cancellation that reaches work in hand is acknowledged before the work's own answer, for a
/// load and for a job, every time: the control thread cancels and acknowledges under the lock the
/// model thread takes to forget the work before it answers, so a model that sees the cancellation
/// at once still cannot answer ahead of the acknowledgement. The rounds show that the answer is
/// never ahead in the orders they reach; that the lock is held through the write is the code's
/// own, since the function that writes takes the guard that holds it. The control is a
/// cancellation that arrives after the answer, which is acknowledged by nothing.
#[test]
fn a_cancelled_load_and_job_are_acknowledged_before_they_answer() {
    let placed = Placed::stub();
    let runtime = placed.directory("loading");
    let script = Script {
        load_until_cancelled: true,
        mark_work: true,
        ..Script::default()
    };
    let mut process = Process::start(&placed, &script, &runtime);
    process.hello();
    process.send(&load(1, &default_profile(), 300_000));
    wait_until_began(&runtime, "load");
    process.send(&Request::Cancel { id: U64::new(1) });
    assert_eq!(
        process.expect_answer(SOON, "the acknowledgement"),
        Answer::Cancelling { id: U64::new(1) }
    );
    assert!(matches!(
        process.expect_answer(SOON, "the cancelled load"),
        Answer::LoadEnded { id, why: LoadEnd::Cancelled, .. } if id.get() == 1
    ));

    // The model looks at its token without pausing, so it answers the moment it is cancelled and
    // only the lock the acknowledgement is written under keeps the answer behind it.
    let runtime = placed.directory("deciding");
    let script = Script {
        generate_until_cancelled: true,
        spin: true,
        ..Script::default()
    };
    let mut process = Process::start(&placed, &script, &runtime);
    process.hello();
    process.send(&load(1, &default_profile(), 300_000));
    process.expect_answer(SOON, "the load");
    for round in 0..20_u64 {
        let id = 2 + round;
        process.send(&generate(id, 1, 30_000));
        process.send(&Request::Cancel { id: U64::new(id) });
        // Either the job was already in the model's hands, which is acknowledged first, or the
        // cancellation reached it before the model thread had taken it from the queue, which is
        // answered cancelled with the acknowledgement still first.
        assert_eq!(
            process.expect_answer(SOON, "the acknowledgement"),
            Answer::Cancelling { id: U64::new(id) },
            "round {round}"
        );
        assert!(
            matches!(
                process.expect_answer(SOON, "the cancelled job"),
                Answer::Ended { id: ended, why: JobEnd::Cancelled, .. } if ended.get() == id
            ),
            "round {round}"
        );
    }
}

/// The control thread says it has read a cancellation while the model thread is still inside the
/// work and ignoring its token, and the work's own answer follows when the model stops. The
/// control is a cancellation of work that has already answered, which is acknowledged by nothing.
#[test]
fn a_cancellation_is_acknowledged_while_the_model_goes_on() {
    let placed = Placed::stub();

    // A job whose model does not look at its token for longer than this test needs: the process's
    // own watchdog ends it once the job's deadline has passed, and the test has long finished with
    // it by then. The acknowledgement is what the test reads; the job's answer is not due.
    let runtime = placed.directory("busy");
    let script = Script {
        ignore_token_ms: 60_000,
        mark_work: true,
        ..Script::default()
    };
    let mut process = Process::start(&placed, &script, &runtime);
    process.hello();
    process.send(&load(1, &default_profile(), 300_000));
    process.expect_answer(SOON, "the load");
    process.send(&generate(2, 1, 30_000));
    wait_until_began(&runtime, "job");
    process.send(&Request::Cancel { id: U64::new(2) });
    assert_eq!(
        process.expect_answer(SOON, "the acknowledgement"),
        Answer::Cancelling { id: U64::new(2) }
    );
    process.kill();

    // The same for a load, and for a check of a file.
    let runtime = placed.directory("loading");
    let script = Script {
        load_ignore_token_ms: 60_000,
        mark_work: true,
        ..Script::default()
    };
    let mut process = Process::start(&placed, &script, &runtime);
    process.hello();
    process.send(&load(1, &default_profile(), 300_000));
    wait_until_began(&runtime, "load");
    process.send(&Request::Cancel { id: U64::new(1) });
    assert_eq!(
        process.expect_answer(SOON, "the acknowledgement"),
        Answer::Cancelling { id: U64::new(1) }
    );
    process.kill();

    // The control: work that has answered is not acknowledged. The job's own answer comes first,
    // and the cancellation that follows it finds nothing in hand.
    let runtime = placed.directory("answered");
    let mut process = Process::start(&placed, &Script::default(), &runtime);
    process.hello();
    process.send(&load(1, &default_profile(), 300_000));
    process.expect_answer(SOON, "the load");
    process.send(&generate(2, 1, 30_000));
    assert!(matches!(
        process.expect_answer(SOON, "the job"),
        Answer::Produced { .. }
    ));
    process.send(&Request::Cancel { id: U64::new(2) });
    // A job the process is given afterwards is answered with nothing before it: the cancellation
    // was acknowledged by no one.
    process.send(&generate(3, 1, 30_000));
    assert!(matches!(
        process.expect_answer(SOON, "the next job"),
        Answer::Produced { id, .. } if id.get() == 3
    ));
}

/// A file is checked against the size and digest its profile's asset records, and the answer says
/// how it came out; a check can be cancelled; a profile or file the catalogue does not hold is
/// refused. The control is the same check of the right file, which passes.
#[test]
fn a_process_checks_a_file_against_the_asset_its_profile_records() {
    use kr_describe::testing::{TestAsset, TestCatalogue, TestProfile};
    use kr_describe::wire::VerifyResult;

    let placed = Placed::stub();
    let weights = b"the weights of a tiny model".to_vec();
    let signed = TestCatalogue::sign(&[TestProfile {
        profile_id: "tiny-default".to_owned(),
        revision: 1,
        candidate: false,
        targets: Some(vec![kr_describe::environment::build_target().to_owned()]),
        assets: vec![TestAsset {
            file_name: "tiny.gguf".to_owned(),
            url: "http://127.0.0.1:1/tiny.gguf".to_owned(),
            bytes: weights.clone(),
        }],
    }]);
    let bundle = placed.directory("bundle").join("catalogue.json");
    signed.write_to(&bundle);
    let files = placed.directory("files");
    std::fs::write(files.join("right"), &weights).expect("the right file");
    std::fs::write(files.join("wrong"), b"the weights of a tiny model, changed")
        .expect("the wrong file");
    std::fs::write(files.join("same-size"), b"the weights of a tiny modeL")
        .expect("a file of the right size and the wrong digest");

    let check = |id: u64, profile: &str, revision: u64, file: &str, path: &Path| Request::Verify {
        id: U64::new(id),
        profile_id: profile.to_owned(),
        revision: U64::new(revision),
        file_name: file.to_owned(),
        path: path.to_string_lossy().into_owned(),
        deadline_ms: U64::new(60_000),
    };
    let result_of = |answer: Answer, id: u64| match answer {
        Answer::Verified {
            id: answered,
            result,
            ..
        } => {
            assert_eq!(answered.get(), id);
            result
        }
        other => panic!("a check is answered with its result: {other:?}"),
    };

    let runtime = placed.directory("runtime");
    let mut process = Process::start_with(&placed, &Script::default(), &runtime, Some(&bundle));
    process.hello();
    for (id, path, expected) in [
        (1, files.join("right"), VerifyResult::Verified),
        (2, files.join("wrong"), VerifyResult::Mismatch),
        (3, files.join("same-size"), VerifyResult::Mismatch),
        (4, files.join("missing"), VerifyResult::Unreadable),
    ] {
        process.send(&check(id, "tiny-default", 1, "tiny.gguf", &path));
        assert_eq!(
            result_of(process.expect_answer(SOON, "the check"), id),
            expected,
            "{}",
            path.display()
        );
    }
    process.send(&check(
        5,
        "a-profile-nobody-signed",
        1,
        "tiny.gguf",
        &files.join("right"),
    ));
    assert_eq!(
        result_of(process.expect_answer(SOON, "the refusal"), 5),
        VerifyResult::Refused
    );
    process.send(&check(
        6,
        "tiny-default",
        1,
        "another.gguf",
        &files.join("right"),
    ));
    assert_eq!(
        result_of(process.expect_answer(SOON, "the refusal"), 6),
        VerifyResult::Refused
    );

    // A check that waits is cancelled, and answers that it was.
    let runtime = placed.directory("cancelling");
    let script = Script {
        verify_until_cancelled: true,
        mark_work: true,
        ..Script::default()
    };
    let mut process = Process::start_with(&placed, &script, &runtime, Some(&bundle));
    process.hello();
    process.send(&check(
        7,
        "tiny-default",
        1,
        "tiny.gguf",
        &files.join("right"),
    ));
    wait_until_began(&runtime, "check");
    process.send(&Request::Cancel { id: U64::new(7) });
    assert_eq!(
        result_of(process.expect_terminal(SOON, "the cancelled check"), 7),
        VerifyResult::Cancelled
    );
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
        .exit_within(SOON)
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
        mark_start: true,
        ..Script::default()
    };
    let mut process = Process::start(&placed, &script, &runtime);
    // The bound is counted from a process that is known to be running.
    wait_until_started(&runtime);
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

/// A process whose standard error cannot be written to still ends itself when its job does not stop
/// and when its control thread is stuck: the watchdog says why on a thread of its own and does not
/// wait behind a write that has stopped for good. The script holds the lock on standard error from
/// before the process serves, as a write waiting on a pipe nobody reads does, and the process
/// serves nothing until it holds it. The control is the process with its standard error free,
/// which ends the same way (above).
#[test]
fn a_process_whose_standard_error_is_held_still_ends_when_it_must() {
    let placed = Placed::stub();

    let runtime = placed.directory("overdue");
    let script = Script {
        ignore_token_ms: 60_000,
        hold_standard_error: true,
        ..Script::default()
    };
    let mut process = Process::start(&placed, &script, &runtime);
    process.hello();
    process.send(&load(1, &default_profile(), 300_000));
    process.expect_answer(SOON, "the load");
    process.send(&generate(2, 1, 200));
    let status = process
        .exit_within(SOON * 3)
        .expect("the process ends itself, though it cannot say why");
    assert_eq!(status.code(), Some(Exit::Overdue.code()));

    let runtime = placed.directory("stuck");
    let script = Script {
        wedge_output_from: Some(1),
        mark_start: true,
        hold_standard_error: true,
        ..Script::default()
    };
    let mut process = Process::start(&placed, &script, &runtime);
    wait_until_started(&runtime);
    process.send(&Request::Hello {
        build: "kr-describe-tests/0".to_owned(),
        wire: U64::new(WIRE_VERSION),
    });
    let status = process
        .exit_within(SOON * 3)
        .expect("the process ends itself, though it cannot say why");
    assert_eq!(status.code(), Some(Exit::ControlStalled.code()));
}

/// A process whose standard error is a pipe nobody reads ends as it must when it has something to
/// say as it ends, and does not wait to say it: its answer cannot be written because its daemon is
/// gone, its model has failed (the panic hook speaks as the program installs it to), or a request it
/// was sent is not a message. Each of the three ends has its own exit status. The first two have no
/// bound of the process's own to end them, since the work in hand is nowhere near its deadline; a
/// notice written before the third form ends the process would be ended by the bound on a control
/// thread stuck on a request, with another exit status, and one written after it is held by nothing
/// but the case's own wait. The script fills the pipe before the process serves, as a pipe nobody
/// reads is filled, so every write to standard error waits for good; on a platform that has no such
/// fill it holds the lock on standard error, which holds the notices written in line and not the
/// panic hook's. The control is the process with its standard error free, which ends the same way.
#[test]
fn a_process_that_ends_with_something_to_say_does_not_wait_for_its_standard_error() {
    let placed = Placed::stub();
    let stopped = |stopped: bool| Script {
        #[cfg(unix)]
        fill_standard_error: stopped,
        #[cfg(not(unix))]
        hold_standard_error: stopped,
        ..Script::default()
    };
    for (form, stop_standard_error) in [("stopped", true), ("free", false)] {
        // The daemon is gone: the answer to the load cannot be written.
        let runtime = placed.directory(&format!("gone-{form}"));
        let script = Script {
            fail_output_from: Some(2),
            ..stopped(stop_standard_error)
        };
        let mut process = Process::start_with_unread_standard_error(&placed, &script, &runtime);
        process.hello();
        process.send(&load(1, &default_profile(), 300_000));
        let status = process
            .exit_within(SOON * 3)
            .expect("the process ends itself, though it cannot say why");
        assert_eq!(status.code(), Some(Exit::DaemonGone.code()), "{form}");

        // The model fails inside a job.
        let runtime = placed.directory(&format!("failed-{form}"));
        let script = Script {
            panic_in_generate: true,
            ..stopped(stop_standard_error)
        };
        let mut process = Process::start_with_unread_standard_error(&placed, &script, &runtime);
        process.hello();
        process.send(&load(1, &default_profile(), 300_000));
        process.expect_answer(SOON, "the load");
        process.send(&generate(2, 1, 300_000));
        let status = process
            .exit_within(SOON * 3)
            .expect("the process ends itself, though it cannot say why");
        assert_eq!(status.code(), Some(Exit::ModelFailed.code()), "{form}");

        // A request that is not a message: a frame cut short by the end of the input.
        let runtime = placed.directory(&format!("refused-{form}"));
        let script = stopped(stop_standard_error);
        let mut process = Process::start_with_unread_standard_error(&placed, &script, &runtime);
        process.hello();
        process.send_raw(&[0, 0]);
        process.close_input();
        let status = process
            .exit_within(SOON * 3)
            .expect("the process ends itself, though it cannot say why");
        assert_eq!(status.code(), Some(Exit::WireBroken.code()), "{form}");
    }
}

/// KR-REQ-22.11: a job that is past its deadline and has been told to stop, with the stop read by
/// the control thread, is given until the stop bound to stop, and the process does not end itself
/// for it at the usual grace after the deadline. The model here does not look at its token for
/// longer than that grace, as a model in the background class on a busy host can take; the process
/// answers the job as stopped. The control is the same job that was told nothing, which ends the
/// process at the grace (above). The job's deadline leaves the control thread the margin of
/// [`STOP_DEADLINE_MS`] to read the stop, and no part of the case depends on it being read sooner.
#[test]
fn a_job_past_its_deadline_that_was_told_to_stop_is_given_time_to_stop() {
    let placed = Placed::stub();
    let runtime = placed.directory("told-to-stop");
    let slow_ms = STOP_DEADLINE_MS + OVERDUE_GRACE_MS + 1_500;
    let script = Script {
        ignore_token_ms: slow_ms,
        mark_work: true,
        ..Script::default()
    };
    let mut process = Process::start(&placed, &script, &runtime);
    process.hello();
    process.send(&load(1, &default_profile(), 300_000));
    process.expect_answer(SOON, "the load");
    process.send(&generate(2, 1, STOP_DEADLINE_MS));
    wait_until_began(&runtime, "job");
    process.send(&Request::Cancel { id: U64::new(2) });
    assert_eq!(
        process.expect_answer(SOON, "the acknowledgement"),
        Answer::Cancelling { id: U64::new(2) }
    );
    // The model looks at its token after the grace, and the process is still there to answer.
    assert!(matches!(
        process.expect_terminal(Duration::from_millis(slow_ms) * 5, "the stopped job"),
        Answer::Ended { id, why: JobEnd::Cancelled, .. } if id.get() == 2
    ));
    assert!(process.exit_within(Duration::from_millis(500)).is_none());
}

/// KR-REQ-22.11: the process gives a job whose stop its control thread has read the stop bound after
/// the job's deadline: a model that acknowledges the cancellation and never returns ends the process
/// as overdue, and not before that bound, which the lower limit of the elapsed time shows (the
/// process cannot end itself sooner than its own bound, whatever the load), and not never, which
/// the wait for the end shows. The wait allows twice the bound so that a loaded host does not fail
/// it, so no elapsed time holds how much later than the bound the process ends. What holds the
/// figure is the process's own record of the bounds it sets for the job as it comes into hand,
/// compared with the guide's two seconds and thirty (the case below holds that the extension to
/// the stop bound is made), and its record of the look that ended it: that look was made against
/// the stop bound the control thread set and no other, and was the first look after it, which the
/// process's own stamps order and no delay of this case's can move. It runs as long as the bound it
/// holds.
#[test]
fn a_job_told_to_stop_that_never_returns_ends_the_process_at_the_stop_bound() {
    let placed = Placed::stub();
    let runtime = placed.directory("never-returns");
    let script = Script {
        ignore_token_ms: 10 * STOP_BOUND_MS,
        mark_work: true,
        ..Script::default()
    };
    let mut process = Process::start(&placed, &script, &runtime);
    process.hello();
    process.send(&load(1, &default_profile(), 300_000));
    process.expect_answer(SOON, "the load");
    let sent = Instant::now();
    process.send(&generate(2, 1, STOP_DEADLINE_MS));
    wait_until_began(&runtime, "job");
    assert_eq!(
        job_bounds(&runtime, 2),
        Some((GUIDE_GRACE_MS, GUIDE_STOP_BOUND_MS)),
        "the grace and the stop bound past the deadline, in milliseconds"
    );
    process.send(&Request::Cancel { id: U64::new(2) });
    assert_eq!(
        process.expect_answer(SOON, "the acknowledgement"),
        Answer::Cancelling { id: U64::new(2) }
    );
    let status = process
        .exit_within(Duration::from_millis(STOP_DEADLINE_MS + STOP_BOUND_MS) * 2)
        .expect("the process ends itself at the stop bound");
    assert_eq!(status.code(), Some(Exit::Overdue.code()));
    assert!(sent.elapsed() >= Duration::from_millis(STOP_DEADLINE_MS + STOP_BOUND_MS));

    // The look that ended it.
    let stop_bound = acknowledging_state(&runtime, 2)
        .expect("the control thread's record")
        .job_stop_due;
    let found = watchdog_found(&runtime).expect("the watchdog's record of the look");
    assert_eq!(
        found.due, stop_bound,
        "the watchdog ended the process against the bound the stop gave the job: {found:?}"
    );
    assert!(
        found.previous_look <= found.due && found.due < found.look,
        "the first look after the bound ended the process: {found:?}"
    );
}

/// KR-REQ-22.11: a job the control thread has read the stop of is cancelled, and has the stop
/// bound, before the control thread begins to write the acknowledgement. The write can take long,
/// on a daemon that is slow to read or a thread the system has set aside, and the watchdog reads
/// the job's bound without a lock, so a write ahead of the extension would carry the watchdog past
/// the grace before the job had its extension and the process would end as overdue. The process
/// records what its control thread had done as the write begins, in the function that writes, and
/// what the token showed as the control thread looked for the job in hand, and the case reads both
/// back once the acknowledgement has arrived: the token cancelled at the look, and the bound the
/// watchdog holds the job to the stop bound that was set as the job began, and not the grace. No
/// delay decides it, and the job's deadline is far off. Written first, the acknowledgement shows
/// the grace; a look made before the cancellation shows a token not yet cancelled; extending by
/// more than the stop bound shows a bound past it.
#[test]
fn a_job_told_to_stop_is_cancelled_and_has_its_bound_before_the_acknowledgement_is_written() {
    let placed = Placed::stub();
    let runtime = placed.directory("acknowledging");
    let script = Script {
        generate_until_cancelled: true,
        mark_work: true,
        ..Script::default()
    };
    let mut process = Process::start(&placed, &script, &runtime);
    process.hello();
    process.send(&load(1, &default_profile(), 300_000));
    process.expect_answer(SOON, "the load");
    process.send(&generate(2, 1, 60_000));
    wait_until_began(&runtime, "job");
    process.send(&Request::Cancel { id: U64::new(2) });
    assert_eq!(
        process.expect_answer(SOON, "the acknowledgement"),
        Answer::Cancelling { id: U64::new(2) }
    );
    assert_eq!(
        token_cancelled_at_the_look(&runtime, 2),
        Some(true),
        "the job is looked for after its token is cancelled"
    );
    let before_the_write = acknowledging_state(&runtime, 2).expect("the control thread's record");
    assert_ne!(before_the_write.job_stop_due, 0, "{before_the_write:?}");
    assert_eq!(
        before_the_write.work_due, before_the_write.job_stop_due,
        "the watchdog holds the job to the stop bound: {before_the_write:?}"
    );
    assert!(matches!(
        process.expect_terminal(SOON, "the stopped job"),
        Answer::Ended { id, why: JobEnd::Cancelled, .. } if id.get() == 2
    ));
}

/// KR-REQ-22.11: a stop the control thread applies after the watchdog has found a job overdue, and
/// before it has decided to end the process, is not missed: the watchdog ends the process only on
/// the bound as it stands when it decides, and a job whose stop has been applied since has the stop
/// bound. The script holds the watchdog between its finding, which it records, and its decision;
/// the case sends the stop once it has seen the record, reads the acknowledgement, which is written
/// after the extension, and lets the watchdog go. The watchdog then leaves the process alone, and
/// the record it leaves says so; what the process does after that is the stop bound's. No delay
/// decides it. A watchdog that decides on the bound it read ends the process as overdue, with the
/// stop applied.
#[test]
fn a_stop_applied_after_the_watchdog_found_the_job_overdue_is_not_missed() {
    let placed = Placed::stub();
    let runtime = placed.directory("held-watchdog");
    let script = Script {
        ignore_token_ms: 60_000,
        mark_work: true,
        hold_watchdog: true,
        ..Script::default()
    };
    let mut process = Process::start(&placed, &script, &runtime);
    process.hello();
    process.send(&load(1, &default_profile(), 300_000));
    process.expect_answer(SOON, "the load");
    process.send(&generate(2, 1, 200));
    wait_for("the watchdog to find the job overdue", || {
        watchdog_found(&runtime).is_some()
    });
    process.send(&Request::Cancel { id: U64::new(2) });
    assert_eq!(
        process.expect_answer(SOON, "the acknowledgement"),
        Answer::Cancelling { id: U64::new(2) }
    );
    release_held_watchdog(&runtime);
    wait_for("the watchdog to decide", || {
        watchdog_has_spared(&runtime) || process.exit_within(Duration::ZERO).is_some()
    });
    assert!(
        watchdog_has_spared(&runtime),
        "the process ended for a job whose stop was applied before the watchdog decided"
    );
}

/// KR-REQ-22.11: a job that ends after the watchdog has found it overdue, and before the watchdog
/// has decided to end the process, leaves the process alone: the bound the watchdog found is gone,
/// and the process is idle. The script holds the watchdog between its finding, which it records,
/// and its decision, and holds the job past its deadline and its grace until the case releases it;
/// each has a release of its own. The case waits for the watchdog's record of the expired bound,
/// so a watchdog that is late finds the job still there; releases the job; waits for the process's
/// record that the job is answered and the bound it held is cleared, and reads that it is nought;
/// and only then releases the watchdog and reads its record that it left the process alone. No
/// delay decides it. A watchdog that ends the process unless the bound has moved later, or a model
/// thread that does not clear the bound when the job is answered, ends or keeps an idle process
/// as overdue. The process also records the bound it holds as the job is forgotten and as its answer
/// is written, which the case reads as not nought: a clear before the write leaves the write with no
/// limit, and a stop that comes between the clear and the forgetting of the job gives an idle
/// process the stop bound.
#[test]
fn a_job_that_ends_after_the_watchdog_found_it_overdue_does_not_end_the_process() {
    let placed = Placed::stub();
    let runtime = placed.directory("job-ends-while-held");
    let script = Script {
        ignore_token_until_released: true,
        mark_work: true,
        hold_watchdog: true,
        ..Script::default()
    };
    let mut process = Process::start(&placed, &script, &runtime);
    process.hello();
    process.send(&load(1, &default_profile(), 300_000));
    process.expect_answer(SOON, "the load");
    process.send(&generate(2, 1, 200));
    wait_for("the watchdog to find the job overdue", || {
        watchdog_found(&runtime).is_some()
    });
    release_held_work(&runtime);
    let answer = process.expect_answer(SOON, "the job's answer");
    assert!(
        matches!(
            answer,
            Answer::Produced { id, .. } | Answer::Ended { id, .. } if id.get() == 2
        ),
        "{answer:?}"
    );
    wait_for("the model thread to clear the job's bound", || {
        bound_held_after_the_answer(&runtime, 2).is_some()
    });
    for (record, as_it) in [
        (bound_held_at_the_forgetting(&runtime, 2), "forgotten"),
        (bound_held_at_the_answer(&runtime, 2), "answered"),
    ] {
        assert!(
            record.is_some_and(|held| held != 0),
            "the bound the job was held to is still held as the job is {as_it}: {record:?}"
        );
    }
    assert_eq!(
        bound_held_after_the_answer(&runtime, 2),
        Some(0),
        "the bound the job was held to is cleared when it is answered"
    );
    release_held_watchdog(&runtime);
    wait_for("the watchdog to decide", || {
        watchdog_has_spared(&runtime) || process.exit_within(Duration::ZERO).is_some()
    });
    assert!(
        watchdog_has_spared(&runtime),
        "the process ended after the job it was found overdue for had ended"
    );
}

/// KR-REQ-22.11: a job whose stop the control thread read before the model thread took it in hand
/// is held to the stop bound from the start, as one whose stop is read after. The cancellation
/// finds no job in hand, and the model thread answers the job cancelled without running it; its
/// answer waits for the lock the acknowledgement is written under, and a watchdog holding the job
/// to the grace would end the process if the write outlasted it. The model thread is in a load the
/// case holds while the job and its cancellation are sent, and releases once the acknowledgement
/// has arrived. The bound the process set for the job is read back from its own record.
#[test]
fn a_job_cancelled_before_it_is_in_hand_is_held_to_the_stop_bound_from_the_start() {
    let placed = Placed::stub();
    let runtime = placed.directory("queued");
    let script = Script {
        load_until_released: true,
        mark_work: true,
        ..Script::default()
    };
    let mut process = Process::start(&placed, &script, &runtime);
    process.hello();
    process.send(&load(1, &default_profile(), 300_000));
    wait_until_began(&runtime, "load");
    process.send(&generate(2, 1, 60_000));
    process.send(&Request::Cancel { id: U64::new(2) });
    assert_eq!(
        process.expect_answer(SOON, "the acknowledgement"),
        Answer::Cancelling { id: U64::new(2) }
    );
    release_held_work(&runtime);
    assert!(matches!(
        process.expect_terminal(SOON, "the load"),
        Answer::Loaded { id, .. } if id.get() == 1
    ));
    assert!(matches!(
        process.expect_terminal(SOON, "the cancelled job"),
        Answer::Ended { id, why: JobEnd::Cancelled, .. } if id.get() == 2
    ));
    assert!(
        !began(&runtime, "job"),
        "the cancelled job is answered without being run"
    );
    assert_eq!(
        job_bounds(&runtime, 2),
        Some((GUIDE_STOP_BOUND_MS, GUIDE_STOP_BOUND_MS)),
        "the job is held to the stop bound as it comes into hand, in milliseconds past its deadline"
    );
}

/// KR-REQ-22.11: a stop that arrives while a job is coming into hand, after the model thread has read
/// the job's token and before it has set the job's bound, is not lost: the cancellation finds the job
/// in hand and extends it, and the model thread's bound does not take the extension back. The script
/// holds the model thread between the two; the case sends the stop once the process says it has read
/// the token (the record holds what the read returned, so it is left after the read, and the case
/// asserts that the read found the token not cancelled, so that the model thread always has the
/// grace to set), reads the acknowledgement, which is written after the extension, and lets the
/// model thread go. The bound the process holds the job to is then read back from the process: the
/// stop bound. No delay decides it. A bound set in place of the extension, or a job put in hand
/// after its bound, leaves the grace.
#[test]
fn a_stop_read_while_a_job_comes_into_hand_is_not_lost() {
    let placed = Placed::stub();
    let runtime = placed.directory("coming-into-hand");
    let script = Script {
        hold_job_start: true,
        mark_work: true,
        ..Script::default()
    };
    let mut process = Process::start(&placed, &script, &runtime);
    process.hello();
    process.send(&load(1, &default_profile(), 300_000));
    process.expect_answer(SOON, "the load");
    process.send(&generate(2, 1, 60_000));
    wait_for("the model thread to read the job's token", || {
        job_token_as_read(&runtime, 2).is_some()
    });
    process.send(&Request::Cancel { id: U64::new(2) });
    assert_eq!(
        process.expect_answer(SOON, "the acknowledgement"),
        Answer::Cancelling { id: U64::new(2) }
    );
    release_held_work(&runtime);
    assert!(matches!(
        process.expect_terminal(SOON, "the cancelled job"),
        Answer::Ended { id, why: JobEnd::Cancelled, .. } if id.get() == 2
    ));
    assert_eq!(
        job_token_as_read(&runtime, 2),
        Some(TokenRead {
            in_hand: true,
            cancelled: false
        }),
        "the job is in hand before its token is read, and the read finds the token not cancelled"
    );
    assert!(
        !began(&runtime, "job"),
        "the cancelled job is answered without being run"
    );
    assert_eq!(
        job_bounds(&runtime, 2),
        Some((GUIDE_STOP_BOUND_MS, GUIDE_STOP_BOUND_MS)),
        "the job is held to the stop bound, in milliseconds past its deadline"
    );
}

/// A process whose model fails inside a job ends itself, so the daemon restarts inference rather
/// than sending work to a process with no model thread; the control is the same job succeeding.
#[test]
fn a_process_whose_model_fails_ends_itself() {
    let placed = Placed::stub();
    let runtime = placed.directory("failing");
    let script = Script {
        panic_in_generate: true,
        ..Script::default()
    };
    let mut process = Process::start(&placed, &script, &runtime);
    process.hello();
    process.send(&load(1, &default_profile(), 300_000));
    process.expect_answer(SOON, "the load");
    process.send(&generate(2, 1, 30_000));
    let status = process
        .exit_within(SOON)
        .expect("the process ends when its model fails");
    assert_eq!(status.code(), Some(Exit::ModelFailed.code()));

    let runtime = placed.directory("succeeding");
    let mut process = Process::start(&placed, &Script::default(), &runtime);
    process.hello();
    process.send(&load(1, &default_profile(), 300_000));
    process.expect_answer(SOON, "the load");
    process.send(&generate(2, 1, 30_000));
    assert!(matches!(
        process.expect_answer(SOON, "the job"),
        Answer::Produced { .. }
    ));
    assert!(process.exit_within(Duration::from_millis(300)).is_none());
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

/// When a job reached a model, and when the process was to be done with it.
#[derive(Clone, Copy, Debug)]
struct Due {
    reached_at: Instant,
    deadline: Instant,
}

/// A model that records what it was asked for, the deadline it was given, and what a read on the
/// thread that runs its loads and its jobs reports of its background class.
#[derive(Clone, Default)]
struct Recording {
    asked: Arc<Mutex<Vec<Asked>>>,
    due: Arc<Mutex<Vec<Due>>>,
    #[cfg(unix)]
    held_at_load: Arc<Mutex<Vec<support::Held>>>,
    #[cfg(unix)]
    held: Arc<Mutex<Vec<support::Held>>>,
}

impl Recording {
    /// How many jobs have reached the model.
    fn jobs(&self) -> usize {
        self.asked.lock().expect("the record").len()
    }
}

impl Model for Recording {
    fn load(&mut self, _work: &LoadWork<'_>, _token: &Cancellation, _deadline: Instant) -> Loading {
        #[cfg(unix)]
        self.held_at_load
            .lock()
            .expect("the record")
            .push(support::held_by_this_thread());
        Loading::Loaded
    }

    fn generate(&mut self, job: &Job<'_>, _token: &Cancellation, deadline: Instant) -> Generating {
        let reached_at = Instant::now();
        #[cfg(unix)]
        self.held
            .lock()
            .expect("the record")
            .push(support::held_by_this_thread());
        self.due.lock().expect("the record").push(Due {
            reached_at,
            deadline,
        });
        self.asked.lock().expect("the record").push(Asked {
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

    fn verify(
        &mut self,
        _asset: &kr_describe::profile::Asset,
        _path: &Path,
        _token: &Cancellation,
        _deadline: Instant,
    ) -> Verifying {
        Verifying::Verified
    }
}

/// What the system reports of the background class this process holds, where this process is what
/// holds one: the process's priority class and I/O class on Windows, its background class and disk
/// policy on macOS, and on Linux the I/O class of the calling thread, which a server run on another
/// thread leaves alone.
fn classes() -> impl PartialEq + std::fmt::Debug {
    #[cfg(windows)]
    {
        kr_ipc::background::process_class()
    }
    #[cfg(target_os = "macos")]
    {
        (
            kr_ipc::background::process_in_background(),
            kr_ipc::background::io_class(),
        )
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        kr_ipc::background::io_class()
    }
}

/// The turn that cases serving inside this process take.
static SERVING: Mutex<()> = Mutex::new(());

/// Serves `model` inside this process: sends it `requests` in order, ends its input once `done`
/// holds, and returns how the server ended, with the moment before each request was sent.
///
/// The server's model thread takes the background class, and on macOS and Windows the class it
/// takes is the whole process's, which every later case of this binary would run in, and which
/// holds every thread of this binary, those of the cases that run beside this one included. So the
/// case notes the class it found and puts it back, and the cases that serve here take turns, since
/// one that puts the class back while another reads it would fail the second for the first's sake.
/// The server keeps its real watchdog (`CONTROL_BOUND_MS`), so a host that stalls one of its
/// threads past it ends the whole test binary, and not a named case.
fn serve_in_process(
    model: impl Model,
    requests: &[Request],
    done: impl Fn() -> bool,
) -> (Exit, Vec<Instant>) {
    let _turn = SERVING.lock().unwrap_or_else(PoisonError::into_inner);
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
    let runtime = tempfile::tempdir().expect("a directory on the internal disk");
    let found = classes();
    let saved = kr_ipc::background::save();
    // A binary run under `taskpolicy -b` is in the class, and would read it without the product.
    #[cfg(target_os = "macos")]
    kr_ipc::background::leave_priority_class()
        .expect("this process leaves the background class it began in");
    let serving = {
        let output = Shared(output.clone());
        let runtime = runtime.path().to_path_buf();
        std::thread::spawn(move || {
            kr_describe::serve::run(
                Options {
                    build: "kr-describe-tests/0".to_owned(),
                    runtime_dir: runtime,
                    catalogue: Catalogue::builtin().expect("the catalogue"),
                    daemon: None,
                },
                model,
                Input(read, Vec::new()),
                output,
            )
        })
    };
    let mut sent_at = Vec::new();
    for request in requests {
        sent_at.push(Instant::now());
        write
            .send(frame_of(request).expect("a frame"))
            .expect("sent");
    }
    let until = Instant::now() + SOON;
    while !done() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(write);
    let ended = serving.join().expect("the serving thread");
    saved.restore().expect("the class is put back");
    assert_eq!(
        classes(),
        found,
        "the process is left in the class it found"
    );
    (ended, sent_at)
}

/// KR-REQ-22.10: a job runs with the thread count and bounds it was sent and with the sampler of
/// the profile the process loaded, and the job's deadline is thirty seconds from a moment between
/// the job's being sent and its reaching the model. The deadline is the one the job was sent with:
/// a second job sent with twelve seconds is given twelve, so the thirty are not a figure the process
/// keeps for itself.
#[test]
fn a_job_runs_with_the_limits_sent_and_the_loaded_profiles_sampler() {
    let recording = Recording::default();
    let profile = default_profile();
    let (ended, sent_at) = serve_in_process(
        recording.clone(),
        &[
            load(1, &profile, 300_000),
            generate(2, 1, 30_000),
            generate(3, 1, 12_000),
        ],
        || recording.jobs() == 2,
    );
    assert_eq!(ended, Exit::Ended);
    let asked = Asked {
        context_tokens: 4_096,
        max_output_tokens: 128,
        cpu_threads: 4,
        sampler: *profile.sampler(),
        ceiling_bytes: 4 << 30,
    };
    let recorded = recording.asked.lock().expect("the record").clone();
    assert_eq!(
        recorded,
        vec![asked, asked],
        "each job ran with what it was sent and with the loaded profile's sampler"
    );

    // The deadline is the sent one, from a moment between the job's being sent and its reaching the
    // model, which orders the three moments and waits for none of them.
    let due = recording.due.lock().expect("the record").clone();
    let [thirty, twelve] = due[..] else {
        panic!("two jobs reached the model: {due:?}");
    };
    for (sent, due, seconds) in [(sent_at[1], thirty, 30), (sent_at[2], twelve, 12)] {
        let deadline = Duration::from_secs(seconds);
        assert!(
            sent + deadline <= due.deadline,
            "the deadline is no sooner than {seconds} seconds after the job was sent"
        );
        assert!(
            due.deadline <= due.reached_at + deadline,
            "the deadline is no later than {seconds} seconds after the job reached the model"
        );
    }
}

/// KR-REQ-22.11: the thread that runs a load and a job is in the background class while it runs
/// them: a read on that thread finds the processor class this build lowers a model thread to
/// (Linux: the batch policy at niceness 19; macOS: the background priority the kernel reports for
/// the thread) and the I/O class it lowers to (Linux: idle; macOS: the
/// throttled disk policy of the process). The server does not hand out the model thread's
/// identifier, so the case reads it on that thread. It shows the model thread and no thread that
/// thread starts: the threads a model starts are read in the Linux case and in the macOS case that
/// follow this one. Windows reads the process's class from outside, in `tests/supervise.rs`.
#[cfg(unix)]
#[test]
fn the_thread_that_runs_a_job_is_in_the_background_class_the_system_reports() {
    let recording = Recording::default();
    let profile = default_profile();
    serve_in_process(
        recording.clone(),
        &[load(1, &profile, 300_000), generate(2, 1, 30_000)],
        || recording.jobs() == 1,
    );
    // The load is the one place the I/O class acts on a read: the model's weights are read once
    // there, and a resident model does no I/O after it. So the class is read at the load as well as
    // at the job.
    let at_load = recording.held_at_load.lock().expect("the record").clone();
    let [at_load] = at_load[..] else {
        panic!("one load reached the model: {at_load:?}");
    };
    let held = recording.held.lock().expect("the record").clone();
    let [held] = held[..] else {
        panic!("one job reached the model: {held:?}");
    };
    for (when, held) in [("load", at_load), ("job", held)] {
        assert!(
            held.cpu_is_lowered(),
            "the thread holds no lowered processor class at its {when}: {held:?}"
        );
        assert!(
            held.io_is_lowered(),
            "the thread holds no lowered I/O class at its {when}: {held:?}"
        );
    }
}

/// A model that starts a thread of its own, with the default attributes, in a load and in a job, as
/// a runtime that reads its weights or computes on a pool does, and records what each of those
/// threads reports of its own background class.
#[cfg(target_os = "linux")]
#[derive(Clone, Default)]
struct Starting {
    at_load: Arc<Mutex<Vec<support::Held>>>,
    at_job: Arc<Mutex<Vec<support::Held>>>,
}

#[cfg(target_os = "linux")]
impl Starting {
    /// What a thread started from the calling thread reports of its class.
    fn held_by_a_thread_started_here() -> support::Held {
        std::thread::Builder::new()
            .name("model-thread".to_owned())
            .spawn(support::held_by_this_thread)
            .expect("a thread starts")
            .join()
            .expect("the thread read its class")
    }
}

#[cfg(target_os = "linux")]
impl Model for Starting {
    fn load(&mut self, _work: &LoadWork<'_>, _token: &Cancellation, _deadline: Instant) -> Loading {
        let held = Self::held_by_a_thread_started_here();
        self.at_load.lock().expect("the record").push(held);
        Loading::Loaded
    }

    fn generate(
        &mut self,
        _job: &Job<'_>,
        _token: &Cancellation,
        _deadline: Instant,
    ) -> Generating {
        let held = Self::held_by_a_thread_started_here();
        self.at_job.lock().expect("the record").push(held);
        Generating::Ended {
            why: JobEnd::Failed,
            detail: None,
        }
    }

    fn verify(
        &mut self,
        _asset: &kr_describe::profile::Asset,
        _path: &Path,
        _token: &Cancellation,
        _deadline: Instant,
    ) -> Verifying {
        Verifying::Verified
    }
}

/// KR-REQ-22.11, the threads a model starts on Linux only: a thread the model starts of its own,
/// in the load and in the job it is given, runs at the background class the process sets for the
/// thread that runs the model, which is the batch policy at niceness 19 and the idle I/O class.
/// The server applies the class on that thread before it hands the model a load or a job, and
/// the new threads inherit it. The case reads the class on the thread the model started, and not
/// on the model thread. The control is a thread started from the test's own thread, outside the
/// server: it reads neither class, so a process that was already in the class as a whole would not
/// pass for the product having put the model's threads there. Not shown here: that a job is
/// cancellable, that the disk's scheduler acts on the idle class, and the other platforms, which
/// the cases beside this one read from outside.
#[cfg(target_os = "linux")]
#[test]
fn a_thread_the_model_starts_is_in_the_background_class_the_system_reports() {
    let model = Starting::default();
    let profile = default_profile();
    serve_in_process(
        model.clone(),
        &[load(1, &profile, 300_000), generate(2, 1, 30_000)],
        || !model.at_job.lock().expect("the record").is_empty(),
    );
    let at_load = model.at_load.lock().expect("the record").clone();
    let [at_load] = at_load[..] else {
        panic!("one load reached the model: {at_load:?}");
    };
    let at_job = model.at_job.lock().expect("the record").clone();
    let [at_job] = at_job[..] else {
        panic!("one job reached the model: {at_job:?}");
    };
    for (when, held) in [("load", at_load), ("job", at_job)] {
        assert!(
            held.cpu_is_lowered(),
            "a thread the model started in its {when} holds no lowered processor class: {held:?}"
        );
        assert!(
            held.io_is_lowered(),
            "a thread the model started in its {when} holds no lowered I/O class: {held:?}"
        );
    }

    let outside = Starting::held_by_a_thread_started_here();
    assert!(
        !outside.cpu_is_lowered() && !outside.io_is_lowered(),
        "a thread this test starts outside the server is already in the class, so the case could \
         not tell the product's work from the process's: {outside:?}"
    );
}

/// KR-REQ-22.11: on macOS every thread of the description process is in the background class the
/// kernel reports while a job runs, the threads the model starts during the job as well as the
/// thread that runs it. The model here starts three threads of its own with the default
/// attributes, as a runtime with a pool of compute threads does, and holds the job. The case reads
/// the kernel's base priority of every thread of the process from outside, and not a
/// record the thread library keeps: a thread that took the lowest priority through the thread
/// library reads 15 there, and the threads it starts read 31. The stub begins outside the class
/// whatever class its starter ran in, so a process the class was never applied to reads 31 on every
/// thread and fails the case.
#[cfg(target_os = "macos")]
#[test]
fn the_threads_a_model_starts_during_a_job_are_in_the_class_the_kernel_reports() {
    use kr_ipc::background::{BACKGROUND_THREAD_PRIORITY, thread_priorities_of};

    let placed = Placed::stub();
    let runtime = placed.directory("job-threads");
    let script = Script {
        job_threads: 3,
        generate_until_cancelled: true,
        mark_work: true,
        ..Script::default()
    };
    let mut process = Process::start(&placed, &script, &runtime);
    process.hello();
    process.send(&load(1, &default_profile(), 300_000));
    process.expect_answer(SOON, "the load");
    let before = thread_priorities_of(process.pid()).expect("the kernel lists the threads");
    process.send(&generate(2, 1, 30_000));
    wait_until_began(&runtime, "threads");

    let priorities = thread_priorities_of(process.pid()).expect("the kernel lists the threads");
    // The three threads the job started are among those the kernel lists now.
    assert!(
        priorities.len() >= before.len() + 3,
        "the job's threads are not among those the kernel lists: {before:?} before, {priorities:?}"
    );
    assert!(
        priorities
            .iter()
            .all(|priority| *priority <= BACKGROUND_THREAD_PRIORITY),
        "a thread of the process is outside the background class: {priorities:?}"
    );

    // The job ends when it is cancelled, which is what the process was held for.
    process.send(&Request::Cancel { id: U64::new(2) });
    assert!(matches!(
        process.expect_terminal(SOON, "the cancelled job"),
        Answer::Ended { id, why: JobEnd::Cancelled, .. } if id.get() == 2
    ));
}
