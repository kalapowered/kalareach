//! A question asked under an agent's binding ends when that binding does.
//!
//! Two bridges. The worker's own broker launched the agent and knows its process by its start
//! identity, so it says which agent a helper belongs to and whether that agent's instance is still
//! live; the source here is this test process, launched as far as the broker is concerned, and the
//! ledger is opened with that broker attached, as the worker service opens it. The other bridge is
//! a double that attests the thread each request was made in, which is what section 11 asks of a
//! bridge before a question records a thread binding.
//!
//! The broker places a helper by the parent chain on Unix and by the job an agent was started in on
//! Windows, so the placement tests are per platform and the rest run on both.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-11.62 | every test below |

use std::sync::Arc;

use kr_protocol::broker::IntegrationMode;
use kr_protocol::error::ErrorCode;
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{
    ActorId, AgentBindingRevision, ApplicationInstanceId, ConnectionId, QuestionId, SessionEpoch,
    SessionId,
};
use kr_protocol::question::{
    CallerToken, Question, QuestionAnswer, QuestionAnswerParams, QuestionCreateParams,
    QuestionEventKind, QuestionKind, QuestionReadOwnParams, QuestionReadParams, QuestionState,
};
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, Uuid};
use kr_worker::broker::{
    Broker, BrokerTransport, Credential, InstanceEnding, ManagedProcess, TransportHandle,
};
use kr_worker::ownership::OwnershipBoundary;
use kr_worker::questions::{Now, Questions, SessionBoundary, VerifiedSource};

fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([7; 16]))
}

fn now(utc_ms: u64) -> Now {
    Now {
        utc_ms: TimestampMs::new(utc_ms),
        boot_ms: utc_ms,
    }
}

fn this_process() -> ProcessStartIdentity {
    kr_ipc::identity::current_process_start_identity().expect("this process's identity")
}

/// The process that started this test, which is alive for as long as the test is and is not a
/// descendant of it.
fn parent_process() -> ProcessStartIdentity {
    kr_ipc::identity::process_start_identity(parent_id()).expect("the parent's identity")
}

#[cfg(unix)]
fn parent_id() -> u32 {
    std::os::unix::process::parent_id()
}

/// The parent this process names, which the test's runner, alive for the whole test, still is.
#[cfg(windows)]
fn parent_id() -> u32 {
    let mut system = sysinfo::System::new();
    let me = sysinfo::Pid::from_u32(std::process::id());
    system.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::Some(&[me]),
        true,
        sysinfo::ProcessRefreshKind::nothing(),
    );
    system
        .process(me)
        .and_then(sysinfo::Process::parent)
        .expect("this process names its parent")
        .as_u32()
}

fn source(process: ProcessStartIdentity, connection: u8) -> VerifiedSource {
    VerifiedSource {
        process,
        executable: None,
        session_member: true,
        ancestry: true,
        launch_channel: false,
        connection_id: ConnectionId::new(Uuid::from_bytes([connection; 16])),
    }
}

/// Registers `process` with the broker as the agent it launched for `instance`.
fn launched(broker: &Broker, instance: ApplicationInstanceId, process: ProcessStartIdentity) {
    broker
        .register_instance(
            instance,
            IntegrationMode::Gateway,
            None,
            Some(ManagedProcess::new(
                instance,
                process.clone(),
                TransportHandle {
                    transport: BrokerTransport::PrivateSocket,
                    application_instance_id: instance,
                    executable_digest: Digest256::from_bytes([1; 32]),
                    process,
                },
                Credential::generate().expect("a launch credential"),
                true,
                TimestampMs::new(1),
            )),
        )
        .expect("the instance is registered");
}

/// The broker, an agent it launched as this test process, and the ledger with the broker attached.
fn bridged() -> (Arc<Broker>, ApplicationInstanceId, Questions) {
    let broker = Arc::new(Broker::open(None, session()).expect("a broker"));
    let instance = ApplicationInstanceId::new(Uuid::from_bytes([9; 16]));
    launched(&broker, instance, this_process());
    let questions = Questions::open(None, session(), SessionEpoch::V1)
        .expect("a ledger")
        .with_agents(Arc::clone(&broker) as Arc<dyn kr_worker::questions::AgentBindings>);
    (broker, instance, questions)
}

fn ask(request_id: &str) -> QuestionCreateParams {
    QuestionCreateParams {
        session_id: session(),
        request_id: request_id.to_owned(),
        agent_name: Nullable::null(),
        context: String::new(),
        question: "shall I?".to_owned(),
        kind: QuestionKind::Confirm,
        choices: Vec::new(),
        requested_expiry_ms: Nullable::null(),
        wait_ms: Nullable::null(),
    }
}

fn answer(question: &Question) -> QuestionAnswerParams {
    QuestionAnswerParams {
        session_id: session(),
        question_id: question.question_id,
        expected_revision: question.revision,
        answer: QuestionAnswer::Decision { decided: true },
    }
}

fn person() -> ActorId {
    ActorId::new("local:501").expect("a principal")
}

/// Every question in the session, as any answering client reads it.
fn every_question(questions: &Questions, at: u64) -> Vec<Question> {
    questions
        .read(
            &QuestionReadParams {
                session_id: session(),
                question_id: Nullable::null(),
                include_resolved: true,
            },
            now(at),
        )
        .expect("the answering surface reads")
        .0
        .questions
}

fn state_of(questions: &[Question], question_id: QuestionId) -> QuestionState {
    questions
        .iter()
        .find(|question| question.question_id == question_id)
        .expect("the question")
        .state
}

/// A bridge that attests the thread each request was made in, as a connector with verified
/// per-request context does: every request from `agent` is made under the binding `revision` names.
#[derive(Debug)]
struct Attesting {
    agent: ProcessStartIdentity,
    instance: ApplicationInstanceId,
    revision: std::sync::Mutex<u64>,
}

impl Attesting {
    fn switch(&self) {
        *self.revision.lock().expect("the lock") += 1;
    }
}

impl kr_worker::questions::AgentBindings for Attesting {
    fn binding_of(&self, process: &ProcessStartIdentity) -> kr_worker::questions::AgentPlacement {
        if process.matches(&self.agent) {
            kr_worker::questions::AgentPlacement::Bound(kr_worker::questions::AgentBinding {
                application_instance_id: self.instance,
                revision: Some(AgentBindingRevision::new(
                    *self.revision.lock().expect("the lock"),
                )),
            })
        } else {
            kr_worker::questions::AgentPlacement::Unbound
        }
    }

    fn current(
        &self,
        application_instance_id: ApplicationInstanceId,
    ) -> Option<AgentBindingRevision> {
        (application_instance_id == self.instance)
            .then(|| AgentBindingRevision::new(*self.revision.lock().expect("the lock")))
    }
}

/// KR-REQ-11.62: a helper under an agent the worker's broker launched asks for that agent: its
/// questions name the agent's application instance, and they end when the instance does, however
/// long their day had left, for every client, with a person's answer refused and the agent's own
/// read showing it. The broker proves which agent a helper belongs to and not which thread a
/// request came from, so no binding revision is recorded and a thread switch it reports claims
/// nothing: the question stays open until the instance ends. A question no bridge describes is
/// application-scoped and ends only with its own source.
#[test]
fn a_launched_agents_questions_are_application_scoped_and_end_with_its_instance() {
    let (broker, instance, questions) = bridged();
    let agent = source(this_process(), 1);
    let elsewhere = source(parent_process(), 2);

    let (asked, _) = questions
        .create(&agent, &ask("asked"), now(1_000))
        .expect("asked");
    let (unbridged, _) = questions
        .create(&elsewhere, &ask("unbridged"), now(1_000))
        .expect("asked");
    assert_eq!(
        asked.question.source.application_instance_id, instance,
        "a helper under a launched agent asks for that agent's instance"
    );
    assert!(
        asked
            .question
            .source
            .agent_binding_revision
            .as_ref()
            .is_none(),
        "membership of an application is not a thread binding"
    );
    assert!(
        unbridged
            .question
            .source
            .agent_binding_revision
            .as_ref()
            .is_none()
    );
    assert_ne!(unbridged.question.source.application_instance_id, instance);

    // A thread switch the broker reports claims nothing for an application-scoped question.
    broker
        .advance_binding(instance, None, TimestampMs::new(1_500))
        .expect("the binding advances");
    assert!(questions.sweep(now(1_600)).expect("sweeps").is_empty());
    assert_eq!(
        state_of(
            &every_question(&questions, 1_700),
            asked.question.question_id
        ),
        QuestionState::Pending
    );

    // The agent's instance ends.
    let ended = broker.end(instance, InstanceEnding::NativeExit);
    assert!(ended.instance_ended);

    let read = every_question(&questions, 2_000);
    assert_eq!(
        state_of(&read, asked.question.question_id),
        QuestionState::Expired
    );
    assert_eq!(
        state_of(&read, unbridged.question.question_id),
        QuestionState::Pending
    );
    let expired: Vec<QuestionId> = questions
        .events_since(0, 64)
        .expect("the feed")
        .into_iter()
        .filter(|(_, event)| event.kind == QuestionEventKind::Expired)
        .map(|(_, event)| event.question.question_id)
        .collect();
    assert_eq!(expired, vec![asked.question.question_id]);
    let refused = questions
        .answer(&person(), None, &answer(&asked.question), now(2_100))
        .expect_err("an answer to it is refused");
    assert_eq!(refused.code(), ErrorCode::QuestionExpired);
    let (own, _) = questions
        .read_own(
            &agent,
            &QuestionReadOwnParams {
                session_id: session(),
                question_id: asked.question.question_id,
                caller_token: CallerToken::new(asked.caller_token.as_slice().to_vec()),
                wait_ms: Nullable::null(),
            },
            now(2_200),
        )
        .expect("the agent reads its question");
    assert_eq!(own.question.state, QuestionState::Expired);
}

/// KR-REQ-11.62: with a bridge that attests the thread each request was made in, a question records
/// the binding revision it was asked under, and a detected switch invalidates the unanswered
/// questions asked under the binding it left. Every client reads the invalidation, the feed carries
/// it once, a person's answer is refused and the worker's check before a dispatch marker refuses it
/// too; an answer given before the switch stays the answer, a question no bridge describes is
/// untouched, and the next question is asked under the new binding and stays open while it holds.
#[test]
fn a_switch_an_attesting_bridge_detects_invalidates_the_questions_asked_under_the_binding_it_left()
{
    let instance = ApplicationInstanceId::new(Uuid::from_bytes([11; 16]));
    let bridge = Arc::new(Attesting {
        agent: this_process(),
        instance,
        revision: std::sync::Mutex::new(1),
    });
    let questions = Questions::open(None, session(), SessionEpoch::V1)
        .expect("a ledger")
        .with_agents(Arc::clone(&bridge) as Arc<dyn kr_worker::questions::AgentBindings>);
    let agent = source(this_process(), 1);
    let elsewhere = source(parent_process(), 2);

    let (waiting, _) = questions
        .create(&agent, &ask("waiting"), now(1_000))
        .expect("asked");
    let (settled, _) = questions
        .create(&agent, &ask("settled"), now(1_000))
        .expect("asked");
    let (unbridged, _) = questions
        .create(&elsewhere, &ask("unbridged"), now(1_000))
        .expect("asked");
    for created in [&waiting, &settled] {
        assert_eq!(created.question.source.application_instance_id, instance);
        assert_eq!(
            created.question.source.agent_binding_revision.as_ref(),
            Some(&AgentBindingRevision::new(1)),
            "the question records the binding it was asked under"
        );
    }
    assert!(
        unbridged
            .question
            .source
            .agent_binding_revision
            .as_ref()
            .is_none(),
        "a source no bridge describes is application-scoped and claims no switch detection"
    );
    questions
        .answer(&person(), None, &answer(&settled.question), now(1_500))
        .expect("answered before the switch");

    // The agent moves to another thread.
    bridge.switch();

    let read = every_question(&questions, 2_100);
    assert_eq!(
        state_of(&read, waiting.question.question_id),
        QuestionState::Expired
    );
    assert_eq!(
        state_of(&read, settled.question.question_id),
        QuestionState::Answered,
        "an answer given before the switch stays the answer"
    );
    assert_eq!(
        state_of(&read, unbridged.question.question_id),
        QuestionState::Pending
    );
    let invalidated = read
        .iter()
        .find(|question| question.question_id == waiting.question.question_id)
        .expect("the question");
    assert!(invalidated.answer.as_ref().is_none());
    assert_eq!(
        invalidated.resolved_at_ms.as_ref().map(|at| at.get()),
        Some(2_100)
    );
    let expired: Vec<QuestionId> = questions
        .events_since(0, 64)
        .expect("the feed")
        .into_iter()
        .filter(|(_, event)| event.kind == QuestionEventKind::Expired)
        .map(|(_, event)| event.question.question_id)
        .collect();
    assert_eq!(expired, vec![waiting.question.question_id]);

    let refused = questions
        .answer(&person(), None, &answer(&waiting.question), now(2_200))
        .expect_err("an answer to an invalidated question is refused");
    assert_eq!(refused.code(), ErrorCode::QuestionExpired);
    assert!(
        questions
            .check_resolvable(
                waiting.question.question_id,
                waiting.question.revision,
                Some(&QuestionAnswer::Decision { decided: true }),
                now(2_200),
            )
            .is_err()
    );

    let (next, _) = questions
        .create(&agent, &ask("after the switch"), now(3_000))
        .expect("asked");
    assert_eq!(
        next.question.source.agent_binding_revision.as_ref(),
        Some(&AgentBindingRevision::new(2))
    );
    assert!(questions.sweep(now(3_100)).expect("sweeps").is_empty());
    assert_eq!(
        state_of(
            &every_question(&questions, 3_200),
            next.question.question_id
        ),
        QuestionState::Pending
    );
}

/// A helper that an agent the broker launched started is bound to the session through the broker,
/// although the backend runs outside the terminal's boundary and the root shell's tree; without the
/// broker's word it is refused as outside the session. Where the session's own boundary cannot be
/// read, nothing establishes it outside, and the broker's word still binds it.
#[cfg(unix)]
#[test]
fn a_helper_under_an_agent_the_broker_launched_is_bound_through_the_broker() {
    let broker = Broker::open(None, session()).expect("a broker");
    let instance = ApplicationInstanceId::new(Uuid::from_bytes([3; 16]));
    let me = this_process();
    // A boundary that holds nothing, read and found empty, and a root shell that is nobody's
    // ancestor.
    let group = tempfile::tempdir().expect("a control group directory");
    std::fs::write(group.path().join("cgroup.procs"), "").expect("an empty membership list");
    let mut stranger = me.clone();
    stranger.start_value = kr_protocol::scalars::U64::new(stranger.start_value.get() ^ 0xFFFF);
    let boundary = SessionBoundary {
        boundary: OwnershipBoundary::ControlGroup {
            path: group.path().to_path_buf(),
        },
        root: stranger.clone(),
    };
    let unreadable = SessionBoundary {
        boundary: OwnershipBoundary::ControlGroup {
            path: std::path::PathBuf::from("/nonexistent/kalareach-test-group"),
        },
        root: stranger,
    };
    let pid = u32::try_from(me.pid.get()).expect("a process identifier");
    let connection = ConnectionId::new(Uuid::from_bytes([4; 16]));

    let refused = kr_worker::questions::binding::verify(
        Some(pid),
        Some(&me),
        connection,
        Some(&boundary),
        Some(&broker),
    )
    .expect_err("nothing admits this process yet");
    assert_eq!(refused.code(), ErrorCode::NotInKrSession);

    // The broker launched this test's parent, so this process is inside that agent's tree.
    launched(&broker, instance, parent_process());
    let admitted = kr_worker::questions::binding::verify(
        Some(pid),
        Some(&me),
        connection,
        Some(&boundary),
        Some(&broker),
    )
    .expect("admitted through the broker");
    assert!(!admitted.session_member);
    assert!(!admitted.ancestry);
    assert!(matches!(
        kr_worker::questions::AgentBindings::binding_of(&broker, &admitted.process),
        kr_worker::questions::AgentPlacement::Bound(binding)
            if binding.application_instance_id == instance
    ));
    // The session's own boundary unreadable: the broker's word binds it all the same.
    kr_worker::questions::binding::verify(
        Some(pid),
        Some(&me),
        connection,
        Some(&unreadable),
        Some(&broker),
    )
    .expect("admitted through the broker");

    let without = kr_worker::questions::binding::verify(
        Some(pid),
        Some(&me),
        connection,
        Some(&boundary),
        None,
    )
    .expect_err("without the broker's word it is outside the session");
    assert_eq!(without.code(), ErrorCode::NotInKrSession);
    // And without it where the boundary cannot be read, nothing establishes where it is.
    let unknown = kr_worker::questions::binding::verify(
        Some(pid),
        Some(&me),
        connection,
        Some(&unreadable),
        None,
    )
    .expect_err("nothing establishes where it is");
    assert_eq!(unknown.code(), ErrorCode::ResourceUnavailable);
}

/// The broker's record of an agent that has ended, naming the identifier a live agent holds now,
/// hides no helper under the live one: the helper is admitted to the session and bound to the
/// live agent, whichever of the two records the broker walks first.
#[cfg(unix)]
#[test]
fn an_ended_agents_record_hides_no_live_agent_that_holds_its_identifier() {
    let me = this_process();
    let parent = parent_process();
    let mut ended = parent.clone();
    ended.start_value = kr_protocol::scalars::U64::new(ended.start_value.get() ^ 0xFFFF);
    // A boundary that holds nothing, read and found empty, and a root shell that is nobody's
    // ancestor: only the broker's word admits this process.
    let group = tempfile::tempdir().expect("a control group directory");
    std::fs::write(group.path().join("cgroup.procs"), "").expect("an empty membership list");
    let mut stranger = me.clone();
    stranger.start_value = kr_protocol::scalars::U64::new(stranger.start_value.get() ^ 0xFFFF);
    let boundary = SessionBoundary {
        boundary: OwnershipBoundary::ControlGroup {
            path: group.path().to_path_buf(),
        },
        root: stranger,
    };
    let pid = u32::try_from(me.pid.get()).expect("a process identifier");
    let connection = ConnectionId::new(Uuid::from_bytes([4; 16]));
    let first = ApplicationInstanceId::new(Uuid::from_bytes([1; 16]));
    let second = ApplicationInstanceId::new(Uuid::from_bytes([2; 16]));
    // Each record under each instance, so the ended one comes first in one of the two whatever
    // order the broker keeps its instances in.
    for (records, live) in [
        ([(first, ended.clone()), (second, parent.clone())], second),
        ([(first, parent.clone()), (second, ended.clone())], first),
    ] {
        let broker = Broker::open(None, session()).expect("a broker");
        for (instance, process) in records {
            launched(&broker, instance, process);
        }
        let admitted = kr_worker::questions::binding::verify(
            Some(pid),
            Some(&me),
            connection,
            Some(&boundary),
            Some(&broker),
        )
        .expect("admitted under the live agent");
        assert!(matches!(
            kr_worker::questions::AgentBindings::binding_of(&broker, &admitted.process),
            kr_worker::questions::AgentPlacement::Bound(binding)
                if binding.application_instance_id == live
        ));
    }
}

/// An agent and the helper it started, as the broker's launch starts one on Windows: in a job of
/// its own, joined before it ran, kept for the broker. The agent is `cmd.exe` and the helper the
/// `ping` it runs, which waits far longer than the test takes; both end with the test.
#[cfg(windows)]
struct Started {
    agent: std::process::Child,
    identity: ProcessStartIdentity,
    job: Arc<kr_worker::windows::job::AgentJob>,
    helper: ProcessStartIdentity,
}

#[cfg(windows)]
impl Started {
    fn new() -> Self {
        let job = Arc::new(kr_worker::windows::job::AgentJob::create().expect("a job"));
        let agent = job
            .start(
                std::process::Command::new("cmd.exe")
                    .args(["/d", "/c", "ping -n 600 127.0.0.1 > NUL"])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null()),
            )
            .expect("the agent starts");
        let identity =
            kr_ipc::identity::started_process_identity(agent.id()).expect("the agent's identity");
        kr_worker::windows::job::keep_agent(identity.clone(), Arc::clone(&job));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let helper = loop {
            let held = job.process_ids().expect("the job's process list");
            if let Some(helper) = held.into_iter().find(|pid| *pid != agent.id()) {
                break helper;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the agent started no helper"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        let helper =
            kr_ipc::identity::process_start_identity(helper).expect("the helper's identity");
        Self {
            agent,
            identity,
            job,
            helper,
        }
    }

    fn helper_pid(&self) -> u32 {
        u32::try_from(self.helper.pid.get()).expect("a process identifier")
    }
}

#[cfg(windows)]
impl Drop for Started {
    fn drop(&mut self) {
        let _ = self.job.terminate(1);
        let _ = self.agent.wait();
    }
}

/// A session whose job holds nothing, found by `root` as a live session's is, and a root shell that
/// is nobody's ancestor: only the broker's word admits a process to it.
#[cfg(windows)]
fn an_empty_session(root: u32) -> (Arc<kr_worker::windows::job::SessionJob>, SessionBoundary) {
    let job = Arc::new(kr_worker::windows::job::SessionJob::create().expect("a session job"));
    kr_worker::windows::job::record(root, &job);
    let mut stranger = this_process();
    stranger.start_value = kr_protocol::scalars::U64::new(stranger.start_value.get() ^ 0xFFFF);
    (
        job,
        SessionBoundary {
            boundary: OwnershipBoundary::JobObject { root },
            root: stranger,
        },
    )
}

/// On Windows, a helper that an agent the broker launched started is bound through the job the
/// agent was started in: it is outside the session's own job and its parent proves nothing, and
/// the agent's job holds it. The helper's identifier with another start value is placed nowhere. A
/// process the agent did not start is outside, and so is the helper without the broker's word. An
/// ended agent's record naming the live agent's identifier hides nothing, whichever the broker
/// reads first.
#[cfg(windows)]
#[test]
fn a_helper_an_agent_started_is_bound_through_the_job_the_agent_was_started_in() {
    let (_session_job, boundary) = an_empty_session(0xF000_0101);
    let started = Started::new();
    let connection = ConnectionId::new(Uuid::from_bytes([4; 16]));
    let verify = |pid: u32, process: &ProcessStartIdentity, broker: Option<&Broker>| {
        kr_worker::questions::binding::verify(
            Some(pid),
            Some(process),
            connection,
            Some(&boundary),
            broker.map(|broker| broker as &dyn kr_worker::questions::AgentBindings),
        )
    };

    let broker = Broker::open(None, session()).expect("a broker");
    let refused = verify(started.helper_pid(), &started.helper, Some(&broker))
        .expect_err("the broker has launched nothing yet");
    assert_eq!(refused.code(), ErrorCode::NotInKrSession, "{refused}");

    let instance = ApplicationInstanceId::new(Uuid::from_bytes([3; 16]));
    launched(&broker, instance, started.identity.clone());
    let admitted = verify(started.helper_pid(), &started.helper, Some(&broker))
        .expect("admitted through the broker");
    assert!(!admitted.session_member);
    assert!(!admitted.ancestry);
    assert!(matches!(
        kr_worker::questions::AgentBindings::binding_of(&broker, &admitted.process),
        kr_worker::questions::AgentPlacement::Bound(binding)
            if binding.application_instance_id == instance
    ));
    // The helper's identifier with a start value it never had names a process that is not the
    // helper, whatever the agent's job lists under that identifier: nothing is placed for it.
    let mut stranger = started.helper.clone();
    stranger.start_value = kr_protocol::scalars::U64::new(stranger.start_value.get() ^ 0xFFFF);
    assert!(matches!(
        kr_worker::questions::AgentBindings::binding_of(&broker, &stranger),
        kr_worker::questions::AgentPlacement::Undetermined(_)
    ));
    let me = this_process();
    let outside = verify(std::process::id(), &me, Some(&broker))
        .expect_err("the agent did not start this process");
    assert_eq!(outside.code(), ErrorCode::NotInKrSession, "{outside}");
    let without = verify(started.helper_pid(), &started.helper, None)
        .expect_err("without the broker's word the helper is outside");
    assert_eq!(without.code(), ErrorCode::NotInKrSession, "{without}");

    let mut ended = started.identity.clone();
    ended.start_value = kr_protocol::scalars::U64::new(ended.start_value.get() ^ 0xFFFF);
    let first = ApplicationInstanceId::new(Uuid::from_bytes([1; 16]));
    let second = ApplicationInstanceId::new(Uuid::from_bytes([2; 16]));
    for (records, live) in [
        (
            [(first, ended.clone()), (second, started.identity.clone())],
            second,
        ),
        (
            [(first, started.identity.clone()), (second, ended.clone())],
            first,
        ),
    ] {
        let broker = Broker::open(None, session()).expect("a broker");
        for (instance, process) in records {
            launched(&broker, instance, process);
        }
        let admitted = verify(started.helper_pid(), &started.helper, Some(&broker))
            .expect("admitted under the live agent");
        assert!(matches!(
            kr_worker::questions::AgentBindings::binding_of(&broker, &admitted.process),
            kr_worker::questions::AgentPlacement::Bound(binding)
                if binding.application_instance_id == live
        ));
    }
}

/// On Windows, an agent the broker names that was started in no job this worker keeps establishes
/// nothing about any process but itself: a process below it is neither admitted nor refused as
/// outside, and the agent itself is admitted.
#[cfg(windows)]
#[test]
fn an_agent_started_in_no_job_places_nothing_below_it() {
    let (_session_job, boundary) = an_empty_session(0xF000_0102);
    let broker = Broker::open(None, session()).expect("a broker");
    let instance = ApplicationInstanceId::new(Uuid::from_bytes([6; 16]));
    let parent = parent_process();
    launched(&broker, instance, parent.clone());
    let connection = ConnectionId::new(Uuid::from_bytes([4; 16]));

    let me = this_process();
    let unknown = kr_worker::questions::binding::verify(
        Some(std::process::id()),
        Some(&me),
        connection,
        Some(&boundary),
        Some(&broker),
    )
    .expect_err("nothing establishes where it is");
    assert_eq!(unknown.code(), ErrorCode::ResourceUnavailable, "{unknown}");

    let pid = u32::try_from(parent.pid.get()).expect("a process identifier");
    kr_worker::questions::binding::verify(
        Some(pid),
        Some(&parent),
        connection,
        Some(&boundary),
        Some(&broker),
    )
    .expect("the agent itself is admitted");
}
