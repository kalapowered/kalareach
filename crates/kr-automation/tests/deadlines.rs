//! Per-workflow limits as section 17 sets them: four concurrent runs, 100 pending runs, a 30-minute
//! run deadline and a ten-minute maximum action wait. A run past the concurrency limit waits as
//! pending and starts when a slot frees; a limit exceeded pauses the workflow and raises one
//! attention item; an action that outlives its wait or its run's deadline is asked to stop.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use kr_automation::{
    ActionOutcome, ActionRunner, AttentionSubject, AutomationService, Dispatch, ManualClock,
    create_workflow_definition,
};
use kr_protocol::automation::{
    EdgeCondition, NodeStatus, WorkflowActionKind, WorkflowDeadlines, WorkflowDefinition,
    WorkflowEdge, WorkflowEnableParams, WorkflowInstallParams, WorkflowReadParams,
    WorkflowRunParams, WorkflowRunStatus,
};
use kr_protocol::ids::{GrantId, WorkflowId};
use kr_protocol::scalars::{Nullable, U64, Uuid};
use tokio::sync::{Notify, Semaphore};

mod common;

use common::Submit;

fn workflow_id(v: u8) -> WorkflowId {
    WorkflowId::new(Uuid::from_bytes([v; 16]))
}

fn grant_id(v: u8) -> GrantId {
    GrantId::new(Uuid::from_bytes([v; 16]))
}

/// A runner whose actions each wait for a permit the test hands out, and that counts how many
/// actions have begun.
struct Gated {
    permits: Arc<Semaphore>,
    entered: Arc<AtomicUsize>,
    arrived: Arc<Notify>,
}

impl Gated {
    fn new() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(0)),
            entered: Arc::new(AtomicUsize::new(0)),
            arrived: Arc::new(Notify::new()),
        }
    }
}

impl ActionRunner for Gated {
    fn cancel(&self, _dispatch: &Dispatch<'_>) -> kr_automation::Cancellation {
        kr_automation::Cancellation::Unsupported
    }

    fn execute(
        &self,
        dispatch: &Dispatch<'_>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = kr_automation::Result<ActionOutcome>> + Send>,
    > {
        let permits = Arc::clone(&self.permits);
        let entered = Arc::clone(&self.entered);
        let arrived = Arc::clone(&self.arrived);
        let kind = dispatch.node.action_kind;
        Box::pin(async move {
            entered.fetch_add(1, Ordering::SeqCst);
            arrived.notify_waiters();
            permits
                .acquire()
                .await
                .expect("the gate stays open")
                .forget();
            Ok(ActionOutcome::Success {
                output: kr_automation::stand_in_output(kind),
            })
        })
    }
}

/// Waits until `count` actions have begun.
async fn entered(gated: &Gated, count: usize) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while gated.entered.load(Ordering::SeqCst) < count {
        assert!(
            std::time::Instant::now() < deadline,
            "{count} actions began within ten seconds"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

fn one_node(id: WorkflowId, grant: GrantId) -> WorkflowDefinition {
    create_workflow_definition(
        id,
        1,
        "limited",
        grant,
        vec![common::node("only", WorkflowActionKind::RunTests)],
        vec![],
    )
}

fn run_params(definition: &WorkflowDefinition, event_id: &str) -> WorkflowRunParams {
    WorkflowRunParams {
        workflow_id: definition.workflow_id,
        revision: definition.revision,
        event_id: event_id.to_owned(),
        event_type: "manual".to_owned(),
        event_payload: Nullable::null(),
    }
}

/// Installs and enables `definition` on `service`.
fn installed(service: &AutomationService, definition: &WorkflowDefinition) {
    service
        .submit_install(
            &WorkflowInstallParams {
                workflow_id: definition.workflow_id,
                revision: definition.revision,
                definition: definition.clone(),
                grant_reference: definition.grant_reference,
            },
            1_000,
        )
        .expect("installs");
    service
        .submit_enable(
            &WorkflowEnableParams {
                workflow_id: definition.workflow_id,
                revision: definition.revision,
            },
            1_000,
        )
        .expect("enables");
}

/// A run past the four a workflow runs at once is admitted and waits as pending, rather than
/// being refused or pausing the workflow. When a running run ends, the pending one starts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_run_past_the_concurrency_limit_waits_as_pending_and_starts_when_a_slot_frees() {
    let gated = Arc::new(Gated::new());
    let service = Arc::new(
        AutomationService::in_memory(common::host(
            Arc::clone(&gated) as Arc<dyn ActionRunner>,
            common::every_right(&[grant_id(1)]),
            Arc::new(ManualClock::new(1_000)),
        ))
        .expect("a service"),
    );
    let definition = one_node(workflow_id(1), grant_id(1));
    installed(&service, &definition);

    let mut running = Vec::new();
    for index in 0..4 {
        let service = Arc::clone(&service);
        let params = run_params(&definition, &format!("evt-{index}"));
        running.push(tokio::spawn(async move {
            service.submit_run(&params, 1_000).await
        }));
    }
    entered(&gated, 4).await;

    let queued = service
        .submit_run(&run_params(&definition, "evt-queued"), 1_000)
        .await
        .expect("a fifth run is admitted to wait");
    assert_eq!(queued.status, WorkflowRunStatus::Pending, "{queued:?}");
    assert!(
        !service
            .store()
            .is_paused(definition.workflow_id, 1)
            .expect("reads"),
        "waiting is not exceeding a limit"
    );

    // While every slot is taken, nothing waiting starts.
    let none = service.start_queued(1_500);
    assert!(none.started.is_empty() && none.stopped.is_none());

    // One running run ends, and the pending one takes its place.
    gated.permits.add_permits(1);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut started = Vec::new();
    while started.is_empty() {
        let pass = service.start_queued(2_000);
        assert!(pass.stopped.is_none(), "{:?}", pass.stopped);
        started = pass.started;
        assert!(
            std::time::Instant::now() < deadline,
            "the pending run started once a slot freed"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(started.len(), 1, "one slot freed, so one run started");
    assert_eq!(started[0].run_id(), queued.run_id, "the oldest pending run");
    for run in started {
        let service = Arc::clone(&service);
        running.push(tokio::spawn(async move { service.execute(run).await }));
    }
    entered(&gated, 5).await;
    gated.permits.add_permits(4);
    for run in running {
        run.await
            .expect("the task ends")
            .expect("the run completes");
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let summary = service
            .store()
            .run_summary(queued.run_id)
            .expect("reads")
            .expect("the queued run is recorded");
        if summary.status == WorkflowRunStatus::Completed {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the queued run completed, and is {:?}",
            summary.status
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// A queue past its hundred pending runs is a limit exceeded: the run is refused, the workflow is
/// paused, and one attention item is raised.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_queue_past_its_pending_limit_pauses_the_workflow_and_raises_one_item() {
    let gated = Arc::new(Gated::new());
    let service = Arc::new(
        AutomationService::in_memory(common::host(
            Arc::clone(&gated) as Arc<dyn ActionRunner>,
            common::every_right(&[grant_id(2)]),
            Arc::new(ManualClock::new(1_000)),
        ))
        .expect("a service"),
    );
    let definition = one_node(workflow_id(2), grant_id(2));
    installed(&service, &definition);

    let mut running = Vec::new();
    for index in 0..4 {
        let service = Arc::clone(&service);
        let params = run_params(&definition, &format!("evt-{index}"));
        running.push(tokio::spawn(async move {
            service.submit_run(&params, 1_000).await
        }));
    }
    entered(&gated, 4).await;
    for index in 0..100 {
        let queued = service
            .submit_run(
                &run_params(&definition, &format!("evt-queued-{index}")),
                1_000,
            )
            .await
            .unwrap_or_else(|error| panic!("pending run {index} is admitted: {error}"));
        assert_eq!(queued.status, WorkflowRunStatus::Pending);
    }

    let refused = service
        .submit_run(&run_params(&definition, "evt-over"), 1_000)
        .await
        .expect_err("the hundred-and-first pending run is refused");
    assert!(refused.to_string().contains("pending"), "{refused}");
    assert!(
        service
            .store()
            .is_paused(definition.workflow_id, 1)
            .expect("reads"),
        "the workflow is paused"
    );
    let pending = service.store().pending_attention().expect("the outbox");
    assert_eq!(pending.len(), 1, "one limit exceeded owes one item");
    assert_eq!(
        pending[0].subject,
        AttentionSubject::Workflow {
            workflow_id: definition.workflow_id,
            revision: 1,
        }
    );
    gated.permits.add_permits(1_000);
    for run in running {
        let _ = run.await;
    }
}

/// A runner whose actions never finish.
#[derive(Default)]
struct Stuck {
    entered: Arc<AtomicUsize>,
}

impl ActionRunner for Stuck {
    fn cancel(&self, _dispatch: &Dispatch<'_>) -> kr_automation::Cancellation {
        kr_automation::Cancellation::Unsupported
    }

    fn execute(
        &self,
        _dispatch: &Dispatch<'_>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = kr_automation::Result<ActionOutcome>> + Send>,
    > {
        self.entered.fetch_add(1, Ordering::SeqCst);
        Box::pin(std::future::pending())
    }
}

/// Waits until `count` actions of a stuck runner have begun.
async fn stuck_entered(stuck: &Stuck, count: usize) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while stuck.entered.load(Ordering::SeqCst) < count {
        assert!(
            std::time::Instant::now() < deadline,
            "{count} actions began within ten seconds"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

/// Two nodes, the second after the first succeeds, with the deadlines given.
fn two_steps(id: WorkflowId, grant: GrantId, run_ms: u64, action_ms: u64) -> WorkflowDefinition {
    let mut definition = create_workflow_definition(
        id,
        1,
        "timed",
        grant,
        vec![
            common::node("first", WorkflowActionKind::RunTests),
            common::node("second", WorkflowActionKind::RequestReview),
        ],
        vec![WorkflowEdge {
            from_node: "first".to_owned(),
            to_node: "second".to_owned(),
            condition: EdgeCondition::Success,
        }],
    );
    definition.deadlines = WorkflowDeadlines {
        run_deadline_ms: U64::new(run_ms),
        action_wait_ms: U64::new(action_ms),
    };
    definition
}

/// Two nodes, the second after the first succeeds, and a third that depends on neither, with the
/// deadlines given. The engine reaches the third only after the first has settled.
fn three_steps(id: WorkflowId, grant: GrantId, run_ms: u64, action_ms: u64) -> WorkflowDefinition {
    let mut definition = two_steps(id, grant, run_ms, action_ms);
    definition
        .nodes
        .push(common::node("later", WorkflowActionKind::AttentionNotice));
    definition
}

/// The receipts of a run, by node.
fn statuses(service: &AutomationService, run: kr_protocol::ids::WorkflowRunId) -> Vec<NodeStatus> {
    let mut receipts = service
        .read(
            &WorkflowReadParams {
                run_id: Nullable::some(run),
                ..WorkflowReadParams::default()
            },
            None,
            1_000,
        )
        .expect("reads")
        .node_receipts;
    receipts.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    receipts.iter().map(|receipt| receipt.status).collect()
}

/// An action that outlives its wait is stopped waiting for. This runner cannot stop it, so what it
/// did is unknown and its dependant pauses for review; the node that depends on nothing is not
/// dispatched either, because the limit stops the run. The limit it exceeded pauses the workflow
/// and raises one attention item.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_action_that_outlives_its_wait_is_left_unknown_when_it_cannot_be_stopped() {
    let stuck = Arc::new(Stuck::default());
    let clock = Arc::new(ManualClock::new(1_000));
    let service = Arc::new(
        AutomationService::in_memory(common::host(
            Arc::clone(&stuck) as Arc<dyn ActionRunner>,
            common::every_right(&[grant_id(3)]),
            Arc::clone(&clock) as Arc<dyn kr_automation::HostClock>,
        ))
        .expect("a service"),
    );
    let definition = three_steps(workflow_id(3), grant_id(3), 1_800_000, 60_000);
    installed(&service, &definition);

    let running = {
        let service = Arc::clone(&service);
        let params = run_params(&definition, "evt-waits");
        tokio::spawn(async move { service.submit_run(&params, 1_000).await })
    };
    stuck_entered(&stuck, 1).await;
    clock.set(1_000 + 60_001);
    let answered = tokio::time::timeout(std::time::Duration::from_secs(10), running)
        .await
        .expect("the run stops waiting once the action's wait has passed")
        .expect("the task ends")
        .expect("the run answers");
    assert_eq!(
        answered.status,
        WorkflowRunStatus::Cancelled,
        "{answered:?}"
    );
    assert_eq!(
        statuses(&service, answered.run_id),
        vec![
            NodeStatus::Unknown,
            NodeStatus::Cancelled,
            NodeStatus::Paused
        ],
        "the stuck action is unknown, the node beside it stops, and its dependant pauses"
    );
    assert_eq!(stuck.entered.load(Ordering::SeqCst), 1, "nothing else ran");
    assert!(
        service
            .store()
            .is_paused(definition.workflow_id, 1)
            .expect("reads"),
        "the workflow is paused"
    );
    assert_eq!(service.store().pending_attention().expect("reads").len(), 1);
}

/// A run past its deadline stops: the active action is stopped waiting for, the node after it
/// waits for review because what the action did is not known, the node that depends on nothing is
/// never dispatched, and the workflow is paused with one attention item.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_run_past_its_deadline_stops_its_undispatched_nodes() {
    let stuck = Arc::new(Stuck::default());
    let clock = Arc::new(ManualClock::new(1_000));
    let service = Arc::new(
        AutomationService::in_memory(common::host(
            Arc::clone(&stuck) as Arc<dyn ActionRunner>,
            common::every_right(&[grant_id(4)]),
            Arc::clone(&clock) as Arc<dyn kr_automation::HostClock>,
        ))
        .expect("a service"),
    );
    let definition = three_steps(workflow_id(4), grant_id(4), 60_000, 600_000);
    installed(&service, &definition);

    let running = {
        let service = Arc::clone(&service);
        let params = run_params(&definition, "evt-late");
        tokio::spawn(async move { service.submit_run(&params, 1_000).await })
    };
    stuck_entered(&stuck, 1).await;
    clock.set(1_000 + 60_001);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), running)
        .await
        .expect("the run stops once its deadline has passed")
        .expect("the task ends");
    let runs = service
        .store()
        .list_runs(Some(definition.workflow_id))
        .expect("reads");
    assert_eq!(
        runs[0].status,
        WorkflowRunStatus::Cancelled,
        "{:?}",
        runs[0]
    );
    assert_eq!(
        statuses(&service, runs[0].run_id),
        vec![
            NodeStatus::Unknown,
            NodeStatus::Cancelled,
            NodeStatus::Paused
        ],
        "the active action is unknown, the node beside it stops, and its dependant pauses"
    );
    assert_eq!(stuck.entered.load(Ordering::SeqCst), 1, "nothing else ran");
    assert!(
        service
            .store()
            .is_paused(definition.workflow_id, 1)
            .expect("reads")
    );
    assert_eq!(service.store().pending_attention().expect("reads").len(), 1);
}

/// A definition may shorten the section 17 deadlines and may not lengthen them or set one to
/// nothing.
#[tokio::test]
async fn a_definition_cannot_lengthen_its_deadlines() {
    let service = AutomationService::in_memory(common::host(
        Arc::new(kr_automation::MockActionRunner::new()),
        common::every_right(&[grant_id(5)]),
        Arc::new(ManualClock::new(1_000)),
    ))
    .expect("a service");
    for (index, (run_ms, action_ms)) in [
        (1_800_001, 600_000),
        (1_800_000, 600_001),
        (0, 600_000),
        (1_800_000, 0),
    ]
    .into_iter()
    .enumerate()
    {
        let mut definition = two_steps(
            workflow_id(10 + index as u8),
            grant_id(5),
            run_ms,
            action_ms,
        );
        definition.name = format!("deadlines {index}");
        let refused = service
            .submit_install(
                &WorkflowInstallParams {
                    workflow_id: definition.workflow_id,
                    revision: definition.revision,
                    definition: definition.clone(),
                    grant_reference: definition.grant_reference,
                },
                1_000,
            )
            .expect_err("the deadline is refused");
        assert!(
            refused.to_string().contains("deadline") || refused.to_string().contains("wait"),
            "{refused}"
        );
    }
    let shorter = two_steps(workflow_id(20), grant_id(5), 60_000, 30_000);
    installed(&service, &shorter);
}

/// A runner whose actions never finish, and which can stop them.
#[derive(Default)]
struct Stoppable {
    entered: Arc<AtomicUsize>,
    stopped: Arc<AtomicUsize>,
}

impl ActionRunner for Stoppable {
    fn cancel(&self, _dispatch: &Dispatch<'_>) -> kr_automation::Cancellation {
        self.stopped.fetch_add(1, Ordering::SeqCst);
        kr_automation::Cancellation::Requested
    }

    fn execute(
        &self,
        _dispatch: &Dispatch<'_>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = kr_automation::Result<ActionOutcome>> + Send>,
    > {
        self.entered.fetch_add(1, Ordering::SeqCst);
        Box::pin(std::future::pending())
    }
}

/// An action that outlives its wait and can be stopped is asked to stop. It settles cancelled,
/// which says the host stopped asking and claims nothing about what it did; neither the node after
/// it nor the one beside it runs, and the run ends cancelled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_action_that_outlives_its_wait_is_asked_to_stop() {
    let stoppable = Arc::new(Stoppable::default());
    let clock = Arc::new(ManualClock::new(1_000));
    let service = Arc::new(
        AutomationService::in_memory(common::host(
            Arc::clone(&stoppable) as Arc<dyn ActionRunner>,
            common::every_right(&[grant_id(6)]),
            Arc::clone(&clock) as Arc<dyn kr_automation::HostClock>,
        ))
        .expect("a service"),
    );
    let definition = three_steps(workflow_id(6), grant_id(6), 1_800_000, 60_000);
    installed(&service, &definition);

    let running = {
        let service = Arc::clone(&service);
        let params = run_params(&definition, "evt-stopped");
        tokio::spawn(async move { service.submit_run(&params, 1_000).await })
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while stoppable.entered.load(Ordering::SeqCst) < 1 {
        assert!(std::time::Instant::now() < deadline, "the action began");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    clock.set(1_000 + 60_001);
    let answered = tokio::time::timeout(std::time::Duration::from_secs(10), running)
        .await
        .expect("the run stops waiting once the action's wait has passed")
        .expect("the task ends")
        .expect("the run answers");
    assert_eq!(
        answered.status,
        WorkflowRunStatus::Cancelled,
        "{answered:?}"
    );
    assert_eq!(
        stoppable.stopped.load(Ordering::SeqCst),
        1,
        "asked to stop once"
    );
    assert_eq!(
        statuses(&service, answered.run_id),
        vec![
            NodeStatus::Cancelled,
            NodeStatus::Cancelled,
            NodeStatus::Cancelled
        ],
        "the stopped action and the nodes the stopped run no longer runs"
    );
    assert_eq!(
        stoppable.entered.load(Ordering::SeqCst),
        1,
        "nothing else ran"
    );
    assert!(
        service
            .store()
            .is_paused(definition.workflow_id, 1)
            .expect("reads")
    );
}

/// A host whose session limit can change while chains run.
#[derive(Debug)]
struct Moving(AtomicUsize);

impl kr_automation::HostCeilings for Moving {
    fn sessions(&self) -> u64 {
        self.0.load(Ordering::SeqCst) as u64
    }

    fn managed_spend(&self) -> u64 {
        0
    }
}

/// A new chain's created-session ceiling is the lower of section 25's ten and the host's session
/// limit at the moment its root is admitted, and it is the root's record a descendant is held to:
/// the host raising its limit later widens no chain already running, while a chain begun after
/// the raise inherits the new one.
#[tokio::test]
async fn a_chain_keeps_the_ceilings_its_root_inherited() {
    let ceilings = Arc::new(Moving(AtomicUsize::new(3)));
    let mut host = common::host(
        Arc::new(kr_automation::MockActionRunner::new()),
        common::every_right(&[grant_id(7)]),
        Arc::new(ManualClock::new(1_000)),
    );
    host.ceilings = Arc::clone(&ceilings) as Arc<dyn kr_automation::HostCeilings>;
    let service = AutomationService::in_memory(host).expect("a service");
    let mut producer = one_node(workflow_id(7), grant_id(7));
    producer.name = "producer".to_owned();
    let mut consumer = one_node(workflow_id(8), grant_id(7));
    consumer.name = "consumer".to_owned();
    consumer.trigger.event_type = "tests.passed".to_owned();
    installed(&service, &producer);
    installed(&service, &consumer);

    let first = service
        .submit_run(&run_params(&producer, "evt-narrow"), 1_000)
        .await
        .expect("the first chain runs");
    let budget = |root| {
        service
            .store()
            .get_budget(root)
            .expect("reads")
            .expect("the chain has a budget")
    };
    assert_eq!(budget(first.causal_root_id).max_sessions, 3);
    assert_eq!(budget(first.causal_root_id).max_managed_spend, 0);

    // The host admits more sessions from here on.
    ceilings.0.store(50, Ordering::SeqCst);
    service
        .dispatch_triggers(1_100)
        .await
        .expect("the descendant is admitted");
    let runs = service
        .store()
        .list_runs(Some(consumer.workflow_id))
        .expect("reads");
    assert_eq!(runs.len(), 1, "the consumer ran as a descendant");
    assert_eq!(runs[0].causal_root_id, first.causal_root_id);
    assert_eq!(
        budget(first.causal_root_id).max_sessions,
        3,
        "a descendant is held to the root's ceiling"
    );

    let second = service
        .submit_run(&run_params(&producer, "evt-wide"), 1_200)
        .await
        .expect("a new chain runs");
    assert_eq!(
        budget(second.causal_root_id).max_sessions,
        10,
        "section 25's default is the most a chain gets"
    );
}

/// A restart resumes the runs that were running and leaves the ones that were waiting as they
/// were: pending, in their order, until a slot frees.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restart_resumes_running_runs_and_leaves_pending_ones_waiting() {
    let journal = tempfile::tempdir().expect("a journal directory");
    let definition = one_node(workflow_id(9), grant_id(9));
    let queued_run = {
        let gated = Arc::new(Gated::new());
        let service = Arc::new(
            AutomationService::open(
                journal.path(),
                common::host(
                    Arc::clone(&gated) as Arc<dyn ActionRunner>,
                    common::every_right(&[grant_id(9)]),
                    Arc::new(ManualClock::new(1_000)),
                ),
            )
            .expect("the journal opens"),
        );
        installed(&service, &definition);
        let mut running = Vec::new();
        for index in 0..4 {
            let service = Arc::clone(&service);
            let params = run_params(&definition, &format!("evt-{index}"));
            running.push(tokio::spawn(async move {
                service.submit_run(&params, 1_000).await
            }));
        }
        entered(&gated, 4).await;
        let queued = service
            .submit_run(&run_params(&definition, "evt-queued"), 1_000)
            .await
            .expect("the fifth run waits");
        // The host stops with four runs mid-action and one waiting.
        for run in running {
            run.abort();
            let _ = run.await;
        }
        queued.run_id
    };

    let service = AutomationService::open(
        journal.path(),
        common::host(
            Arc::new(kr_automation::MockActionRunner::new()),
            common::every_right(&[grant_id(9)]),
            Arc::new(ManualClock::new(2_000)),
        ),
    )
    .expect("the journal opens again");
    let resumed = service.recover(2_000).expect("recovers");
    assert_eq!(resumed.len(), 4, "the running runs resume");
    assert!(resumed.iter().all(|run| run.run_id() != queued_run));
    assert_eq!(
        service
            .store()
            .run_summary(queued_run)
            .expect("reads")
            .expect("recorded")
            .status,
        WorkflowRunStatus::Pending,
        "the waiting run still waits"
    );
    assert!(
        service.start_queued(2_000).started.is_empty(),
        "no slot is free while the resumed runs hold them"
    );
    for run in resumed {
        let _ = service.execute(run).await;
    }
    let started = service.start_queued(2_100).started;
    assert_eq!(started.len(), 1);
    assert_eq!(started[0].run_id(), queued_run);
}

/// A runner whose action reports at once, having found the host's clock already past its wait:
/// what a host that was suspended, or not scheduled, while the action ran reads when it resumes.
struct Late {
    clock: Arc<ManualClock>,
    reported_at: u64,
}

impl ActionRunner for Late {
    fn cancel(&self, _dispatch: &Dispatch<'_>) -> kr_automation::Cancellation {
        kr_automation::Cancellation::Unsupported
    }

    fn execute(
        &self,
        dispatch: &Dispatch<'_>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = kr_automation::Result<ActionOutcome>> + Send>,
    > {
        let clock = Arc::clone(&self.clock);
        let reported_at = self.reported_at;
        let kind = dispatch.node.action_kind;
        Box::pin(async move {
            clock.set(reported_at);
            Ok(ActionOutcome::Success {
                output: kr_automation::stand_in_output(kind),
            })
        })
    }
}

/// A report the host reads only once its clock has passed the action's wait is not taken: the
/// wait was exceeded however the host got past it, so the node settles as one that outlived its
/// wait, its dependant waits for review, and the workflow pauses with one attention item.
#[tokio::test]
async fn a_report_read_after_the_wait_has_passed_is_not_taken() {
    let clock = Arc::new(ManualClock::new(1_000));
    let service = AutomationService::in_memory(common::host(
        Arc::new(Late {
            clock: Arc::clone(&clock),
            reported_at: 1_000 + 60_001,
        }),
        common::every_right(&[grant_id(21)]),
        Arc::clone(&clock) as Arc<dyn kr_automation::HostClock>,
    ))
    .expect("a service");
    let definition = two_steps(workflow_id(21), grant_id(21), 1_800_000, 60_000);
    installed(&service, &definition);

    let answered = service
        .submit_run(&run_params(&definition, "evt-late-report"), 1_000)
        .await
        .expect("the run answers");
    assert_eq!(
        answered.status,
        WorkflowRunStatus::Cancelled,
        "{answered:?}"
    );
    assert_eq!(
        statuses(&service, answered.run_id),
        vec![NodeStatus::Unknown, NodeStatus::Paused],
        "the late report is not the node's outcome, and its dependant does not run on it"
    );
    assert!(
        service
            .store()
            .is_paused(definition.workflow_id, 1)
            .expect("reads")
    );
    assert_eq!(service.store().pending_attention().expect("reads").len(), 1);
}

/// A run a restart finds interrupted after its deadline has passed is stopped for its deadline:
/// its interrupted node is unknown, and the workflow pauses with one attention item, rather than
/// the run ending paused as though no limit had been exceeded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_run_a_restart_finds_past_its_deadline_is_stopped_for_it() {
    let journal = tempfile::tempdir().expect("a journal directory");
    let mut definition = one_node(workflow_id(22), grant_id(22));
    definition.deadlines.run_deadline_ms = U64::new(60_000);
    let run_id = {
        let stuck = Arc::new(Stuck::default());
        let service = Arc::new(
            AutomationService::open(
                journal.path(),
                common::host(
                    Arc::clone(&stuck) as Arc<dyn ActionRunner>,
                    common::every_right(&[grant_id(22)]),
                    Arc::new(ManualClock::new(1_000)),
                ),
            )
            .expect("the journal opens"),
        );
        installed(&service, &definition);
        let running = {
            let service = Arc::clone(&service);
            let params = run_params(&definition, "evt-interrupted");
            tokio::spawn(async move { service.submit_run(&params, 1_000).await })
        };
        stuck_entered(&stuck, 1).await;
        // The host stops with the action dispatched.
        running.abort();
        let _ = running.await;
        service
            .store()
            .list_runs(Some(definition.workflow_id))
            .expect("reads")[0]
            .run_id
    };

    let service = AutomationService::open(
        journal.path(),
        common::host(
            Arc::new(kr_automation::MockActionRunner::new()),
            common::every_right(&[grant_id(22)]),
            Arc::new(ManualClock::new(1_000 + 60_001)),
        ),
    )
    .expect("the journal opens again");
    let resumed = service.recover(1_000 + 60_001).expect("recovers");
    assert_eq!(resumed.len(), 1);
    let answered = service
        .execute(resumed.into_iter().next().expect("the run"))
        .await
        .expect("the run answers");
    assert_eq!(answered.run_id, run_id);
    assert_eq!(
        answered.status,
        WorkflowRunStatus::Cancelled,
        "{answered:?}"
    );
    assert_eq!(statuses(&service, run_id), vec![NodeStatus::Unknown]);
    assert!(
        service
            .store()
            .is_paused(definition.workflow_id, 1)
            .expect("reads"),
        "the deadline is a limit exceeded"
    );
    assert_eq!(service.store().pending_attention().expect("reads").len(), 1);
}

/// A run whose execution ends without settling it, here because the task executing it stopped
/// mid-action, is taken up by the same service without a restart, so it does not hold one of its
/// workflow's places until the host next starts. While its execution is still under way nothing
/// takes it up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_run_whose_execution_ended_unsettled_is_taken_up_without_a_restart() {
    let gated = Arc::new(Gated::new());
    let service = Arc::new(
        AutomationService::in_memory(common::host(
            Arc::clone(&gated) as Arc<dyn ActionRunner>,
            common::every_right(&[grant_id(23)]),
            Arc::new(ManualClock::new(1_000)),
        ))
        .expect("a service"),
    );
    let definition = one_node(workflow_id(23), grant_id(23));
    installed(&service, &definition);

    let running = {
        let service = Arc::clone(&service);
        let params = run_params(&definition, "evt-abandoned");
        tokio::spawn(async move { service.submit_run(&params, 1_000).await })
    };
    entered(&gated, 1).await;
    assert!(
        service.recover(1_000).expect("reads").is_empty(),
        "a run under way is not taken up"
    );

    running.abort();
    let _ = running.await;
    let taken_up = service.recover(1_100).expect("takes up");
    assert_eq!(taken_up.len(), 1, "the run nothing executes is taken up");
    assert!(
        service.recover(1_100).expect("reads").is_empty(),
        "and is taken up once"
    );
    let answered = service
        .execute(taken_up.into_iter().next().expect("the run"))
        .await
        .expect("the run answers");
    assert_eq!(
        answered.status,
        WorkflowRunStatus::Paused,
        "the action it dispatched has an outcome nobody knows: {answered:?}"
    );
    assert_eq!(
        statuses(&service, answered.run_id),
        vec![NodeStatus::Unknown]
    );
}
