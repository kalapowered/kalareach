//! Tests for SQLite persistence across drop/reopen and trigger deduplication key semantics.

use std::sync::Arc;

use kr_automation::{CausalContext, WorkflowStore, create_workflow_definition};
use kr_protocol::automation::WorkflowActionKind;
use kr_protocol::automation::{NodeStatus, WorkflowRunStatus};
use kr_protocol::ids::{GrantId, WorkflowId, WorkflowRunId};
use kr_protocol::scalars::{Nullable, Uuid};

mod common;

use common::Submit;

fn test_wf_id(v: u8) -> WorkflowId {
    WorkflowId::new(Uuid::from_bytes([v; 16]))
}

fn test_grant_id(v: u8) -> GrantId {
    GrantId::new(Uuid::from_bytes([v; 16]))
}

/// The grants these definitions name, as the host holds them.
///
/// A definition names a grant and the host reads it from its own store, so every suite that runs
/// one puts that grant in first. What a narrower or withdrawn grant does is its own suite's
/// subject.
fn authority() -> std::sync::Arc<kr_automation::GrantTable> {
    common::every_right(&[test_grant_id(1), test_grant_id(5)])
}

fn test_run_id(v: u8) -> WorkflowRunId {
    WorkflowRunId::new(Uuid::from_bytes([v; 16]))
}

#[test]
fn sqlite_persistence_survives_drop_and_reopen() {
    let tmp_dir = tempfile::tempdir().unwrap();

    let wf_id = test_wf_id(1);
    let grant_id = test_grant_id(1);
    let run_id = test_run_id(1);

    // Phase 1: Write state and drop connection
    {
        let store = WorkflowStore::open(tmp_dir.path()).unwrap();

        let n1 = common::node("step1", WorkflowActionKind::RunTests);

        let def = create_workflow_definition(wf_id, 1, "durable-wf", grant_id, vec![n1], vec![]);
        store.save_definition(&def, 1000).unwrap();

        let causal_ctx = CausalContext::new_root();
        store
            .commit_trigger_and_run(run_id, &def, "evt-init", &causal_ctx, 1050)
            .unwrap();

        // Update node receipt and run status
        store
            .update_node_receipt(
                run_id,
                "step1",
                NodeStatus::Success,
                Some(&kr_automation::stand_in_output(
                    WorkflowActionKind::RunTests,
                )),
                None,
                Some(1100),
            )
            .unwrap();

        store
            .update_run_status(run_id, WorkflowRunStatus::Completed, Some(1105))
            .unwrap();
    }

    // Phase 2: Reopen from disk and verify exact recovery
    {
        let store = WorkflowStore::open(tmp_dir.path()).unwrap();

        // Verify definition
        let defs = store.list_definitions(Some(wf_id)).unwrap();
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].name, "durable-wf");
        assert_eq!(defs[0].revision.get(), 1);

        // Verify run
        let runs = store.list_runs(Some(wf_id)).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run_id, run_id);
        assert_eq!(runs[0].status, WorkflowRunStatus::Completed);
        assert_eq!(runs[0].trigger_event_id, "evt-init");

        // Verify node receipt
        let receipts = store.list_node_receipts(run_id).unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].node_id, "step1");
        assert_eq!(receipts[0].status, NodeStatus::Success);
        assert_eq!(
            receipts[0].output.0,
            Some(kr_automation::stand_in_output(WorkflowActionKind::RunTests)),
            "the typed output reads back as it was written"
        );

        // Verify causal budget
        let budget = store
            .get_budget(runs[0].causal_root_id)
            .unwrap()
            .expect("causal budget must exist");
        assert_eq!(budget.total_runs, 1);
    }
}

#[test]
fn deduplication_key_prevents_duplicate_runs() {
    let store = WorkflowStore::in_memory().unwrap();
    let wf_id = test_wf_id(2);
    let grant_id = test_grant_id(1);

    let def = create_workflow_definition(wf_id, 1, "dedup-wf", grant_id, vec![], vec![]);
    store.save_definition(&def, 1000).unwrap();

    let run1 = test_run_id(10);
    let causal_ctx = CausalContext::new_root();

    // First commit for (wf_id, rev 1, "evt-dup") succeeds
    assert!(
        store
            .commit_trigger_and_run(run1, &def, "evt-dup", &causal_ctx, 1000)
            .is_ok()
    );

    // Second commit with exact same deduplication key fails atomically
    let run2 = test_run_id(11);
    let err = store
        .commit_trigger_and_run(run2, &def, "evt-dup", &causal_ctx, 1005)
        .unwrap_err();

    assert!(err.to_string().contains("duplicate trigger"));

    // A different event ID succeeds
    let run3 = test_run_id(12);
    assert!(
        store
            .commit_trigger_and_run(run3, &def, "evt-different", &causal_ctx, 1010)
            .is_ok()
    );
}

/// A journal written to another schema version is refused, not misread.
#[test]
fn a_journal_from_another_schema_version_is_refused() {
    let directory = tempfile::tempdir().expect("a journal directory");
    let path = directory
        .path()
        .join(kr_automation::store::WORKFLOW_DB_NAME);

    {
        let connection = rusqlite::Connection::open(&path).expect("the journal opens");
        connection
            .execute_batch("CREATE TABLE workflow_runs (run_id TEXT PRIMARY KEY);")
            .expect("an older table");
        connection
            .pragma_update(None, "user_version", 0_u32)
            .expect("an older version");
    }

    let error = WorkflowStore::open(directory.path())
        .expect_err("a journal this build cannot read is refused");
    assert!(error.to_string().contains("schema version"), "{error}");
}

/// A revision filter selects one revision, and a run of another workflow is not shown with it.
#[test]
fn read_answers_about_the_revision_it_was_asked_about() {
    use kr_automation::{AutomationService, ManualClock, MockActionRunner};
    use kr_protocol::automation::{WorkflowInstallParams, WorkflowReadParams};
    use kr_protocol::scalars::{Nullable, U64};
    use std::sync::Arc;

    let service = AutomationService::in_memory(common::host(
        Arc::new(MockActionRunner::new()),
        authority(),
        Arc::new(ManualClock::new(1_000)),
    ))
    .expect("a service");

    let workflow_id = test_wf_id(5);
    for revision in [1_u64, 2] {
        let node = common::node("step", WorkflowActionKind::RunTests);
        let definition = create_workflow_definition(
            workflow_id,
            revision,
            "versioned",
            test_grant_id(5),
            vec![node],
            vec![],
        );
        service
            .submit_install(
                &WorkflowInstallParams {
                    workflow_id,
                    revision: U64::new(revision),
                    definition: definition.clone(),
                    grant_reference: definition.grant_reference,
                },
                1_000,
            )
            .expect("the revision installs");
    }

    let both = service
        .read(
            &WorkflowReadParams {
                workflow_id: Nullable::some(workflow_id),
                ..WorkflowReadParams::default()
            },
            None,
            1_000,
        )
        .expect("the read answers");
    assert_eq!(both.definitions.len(), 2);

    let one = service
        .read(
            &WorkflowReadParams {
                workflow_id: Nullable::some(workflow_id),
                revision: Nullable::some(U64::new(2)),
                ..WorkflowReadParams::default()
            },
            None,
            1_000,
        )
        .expect("the read answers");
    assert_eq!(one.definitions.len(), 1);
    assert_eq!(one.definitions[0].revision.get(), 2);
}

/// A runner that counts the actions it was asked to perform, and reports each one done.
#[derive(Debug, Default)]
struct Counting(std::sync::atomic::AtomicUsize);

impl kr_automation::ActionRunner for Counting {
    fn cancel(&self, _dispatch: &kr_automation::Dispatch<'_>) -> kr_automation::Cancellation {
        kr_automation::Cancellation::Unsupported
    }

    fn execute(
        &self,
        dispatch: &kr_automation::Dispatch<'_>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = kr_automation::Result<kr_automation::ActionOutcome>>
                + Send,
        >,
    > {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let kind = dispatch.node.action_kind;
        Box::pin(async move {
            Ok(kr_automation::ActionOutcome::Success {
                output: kr_automation::stand_in_output(kind),
            })
        })
    }
}

/// Two nodes, the second depending on the first's success.
fn two_steps(workflow: u8, grant: GrantId) -> kr_protocol::automation::WorkflowDefinition {
    let node = |id: &str| common::node(id, WorkflowActionKind::RunTests);
    create_workflow_definition(
        test_wf_id(workflow),
        1,
        "two steps",
        grant,
        vec![node("first"), node("second")],
        vec![kr_protocol::automation::WorkflowEdge {
            from_node: "first".to_owned(),
            to_node: "second".to_owned(),
            condition: kr_protocol::automation::EdgeCondition::Success,
        }],
    )
}

/// Leaves a run in the journal as a host that stopped mid-run would: the run recorded, the first
/// node claimed for dispatch, and nothing after that.
fn stopped_mid_run(
    journal: &std::path::Path,
    definition: &kr_protocol::automation::WorkflowDefinition,
    first_settled: bool,
) -> WorkflowRunId {
    let store = WorkflowStore::open(journal).expect("the journal opens");
    store.save_definition(definition, 1_000).expect("installed");
    let run_id = test_run_id(40);
    store
        .commit_trigger_and_run(
            run_id,
            definition,
            "evt-1",
            &CausalContext::new_root(),
            1_000,
        )
        .expect("the run is recorded");
    assert!(
        store
            .claim_node_for_dispatch(run_id, "first")
            .expect("claimed")
    );
    if first_settled {
        assert!(
            store
                .settle_node(&kr_automation::NodeSettlement {
                    run_id,
                    node_id: "first",
                    status: NodeStatus::Success,
                    output: Some(&kr_automation::stand_in_output(
                        WorkflowActionKind::RunTests
                    )),
                    error: None,
                    produced: None,
                    at_ms: 1_100,
                })
                .expect("settled")
        );
    }
    run_id
}

fn reopened(
    journal: &std::path::Path,
    runner: Arc<Counting>,
    authority: Arc<kr_automation::GrantTable>,
) -> kr_automation::AutomationService {
    kr_automation::AutomationService::open(
        journal,
        common::host(
            runner,
            authority,
            Arc::new(kr_automation::ManualClock::new(2_000)),
        ),
    )
    .expect("the journal reopens")
}

/// A node that was running when the host stopped may have been dispatched, so after a restart its
/// outcome is unknown and its dependant pauses for review. Nothing is dispatched again.
#[tokio::test]
async fn a_restart_leaves_an_interrupted_node_unknown_and_pauses_its_dependant() {
    let journal = tempfile::tempdir().expect("a journal directory");
    let definition = two_steps(30, test_grant_id(1));
    let run_id = stopped_mid_run(journal.path(), &definition, false);

    let runner = Arc::new(Counting::default());
    let service = reopened(journal.path(), Arc::clone(&runner), authority());
    let mut resumed = service.recover(2_000).expect("recovery");
    assert_eq!(resumed.len(), 1);
    let result = service
        .execute(resumed.remove(0))
        .await
        .expect("the resumed run stops where it must");

    assert_eq!(result.status, WorkflowRunStatus::Paused);
    assert_eq!(
        runner.0.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "nothing was dispatched a second time"
    );
    let receipts = service.store().list_node_receipts(run_id).unwrap();
    let status = |id: &str| receipts.iter().find(|r| r.node_id == id).unwrap().status;
    assert_eq!(status("first"), NodeStatus::Unknown);
    assert_eq!(status("second"), NodeStatus::Paused);
}

/// Only undispatched and still-authorised steps resume: the node whose predecessor settled goes
/// on after a restart, and does not when the grant was withdrawn in the meantime.
#[tokio::test]
async fn a_restart_resumes_only_undispatched_steps_whose_grant_still_stands() {
    let journal = tempfile::tempdir().expect("a journal directory");
    let definition = two_steps(31, test_grant_id(1));
    let run_id = stopped_mid_run(journal.path(), &definition, true);

    let runner = Arc::new(Counting::default());
    let service = reopened(journal.path(), Arc::clone(&runner), authority());
    let mut resumed = service.recover(2_000).expect("recovery");
    let result = service
        .execute(resumed.remove(0))
        .await
        .expect("the run completes");
    assert_eq!(result.status, WorkflowRunStatus::Completed);
    assert_eq!(runner.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(
        service
            .store()
            .list_node_receipts(run_id)
            .unwrap()
            .iter()
            .all(|receipt| receipt.status == NodeStatus::Success)
    );

    // The same journal state, and a grant revoked while the host was down.
    let journal = tempfile::tempdir().expect("a journal directory");
    stopped_mid_run(journal.path(), &definition, true);
    let withdrawn = common::standing(test_grant_id(1), kr_automation::GrantStanding::Revoked);
    let runner = Arc::new(Counting::default());
    let service = reopened(journal.path(), Arc::clone(&runner), withdrawn);
    let mut resumed = service.recover(2_000).expect("recovery");
    let refusal = service
        .execute(resumed.remove(0))
        .await
        .expect_err("a withdrawn grant dispatches nothing");
    assert!(refusal.to_string().contains("revoked"), "{refusal}");
    assert_eq!(runner.0.load(std::sync::atomic::Ordering::SeqCst), 0);
}

/// The consumer contract: an event is removed only once every consumer registered for its type
/// has passed it, and an event of a type nobody is registered for is never removed. An attention
/// record therefore waits for the attention state however far the trigger dispatcher has read.
#[tokio::test]
async fn an_event_waits_for_every_consumer_registered_for_its_type() {
    use kr_automation::store::{ATTENTION_CONSUMER, ATTENTION_EVENTS, EVENT_NODE_SETTLED};

    let service = kr_automation::AutomationService::in_memory(common::host(
        Arc::new(Counting::default()),
        authority(),
        Arc::new(kr_automation::ManualClock::new(1_000)),
    ))
    .expect("a service");
    let definition = two_steps(32, test_grant_id(1));
    service
        .submit_install(
            &kr_protocol::automation::WorkflowInstallParams {
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
            &kr_protocol::automation::WorkflowEnableParams {
                workflow_id: definition.workflow_id,
                revision: definition.revision,
            },
            1_000,
        )
        .expect("enables");
    service
        .submit_run(
            &kr_protocol::automation::WorkflowRunParams {
                workflow_id: definition.workflow_id,
                revision: definition.revision,
                event_id: "evt-1".to_owned(),
                event_type: "manual".to_owned(),
                event_payload: Nullable::null(),
            },
            1_000,
        )
        .await
        .expect("the run completes");
    service
        .store()
        .pause_workflow_on_breach(definition.workflow_id, 1, "a limit was breached", 1_100)
        .expect("paused");

    let settled = |service: &kr_automation::AutomationService| {
        service
            .store()
            .events_after(0, &[EVENT_NODE_SETTLED], 100)
            .unwrap()
            .len()
    };
    assert_eq!(settled(&service), 2, "one event per settled node");

    // Nobody reads anything yet, so nothing goes.
    assert_eq!(service.store().prune().unwrap(), 0);

    // The dispatcher reads the node events. Once it has passed them they go; the attention
    // record stays, because no attention consumer has registered to read it.
    assert!(service.admit_triggers(1_200).stopped.is_none(), "a pass");
    assert!(service.store().prune().unwrap() >= 2);
    assert_eq!(settled(&service), 0);
    assert_eq!(service.store().pending_attention().unwrap().len(), 1);

    // An attention consumer that registered and has not read holds it.
    service
        .store()
        .register_consumer(ATTENTION_CONSUMER, ATTENTION_EVENTS, 1_300)
        .unwrap();
    service.store().prune().unwrap();
    let pending = service.store().pending_attention().unwrap();
    assert_eq!(pending.len(), 1);

    // Once it has acknowledged the record, the record goes.
    service
        .store()
        .acknowledge(ATTENTION_CONSUMER, pending[0].sequence)
        .unwrap();
    assert_eq!(service.store().prune().unwrap(), 1);
    assert!(service.store().pending_attention().unwrap().is_empty());
}

/// A journal an earlier build wrote to schema version 3 is refused by name: its stored events and
/// definitions have another shape, and reading them as this build's would fail part way.
#[test]
fn a_journal_at_an_earlier_development_version_is_refused() {
    // Version 4 held node outputs as text, where this build reads typed ones.
    for version in [3_u32, 4] {
        let directory = tempfile::tempdir().expect("a journal directory");
        let path = directory
            .path()
            .join(kr_automation::store::WORKFLOW_DB_NAME);
        {
            let connection = rusqlite::Connection::open(&path).expect("the journal opens");
            connection
                .execute_batch("CREATE TABLE outbox_events (outbox_id INTEGER PRIMARY KEY);")
                .expect("an older table");
            connection
                .pragma_update(None, "user_version", version)
                .expect("an older version");
        }
        let error = WorkflowStore::open(directory.path())
            .expect_err("a journal at an earlier development version is refused");
        assert!(
            error
                .to_string()
                .contains(&format!("schema version {version}")),
            "{error}"
        );
    }
}
