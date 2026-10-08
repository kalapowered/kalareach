//! A view-only recipient reaches no input through an intermediary.
//!
//! A session shared as a viewer is a grant that carries `session.view` and nothing else. What a
//! recipient could try instead of typing is to ask something else to type for it: a workflow that
//! sends a command to a shell or runs a test suite, whose nodes act under a grant of their own.
//! These tests drive that through a real daemon and a real paired device that holds such a share:
//! KR-REQ-19.01.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-19.01 | `kr_req_19_01_a_view_only_recipient_installs_no_workflow_that_types_for_it` |

mod net_support;

use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::grant::SessionSelector;
use kr_protocol::ids::{ActionId, GrantId, SessionId, WorkflowId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Nullable, U64, Uuid};
use kr_protocol::sharing::{
    AuthorityNotice, GrantCreateParams, GrantCreateResult, GrantRedeemParams, RoleSelection,
    SessionRole,
};
use net_support::{Device, Host, RawDevice, pair_with, proposal};

use kr_protocol::automation::{
    WorkflowActionKind, WorkflowDeadlines, WorkflowDefinition, WorkflowInstallParams, WorkflowNode,
    WorkflowResourceScope, WorkflowTrigger,
};

/// A target that names this host and no session.
fn on_the_host(host: &Host) -> ActionTarget {
    ActionTarget {
        environment_id: host.environment_id,
        session_id: Nullable::null(),
        session_epoch: Nullable::null(),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    }
}

/// A one-node workflow that acts under `grant`.
fn workflow(id: u8, grant: GrantId, node: WorkflowNode) -> WorkflowDefinition {
    WorkflowDefinition {
        workflow_id: WorkflowId::new(Uuid::from_bytes([id; 16])),
        revision: U64::new(1),
        name: format!("workflow {id}"),
        description: Nullable::null(),
        trigger: WorkflowTrigger {
            event_type: "manual".to_owned(),
        },
        resource_scope: WorkflowResourceScope::default(),
        nodes: vec![node],
        edges: Vec::new(),
        deadlines: WorkflowDeadlines::default(),
        grant_reference: grant,
        enabled: false,
        explicit_recurrence: false,
    }
}

/// A node of `kind` with the parameters that kind takes.
fn node(host: &Host, kind: WorkflowActionKind) -> WorkflowNode {
    let params = match kind {
        WorkflowActionKind::RunTests => {
            serde_json::to_string(&kr_protocol::automation::RunTestsParams {
                suite: "unit".to_owned(),
                version: kr_protocol::changeset::VersionRef {
                    change_set_id: kr_protocol::ids::ChangeSetId::new(Uuid::from_bytes([0x5d; 16])),
                    version: kr_protocol::ids::ChangeSetVersion::new(1),
                },
            })
        }
        WorkflowActionKind::ShellCommand => {
            serde_json::to_string(&kr_protocol::automation::ShellCommandParams {
                command: "cargo test".to_owned(),
            })
        }
        WorkflowActionKind::AttentionNotice => {
            serde_json::to_string(&kr_protocol::automation::AttentionNoticeParams {
                summary: "the build is ready".to_owned(),
            })
        }
        other => panic!("{other:?} is not a node these tests install"),
    }
    .expect("the node's typed parameters");
    WorkflowNode {
        node_id: "only".to_owned(),
        action_kind: kind,
        action_params: params,
        // A node that sends a command to a shell names the environment it runs in.
        declared_environment: if kind == WorkflowActionKind::ShellCommand {
            Nullable::some(host.environment_id)
        } else {
            Nullable::null()
        },
    }
}

/// Installs `definition` as the device does, and returns the daemon's refusal or its answer.
async fn install(
    host: &Host,
    connection: &RawDevice,
    definition: &WorkflowDefinition,
) -> Result<(), kr_protocol::error::ProtocolError> {
    connection
        .mutate(
            Method::WorkflowInstall,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &WorkflowInstallParams {
                workflow_id: definition.workflow_id,
                revision: definition.revision,
                definition: definition.clone(),
                grant_reference: definition.grant_reference,
            },
        )
        .await
        .map(drop)
}

/// A device paired with `actions` and no session, which the owner then shares a session with as a
/// viewer and which redeems the invitation: it holds a share that carries `session.view` and
/// nothing else, beside the pairing grant it was admitted under.
async fn viewer_with(
    host: &Host,
    owner: &DeviceKeys,
    actions: &[ActionRight],
) -> (Device, RawDevice, GrantId, GrantId) {
    let device = Device::create().await;
    let mut grant = proposal(actions);
    grant.session_selector = SessionSelector::None;
    let record = pair_with(host, &device, owner, grant).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let selection = RoleSelection::plain(SessionRole::Viewer);
    let issued: GrantCreateResult = host
        .client()
        .await
        .mutate(
            Method::GrantCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget {
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
                ..on_the_host(host)
            },
            &GrantCreateParams {
                session_id,
                recipient_device_id: record.device_id,
                parent_grant_id: Nullable::null(),
                accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
                selection,
                lifetime_ms: Nullable::null(),
                owner_confirmation: Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("the share is written")
        .to_typed()
        .expect("decodes");
    let connection = RawDevice::connect(host, &device, &record).await;
    connection
        .mutate(
            Method::GrantRedeem,
            ActionId::new(kr_ipc::new_uuid()),
            on_the_host(host),
            &GrantRedeemParams {
                invitation_id: issued.preview.invitation_id,
            },
        )
        .await
        .expect("the invitation is redeemed");
    (
        device,
        connection,
        issued.grant.grant_id,
        record.grant.grant_id,
    )
}

/// KR-REQ-19.01: a recipient holding a view-only share obtains no terminal input through a
/// workflow. Its pairing grant lets it manage automations and not type; it names the share, and the
/// pairing grant, as the grant a workflow acts under, and puts a node in it that sends a command
/// to a shell or runs a test suite. The share is no grant a workflow acts under, and the pairing
/// grant holds no right to type, so each definition is refused and nothing is installed. The
/// controls: the same device installs a workflow whose node needs only what its pairing grant
/// holds, and a device whose pairing grant also holds the right to type installs the test node.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_19_01_a_view_only_recipient_installs_no_workflow_that_types_for_it() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (_viewer_device, viewer, share, pairing) = viewer_with(
        &host,
        &owner,
        &[ActionRight::AutomationManage, ActionRight::SessionView],
    )
    .await;

    // The share is no grant a workflow acts under, whatever the node asks of it.
    let under_the_share = install(
        &host,
        &viewer,
        &workflow(1, share, node(&host, WorkflowActionKind::AttentionNotice)),
    )
    .await
    .expect_err("a workflow does not act under a share");
    assert_eq!(under_the_share.code, ErrorCode::PermissionDenied);

    // The pairing grant manages automations and cannot type, so no node that types is installed.
    for (id, kind) in [
        (2, WorkflowActionKind::RunTests),
        (3, WorkflowActionKind::ShellCommand),
    ] {
        let refused = install(&host, &viewer, &workflow(id, pairing, node(&host, kind)))
            .await
            .expect_err("a node that types needs the right to type");
        assert_eq!(
            refused.code,
            ErrorCode::PermissionDenied,
            "{kind:?}: {refused:?}"
        );
    }

    // The controls.
    install(
        &host,
        &viewer,
        &workflow(4, pairing, node(&host, WorkflowActionKind::AttentionNotice)),
    )
    .await
    .expect("a node that needs only what the pairing grant holds is installed");
    let (_typist_device, typist, _, typist_pairing) = viewer_with(
        &host,
        &owner,
        &[
            ActionRight::AutomationManage,
            ActionRight::SessionView,
            ActionRight::TerminalInput,
        ],
    )
    .await;
    install(
        &host,
        &typist,
        &workflow(5, typist_pairing, node(&host, WorkflowActionKind::RunTests)),
    )
    .await
    .expect("a grant that holds the right to type installs the node that types");

    viewer.close();
    typist.close();
    host.stop().await;
}
