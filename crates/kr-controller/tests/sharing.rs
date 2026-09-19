//! Roles, invitations, delegation, transfer of control and the sharing method group.
//!
//! The thing these tests are really about is that a *word* never authorises anything. "Controller"
//! is a word; `terminal.input` is a right. An invitation issued under a role writes the rights
//! down, and every later decision reads the rights. So each test here either checks that the
//! compilation is faithful, or takes a word away and checks that the decision is unchanged.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-18.03 | `an_invitation_is_scoped_to_the_session_it_shares`, `a_delegation_narrows_what_the_issuer_holds`, `transfer_of_control_hands_over_only_what_the_transferring_grant_carries` |
//! | KR-REQ-19.01 | `a_view_only_invitation_obtains_no_input_through_a_plugin_an_attachment_action_or_a_workflow` |
//! | KR-REQ-23.49 | `sharing_checks_parent_rights_expiry_and_owner_confirmation`, `revoking_a_shared_grant_completes_through_the_dispatch_barrier` |
//! | KR-REQ-25.07 | `each_role_compiles_to_explicit_actions_and_the_host_decides_from_those`, `only_controller_and_owner_answer_questions_without_an_explicit_option` |
//! | KR-REQ-25.10 | `an_invitation_is_single_use_and_expires`, `the_issuer_sees_what_is_being_shared_and_no_historical_attachment_keys` |

use std::sync::Arc;
use std::time::Duration;

use kr_controller::grants::{AccessRequest, GrantRecord, HostPolicy, Refusal, decide};
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::sharing::{
    Intermediary, ShareRequest, SharingService, effective_rights, requires_owner_confirmation,
    roles, transfer,
};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::actor::ActorIngress;
use kr_protocol::grant::{Grant, GrantExpiry, SessionSelector};
use kr_protocol::ids::{
    AuthorityRevision, BuildId, DeviceId, EnvironmentId, GrantId, InvitationId, SessionId,
};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs, Uuid};
use kr_protocol::sharing::{AuthorityNotice, RoleSelection, SessionRole};

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

const NOW: u64 = 1_000_000;

fn device_id(byte: u8) -> DeviceId {
    DeviceId::new(Uuid::from_bytes([byte; 16]))
}

fn session_id(byte: u8) -> SessionId {
    SessionId::new(Uuid::from_bytes([byte; 16]))
}

fn environment_id(byte: u8) -> EnvironmentId {
    EnvironmentId::new(Uuid::from_bytes([byte; 16]))
}

fn grant_id(byte: u8) -> GrantId {
    GrantId::new(Uuid::from_bytes([byte; 16]))
}

fn invitation_id(byte: u8) -> InvitationId {
    InvitationId::new(Uuid::from_bytes([byte; 16]))
}

/// A share request for one role, with the notices that role actually carries already accepted.
fn share(role: SessionRole, byte: u8) -> ShareRequest {
    let selection = RoleSelection::plain(role);
    ShareRequest {
        invitation_id: invitation_id(byte),
        grant_id: grant_id(byte),
        environment_id: environment_id(0xe0),
        session_id: session_id(0xa0),
        issuer_device_id: device_id(0xf0),
        recipient_device_id: device_id(0xf1),
        parent_grant_id: None,
        accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
        selection,
        lifetime_ms: None,
        live_screen: None,
        named_questions: Vec::new(),
        named_approvals: Vec::new(),
        authority_revision: AuthorityRevision::new(1),
        owner_confirmed: false,
        now_ms: NOW,
    }
}

fn request(method: Method, now_ms: u64) -> AccessRequest {
    AccessRequest {
        method,
        ingress: ActorIngress::PairedDevice,
        environment_id: environment_id(0xe0),
        session_id: Some(session_id(0xa0)),
        claims_geometry: false,
        own_subject: None,
        now_ms,
    }
}

fn stored(grant: &Grant) -> GrantRecord {
    GrantRecord {
        grant: grant.clone(),
        session_id: Some(session_id(0xa0)),
        issued_at_ms: NOW,
        revoked_at_ms: None,
        revoked_by_parent: None,
    }
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-25.07: roles compile to explicit grants
// ---------------------------------------------------------------------------------------------

#[test]
fn each_role_compiles_to_explicit_actions_and_the_host_decides_from_those() {
    let service = SharingService::in_memory().expect("a sharing service");
    let policy = HostPolicy::personal(AuthorityRevision::new(1));

    let viewer = service
        .share(&share(SessionRole::Viewer, 1))
        .expect("a viewer");
    assert_eq!(
        viewer.grant.actions.iter().copied().collect::<Vec<_>>(),
        vec![ActionRight::SessionView],
        "a viewer sees the session and nothing else"
    );

    let controller = service
        .share(&ShareRequest {
            recipient_device_id: device_id(0xf2),
            ..share(SessionRole::Controller, 2)
        })
        .expect("a controller");
    assert!(controller.grant.permits(ActionRight::TerminalInput));
    assert!(controller.grant.permits(ActionRight::QuestionRespond));

    // The decision reads the actions. A viewer's grant refuses input; a controller's allows it.
    assert_eq!(
        decide(
            &viewer.grant,
            &stored(&viewer.grant),
            &policy,
            request(Method::InputWrite, NOW)
        ),
        Err(Refusal::MissingRight {
            right: ActionRight::TerminalInput
        })
    );
    decide(
        &controller.grant,
        &stored(&controller.grant),
        &policy,
        request(Method::InputWrite, NOW),
    )
    .expect("a controller holds terminal input");

    // The role is not in the grant at all, so nothing downstream could authorise from it even by
    // mistake: what a person is shown beside a grant is derived from the actions, not carried.
    let encoded = serde_json::to_string(&viewer.grant).expect("a grant encodes");
    assert!(
        !encoded.contains("viewer") && !encoded.contains("role"),
        "a grant carries actions, never a role label: {encoded}"
    );
    assert_eq!(
        roles::describes(&controller.grant.actions),
        Some(SessionRole::Controller),
        "a label may be derived for display, and only for display"
    );

    // A grant whose actions were narrowed below its role no longer describes that role, so a
    // surface cannot keep calling it one.
    let narrowed: CanonicalSet<ActionRight> = [ActionRight::SessionView].into_iter().collect();
    assert_eq!(roles::describes(&narrowed), Some(SessionRole::Viewer));
}

#[test]
fn only_controller_and_owner_answer_questions_without_an_explicit_option() {
    let service = SharingService::in_memory().expect("a sharing service");
    for (byte, role) in [(1_u8, SessionRole::Viewer), (2, SessionRole::Reviewer)] {
        let plain = service
            .share(&ShareRequest {
                recipient_device_id: device_id(byte),
                ..share(role, byte)
            })
            .expect("a plain invitation");
        assert!(
            !plain.grant.permits(ActionRight::QuestionRespond),
            "{role} does not answer questions by default"
        );
        assert!(
            !plain
                .preview
                .notices
                .contains(&AuthorityNotice::AgentPermissions),
            "and the issuer is not warned about a consequence the grant does not carry"
        );
    }

    for (byte, role) in [(3_u8, SessionRole::Controller), (4, SessionRole::Owner)] {
        let held = service
            .share(&ShareRequest {
                recipient_device_id: device_id(byte),
                ..share(role, byte)
            })
            .expect("an invitation");
        assert!(held.grant.permits(ActionRight::QuestionRespond));
        assert!(
            held.preview
                .notices
                .contains(&AuthorityNotice::AgentPermissions),
            "{role} carries the notice that says what an answer is"
        );
    }

    // A viewer receives it only through the explicit option, and the option carries the warning.
    let selection = RoleSelection {
        include_question_respond: true,
        ..RoleSelection::plain(SessionRole::Viewer)
    };
    let opted = service
        .share(&ShareRequest {
            recipient_device_id: device_id(9),
            accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
            selection,
            ..share(SessionRole::Viewer, 9)
        })
        .expect("an opted-in viewer");
    assert!(opted.grant.permits(ActionRight::QuestionRespond));
    assert!(
        opted
            .preview
            .notices
            .contains(&AuthorityNotice::AgentPermissions)
    );
    assert!(
        AuthorityNotice::AgentPermissions
            .sentence()
            .contains("not a restricted sandbox"),
        "the warning says what the upstream actually enforces"
    );
}

#[test]
fn an_issuer_that_accepted_different_consequences_does_not_get_the_grant() {
    let service = SharingService::in_memory().expect("a sharing service");
    // A surface that showed a controller invitation without the account-access notice.
    let softened = ShareRequest {
        accepted_notices: CanonicalSet::from_iter([AuthorityNotice::AgentPermissions]),
        ..share(SessionRole::Controller, 1)
    };
    let error = service
        .share(&softened)
        .expect_err("the grant carries a consequence the issuer was not shown");
    assert!(
        error.to_string().contains("different set of consequences"),
        "unexpected refusal: {error}"
    );
    assert!(
        service
            .grants()
            .record(grant_id(1))
            .expect("readable")
            .is_none(),
        "and nothing was written"
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-25.10: single use, expiring, previewed, and no historical attachment keys
// ---------------------------------------------------------------------------------------------

#[test]
fn an_invitation_is_single_use_and_expires() {
    let service = SharingService::in_memory().expect("a sharing service");
    let issued = service
        .share(&share(SessionRole::Viewer, 1))
        .expect("issued");
    let invitation_id = issued.preview.invitation_id;

    let redeemed = service
        .invitations()
        .redeem(invitation_id, device_id(0xf1), NOW + 1_000)
        .expect("the first redemption succeeds");
    assert_eq!(redeemed.redeemed_by, Some(device_id(0xf1)));

    let error = service
        .invitations()
        .redeem(invitation_id, device_id(0xf3), NOW + 1_100)
        .expect_err("a second device cannot redeem the same invitation");
    assert!(
        error.to_string().contains("already been redeemed"),
        "unexpected refusal: {error}"
    );
    // Not even the device that redeemed it can do so twice.
    service
        .invitations()
        .redeem(invitation_id, device_id(0xf1), NOW + 1_200)
        .expect_err("single use means once");

    // And an invitation nobody redeemed stops working at its deadline.
    let second = service
        .share(&ShareRequest {
            recipient_device_id: device_id(0xf4),
            ..share(SessionRole::Viewer, 2)
        })
        .expect("issued");
    let expires_at = second.preview.expires_at_ms.get();
    let error = service
        .invitations()
        .redeem(second.preview.invitation_id, device_id(0xf4), expires_at)
        .expect_err("an expired invitation is refused");
    assert!(
        error.to_string().contains("expired"),
        "unexpected refusal: {error}"
    );
}

#[test]
fn the_issuer_sees_what_is_being_shared_and_no_historical_attachment_keys() {
    use kr_protocol::sharing::LiveScreenPreview;

    let service = SharingService::in_memory().expect("a sharing service");
    let selection = RoleSelection {
        include_live_screen: true,
        ..RoleSelection::plain(SessionRole::Viewer)
    };
    let screen = LiveScreenPreview {
        // Text printed long before the invitation existed. The preview shows it rather than
        // describing the sharing.
        lines: vec![
            "$ cat /home/me/notes/salary-review.txt".to_owned(),
            "band 4, effective March".to_owned(),
        ],
        truncated: false,
    };
    let request = ShareRequest {
        accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
        selection,
        live_screen: Some(screen.clone()),
        ..share(SessionRole::Viewer, 1)
    };

    let preview = service.preview(&request).expect("a preview");
    assert_eq!(
        preview.live_screen.as_ref(),
        Some(&screen),
        "the issuer is shown the text, not a promise about it"
    );
    assert!(
        !preview.historical_attachment_keys,
        "a new recipient receives no historical attachment keys"
    );
    assert!(preview.single_use);
    assert!(preview.history.include_live_screen);

    let issued = service.share(&request).expect("issued");
    assert_eq!(
        issued.preview, preview,
        "what was written is what was shown"
    );
    let kept = service
        .invitations()
        .record(preview.invitation_id)
        .expect("readable")
        .expect("present");
    assert_eq!(
        kept.preview, preview,
        "the preview is kept, so what a recipient gets can be compared with what was shown"
    );

    // Without the option there is no screen in the preview and none in the grant.
    let plain = service
        .preview(&ShareRequest {
            invitation_id: invitation_id(2),
            grant_id: grant_id(2),
            ..share(SessionRole::Viewer, 2)
        })
        .expect("a preview");
    assert!(plain.live_screen.as_ref().is_none());
    assert!(!plain.history.include_live_screen);
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-18.03: scoped invitations, delegation and transfer of control
// ---------------------------------------------------------------------------------------------

#[test]
fn an_invitation_is_scoped_to_the_session_it_shares() {
    let service = SharingService::in_memory().expect("a sharing service");
    let issued = service
        .share(&share(SessionRole::Viewer, 1))
        .expect("issued");
    assert_eq!(
        issued.grant.session_selector,
        SessionSelector::These {
            session_ids: [session_id(0xa0)].into_iter().collect()
        },
        "an invitation shares one session, not the host"
    );
    let policy = HostPolicy::personal(AuthorityRevision::new(1));
    let elsewhere = AccessRequest {
        session_id: Some(session_id(0xb0)),
        ..request(Method::SessionRead, NOW)
    };
    assert_eq!(
        decide(&issued.grant, &stored(&issued.grant), &policy, elsewhere),
        Err(Refusal::SessionOutsideGrant)
    );
}

#[test]
fn a_delegation_narrows_what_the_issuer_holds() {
    let service = SharingService::in_memory().expect("a sharing service");
    let reviewer = service
        .share(&share(SessionRole::Reviewer, 1))
        .expect("a reviewer");

    // The reviewer delegates a viewer's grant to a third device: narrower, and accepted.
    let narrower = service
        .share(&ShareRequest {
            invitation_id: invitation_id(2),
            grant_id: grant_id(2),
            issuer_device_id: device_id(0xf1),
            recipient_device_id: device_id(0xf2),
            parent_grant_id: Some(reviewer.grant.grant_id),
            ..share(SessionRole::Viewer, 2)
        })
        .expect("a narrower delegation");
    assert_eq!(
        narrower.grant.parent_grant_id.as_ref(),
        Some(&reviewer.grant.grant_id),
        "a delegated grant names its parent"
    );

    // The reviewer tries to delegate a controller's grant, which it does not hold.
    let selection = RoleSelection::plain(SessionRole::Controller);
    let error = service
        .share(&ShareRequest {
            invitation_id: invitation_id(3),
            grant_id: grant_id(3),
            issuer_device_id: device_id(0xf1),
            recipient_device_id: device_id(0xf3),
            parent_grant_id: Some(reviewer.grant.grant_id),
            accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
            selection,
            ..share(SessionRole::Controller, 3)
        })
        .expect_err("a reviewer cannot make somebody a controller");
    // The refusal names one of the rights the reviewer does not hold, so a person reading it
    // learns what was asked for rather than only that something was.
    let detail = error.to_string();
    let named = ActionRight::ALL
        .iter()
        .find(|right| detail.contains(right.as_str()))
        .unwrap_or_else(|| panic!("the refusal names a right: {detail}"));
    assert!(
        !reviewer.grant.permits(*named),
        "the refusal names a right the reviewer actually holds: {detail}"
    );
    assert!(
        SessionRole::Controller.default_actions().contains(named),
        "and one the controller invitation asked for: {detail}"
    );

    // Revoking the reviewer takes the delegation with it.
    let revocation = service
        .revoke(reviewer.grant.grant_id, NOW + 10)
        .expect("revoked");
    assert!(revocation.revoked.contains(&narrower.grant.grant_id));
}

#[test]
fn transfer_of_control_hands_over_only_what_the_transferring_grant_carries() {
    let service = SharingService::in_memory().expect("a sharing service");
    let owner = service
        .share(&share(SessionRole::Owner, 1))
        .expect("an owner");
    let plan = transfer::TransferPlan {
        session_id: session_id(0xa0),
        from_device_id: device_id(0xf1),
        to_device_id: device_id(0xf2),
        revoking_grant_id: owner.grant.grant_id,
        issuing_grant_id: grant_id(2),
        actions: transfer::transferable_actions(&owner.grant),
    };
    transfer::check_transfer(&plan, &owner.grant).expect("an owner may transfer control");
    assert!(plan.actions.contains(&ActionRight::SessionShare));
    assert_eq!(
        transfer::TransferPlan::sensitive_action(),
        kr_protocol::pairing::SensitiveAction::ChangeHostAuthority,
        "transferring control changes who holds host authority, and is confirmed as that"
    );

    // A controller holds no `session.share`, so it cannot transfer anything.
    let controller = service
        .share(&ShareRequest {
            invitation_id: invitation_id(3),
            grant_id: grant_id(3),
            recipient_device_id: device_id(0xf4),
            ..share(SessionRole::Controller, 3)
        })
        .expect("a controller");
    let refused = transfer::TransferPlan {
        from_device_id: device_id(0xf4),
        revoking_grant_id: controller.grant.grant_id,
        actions: transfer::transferable_actions(&controller.grant),
        ..plan.clone()
    };
    let error = transfer::check_transfer(&refused, &controller.grant)
        .expect_err("a controller cannot transfer control");
    assert!(
        error.to_string().contains("session.share"),
        "unexpected refusal: {error}"
    );

    // And a plan that hands over more than the transferring grant carries is refused, even when
    // the transferring grant does hold `session.share`.
    let narrowed = Grant {
        actions: [ActionRight::SessionView, ActionRight::SessionShare]
            .into_iter()
            .collect(),
        ..owner.grant.clone()
    };
    let overreaching = transfer::TransferPlan {
        actions: [ActionRight::SessionView, ActionRight::TerminalInput]
            .into_iter()
            .collect(),
        ..plan
    };
    let error = transfer::check_transfer(&overreaching, &narrowed)
        .expect_err("a transfer cannot hand over what was never held");
    assert!(
        error.to_string().contains("terminal.input"),
        "unexpected refusal: {error}"
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-19.01: no input through an intermediary
// ---------------------------------------------------------------------------------------------

#[test]
fn a_view_only_invitation_obtains_no_input_through_a_plugin_an_attachment_action_or_a_workflow() {
    let service = SharingService::in_memory().expect("a sharing service");
    let viewer = service
        .share(&share(SessionRole::Viewer, 1))
        .expect("a viewer");
    let actor = viewer.grant.actions.clone();

    // Each intermediary declares terminal input of its own. None of them can lend it.
    let declared: CanonicalSet<ActionRight> = [
        ActionRight::SessionView,
        ActionRight::TerminalInput,
        ActionRight::FilesApplyDiff,
    ]
    .into_iter()
    .collect();
    for via in [
        Intermediary::PluginAction {
            declared: declared.clone(),
        },
        Intermediary::AttachmentAction {
            declared: declared.clone(),
        },
        Intermediary::Workflow {
            declared: declared.clone(),
        },
    ] {
        let effective = effective_rights(&actor, &via);
        assert!(
            !effective.contains(&ActionRight::TerminalInput),
            "{} lent a viewer terminal input",
            via.as_str()
        );
        assert!(
            !effective.contains(&ActionRight::FilesApplyDiff),
            "{} lent a viewer a file write",
            via.as_str()
        );
        assert!(
            effective.contains(&ActionRight::SessionView),
            "what the actor does hold still passes through"
        );
        let error = roles::check_indirect(&actor, &via, ActionRight::TerminalInput)
            .expect_err("the refusal is explicit");
        assert!(
            error.to_string().contains("terminal.input"),
            "unexpected refusal: {error}"
        );
    }

    // The intersection bounds the other way too: a controller calling a plugin that declares only
    // reads obtains only reads.
    let controller = service
        .share(&ShareRequest {
            invitation_id: invitation_id(2),
            grant_id: grant_id(2),
            recipient_device_id: device_id(0xf2),
            ..share(SessionRole::Controller, 2)
        })
        .expect("a controller");
    let reads_only = Intermediary::PluginAction {
        declared: [ActionRight::SessionView].into_iter().collect(),
    };
    let effective = effective_rights(&controller.grant.actions, &reads_only);
    assert!(!effective.contains(&ActionRight::TerminalInput));
    assert!(effective.contains(&ActionRight::SessionView));
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-23.49: the sharing method group
// ---------------------------------------------------------------------------------------------

#[test]
fn sharing_checks_parent_rights_expiry_and_owner_confirmation() {
    let service = SharingService::in_memory().expect("a sharing service");

    // Parent rights: a delegation from a grant this host does not hold is refused.
    let error = service
        .share(&ShareRequest {
            parent_grant_id: Some(grant_id(0xcc)),
            ..share(SessionRole::Viewer, 1)
        })
        .expect_err("a parent this host does not hold");
    assert!(
        error.to_string().contains("no such parent grant"),
        "unexpected refusal: {error}"
    );

    // Expiry: every invitation has one, and it is inside the bound.
    let issued = service
        .share(&share(SessionRole::Viewer, 2))
        .expect("issued");
    let GrantExpiry::At { expires_at_ms } = issued.grant.expiry else {
        panic!("an invitation expires");
    };
    assert_eq!(
        expires_at_ms.get(),
        NOW + kr_protocol::sharing::DEFAULT_INVITATION_LIFETIME_MS
    );

    // Owner confirmation: a persistent enlargement needs it, a bounded invitation does not.
    let held: CanonicalSet<ActionRight> = [ActionRight::SessionView].into_iter().collect();
    assert!(
        !requires_owner_confirmation(&issued.grant, &CanonicalSet::from_iter([])),
        "a bounded invitation is not a persistent enlargement, however wide"
    );
    let persistent = Grant {
        expiry: GrantExpiry::Never,
        actions: [ActionRight::SessionView, ActionRight::TerminalInput]
            .into_iter()
            .collect(),
        ..issued.grant.clone()
    };
    assert!(
        requires_owner_confirmation(&persistent, &held),
        "a persistent grant that adds a right the device does not hold is an enlargement"
    );
    assert!(
        !requires_owner_confirmation(&persistent, &persistent.actions),
        "re-issuing what a device already holds enlarges nothing"
    );

    // Listing: the issuer sees what it issued and everything delegated from it, and nothing else.
    let other_issuer = service
        .share(&ShareRequest {
            invitation_id: invitation_id(4),
            grant_id: grant_id(4),
            issuer_device_id: device_id(0xaa),
            recipient_device_id: device_id(0xab),
            ..share(SessionRole::Viewer, 4)
        })
        .expect("another issuer's grant");
    let listed = service
        .list_for_issuer(device_id(0xf0), None, false, NOW)
        .expect("a list");
    let ids: Vec<GrantId> = listed
        .grants
        .iter()
        .map(|summary| summary.grant.grant_id)
        .collect();
    assert!(ids.contains(&issued.grant.grant_id));
    assert!(
        !ids.contains(&other_issuer.grant.grant_id),
        "holding a right a grant contains is not authority over the grant"
    );
}

/// A supervisor that starts nothing.
///
/// These tests are about sharing rather than about sessions, so nothing here creates one.
#[derive(Debug)]
struct SilentSupervisor;

impl WorkerSupervisor for SilentSupervisor {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: "this test starts no worker".to_owned(),
        }
    }

    fn describe(&self) -> String {
        "a supervisor that starts nothing".to_owned()
    }
}

async fn daemon() -> (kr_ipc::testing::TempHost, Arc<Controller>) {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let secrets = environment.secrets_dir();
    let controller = Controller::start(ControllerSetup {
        paths: environment.clone(),
        environment_id,
        identity: Box::new(move || {
            let store = open_store_in(&secrets).expect("a secret store for the test environment");
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        secret_store: StoreSelection::File,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(SilentSupervisor),
        worker_program: std::path::PathBuf::from("/nonexistent/kr-worker"),
        build_id: BuildId::new("kr-test/0").expect("a build identifier"),
        release: "0".to_owned(),
    })
    .await
    .expect("the daemon starts");
    (temp, controller)
}

#[tokio::test]
async fn revoking_a_shared_grant_completes_through_the_dispatch_barrier() {
    let (_temp, controller) = daemon().await;
    let environment_id = controller.paths().environment_id();
    let host_device_id = DeviceId::new(environment_id.get());

    let issued = controller
        .sharing()
        .share(&ShareRequest {
            environment_id,
            issuer_device_id: host_device_id,
            authority_revision: controller.policy().authority_revision(),
            ..share(SessionRole::Controller, 1)
        })
        .expect("the host shares a session");

    // A delegation from it, so the revocation has a descendant to take with it.
    let delegated = controller
        .sharing()
        .share(&ShareRequest {
            environment_id,
            invitation_id: invitation_id(2),
            grant_id: grant_id(2),
            issuer_device_id: device_id(0xf1),
            recipient_device_id: device_id(0xf2),
            parent_grant_id: Some(issued.grant.grant_id),
            authority_revision: controller.policy().authority_revision(),
            ..share(SessionRole::Viewer, 2)
        })
        .expect("a delegation");

    let before = controller.policy().authority_revision();
    let result = tokio::time::timeout(
        Duration::from_secs(20),
        controller.revoke_grant(issued.grant.grant_id),
    )
    .await
    .expect("the revocation completes")
    .expect("it succeeds");

    assert!(result.authority_revision.get() > before.get());
    assert!(result.revoked_grants.contains(&issued.grant.grant_id));
    assert!(
        result.revoked_grants.contains(&delegated.grant.grant_id),
        "revoking a parent revokes its descendants"
    );
    assert_eq!(
        result.barrier.authority_revision, result.authority_revision,
        "the answer carries the per-worker completion status, not only the revision"
    );

    let listed = controller
        .sharing()
        .list_for_issuer(host_device_id, None, false, NOW)
        .expect("a list");
    assert!(
        listed.grants.is_empty(),
        "nothing active is left after the revocation"
    );
}
