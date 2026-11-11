//! What the door does with a paired device's three draft writes: `draft.create`, `draft.update`
//! and `agent.draft.add_attachment`.
//!
//! The transfer service performs each under the device's own principal, so a draft the device makes
//! is the device's and nobody else's, and the owner's drafts are unknown to it. A draft bound to a
//! session is written only by a request that names that session, a device's draft names the
//! session it is for, a device labels what it makes with its own identity or none, and the drafts
//! a device holds open are bounded: a draft stops counting when a prompt sends it to a session or
//! the session it targets closes. The answer the
//! service reads from its own record of an earlier submission is told to a device as a copy.

use kr_protocol::envelope::{ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{
    ActorId, AgentBindingRevision, ApplicationInstanceId, DeviceId, DraftId, DraftRevision,
    SessionEpoch, SessionId,
};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Nullable, U64, Uuid};
use kr_protocol::transfer::{
    AgentDraftAddAttachmentParams, AgentDraftAddAttachmentResult, AttachmentContribution,
    DraftCreateParams, DraftCreateResult, DraftUpdateParams, DraftUpdateResult, InsertionMethod,
};

use super::a_copy_from_a_services_record::{EVERY_RIGHT, mutation_of, two_copies, written};
use super::write_boundary::paired_connection;
use crate::service::a_close_a_worker_never_answers as fake;
use crate::transfer::DEVICE_OPEN_DRAFTS;

/// How long a case waits for a copy to reach the place it is stopped at.
const WAIT_BOUND: std::time::Duration = std::time::Duration::from_secs(30);

fn create_params(
    world: &fake::Silent,
    session: Option<SessionId>,
    label: Option<DeviceId>,
    text: &str,
) -> DraftCreateParams {
    DraftCreateParams {
        environment_id: world.environment_id,
        device_id: Nullable(label),
        session_id: Nullable(session),
        application_instance_id: Nullable::null(),
        text: text.to_owned(),
    }
}

/// A write of `method` on `connection` that names `session`, or the whole environment.
fn write_naming(
    world: &fake::Silent,
    connection: &super::RemoteConnection,
    method: Method,
    request_id: u64,
    params: &impl serde::Serialize,
    session: Option<SessionId>,
) -> MutationRequest {
    write_naming_application(world, connection, method, request_id, params, session, None)
}

/// A write of `method` on `connection` that names `session` and, inside it, `application`.
fn write_naming_application(
    world: &fake::Silent,
    connection: &super::RemoteConnection,
    method: Method,
    request_id: u64,
    params: &impl serde::Serialize,
    session: Option<SessionId>,
    application: Option<ApplicationInstanceId>,
) -> MutationRequest {
    let mut mutation = mutation_of(
        world,
        connection,
        method,
        request_id,
        ParamsValue::from_typed(params).expect("encodes"),
    );
    if let Some(session_id) = session {
        mutation.target = ActionTarget {
            environment_id: world.environment_id,
            session_id: Nullable::some(session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable(application),
            agent_binding_revision: Nullable(application.map(|_| AgentBindingRevision::new(1))),
        };
    }
    mutation
}

fn an_application(byte: u8) -> ApplicationInstanceId {
    ApplicationInstanceId::new(Uuid::from_bytes([byte; 16]))
}

/// Parameters of a create for `session` that names `application`, or none.
fn create_params_for(
    world: &fake::Silent,
    session: SessionId,
    application: Option<ApplicationInstanceId>,
    text: &str,
) -> DraftCreateParams {
    DraftCreateParams {
        application_instance_id: Nullable(application),
        ..create_params(world, Some(session), None, text)
    }
}

/// One draft for `actor` in `session` that targets `application`, made in the service directly.
fn a_draft_of(
    world: &fake::Silent,
    actor: &ActorId,
    session: SessionId,
    application: Option<ApplicationInstanceId>,
) -> kr_protocol::transfer::DraftRecord {
    world
        .controller
        .transfer()
        .service()
        .draft_create(
            actor,
            &create_params_for(world, session, application, "an open draft"),
            None,
            None,
        )
        .expect("creates the draft")
        .draft
}

/// The result an answer carries.
fn result_of<T: kr_protocol::wire::WireMessage>(answer: &ControlFrame) -> T {
    let ControlFrame::Response(kr_protocol::envelope::Response {
        outcome: Outcome::Ok(value),
        ..
    }) = answer
    else {
        panic!("a result was expected: {answer:?}");
    };
    value.to_typed().expect("a result of the declared shape")
}

fn update_of(draft_id: DraftId, expected_revision: DraftRevision, text: &str) -> DraftUpdateParams {
    DraftUpdateParams {
        draft_id,
        expected_revision,
        text: text.to_owned(),
    }
}

/// One draft for `actor` that nothing bounds, made in the service directly.
fn a_draft_for(
    world: &fake::Silent,
    actor: &ActorId,
    session: Option<SessionId>,
) -> kr_protocol::transfer::DraftRecord {
    world
        .controller
        .transfer()
        .service()
        .draft_create(
            actor,
            &create_params(world, session, None, "an open draft"),
            None,
            None,
        )
        .expect("creates the draft")
        .draft
}

fn the_owner() -> ActorId {
    ActorId::new("local:test").expect("a principal")
}

/// KR-REQ-23.41 and KR-REQ-14.07: a paired device makes a draft of its own and updates it at its
/// exact revision, and a stale revision is the service's `DRAFT_CONFLICT`. The drafts are scoped by
/// the principal that made them: the device's is unknown to the owner, and the owner's, named by the
/// device, is refused as unknown and left as it was. The control is the owner's own draft, which the
/// owner reads back whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_makes_and_updates_drafts_of_its_own_and_reaches_none_of_the_owners() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let service = controller.transfer().service();
    let session = world.session_id;
    let owner = the_owner();
    let owners = a_draft_for(&world, &owner, None);
    let (connection, _) = paired_connection(controller, 31, &[ActionRight::SessionView]);
    let device = connection.device.principal();

    let created: DraftCreateResult = result_of(
        &connection
            .mutate(&write_naming(
                &world,
                &connection,
                Method::DraftCreate,
                1,
                &create_params(&world, Some(session), None, "first"),
                Some(session),
            ))
            .await,
    );
    let id = created.draft.draft_id;
    assert_eq!(created.draft.revision, DraftRevision::new(1));
    assert_eq!(
        service.draft(&device, id).expect("the device's").text,
        "first"
    );

    let updated: DraftUpdateResult = result_of(
        &connection
            .mutate(&write_naming(
                &world,
                &connection,
                Method::DraftUpdate,
                2,
                &update_of(id, created.draft.revision, "second"),
                Some(session),
            ))
            .await,
    );
    assert_eq!(updated.draft.revision, DraftRevision::new(2));
    let stale = connection
        .mutate(&write_naming(
            &world,
            &connection,
            Method::DraftUpdate,
            3,
            &update_of(id, created.draft.revision, "stale"),
            Some(session),
        ))
        .await;
    assert_eq!(
        super::tests::error_of(&stale).code,
        ErrorCode::DraftConflict
    );
    assert_eq!(
        service.draft(&device, id).expect("the device's").text,
        "second"
    );

    let taken = connection
        .mutate(&write_naming(
            &world,
            &connection,
            Method::DraftUpdate,
            4,
            &update_of(owners.draft_id, owners.revision, "taken"),
            None,
        ))
        .await;
    assert_eq!(
        super::tests::error_of(&taken).code,
        ErrorCode::InvalidArgument
    );
    let kept = service.draft(&owner, owners.draft_id).expect("the owner's");
    assert_eq!(kept.text, "an open draft", "the owner's draft is as it was");
    assert_eq!(kept.revision, owners.revision);
    assert!(
        service.draft(&owner, id).is_err(),
        "the device's draft is unknown to the owner"
    );
    world.serving.abort();
}

/// KR-REQ-23.41: a draft bound to a session is written only by a request that names that session.
/// An update that names none, or another session, is refused and leaves the draft as it was; the
/// control is the update that names the session, which is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_draft_bound_to_a_session_is_written_only_by_a_request_that_names_that_session() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let session = world.session_id;
    let (connection, _) = paired_connection(controller, 32, EVERY_RIGHT);
    let device = connection.device.principal();

    let created: DraftCreateResult = result_of(
        &connection
            .mutate(&write_naming(
                &world,
                &connection,
                Method::DraftCreate,
                1,
                &create_params(&world, Some(session), None, "for a session"),
                Some(session),
            ))
            .await,
    );
    let draft = created.draft;
    assert_eq!(draft.session_id.0, Some(session));
    let unchanged = || {
        let read = controller
            .transfer()
            .service()
            .draft(&device, draft.draft_id)
            .expect("the device's draft");
        assert_eq!(
            (read.revision, read.text.as_str()),
            (draft.revision, "for a session")
        );
    };

    let naming_none = connection
        .mutate(&write_naming(
            &world,
            &connection,
            Method::DraftUpdate,
            2,
            &update_of(draft.draft_id, draft.revision, "no session"),
            None,
        ))
        .await;
    assert_eq!(
        super::tests::error_of(&naming_none).code,
        ErrorCode::InvalidArgument
    );
    unchanged();
    let elsewhere = SessionId::new(Uuid::from_bytes([0x77; 16]));
    let naming_another = connection
        .mutate(&write_naming(
            &world,
            &connection,
            Method::DraftUpdate,
            3,
            &update_of(draft.draft_id, draft.revision, "another session"),
            Some(elsewhere),
        ))
        .await;
    assert!(
        matches!(
            naming_another,
            ControlFrame::Response(kr_protocol::envelope::Response {
                outcome: Outcome::Error(_),
                ..
            })
        ),
        "{naming_another:?}"
    );
    unchanged();

    let named: DraftUpdateResult = result_of(
        &connection
            .mutate(&write_naming(
                &world,
                &connection,
                Method::DraftUpdate,
                4,
                &update_of(draft.draft_id, draft.revision, "this session"),
                Some(session),
            ))
            .await,
    );
    assert_eq!(named.draft.revision, DraftRevision::new(2));
    world.serving.abort();
}

/// KR-REQ-23.41: a `draft.create` names in its target the application its parameters name, as it
/// names the session: both absent, or the same. A create whose target and parameters differ in the
/// application is refused and stores nothing; one that agrees is served, and the draft keeps the
/// application. The control is a create that names none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_names_in_its_target_the_application_its_parameters_name() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let session = world.session_id;
    let (connection, _) = paired_connection(controller, 41, EVERY_RIGHT);
    let device = connection.device.principal();
    let (first, second) = (an_application(0x41), an_application(0x42));

    let create = async |request_id: u64,
                        carried: Option<ApplicationInstanceId>,
                        named: Option<ApplicationInstanceId>| {
        connection
            .mutate(&write_naming_application(
                &world,
                &connection,
                Method::DraftCreate,
                request_id,
                &create_params_for(&world, session, carried, "a draft"),
                Some(session),
                named,
            ))
            .await
    };
    for (request_id, (carried, named)) in [
        (Some(first), None),
        (None, Some(first)),
        (Some(first), Some(second)),
    ]
    .into_iter()
    .enumerate()
    {
        let refused = create(request_id as u64 + 1, carried, named).await;
        assert_eq!(
            super::tests::error_of(&refused).code,
            ErrorCode::InvalidArgument,
            "a create whose parameters name {carried:?} and whose target names {named:?}"
        );
    }
    assert_eq!(
        controller
            .transfer()
            .service()
            .open_drafts(&device)
            .expect("counts"),
        0,
        "a refused create stores nothing"
    );

    let made: DraftCreateResult = result_of(&create(10, Some(first), Some(first)).await);
    assert_eq!(made.draft.application_instance_id.0, Some(first));
    assert_eq!(made.draft.session_id.0, Some(session));
    let plain: DraftCreateResult = result_of(&create(11, None, None).await);
    assert_eq!(plain.draft.application_instance_id.0, None);
    world.serving.abort();
}

/// KR-REQ-23.41: a draft made for an application is updated by a request whose target names that
/// application, and by no other. An update that names another application, or none, is refused,
/// and so is one that names an application for a draft that has none; each leaves the draft as it
/// was. The control is the update that names the draft's own application, which is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_draft_for_an_application_is_updated_only_by_a_request_that_names_that_application() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let session = world.session_id;
    let (connection, _) = paired_connection(controller, 42, EVERY_RIGHT);
    let device = connection.device.principal();
    let (application, other) = (an_application(0x41), an_application(0x42));
    let with = a_draft_of(&world, &device, session, Some(application));
    let without = a_draft_of(&world, &device, session, None);

    let update = async |request_id: u64,
                        draft: &kr_protocol::transfer::DraftRecord,
                        named: Option<ApplicationInstanceId>| {
        connection
            .mutate(&write_naming_application(
                &world,
                &connection,
                Method::DraftUpdate,
                request_id,
                &update_of(draft.draft_id, draft.revision, "changed"),
                Some(session),
                named,
            ))
            .await
    };
    let unchanged = |draft: &kr_protocol::transfer::DraftRecord| {
        let read = controller
            .transfer()
            .service()
            .draft(&device, draft.draft_id)
            .expect("the device's draft");
        assert_eq!(
            (read.revision, read.text.as_str()),
            (draft.revision, "an open draft")
        );
    };

    for (request_id, (draft, named)) in [
        (&with, None),
        (&with, Some(other)),
        (&without, Some(application)),
    ]
    .into_iter()
    .enumerate()
    {
        let refused = update(request_id as u64 + 1, draft, named).await;
        assert_eq!(
            super::tests::error_of(&refused).code,
            ErrorCode::InvalidArgument,
            "an update of a draft for {:?} whose target names {named:?}",
            draft.application_instance_id.0
        );
        unchanged(draft);
    }

    let served: DraftUpdateResult = result_of(&update(10, &with, Some(application)).await);
    assert_eq!(served.draft.revision, DraftRevision::new(2));
    assert_eq!(served.draft.application_instance_id.0, Some(application));
    let served: DraftUpdateResult = result_of(&update(11, &without, None).await);
    assert_eq!(served.draft.revision, DraftRevision::new(2));
    world.serving.abort();
}

/// KR-REQ-23.41 and KR-REQ-09.09: an exact repeat of an update of a draft for an application is
/// answered from the service's record and changes nothing: the draft stays at the revision the
/// first update made. The repeat is held as a kept answer, which a device that may read the
/// session's receipts is given, and one that may not is told the outcome is unknown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeated_update_of_a_draft_for_an_application_is_answered_from_its_record() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let session = world.session_id;
    let application = an_application(0x41);
    let (blind, recording) = paired_connection(controller, 43, &[ActionRight::AgentPrompt]);
    let (sighted, _) = paired_connection(
        controller,
        44,
        &[ActionRight::AgentPrompt, ActionRight::SessionView],
    );

    for (connection, may_not_read) in [(&blind, true), (&sighted, false)] {
        let device = connection.device.principal();
        let draft = a_draft_of(&world, &device, session, Some(application));
        let update = write_naming_application(
            &world,
            connection,
            Method::DraftUpdate,
            1,
            &update_of(draft.draft_id, draft.revision, "once"),
            Some(session),
            Some(application),
        );
        let first = connection
            .answer_now(ControlFrame::Mutation(Box::new(update.clone())))
            .await
            .expect("the first is answered");
        assert!(
            first.asked.as_ref().is_some_and(|asked| !asked.is_kept()),
            "the update that performed is a fresh answer"
        );
        let performed: DraftUpdateResult = result_of(first.frame());
        assert_eq!(performed.draft.revision, DraftRevision::new(2));
        assert!(
            connection.write_answer(connection.output(), first).await,
            "the connection stands"
        );

        let repeat = connection
            .answer_now(ControlFrame::Mutation(Box::new(update)))
            .await
            .expect("the repeat is answered");
        assert!(
            repeat
                .asked
                .as_ref()
                .is_some_and(super::decision::Asked::is_kept),
            "the repeat is held as a kept answer"
        );
        if may_not_read {
            let told = written(connection, &recording, repeat).await;
            assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");
        } else {
            let repeated: DraftUpdateResult = result_of(repeat.frame());
            assert_eq!(repeated, performed, "the repeat is given the record");
        }
        let read = controller
            .transfer()
            .service()
            .draft(&device, draft.draft_id)
            .expect("the device's draft");
        assert_eq!(
            (read.revision, read.text.as_str()),
            (DraftRevision::new(2), "once"),
            "the repeat changed nothing"
        );
    }
    world.serving.abort();
}

/// KR-REQ-23.41: naming an application widens nothing. A connection that serves one session under
/// one grant is refused a draft write for another session and one under another grant, and the
/// application the target names changes neither refusal: each is told the same as the write that
/// names none, and nothing is stored or changed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_target_that_names_an_application_reaches_nothing_its_connection_does_not_serve() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let session = world.session_id;
    let elsewhere = SessionId::new(Uuid::from_bytes([0x77; 16]));
    let application = an_application(0x41);
    let (connection, _) = paired_connection(controller, 45, EVERY_RIGHT);
    let device = connection.device.principal();
    let held = a_draft_of(&world, &device, session, Some(application));
    *connection.scope.lock().expect("the scope") = super::opening::Scope::Session {
        session_id: session,
        grant_id: kr_protocol::ids::GrantId::new(kr_ipc::new_uuid()),
    };

    let mut told = Vec::new();
    for (request_id, named) in [(1, None), (2, Some(application))] {
        let create = connection
            .mutate(&write_naming_application(
                &world,
                &connection,
                Method::DraftCreate,
                request_id,
                &create_params_for(&world, elsewhere, named, "elsewhere"),
                Some(elsewhere),
                named,
            ))
            .await;
        let update = connection
            .mutate(&write_naming_application(
                &world,
                &connection,
                Method::DraftUpdate,
                request_id + 10,
                &update_of(held.draft_id, held.revision, "under another grant"),
                Some(session),
                named,
            ))
            .await;
        told.push((
            super::tests::error_of(&create).clone(),
            super::tests::error_of(&update).clone(),
        ));
    }
    assert_eq!(told[0].0.code, ErrorCode::InvalidArgument);
    assert_eq!(told[0].1.code, ErrorCode::PermissionDenied);
    for (without, with) in [(&told[0].0, &told[1].0), (&told[0].1, &told[1].1)] {
        assert_eq!(
            (with.code, &with.message),
            (without.code, &without.message),
            "naming an application changes no refusal"
        );
    }
    let service = controller.transfer().service();
    assert_eq!(service.open_drafts(&device).expect("counts"), 1);
    let read = service.draft(&device, held.draft_id).expect("the draft");
    assert_eq!(
        (read.revision, read.text.as_str()),
        (held.revision, "an open draft")
    );
    world.serving.abort();
}

/// KR-REQ-23.41: a draft a device makes names the session it is for, because only the end of its
/// session or a prompt that sends it ends a draft and a device holds a bounded number. A create
/// that names no session is refused `INVALID_ARGUMENT` before anything is counted or written, and
/// leaves no record: the same action identifier then carries a create that names a session, which
/// is served. The control is the person at this machine, who has no bound and makes a draft with
/// none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_makes_no_draft_that_names_no_session() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let session = world.session_id;
    let (connection, _) = paired_connection(controller, 46, EVERY_RIGHT);
    let device = connection.device.principal();
    let service = controller.transfer().service();

    let sessionless = write_naming(
        &world,
        &connection,
        Method::DraftCreate,
        1,
        &create_params(&world, None, None, "no session"),
        None,
    );
    let refused = connection.mutate(&sessionless).await;
    assert_eq!(
        super::tests::error_of(&refused).code,
        ErrorCode::InvalidArgument
    );
    assert_eq!(service.open_drafts(&device).expect("counts"), 0);

    let mut named = write_naming(
        &world,
        &connection,
        Method::DraftCreate,
        2,
        &create_params(&world, Some(session), None, "for a session"),
        Some(session),
    );
    named.action_id = sessionless.action_id;
    let made: DraftCreateResult = result_of(&connection.mutate(&named).await);
    assert_eq!(made.draft.session_id.0, Some(session));
    assert_eq!(service.open_drafts(&device).expect("counts"), 1);

    let admission = fake::admission(controller, world.accepted).await;
    let window = controller
        .windows
        .issue(admission.connection_id, controller.boot_epoch)
        .expect("a window");
    let mut local = mutation_of(
        &world,
        &connection,
        Method::DraftCreate,
        3,
        ParamsValue::from_typed(&create_params(&world, None, None, "the owner's"))
            .expect("encodes"),
    );
    local.action_window_id = window.action_window_id;
    let owners: DraftCreateResult = result_of(
        &controller
            .perform(&the_owner(), admission.connection_id, None, local)
            .await,
    );
    assert_eq!(owners.draft.session_id.0, None);
    world.serving.abort();
}

/// The contribution a manual terminal workflow declares: no declaration from the session's
/// integration is needed for it.
fn manual_contribution(handle: &kr_protocol::transfer::AttachmentHandle) -> AttachmentContribution {
    AttachmentContribution {
        operation_id: "attach".to_owned(),
        accepted_media_types: vec![handle.declared_media_type.clone()],
        max_byte_len: U64::new(1024),
        max_count: U64::new(4),
        insertion_method: InsertionMethod::ManualTerminalWorkflow,
        external_destination: Nullable::null(),
        model_media_capability: false,
    }
}

/// KR-REQ-23.41 and KR-REQ-14.07: a device binds a finished upload of its own to a draft of its own
/// for a session its grant reaches, and an upload another principal finished is unknown to it, so
/// nothing of the owner's is bound through it. The control for the right is a device that may not
/// prompt the session: it is refused before the service is asked, and its draft holds nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_binds_its_own_finished_upload_to_its_own_draft_and_no_ones_else() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let session = world.session_id;
    let owner = the_owner();
    let (connection, _) = paired_connection(controller, 33, EVERY_RIGHT);
    let device = connection.device.principal();
    let own = super::tests::a_published_attachment_for(
        controller,
        world.environment_id,
        &device,
        "own.bin",
        Some(session),
    );
    let theirs = super::tests::a_published_attachment_for(
        controller,
        world.environment_id,
        &owner,
        "theirs.bin",
        Some(session),
    );
    let draft = a_draft_for(&world, &device, Some(session));
    let add = |connection: &super::RemoteConnection,
               request_id: u64,
               draft: &kr_protocol::transfer::DraftRecord,
               handle: &kr_protocol::transfer::AttachmentHandle| {
        write_naming(
            &world,
            connection,
            Method::AgentDraftAddAttachment,
            request_id,
            &AgentDraftAddAttachmentParams {
                draft_id: draft.draft_id,
                expected_revision: draft.revision,
                transfer_id: handle.transfer_id,
                contribution: manual_contribution(handle),
            },
            Some(session),
        )
    };

    let refused = connection
        .mutate(&add(&connection, 1, &draft, &theirs))
        .await;
    assert_eq!(
        super::tests::error_of(&refused).code,
        ErrorCode::InvalidArgument
    );
    let held = |actor: &ActorId, id: DraftId| {
        controller
            .transfer()
            .service()
            .draft(actor, id)
            .expect("the draft")
            .attachments
            .len()
    };
    assert_eq!(
        held(&device, draft.draft_id),
        0,
        "nothing of the owner's was bound"
    );

    let bound: AgentDraftAddAttachmentResult =
        result_of(&connection.mutate(&add(&connection, 2, &draft, &own)).await);
    assert_eq!(bound.attachment.handle.transfer_id, own.transfer_id);
    assert_eq!(held(&device, draft.draft_id), 1);

    let (limited, _) = paired_connection(
        controller,
        34,
        &[ActionRight::FilesUpload, ActionRight::SessionView],
    );
    let limited_actor = limited.device.principal();
    let theirs_own = super::tests::a_published_attachment_for(
        controller,
        world.environment_id,
        &limited_actor,
        "limited.bin",
        Some(session),
    );
    let limited_draft = a_draft_for(&world, &limited_actor, Some(session));
    let refused = limited
        .mutate(&add(&limited, 3, &limited_draft, &theirs_own))
        .await;
    assert_eq!(
        super::tests::error_of(&refused).code,
        ErrorCode::PermissionDenied
    );
    assert_eq!(held(&limited_actor, limited_draft.draft_id), 0);
    world.serving.abort();
}

/// KR-REQ-23.41: a device labels a draft with its own identity or none, and not with another
/// device's: the label is recorded as the service finds it, and a device does not name what it
/// makes as another's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_labels_its_drafts_with_its_own_identity_or_none() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let (connection, _) = paired_connection(controller, 35, &[ActionRight::SessionView]);
    let own = connection.device.device_id;
    let another = DeviceId::new(Uuid::from_bytes([0x99; 16]));
    let create = |request_id: u64, label: Option<DeviceId>| {
        write_naming(
            &world,
            &connection,
            Method::DraftCreate,
            request_id,
            &create_params(&world, Some(world.session_id), label, "labelled"),
            Some(world.session_id),
        )
    };

    let refused = connection.mutate(&create(1, Some(another))).await;
    assert_eq!(
        super::tests::error_of(&refused).code,
        ErrorCode::PermissionDenied
    );
    let made: DraftCreateResult = result_of(&connection.mutate(&create(2, Some(own))).await);
    assert_eq!(made.draft.device_id.0, Some(own));
    let made: DraftCreateResult = result_of(&connection.mutate(&create(3, None)).await);
    assert_eq!(made.draft.device_id.0, None);
    world.serving.abort();
}

/// KR-REQ-23.41 and KR-REQ-09.09: a `draft.create` that another copy of the action performed
/// while this one was on its way to the service is told as the copy it is, whichever place the copy
/// finds the record at: the door's own lookup before the service is asked, or the service's after
/// its lock is taken.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_draft_create_read_from_the_record_is_held_as_kept() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let session = world.session_id;
    let (connection, _) = paired_connection(controller, 86, EVERY_RIGHT);
    let mutation = write_naming(
        &world,
        &connection,
        Method::DraftCreate,
        91,
        &create_params(&world, Some(session), None, "once"),
        Some(session),
    );

    let (copied, fresh) = two_copies(controller, &connection, &mutation).await;
    for answered in [&copied, &fresh] {
        assert!(
            matches!(
                answered.frame(),
                ControlFrame::Response(kr_protocol::envelope::Response {
                    outcome: Outcome::Ok(_),
                    ..
                })
            ),
            "the create is performed once and answered to both copies: {:?}",
            answered.frame()
        );
    }
    assert!(
        copied
            .asked
            .as_ref()
            .is_some_and(super::decision::Asked::is_kept),
        "the copy that read the result from the record is held as a kept answer"
    );
    assert!(
        fresh.asked.as_ref().is_some_and(|asked| !asked.is_kept()),
        "the copy that performed is a fresh answer"
    );
    world.serving.abort();
}

/// Serves `mutation` twice at once, the first copy stopped inside the transfer service, once it
/// has passed the door's check and before it takes the service's lock, and returns what each copy
/// was answered with.
async fn two_copies_stopped_in_the_service(
    controller: &std::sync::Arc<crate::service::Controller>,
    connection: &super::RemoteConnection,
    mutation: &MutationRequest,
) -> (super::Answered, super::Answered) {
    let (arrived, release) = controller.transfer().pause_after_the_outer_check();
    let first = connection.answer_now(ControlFrame::Mutation(Box::new(mutation.clone())));
    tokio::pin!(first);
    let waiting = tokio::task::spawn_blocking(move || arrived.recv_timeout(WAIT_BOUND));
    tokio::pin!(waiting);
    tokio::select! {
        arrived = &mut waiting => {
            arrived
                .expect("the waiting thread finishes")
                .expect("the first copy reaches the service");
        }
        early = &mut first => panic!("the first copy was answered before the service: {early:?}"),
    }
    let (copied, fresh) = tokio::join!(first, async {
        let fresh = connection
            .answer_now(ControlFrame::Mutation(Box::new(mutation.clone())))
            .await;
        release.send(()).expect("the first copy goes on");
        fresh
    });
    (
        copied.expect("the first copy is answered"),
        fresh.expect("the second copy is answered"),
    )
}

/// KR-REQ-23.41 and KR-REQ-09.09: the copy a service reads from its record after the door's own
/// lookup found nothing is told to a device as a recorded answer is: a device that may not read the
/// session's receipts is told the outcome is unknown, and one that may is given the record. The
/// copy that performed is a fresh answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_draft_create_a_service_copied_after_the_door_looked_is_told_as_a_copy() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let session = world.session_id;
    let params = create_params(&world, Some(session), None, "for a session");

    // A device that may prompt the session and not view it: its draft write is served, and the
    // receipt of it is not its to read.
    let (blind, recording) = paired_connection(controller, 38, &[ActionRight::AgentPrompt]);
    let mutation = write_naming(
        &world,
        &blind,
        Method::DraftCreate,
        91,
        &params,
        Some(session),
    );
    let (copied, fresh) = two_copies_stopped_in_the_service(controller, &blind, &mutation).await;
    assert!(
        copied
            .asked
            .as_ref()
            .is_some_and(super::decision::Asked::is_kept),
        "the copy that read the record is held as a kept answer"
    );
    assert!(
        fresh.asked.as_ref().is_some_and(|asked| !asked.is_kept()),
        "the copy that performed is a fresh answer"
    );
    let told = written(&blind, &recording, copied).await;
    assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");

    // The control: a device that may view the session is given the record.
    let (sighted, recording) = paired_connection(
        controller,
        39,
        &[ActionRight::AgentPrompt, ActionRight::SessionView],
    );
    let mutation = write_naming(
        &world,
        &sighted,
        Method::DraftCreate,
        92,
        &params,
        Some(session),
    );
    let (copied, fresh) = two_copies_stopped_in_the_service(controller, &sighted, &mutation).await;
    assert!(
        sighted.write_answer(sighted.output(), copied).await,
        "the connection stands"
    );
    assert!(
        sighted.write_answer(sighted.output(), fresh).await,
        "the connection stands"
    );
    let frames = recording.frames();
    assert!(
        frames.iter().rev().take(2).all(|frame| matches!(
            frame,
            ControlFrame::Response(kr_protocol::envelope::Response {
                outcome: Outcome::Ok(_),
                ..
            })
        )),
        "both copies are given the draft: {frames:?}"
    );
    world.serving.abort();
}

/// KR-REQ-23.41: a device holds at most `DEVICE_OPEN_DRAFTS` drafts open, and the refusal is the
/// service's quota code in words that name the bound. A prompt that sends one of them frees its
/// place. The person at this machine is held to no bound: past the same number, the owner's create
/// at the local door is served. The refusal is the action's outcome, so a repeat of it is answered
/// the same, and a new action under a place that was freed is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_holds_at_most_the_bound_of_open_drafts_and_the_owner_is_held_to_none() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let service = controller.transfer().service();
    let (connection, _) = paired_connection(controller, 36, EVERY_RIGHT);
    let device = connection.device.principal();
    let mut sent = Vec::new();
    for _ in 1..DEVICE_OPEN_DRAFTS {
        sent.push(a_draft_for(&world, &device, Some(world.session_id)).draft_id);
    }
    let create = |request_id: u64| {
        write_naming(
            &world,
            &connection,
            Method::DraftCreate,
            request_id,
            &create_params(&world, Some(world.session_id), None, "one more"),
            Some(world.session_id),
        )
    };

    let last: DraftCreateResult = result_of(&connection.mutate(&create(1)).await);
    let full = create(2);
    let refused = connection.mutate(&full).await;
    let refusal = super::tests::error_of(&refused);
    assert_eq!(refusal.code, ErrorCode::QuotaExceeded, "{refusal:?}");
    assert!(
        refusal
            .message
            .contains(&format!("{DEVICE_OPEN_DRAFTS} of the {DEVICE_OPEN_DRAFTS}")),
        "the words name the bound: {refusal:?}"
    );

    // A prompt sends a draft to a session, and its place is free for a new action.
    service
        .record_prompt(
            &device,
            last.draft.draft_id,
            world.session_id,
            kr_protocol::ids::ApplicationInstanceId::new(kr_ipc::new_uuid()),
            &kr_transfer::service::Admission::none(),
        )
        .expect("the prompt sends the draft");
    let again = connection.mutate(&full).await;
    assert_eq!(
        super::tests::error_of(&again).code,
        ErrorCode::QuotaExceeded,
        "the refusal is the action's outcome, and a repeat of it is answered as it was"
    );
    let _: DraftCreateResult = result_of(&connection.mutate(&create(3)).await);
    assert_eq!(
        super::tests::error_of(&connection.mutate(&create(4)).await).code,
        ErrorCode::QuotaExceeded,
        "the freed place is taken"
    );

    // The person at this machine has no bound, though it holds as many.
    let owner = the_owner();
    for _ in 0..DEVICE_OPEN_DRAFTS {
        a_draft_for(&world, &owner, None);
    }
    let admission = fake::admission(controller, world.accepted).await;
    let window = controller
        .windows
        .issue(admission.connection_id, controller.boot_epoch)
        .expect("a window");
    let mut local = mutation_of(
        &world,
        &connection,
        Method::DraftCreate,
        5,
        ParamsValue::from_typed(&create_params(&world, None, None, "the owner's"))
            .expect("encodes"),
    );
    local.action_window_id = window.action_window_id;
    let answered = controller
        .perform(&owner, admission.connection_id, None, local)
        .await;
    let _: DraftCreateResult = result_of(&answered);
    world.serving.abort();
}

/// KR-REQ-23.41 and KR-REQ-09.09: the bound is said only to a device whose authority stands. A
/// create at the bound whose registration is withdrawn after the door's own check is refused for
/// its authority, under the registration's code, and the answer says nothing of how many drafts
/// the device holds. The control is the same create with its registration standing, which is told
/// the bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_at_the_bound_whose_registration_is_withdrawn_is_told_nothing_of_the_count() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let (connection, _) = paired_connection(controller, 40, EVERY_RIGHT);
    let device = connection.device.principal();
    for _ in 0..DEVICE_OPEN_DRAFTS {
        a_draft_for(&world, &device, Some(world.session_id));
    }
    let create = |request_id: u64| {
        write_naming(
            &world,
            &connection,
            Method::DraftCreate,
            request_id,
            &create_params(&world, Some(world.session_id), None, "one past the bound"),
            Some(world.session_id),
        )
    };

    let told = connection.mutate(&create(1)).await;
    assert_eq!(
        super::tests::error_of(&told).code,
        ErrorCode::QuotaExceeded,
        "the control: a standing registration is told the bound"
    );

    let (arrived, release) = controller.transfer().pause_after_the_outer_check();
    let withdrawn = create(2);
    let (answered, ()) = tokio::join!(connection.mutate(&withdrawn), async {
        tokio::task::spawn_blocking(move || arrived.recv_timeout(WAIT_BOUND))
            .await
            .expect("the waiting thread finishes")
            .expect("the create reaches the service");
        controller
            .admitted_write()
            .remove(&connection.connection_id());
        release.send(()).expect("the create goes on");
    });
    let refusal = super::tests::error_of(&answered);
    assert_eq!(refusal.code, ErrorCode::PermissionDenied, "{refusal:?}");
    assert!(
        !refusal.message.contains(&DEVICE_OPEN_DRAFTS.to_string()),
        "the answer names no count: {refusal:?}"
    );
    world.serving.abort();
}

/// A device holding as many open drafts as it may, every one bound to the session of `world`.
fn at_the_bound_for_a_session(world: &fake::Silent, byte: u8) -> super::RemoteConnection {
    let (connection, _) = paired_connection(&world.controller, byte, EVERY_RIGHT);
    let device = connection.device.principal();
    for _ in 0..DEVICE_OPEN_DRAFTS {
        a_draft_for(world, &device, Some(world.session_id));
    }
    connection
}

/// The create such a device sends for another session than the one its drafts are bound to.
fn a_create_for_another_session(
    world: &fake::Silent,
    connection: &super::RemoteConnection,
    request_id: u64,
) -> MutationRequest {
    let another = SessionId::new(Uuid::from_bytes([9; 16]));
    write_naming(
        world,
        connection,
        Method::DraftCreate,
        request_id,
        &create_params(world, Some(another), None, "for another session"),
        Some(another),
    )
}

/// KR-REQ-23.41: a draft stops counting when the session it targets closes. A device at its bound is
/// refused while the session lives; once the daemon has closed the session, through its own
/// closure, a create is served at once, and the closure's own queued write for the session's drafts
/// is not what it waits for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_draft_stops_counting_when_its_session_closes() {
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::closure_of;

    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let connection = at_the_bound_for_a_session(&world, 41);
    let refused = connection
        .mutate(&a_create_for_another_session(&world, &connection, 1))
        .await;
    assert_eq!(
        super::tests::error_of(&refused).code,
        ErrorCode::QuotaExceeded,
        "the drafts bound to a live session count"
    );

    controller
        .retire(&closure_of(world.session_id))
        .await
        .expect("the session closes");
    let _: DraftCreateResult = result_of(
        &connection
            .mutate(&a_create_for_another_session(&world, &connection, 2))
            .await,
    );
    world.serving.abort();
}

/// KR-REQ-23.41: a draft stops counting when the registry records its session closed, whether or not
/// the write the closure queues for the session's drafts has run: that write is made up by the
/// sweep and the next start, and the bound does not wait for either. Here the registry holds the
/// closure and the transfer service has not been told, as after a write that failed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_draft_stops_counting_when_the_registry_holds_its_session_closed() {
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::closure_of;

    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let connection = at_the_bound_for_a_session(&world, 42);
    let refused = connection
        .mutate(&a_create_for_another_session(&world, &connection, 1))
        .await;
    assert_eq!(
        super::tests::error_of(&refused).code,
        ErrorCode::QuotaExceeded,
        "the drafts bound to a live session count"
    );

    controller
        .registry
        .lock()
        .await
        .record_closure(&closure_of(world.session_id))
        .expect("the registry records the closure");
    let _: DraftCreateResult = result_of(
        &connection
            .mutate(&a_create_for_another_session(&world, &connection, 2))
            .await,
    );
    world.serving.abort();
}

/// KR-REQ-23.41: the bound refuses a create only for drafts that are open, whatever else the device
/// is creating. The device here holds one place fewer than its bound by the registry's account, which
/// records the closure of the session one of its drafts targets while the transfer service has not
/// been told. Two creates that run together are both served: the one stopped after the door's
/// settle and before the service is entered is not refused for a draft the other made while it
/// waited. The startup sweep has ended first, so it cannot write the closure and hide the fault.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_creates_together_beside_a_closure_not_yet_written_are_both_served() {
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::closure_of;

    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    controller.transfer().until_a_sweep_has_ended().await;
    let (connection, _) = paired_connection(controller, 43, EVERY_RIGHT);
    let device = connection.device.principal();
    a_draft_for(&world, &device, Some(world.session_id));
    for _ in 1..DEVICE_OPEN_DRAFTS - 1 {
        a_draft_for(&world, &device, None);
    }
    controller
        .registry
        .lock()
        .await
        .record_closure(&closure_of(world.session_id))
        .expect("the registry records the closure");

    let (arrived, release) = controller.transfer().pause_after_the_outer_check();
    let first = connection.answer_now(ControlFrame::Mutation(Box::new(
        a_create_for_another_session(&world, &connection, 1),
    )));
    tokio::pin!(first);
    let waiting = tokio::task::spawn_blocking(move || arrived.recv_timeout(WAIT_BOUND));
    tokio::pin!(waiting);
    tokio::select! {
        arrived = &mut waiting => {
            arrived
                .expect("the waiting thread finishes")
                .expect("the first create reaches the service");
        }
        early = &mut first => panic!("the first create was answered before the service: {early:?}"),
    }
    let (first, second) = tokio::join!(first, async {
        let second = connection
            .answer_now(ControlFrame::Mutation(Box::new(
                a_create_for_another_session(&world, &connection, 2),
            )))
            .await;
        release.send(()).expect("the first create goes on");
        second
    });
    for answered in [first, second] {
        let _: DraftCreateResult = result_of(answered.expect("the create is answered").frame());
    }
    assert_eq!(
        controller.transfer().second_tries(),
        0,
        "both creates were served by their first try: the door's settle made the place"
    );
    world.serving.abort();
}

/// KR-REQ-23.41: a create that names a session the registry holds closed is refused as the service
/// refuses any draft for an ended session, though the write that tells the transfer service of the
/// closure has not run, and a create that names another session is served beside it. The device
/// holds one place fewer than its bound and none of its drafts targets the closed session, so the
/// settle finds it only by the session the create names.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_that_names_a_session_the_registry_holds_closed_is_refused_for_it() {
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::closure_of;

    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    controller.transfer().until_a_sweep_has_ended().await;
    let (connection, _) = paired_connection(controller, 44, EVERY_RIGHT);
    let device = connection.device.principal();
    for _ in 1..DEVICE_OPEN_DRAFTS {
        a_draft_for(&world, &device, None);
    }
    controller
        .registry
        .lock()
        .await
        .record_closure(&closure_of(world.session_id))
        .expect("the registry records the closure");

    let closed = world.session_id;
    let refused = connection
        .mutate(&write_naming(
            &world,
            &connection,
            Method::DraftCreate,
            1,
            &create_params(&world, Some(closed), None, "for the closed session"),
            Some(closed),
        ))
        .await;
    assert_eq!(
        super::tests::error_of(&refused).code,
        ErrorCode::SessionClosed,
        "a draft for a session recorded closed is not made"
    );
    let another = SessionId::new(Uuid::from_bytes([9; 16]));
    let _: DraftCreateResult = result_of(
        &connection
            .mutate(&write_naming(
                &world,
                &connection,
                Method::DraftCreate,
                2,
                &create_params(&world, Some(another), None, "for another session"),
                Some(another),
            ))
            .await,
    );
    world.serving.abort();
}

/// KR-REQ-23.41: a refusal at the bound is kept as the action's outcome, so it is not given on a
/// count that a draft for a closed session, inserted after the door settled, filled. The first
/// create is stopped after the door's settle and before the service is entered; a draft for a
/// session the registry holds closed is then made, as another create that settled before the
/// closure was seen would make it, and the first create is served on its second try, after the
/// closed sessions are settled once more.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_is_tried_again_after_a_second_settle_before_a_refusal_at_the_bound_is_kept() {
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::closure_of;

    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    controller.transfer().until_a_sweep_has_ended().await;
    let (connection, _) = paired_connection(controller, 45, EVERY_RIGHT);
    let device = connection.device.principal();
    for _ in 1..DEVICE_OPEN_DRAFTS {
        a_draft_for(&world, &device, None);
    }
    controller
        .registry
        .lock()
        .await
        .record_closure(&closure_of(world.session_id))
        .expect("the registry records the closure");

    let (arrived, release) = controller.transfer().pause_after_the_outer_check();
    let create = connection.answer_now(ControlFrame::Mutation(Box::new(
        a_create_for_another_session(&world, &connection, 1),
    )));
    tokio::pin!(create);
    let waiting = tokio::task::spawn_blocking(move || arrived.recv_timeout(WAIT_BOUND));
    tokio::pin!(waiting);
    tokio::select! {
        arrived = &mut waiting => {
            arrived
                .expect("the waiting thread finishes")
                .expect("the create reaches the service");
        }
        early = &mut create => panic!("the create was answered before the service: {early:?}"),
    }
    // The device now holds its bound by the transfer service's account: this draft is for a
    // session whose closure the service has not been told.
    a_draft_for(&world, &device, Some(world.session_id));
    release.send(()).expect("the create goes on");
    let answered = create.await.expect("the create is answered");
    let _: DraftCreateResult = result_of(answered.frame());
    assert_eq!(
        controller.transfer().second_tries(),
        1,
        "the create was served by its second try"
    );
    world.serving.abort();
}

/// Two copies of one `draft.create` on a device at its bound. The first is refused by the count, is
/// stopped between its two tries, and the second copy commits while it waits: a session whose
/// draft makes the device's last place closes in the registry after the first copy's door settle,
/// and the first copy's own second settle ends it. Returns what each copy was answered with.
async fn a_copy_stopped_between_its_tries_while_another_commits(
    world: &fake::Silent,
    connection: &super::RemoteConnection,
    closed: SessionId,
    request_id: u64,
) -> (super::Answered, super::Answered) {
    use crate::service::a_read_that_meets_a_worker_on_its_way_out::closure_of;

    let controller = &world.controller;
    let device = connection.device.principal();
    for _ in 1..DEVICE_OPEN_DRAFTS {
        a_draft_for(world, &device, None);
    }
    a_draft_for(world, &device, Some(closed));
    let mutation = write_naming(
        world,
        connection,
        Method::DraftCreate,
        request_id,
        &create_params(world, Some(world.session_id), None, "the same action twice"),
        Some(world.session_id),
    );
    let (arrived, release) = controller.transfer().pause_after_the_outer_check();
    let (between, go_on) = controller.transfer().pause_between_the_tries();
    let first = connection.answer_now(ControlFrame::Mutation(Box::new(mutation.clone())));
    tokio::pin!(first);
    let waiting = tokio::task::spawn_blocking(move || arrived.recv_timeout(WAIT_BOUND));
    tokio::pin!(waiting);
    tokio::select! {
        arrived = &mut waiting => {
            arrived
                .expect("the waiting thread finishes")
                .expect("the first copy reaches the service");
        }
        early = &mut first => panic!("the first copy was answered before the service: {early:?}"),
    }
    controller
        .registry
        .lock()
        .await
        .record_closure(&closure_of(closed))
        .expect("the registry records the closure");
    release.send(()).expect("the first copy goes on");
    let waiting = tokio::task::spawn_blocking(move || between.recv_timeout(WAIT_BOUND));
    tokio::pin!(waiting);
    tokio::select! {
        between = &mut waiting => {
            between
                .expect("the waiting thread finishes")
                .expect("the first copy reaches its second try");
        }
        early = &mut first => panic!("the first copy was answered before its second try: {early:?}"),
    }
    let second = connection
        .answer_now(ControlFrame::Mutation(Box::new(mutation)))
        .await
        .expect("the second copy is answered");
    go_on.send(()).expect("the first copy goes on");
    (first.await.expect("the first copy is answered"), second)
}

/// KR-REQ-23.41 and KR-REQ-09.09: what a create finds in its second try is a copy's. A record the
/// second copy wrote while the first was between its tries is given back to the first only under
/// the authority the first arrived under: a device that may not read the session's receipts is told
/// the outcome is unknown, and one that may is given the record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_found_by_the_second_try_is_told_as_a_copy() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    controller.transfer().until_a_sweep_has_ended().await;

    let (blind, recording) = paired_connection(controller, 46, &[ActionRight::AgentPrompt]);
    let (first, second) = a_copy_stopped_between_its_tries_while_another_commits(
        &world,
        &blind,
        SessionId::new(Uuid::from_bytes([7; 16])),
        1,
    )
    .await;
    let _: DraftCreateResult = result_of(second.frame());
    assert!(
        first
            .asked
            .as_ref()
            .is_some_and(super::decision::Asked::is_kept),
        "the record the second try found is held as a kept answer"
    );
    let told = written(&blind, &recording, first).await;
    assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");

    // The control: a device that may view the session is given the record.
    let (sighted, recording) = paired_connection(
        controller,
        47,
        &[ActionRight::AgentPrompt, ActionRight::SessionView],
    );
    let (first, second) = a_copy_stopped_between_its_tries_while_another_commits(
        &world,
        &sighted,
        SessionId::new(Uuid::from_bytes([8; 16])),
        2,
    )
    .await;
    assert!(
        sighted.write_answer(sighted.output(), first).await,
        "the connection stands"
    );
    assert!(
        sighted.write_answer(sighted.output(), second).await,
        "the connection stands"
    );
    let frames = recording.frames();
    assert!(
        frames.iter().rev().take(2).all(|frame| matches!(
            frame,
            ControlFrame::Response(kr_protocol::envelope::Response {
                outcome: Outcome::Ok(_),
                ..
            })
        )),
        "both copies are given the draft: {frames:?}"
    );
    assert_eq!(
        controller.transfer().second_tries(),
        2,
        "each first copy was tried a second time"
    );
    world.serving.abort();
}

/// KR-REQ-23.41 and KR-REQ-09.09: a `draft.create` whose deadline passes after the door's own check
/// and before the service writes is refused for its deadline and writes nothing, and the refusal is
/// not the action's record: the same action under an admission that stands is a first admission and
/// is served, not answered from a record. The deadline is the one the host accepted the action
/// under, asked again inside the service.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_whose_deadline_passes_after_the_doors_check_writes_nothing() {
    use crate::service::the_fence_at_every_effect::{admitted, carried, daemon};

    let (temp, controller, clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let params = DraftCreateParams {
        environment_id: temp.environment_id(),
        device_id: Nullable::null(),
        session_id: Nullable::null(),
        application_instance_id: Nullable::null(),
        text: "a draft that waits".to_owned(),
    };
    let mutation = crate::service::the_fence_at_every_effect::mutation_of(
        &temp,
        Method::DraftCreate,
        ParamsValue::from_typed(&params).expect("encodes"),
    );
    let write = |admission| {
        controller.transfer().write(
            &actor_id,
            &mutation,
            Method::DraftCreate,
            crate::transfer::TransferAdmission::new(std::sync::Arc::clone(&controller), admission),
            Some(crate::transfer::PAIRED_DEVICE),
        )
    };

    let (arrived, release) = controller.transfer().pause_after_the_outer_check();
    let waiting = write(carried(&controller, connection_id));
    let (given, ()) = tokio::join!(waiting, async {
        tokio::task::spawn_blocking(move || arrived.recv_timeout(WAIT_BOUND))
            .await
            .expect("the waiting thread finishes")
            .expect("the create reaches the service");
        clock.advance(std::time::Duration::from_secs(61));
        release.send(()).expect("the create goes on");
    });
    assert!(!given.is_copied(), "a refusal of this attempt is no copy");
    let refused = given.into_answer().expect_err("the deadline passed");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(refused.message.contains("deadline"), "{refused:?}");

    let served = write(carried(&controller, connection_id)).await;
    assert!(
        !served.is_copied(),
        "nothing was recorded for the action, so this is a first admission"
    );
    served
        .into_answer()
        .expect("an admission that stands is served");
}
