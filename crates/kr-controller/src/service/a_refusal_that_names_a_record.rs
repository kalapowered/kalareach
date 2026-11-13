//! What a refusal that names another attempt's record goes back under.
//!
//! A service that reads the record of an action after a wait (a claim, a lookup, a store) can meet
//! something that is no answer and still tells the caller of another attempt: a refusal kept under a
//! code this build cannot read, a row that cannot be decoded, the identifier another request spent.
//! Section 9 has the host check current authority before a retained receipt goes back, so each of
//! these goes back only under the authority the copy arrived under, asked with it in hand: a fence
//! this host owes stops it, as it stops a recorded answer, and the caller is told the fence.
//!
//! Each case plants what the other attempt left, and asks the service the control (nothing owed:
//! the refusal is told) and then a fence. Where the service asks its check on the async side, the
//! fence lands at the pause that check starts with, so the case shows the check is asked after the
//! record is read. Where the check runs on a thread that blocks (the project service), or a case
//! sets the fence before the call, no pause stops it, and the case shows that the check runs, not
//! when.

use std::sync::Arc;
use std::time::Duration;

use kr_protocol::envelope::{MutationRequest, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, ActorId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{DurationMs, Nullable};

use super::a_recorded_answer_another_copy_wrote::{
    FenceAtTheRetainedCheck, a_deadline_that_passed, a_late_attention_copy_at_the_store,
    a_workflow_install, answered_after_a_fence_lands_at, answered_after_a_fence_lands_at_the_check,
    attention_answer, cancellation, changeset_answer, materialisation, plant_a_project_refusal,
    project_answer, refused_for_the_fence, setting_quiet_hours,
};
use super::authority_changes::AuthorityCaller;
use super::the_fence_at_every_effect::{
    CountingSupervisor, admitted, carried, daemon, mutation_of, refused_for_a_fence, told_now,
};
use crate::authority::AdmittedMutation;
use crate::given::Given;
use crate::service::Controller;

/// Another request under the action identifier of `mutation`: it asks for a window's lifetime one
/// millisecond shorter, which its digest covers, so the identifier is spent on a request that is
/// not this one.
fn another_request_under(mutation: &MutationRequest) -> MutationRequest {
    let mut other = mutation.clone();
    other.requested_ttl_ms = DurationMs::new(29_999);
    other
}

// ---------------------------------------------------------------------------------------------
// A refusal kept under a code this build cannot read
// ---------------------------------------------------------------------------------------------

/// Writes the claim another attempt of `mutation` left, settled as a refusal under a code this
/// build cannot read: what that attempt did is not known, and the record says that it exists.
fn plant_a_refusal_this_build_cannot_read(
    temp: &kr_ipc::testing::TempHost,
    actor_id: &ActorId,
    mutation: &MutationRequest,
) {
    let digest = kr_protocol::digest::mutation_digest(mutation, actor_id).expect("a digest");
    let registry = rusqlite::Connection::open(temp.environment().registry_database())
        .expect("the registry opens beside the daemon's own handle");
    registry
        .busy_timeout(Duration::from_secs(10))
        .expect("waits for the daemon's own writes");
    registry
        .execute(
            "INSERT INTO authority_receipts
                 (actor_id, action_id, payload_digest, claimed_at_ms, result, recorded_at_ms,
                  refusal_code, refusal_detail)
             VALUES (?1, ?2, ?3, 1, NULL, 1, 'A_CODE_THIS_BUILD_LACKS', 'no')",
            rusqlite::params![
                actor_id.as_str(),
                mutation.action_id.get().as_bytes().as_slice(),
                digest.as_bytes().as_slice(),
            ],
        )
        .expect("the receipt is written");
}

/// What `attempt`, a service that claims its action and meets a record that cannot be read, is
/// told: the control (nothing owed: what became of the action is not known, told as a copy of the
/// record), and then, with a fence landing once that is in hand, the fence, as the refusal of a copy
/// the service withheld.
async fn a_record_that_cannot_be_read_is_told_only_under_its_authority(
    controller: &Controller,
    attempt: impl AsyncFn() -> Given<crate::error::Result<ParamsValue>>,
) {
    let control = attempt().await;
    assert!(
        control.is_copied(),
        "a record that cannot be read says that it exists, so it is a copy"
    );
    let told = control
        .into_answer_for_test()
        .expect_err("a record that cannot be read does not answer the copy");
    assert_eq!(told.code(), ErrorCode::OutcomeUnknown, "{told}");

    let refused = answered_after_a_fence_lands_at_the_check(controller, attempt())
        .await
        .into_withheld()
        .expect_err("a fence that landed once the record was met is the answer");
    refused_for_a_fence(&refused.to_protocol_error());
}

/// KR-REQ-09.09, a refusal kept under a code this build cannot read, met where a machine group step
/// claims its action: it says that another attempt's record exists, so it goes back only under the
/// authority this attempt arrived under. The control: with nothing owed the copy is told that what
/// became of the action is not known. A fence that lands once the record is met is the answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_machine_group_step_that_meets_a_refusal_it_cannot_read_is_not_told_after_a_fence_lands()
{
    use kr_protocol::machine::{MachineExpected, MachineSplitParams};

    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let group = controller
        .machine_report()
        .expect("this daemon serves a machine group record");
    let mutation = mutation_of(
        &temp,
        Method::MachineSplit,
        ParamsValue::from_typed(&MachineSplitParams {
            expected: MachineExpected {
                machine_id: group.machine_id,
                revision: group.revision,
            },
        })
        .expect("encodes"),
    );
    plant_a_refusal_this_build_cannot_read(&temp, &actor_id, &mutation);
    let admission = carried(&controller, connection_id);
    a_record_that_cannot_be_read_is_told_only_under_its_authority(&controller, async || {
        controller
            .machine_step(&actor_id, &mutation, Method::MachineSplit, admission)
            .await
    })
    .await;
}

/// KR-REQ-09.09, a refusal kept under a code this build cannot read, met where an authority change,
/// a preview key's update and a push registration claim their action: it goes back only under the
/// authority this attempt arrived under, as it does for a machine group step.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_authority_change_that_meets_a_refusal_it_cannot_read_is_not_told_after_a_fence_lands() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let admission = carried(&controller, connection_id);

    let revoking = mutation_of(&temp, Method::GrantRevoke, ParamsValue::empty());
    plant_a_refusal_this_build_cannot_read(&temp, &actor_id, &revoking);
    a_record_that_cannot_be_read_is_told_only_under_its_authority(&controller, async || {
        controller
            .authority_change(
                &actor_id,
                AuthorityCaller::Owner,
                &revoking,
                Method::GrantRevoke,
                admission,
            )
            .await
            .into_given()
    })
    .await;

    let rotating = mutation_of(&temp, Method::DevicePreviewKeyUpdate, ParamsValue::empty());
    plant_a_refusal_this_build_cannot_read(&temp, &actor_id, &rotating);
    a_record_that_cannot_be_read_is_told_only_under_its_authority(&controller, async || {
        controller
            .preview_key_update_action(&actor_id, &rotating, admission)
            .await
    })
    .await;

    let registering = mutation_of(&temp, Method::DevicePushRegister, ParamsValue::empty());
    plant_a_refusal_this_build_cannot_read(&temp, &actor_id, &registering);
    a_record_that_cannot_be_read_is_told_only_under_its_authority(&controller, async || {
        controller
            .push_register_action(&actor_id, &registering, admission)
            .await
    })
    .await;
}

/// KR-REQ-09.09, a refusal kept under a code this build cannot read, met where an action the host
/// performs under one claim in the shared store (a privacy change) claims its action: it goes back
/// only under the authority this attempt arrived under. The control: with nothing owed the copy is
/// told that what became of the action is not known. While this host owes a fence the caller is told
/// that what became of it is not shown, which is not the record's word and not the fence's: the
/// refusal of the authority is a definite word, and an earlier attempt may have carried the action
/// out. The fence is set before the call: the door's own function asks the check, with no pause
/// before it, so the case shows that the check runs, not when.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_privacy_change_that_meets_a_refusal_it_cannot_read_is_not_told_while_a_fence_is_owed() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let mutation = mutation_of(
        &temp,
        Method::PrivacySet,
        ParamsValue::from_typed(&kr_protocol::privacy::PrivacySetParams { enabled: true })
            .expect("encodes"),
    );
    plant_a_refusal_this_build_cannot_read(&temp, &actor_id, &mutation);
    let attempt = || {
        told_now(
            &controller,
            connection_id,
            &mutation,
            controller.write_method(
                &actor_id,
                &mutation,
                Method::PrivacySet,
                connection_id,
                None,
                Some(super::the_fence_at_every_effect::accepted(&controller)),
                controller.admitted_revision(connection_id).ok(),
            ),
        )
    };
    let control = attempt().await;
    let control = super::the_fence_at_every_effect::refusal(&control)
        .unwrap_or_else(|| panic!("a record that cannot be read does not answer the copy"))
        .clone();
    assert_eq!(control.code, ErrorCode::OutcomeUnknown, "{control:?}");

    controller.hold_fence(true);
    let refused = attempt().await;
    controller.hold_fence(false);
    let told = super::the_fence_at_every_effect::refusal(&refused)
        .unwrap_or_else(|| panic!("a fence this host owes stops it: {refused:?}"));
    assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");
    assert_eq!(
        told.message,
        crate::error::ControllerError::outcome_not_shown().to_string(),
        "the caller is told the outcome is not shown, and not what the record said"
    );
    assert_ne!(told.message, control.message);
}

// ---------------------------------------------------------------------------------------------
// The attention store
// ---------------------------------------------------------------------------------------------

/// KR-REQ-09.09, the attention store meeting the identifier another request spent: the store
/// refuses the copy as a conflict before it gives an answer, which tells the caller of another
/// attempt, so it goes back only under the authority the copy arrived under, asked once the store
/// has refused it. The control: with nothing owed the conflict is told. A fence that lands once the
/// copy is at the store is the answer instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attention_action_that_meets_another_requests_identifier_is_not_told_after_a_fence_lands()
 {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let mutation = setting_quiet_hours(&temp);
    let admission = carried(&controller, connection_id);
    attention_answer(&controller, &actor_id, &mutation, admission)
        .await
        .into_answer_for_test()
        .expect("the window is set");
    let other = another_request_under(&mutation);

    let told = a_late_attention_copy_at_the_store(&controller, &actor_id, &other, admission, false)
        .await
        .into_answer_for_test()
        .expect_err("with nothing owed the conflict is told");
    assert_eq!(told.code, ErrorCode::IdConflict, "{told:?}");

    let refused =
        a_late_attention_copy_at_the_store(&controller, &actor_id, &other, admission, true)
            .await
            .into_answer_for_test()
            .expect_err("a fence that landed at the store is the answer");
    refused_for_a_fence(&refused);
}

/// KR-REQ-09.09, the attention store meeting a row it cannot decode: that the action's row exists is
/// what the caller would be told, so the refusal goes back only under the authority the copy
/// arrived under. The control: with nothing owed the copy is told that what became of the action is
/// not known. A fence that lands once the copy is at the store is the answer instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attention_action_whose_row_cannot_be_decoded_is_not_told_after_a_fence_lands() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let mutation = setting_quiet_hours(&temp);
    let admission = carried(&controller, connection_id);
    attention_answer(&controller, &actor_id, &mutation, admission)
        .await
        .into_answer_for_test()
        .expect("the window is set");
    let store =
        rusqlite::Connection::open(temp.environment().state_dir().join("attention.sqlite3"))
            .expect("opens the attention store");
    store
        .busy_timeout(Duration::from_secs(10))
        .expect("waits for the daemon's own writes");
    store
        .execute("UPDATE attention_actions SET recorded_at_ms = -1", [])
        .expect("the row cannot be decoded");

    let told =
        a_late_attention_copy_at_the_store(&controller, &actor_id, &mutation, admission, false)
            .await
            .into_answer_for_test()
            .expect_err("a row that cannot be decoded does not answer the copy");
    assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");

    let refused =
        a_late_attention_copy_at_the_store(&controller, &actor_id, &mutation, admission, true)
            .await
            .into_answer_for_test()
            .expect_err("a fence that landed at the store is the answer");
    refused_for_a_fence(&refused);
}

// ---------------------------------------------------------------------------------------------
// The catalogue
// ---------------------------------------------------------------------------------------------

/// KR-REQ-09.09, the catalogue meeting a receipt it cannot decode: that a receipt exists is what the
/// caller would be told, so the refusal goes back only under the authority the copy arrived under,
/// asked once the receipt has been refused. The control: with nothing owed the copy is told the
/// store's refusal. A fence that lands once it is in hand is the answer instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_catalogue_receipt_that_cannot_be_decoded_is_not_told_after_a_fence_lands() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let mutation = mutation_of(
        &temp,
        Method::CataloguePin,
        ParamsValue::from_typed(&kr_protocol::catalogue::CataloguePinParams {
            environment_id: temp.environment_id(),
            catalogue_id: "nobody-enrolled-this".to_owned(),
            generation: Nullable(Some(kr_protocol::ids::RepositoryGeneration::new(1))),
        })
        .expect("encodes"),
    );
    let admission = carried(&controller, connection_id);
    let attempt = |landing: bool| {
        let admission: Arc<dyn crate::catalogue::Admission> = Arc::new(FenceAtTheRetainedCheck {
            inner: crate::catalogue::DaemonAdmission::new(Arc::clone(&controller), admission),
            controller: Arc::clone(&controller),
            landing: std::sync::atomic::AtomicBool::new(landing),
        });
        controller.catalogue().write(
            &actor_id,
            &mutation,
            Method::CataloguePin,
            None,
            admission,
            None,
        )
    };
    attempt(false)
        .await
        .into_answer_for_test()
        .expect_err("a catalogue nobody enrolled is refused, and the refusal is kept");
    let receipts = rusqlite::Connection::open(
        temp.environment()
            .state_dir()
            .join("catalogue")
            .join("catalogue.sqlite3"),
    )
    .expect("opens the catalogue's store");
    receipts
        .busy_timeout(Duration::from_secs(10))
        .expect("waits for the daemon's own writes");
    receipts
        .execute("UPDATE receipts SET state = 'a state this build lacks'", [])
        .expect("the receipt cannot be decoded");

    let told = attempt(false)
        .await
        .into_answer_for_test()
        .expect_err("a receipt that cannot be decoded does not answer the copy");
    assert_ne!(told.code, ErrorCode::PermissionDenied, "{told:?}");

    let refused = attempt(true)
        .await
        .into_answer_for_test()
        .expect_err("a fence that landed once the refusal was in hand is the answer");
    refused_for_a_fence(&refused);
    controller.hold_fence(false);
}

// ---------------------------------------------------------------------------------------------
// The automation journal
// ---------------------------------------------------------------------------------------------

/// KR-REQ-09.09, the workflow journal meeting the identifier another request spent: the journal
/// refuses the copy as a reused identifier, which tells the caller of another attempt, so it goes
/// back only under the authority the copy arrived under, asked once the journal has refused it. The
/// copy passes the daemon's own check and is stopped before the journal, where a fence lands. The
/// control: with nothing owed the conflict is told.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_automation_action_that_meets_another_requests_identifier_is_not_told_after_a_fence_lands()
 {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let mutation = a_workflow_install(&temp, &controller);
    let admission = carried(&controller, connection_id);
    let ask = async |request: &MutationRequest| {
        controller
            .automation_mutation(&actor_id, request, Method::WorkflowInstall, admission, None)
            .await
    };
    ask(&mutation)
        .await
        .into_answer_for_test()
        .expect("the first copy installs it");
    let other = another_request_under(&mutation);

    let told = ask(&other)
        .await
        .into_answer_for_test()
        .expect_err("with nothing owed the conflict is told");
    assert_eq!(told.code, ErrorCode::IdConflict, "{told:?}");

    let refused = answered_after_a_fence_lands_at(
        &controller,
        controller.pause_after_the_automation_admission(),
        ask(&other),
    )
    .await
    .into_answer_for_test()
    .expect_err("a fence that landed before the journal is the answer");
    refused_for_a_fence(&refused);
}

// ---------------------------------------------------------------------------------------------
// A create
// ---------------------------------------------------------------------------------------------

/// A create that a first copy made, and the parameters it carried.
async fn a_create_another_copy_made(
    temp: &kr_ipc::testing::TempHost,
    controller: &Arc<Controller>,
    connection_id: kr_protocol::ids::ConnectionId,
    actor_id: &ActorId,
) -> MutationRequest {
    use kr_protocol::session::{LaunchProfile, Presentation, SessionCreateParams, ShellMode};

    let params = SessionCreateParams {
        environment_id: temp.environment_id(),
        presentation: Presentation::Invisible,
        shell: Nullable::null(),
        shell_mode: ShellMode::NativeCompat,
        cwd: Nullable::some("/".to_owned()),
        dimensions: Nullable::null(),
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        environment_snapshot: Vec::new(),
        palette: Nullable::null(),
        launch_profile: LaunchProfile::default(),
        terminal: Nullable::null(),
    };
    let mutation = mutation_of(
        temp,
        Method::SessionCreate,
        ParamsValue::from_typed(&params).expect("encodes"),
    );
    // The supervisor starts nothing, so what the reservation leaves is the launch's failure.
    controller
        .write_method(
            actor_id,
            &mutation,
            Method::SessionCreate,
            connection_id,
            None,
            Some(super::the_fence_at_every_effect::accepted(controller)),
            controller.admitted_revision(connection_id).ok(),
        )
        .await
        .into_answer_for_test();
    mutation
}

/// KR-REQ-09.09, a create meeting the token another request reserved: the registry refuses it as a
/// reused identifier after the wait for the registry, which tells the caller of another attempt's
/// reservation, so it goes back only under the authority the create arrived under, asked once the
/// registry has refused it. The control: with nothing owed the conflict is told. A fence that lands
/// once it is in hand is the answer instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_that_meets_the_token_another_request_reserved_is_not_told_after_a_fence_lands() {
    let temp = kr_ipc::testing::TempHost::create();
    let mut setup = super::a_floor_owed_its_record::setup(&temp);
    setup.supervisor = Box::new(CountingSupervisor::default());
    let controller = Controller::start(setup).await.expect("the daemon starts");
    let (connection_id, actor_id) = admitted(&controller).await;
    let mutation = a_create_another_copy_made(&temp, &controller, connection_id, &actor_id).await;
    let other = another_request_under(&mutation);
    let admission = carried(&controller, connection_id);
    let attempt = async || {
        controller
            .session_create(&actor_id, &other, admission)
            .await
            .into_answer_for_test()
    };

    let told = attempt()
        .await
        .expect_err("with nothing owed the conflict is told");
    assert_eq!(told.code(), ErrorCode::IdConflict, "{told}");

    let refused = answered_after_a_fence_lands_at_the_check(&controller, attempt())
        .await
        .expect_err("a fence that landed once the conflict was in hand is the answer");
    refused_for_a_fence(&refused.to_protocol_error());
}

/// KR-REQ-09.09, a create whose token's reservation cannot be read: the registry's refusal says that
/// an earlier attempt may have made the session, so it goes back only under the authority the create
/// arrived under. The control: with nothing owed the create is told that what became of the action
/// is not known. A fence that lands once that is in hand is the answer instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_whose_reservation_cannot_be_read_is_not_told_after_a_fence_lands() {
    let temp = kr_ipc::testing::TempHost::create();
    let mut setup = super::a_floor_owed_its_record::setup(&temp);
    setup.supervisor = Box::new(CountingSupervisor::default());
    let controller = Controller::start(setup).await.expect("the daemon starts");
    let (connection_id, actor_id) = admitted(&controller).await;
    let mutation = a_create_another_copy_made(&temp, &controller, connection_id, &actor_id).await;
    let admission = carried(&controller, connection_id);
    let attempt = async || {
        controller
            .session_create(&actor_id, &mutation, admission)
            .await
            .into_answer_for_test()
    };
    let registry = rusqlite::Connection::open(temp.environment().registry_database())
        .expect("the registry opens beside the daemon's own handle");
    registry
        .busy_timeout(Duration::from_secs(10))
        .expect("waits for the daemon's own writes");
    registry
        .execute_batch("ALTER TABLE reservations RENAME TO reservations_aside;")
        .expect("the reservations cannot be read");

    let told = attempt()
        .await
        .expect_err("a reservation that cannot be read does not answer the create");
    assert_eq!(told.code(), ErrorCode::OutcomeUnknown, "{told}");

    let refused = answered_after_a_fence_lands_at_the_check(&controller, attempt())
        .await
        .expect_err("a fence that landed once the refusal was in hand is the answer");
    refused_for_a_fence(&refused.to_protocol_error());
    registry
        .execute_batch("ALTER TABLE reservations_aside RENAME TO reservations;")
        .expect("the reservations can be read again");
}

// ---------------------------------------------------------------------------------------------
// The project service
// ---------------------------------------------------------------------------------------------

/// The check a first admission of a project action begins under, as a case supplies it.
type Begin = Box<dyn Fn() -> Result<(), ProtocolError> + Send>;

/// What the project service tells a copy that meets another request's use of its identifier: the
/// control (nothing owed: the conflict), and then, with a fence owed, the fence. `scenario` makes a
/// fresh request each time, with the check its first admission begins under, which is where a case
/// writes the other request's record when the service is to find it later than its own look.
async fn a_conflict_the_project_service_meets_is_told_only_under_its_authority(
    controller: &Arc<Controller>,
    actor_id: &ActorId,
    admission: AdmittedMutation,
    scenario: impl Fn() -> (MutationRequest, Begin),
) {
    let (mutation, begin) = scenario();
    let told = project_answer(controller, actor_id, &mutation, admission, begin)
        .await
        .into_answer_for_test()
        .expect_err("with nothing owed the conflict is told");
    assert_eq!(told.code, ErrorCode::IdConflict, "{told:?}");

    let (mutation, begin) = scenario();
    controller.hold_fence(true);
    let refused = project_answer(controller, actor_id, &mutation, admission, begin)
        .await
        .into_answer_for_test()
        .expect_err("a fence this host owes stops the conflict");
    refused_for_a_fence(&refused);
    controller.hold_fence(false);
}

/// KR-REQ-09.09, the project service's own look finding another request's record under the action's
/// identifier: the look refuses with a conflict before any answer, which tells the caller of another
/// attempt, so it goes back only under the authority the copy arrived under. The fence is set before
/// the call: the look and the check run on a thread that blocks, where no pause stops them, so the
/// case shows that the check runs, not when.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_project_action_that_meets_another_requests_record_is_not_told_while_a_fence_is_owed() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let admission = carried(&controller, connection_id);
    a_conflict_the_project_service_meets_is_told_only_under_its_authority(
        &controller,
        &actor_id,
        admission,
        || {
            let mutation = cancellation(&temp);
            plant_a_project_refusal(&controller, &actor_id, &another_request_under(&mutation));
            (
                mutation,
                Box::new(controller.admission_in_service(admission)),
            )
        },
    )
    .await;
}

/// KR-REQ-09.09, the project service's own look meeting a journal it cannot read: that a record may
/// exist is what the caller would be told, so the look's refusal goes back only under the authority
/// the copy arrived under. The control: with nothing owed the copy is told that what became of the
/// action is not known. The fence is set before the call, as in the cases around it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_project_action_whose_journal_cannot_be_read_is_not_told_while_a_fence_is_owed() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let admission = carried(&controller, connection_id);
    let mutation = cancellation(&temp);
    let journal = rusqlite::Connection::open(
        kr_project::ProjectService::root_of(&controller.paths)
            .join(kr_project::store::STORE_FILE_NAME),
    )
    .expect("the journal opens beside the daemon's own handle");
    journal
        .busy_timeout(Duration::from_secs(10))
        .expect("waits for the daemon's own writes");
    journal
        .execute_batch("ALTER TABLE actions RENAME TO actions_aside;")
        .expect("the journal cannot be read");
    let begin = || controller.admission_in_service(admission);

    let told = project_answer(&controller, &actor_id, &mutation, admission, begin())
        .await
        .into_answer_for_test()
        .expect_err("a journal that cannot be read does not answer the copy");
    assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");

    controller.hold_fence(true);
    let refused = project_answer(&controller, &actor_id, &mutation, admission, begin())
        .await
        .into_answer_for_test()
        .expect_err("a fence this host owes stops what the look refuses with");
    refused_for_a_fence(&refused);
    controller.hold_fence(false);
    journal
        .execute_batch("ALTER TABLE actions_aside RENAME TO actions;")
        .expect("the journal can be read again");
}

/// KR-REQ-09.09, the project service reading what the journal holds once its admission has refused:
/// another request's record, written while the admission was asked, is a conflict that tells the
/// caller of another attempt, so it goes back only under the authority the copy arrived under. The
/// fence is set before the call, as in the case above.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_project_action_whose_admission_refuses_beside_another_requests_record_is_not_told_while_a_fence_is_owed()
 {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let admission = carried(&controller, connection_id);
    a_conflict_the_project_service_meets_is_told_only_under_its_authority(
        &controller,
        &actor_id,
        admission,
        || {
            let mutation = cancellation(&temp);
            let other = another_request_under(&mutation);
            let (controller, actor_id) = (Arc::clone(&controller), actor_id.clone());
            (
                mutation,
                Box::new(move || {
                    plant_a_project_refusal(&controller, &actor_id, &other);
                    Err(a_deadline_that_passed())
                }),
            )
        },
    )
    .await;
}

/// KR-REQ-09.09, the project service reading what the journal holds once its admission has refused,
/// and meeting a journal it cannot read: the look before the admission found no record, and the
/// journal went out of reach while the admission was asked. That a record may exist is what the
/// caller would be told, so what the second look refuses with goes back only under the authority
/// the copy arrived under. The control: with nothing owed the copy is told that what became of the
/// action is not known, as a copy of the record. While this host owes a fence it is refused for the
/// fence, as the refusal of a copy the service withheld. The fence is set before the call, as in
/// the cases around it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_project_action_whose_admission_refuses_beside_a_journal_it_cannot_read_is_not_told_while_a_fence_is_owed()
 {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let admission = carried(&controller, connection_id);
    let mutation = cancellation(&temp);
    let journal_file = kr_project::ProjectService::root_of(&controller.paths)
        .join(kr_project::store::STORE_FILE_NAME);
    let beside_the_journal = || {
        let journal = rusqlite::Connection::open(&journal_file)
            .expect("the journal opens beside the daemon's own handle");
        journal
            .busy_timeout(Duration::from_secs(10))
            .expect("waits for the daemon's own writes");
        journal
    };
    // The admission the first look has passed: it puts the journal out of reach, and refuses.
    let begin = || -> Begin {
        let journal_file = journal_file.clone();
        Box::new(move || {
            let journal = rusqlite::Connection::open(&journal_file)
                .expect("the journal opens beside the daemon's own handle");
            journal
                .busy_timeout(Duration::from_secs(10))
                .expect("waits for the daemon's own writes");
            journal
                .execute_batch("ALTER TABLE actions RENAME TO actions_aside;")
                .expect("the journal cannot be read");
            Err(a_deadline_that_passed())
        })
    };

    let control = project_answer(&controller, &actor_id, &mutation, admission, begin()).await;
    assert!(
        control.is_copied(),
        "a journal that cannot be read says that a record may exist, so it is a copy"
    );
    let told = control
        .into_answer_for_test()
        .expect_err("a journal that cannot be read does not answer the copy");
    assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");
    beside_the_journal()
        .execute_batch("ALTER TABLE actions_aside RENAME TO actions;")
        .expect("the journal can be read again");

    controller.hold_fence(true);
    let refused = project_answer(&controller, &actor_id, &mutation, admission, begin())
        .await
        .into_withheld()
        .expect_err("a fence this host owes stops what the second look refuses with");
    refused_for_a_fence(&refused);
    controller.hold_fence(false);
    beside_the_journal()
        .execute_batch("ALTER TABLE actions_aside RENAME TO actions;")
        .expect("the journal can be read again");
}

// ---------------------------------------------------------------------------------------------
// The change-set service
// ---------------------------------------------------------------------------------------------

/// KR-REQ-09.09, the change-set service's own look meeting a record of actions it cannot read: that
/// a record may exist is what the caller would be told, so what the look refuses with goes back
/// only under the authority the copy arrived under. The control: with nothing owed the copy is
/// told that what became of the action is not known, as a copy of the record. A fence that lands
/// once that is in hand refuses it, as the refusal of a copy the service withheld.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_set_action_whose_records_cannot_be_read_is_not_told_after_a_fence_lands() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let admission = carried(&controller, connection_id);
    let mutation = materialisation(&temp);
    let records = rusqlite::Connection::open(
        kr_changeset::ChangeSetService::root_of(&controller.paths)
            .join(kr_changeset::store::STORE_FILE_NAME),
    )
    .expect("the records open beside the daemon's own handle");
    records
        .busy_timeout(Duration::from_secs(10))
        .expect("waits for the daemon's own writes");
    records
        .execute_batch("ALTER TABLE actions RENAME TO actions_aside;")
        .expect("the records cannot be read");

    let control = changeset_answer(&controller, &actor_id, &mutation, admission).await;
    assert!(
        control.is_copied(),
        "records that cannot be read say that one may exist, so the answer is a copy"
    );
    let told = control
        .into_answer_for_test()
        .expect_err("records that cannot be read do not answer the copy");
    assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");

    let refused = answered_after_a_fence_lands_at_the_check(
        &controller,
        changeset_answer(&controller, &actor_id, &mutation, admission),
    )
    .await
    .into_withheld()
    .expect_err("a fence that landed once the refusal was in hand is the answer");
    refused_for_a_fence(&refused);
    records
        .execute_batch("ALTER TABLE actions_aside RENAME TO actions;")
        .expect("the records can be read again");
}

/// KR-REQ-09.09, the change-set service's own look finding another request's record under the
/// action's identifier: the conflict goes back only under the authority the copy arrived under. The
/// control: with nothing owed the conflict is told. While this host owes a fence it is refused for
/// the fence.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_set_action_that_meets_another_requests_record_is_not_told_while_a_fence_is_owed()
{
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let admission = carried(&controller, connection_id);
    let mutation = materialisation(&temp);
    changeset_answer(&controller, &actor_id, &mutation, admission)
        .await
        .into_answer_for_test()
        .expect_err("a version nobody captured is refused, and the refusal is kept");
    let other = another_request_under(&mutation);

    let told = changeset_answer(&controller, &actor_id, &other, admission)
        .await
        .into_answer_for_test()
        .expect_err("with nothing owed the conflict is told");
    assert_eq!(told.code, ErrorCode::IdConflict, "{told:?}");

    refused_for_the_fence(&controller, async || {
        changeset_answer(&controller, &actor_id, &other, admission)
            .await
            .into_answer_for_test()
    })
    .await;
}

// ---------------------------------------------------------------------------------------------
// The pairing door
// ---------------------------------------------------------------------------------------------

/// KR-REQ-09.09, the pairing door meeting the identifier another request spent: the refusal is no
/// copy of a record, but it tells the caller of another attempt, so it goes back only under the
/// authority the request arrived under. The control: with nothing owed the conflict is told. While
/// this host owes a fence it is refused for the fence. The fence is set before the call: the door's
/// check runs on a thread that blocks, so the case shows that the check runs, not when.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_confirmation_request_that_meets_another_requests_identifier_is_not_told_while_a_fence_is_owed()
 {
    use kr_protocol::confirmation::{ConfirmationSubject, OwnerConfirmationRequestParams};

    use super::an_owner_establishes_the_clock::{Door, distrusting};
    use crate::service::net::owner::Caller;

    let (temp, controller, ..) = distrusting().await;
    controller
        .update_policy(|policy| policy.set_exclusively_managed(true))
        .expect("the host is made exclusively organisation-managed");
    let door = Door::open(&temp, &controller).await;
    let action = ActionId::new(kr_ipc::new_uuid());
    let asking = |exclusive: bool| {
        door.mutation(
            Method::OwnerConfirmationRequest,
            action,
            30_000,
            &OwnerConfirmationRequestParams {
                subject: ConfirmationSubject::SetExclusiveManagement { exclusive },
            },
        )
    };
    let connection_id = door.connection_id();
    let revision = controller.admitted_revision(connection_id).ok();
    let deadline = Some(door.accepted().deadline);
    let attempt = async |request: &MutationRequest| {
        controller
            .pairing_write(
                Caller::local(door.actor_id().clone()),
                Method::OwnerConfirmationRequest,
                request,
                controller.pairing_admission(connection_id, revision, deadline),
                controller.pairing_standing(connection_id, revision),
                controller.pairing_guard(connection_id, revision, deadline),
                controller.pairing_life(deadline),
            )
            .await
    };
    attempt(&asking(false))
        .await
        .into_answer_for_test()
        .expect("the first request is answered");
    let other = asking(true);

    let told = attempt(&other)
        .await
        .into_answer_for_test()
        .expect_err("with nothing owed the conflict is told");
    assert_eq!(told.to_protocol_error().code, ErrorCode::IdConflict);

    controller.hold_fence(true);
    let refused = attempt(&other)
        .await
        .into_answer_for_test()
        .expect_err("a fence this host owes stops the conflict");
    refused_for_a_fence(&refused.to_protocol_error());
    controller.hold_fence(false);
}

// ---------------------------------------------------------------------------------------------
// The local door
// ---------------------------------------------------------------------------------------------

/// `mutation` as the local door performs it once its own look for a record has found none, which is
/// what a copy that is admitted before another copy records reaches.
async fn at_the_local_door(
    controller: &Arc<Controller>,
    connection_id: kr_protocol::ids::ConnectionId,
    actor_id: &ActorId,
    mutation: &MutationRequest,
    method: Method,
) -> kr_protocol::envelope::ControlFrame {
    controller
        .write_method(
            actor_id,
            mutation,
            method,
            connection_id,
            None,
            Some(super::the_fence_at_every_effect::accepted(controller)),
            controller.admitted_revision(connection_id).ok(),
        )
        .await
        .into_answer_for_test()
}

/// What the local door tells a copy that a service read from its record and withheld, whatever the
/// service: not the refusal of the authority, which is a definite word and says the action did not
/// happen, but that what became of the action is not shown, as a paired device is told. The control
/// is told what the record said, and the case compares the two.
fn told_as_not_shown_after(
    control: &kr_protocol::envelope::ControlFrame,
    raced: &kr_protocol::envelope::ControlFrame,
) {
    let control = super::the_fence_at_every_effect::refusal(control)
        .unwrap_or_else(|| panic!("a record that cannot be read does not answer the copy"));
    assert_eq!(control.code, ErrorCode::OutcomeUnknown, "{control:?}");
    let told = super::the_fence_at_every_effect::refusal(raced)
        .unwrap_or_else(|| panic!("a fence this host owes stops the copy: {raced:?}"));
    assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");
    assert_eq!(
        told.message,
        crate::error::ControllerError::outcome_not_shown().to_string(),
        "the caller is told the outcome is not shown, and not the authority's refusal"
    );
    assert_ne!(told.message, control.message);
}

/// KR-REQ-09.09, the local door's answer for a machine group step whose copy the service read from
/// its record and withheld: a refusal kept under a code this build cannot read says that another
/// attempt's record exists, and a fence that lands once it is met stops it. The caller at this
/// machine is told that what became of the action is not shown, as a paired device is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_machine_group_step_a_service_withheld_is_told_at_the_local_door_as_not_shown() {
    use kr_protocol::machine::{MachineExpected, MachineSplitParams};

    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let group = controller
        .machine_report()
        .expect("this daemon serves a machine group record");
    let mutation = mutation_of(
        &temp,
        Method::MachineSplit,
        ParamsValue::from_typed(&MachineSplitParams {
            expected: MachineExpected {
                machine_id: group.machine_id,
                revision: group.revision,
            },
        })
        .expect("encodes"),
    );
    plant_a_refusal_this_build_cannot_read(&temp, &actor_id, &mutation);
    let attempt = || {
        at_the_local_door(
            &controller,
            connection_id,
            &actor_id,
            &mutation,
            Method::MachineSplit,
        )
    };
    let control = attempt().await;
    let raced = answered_after_a_fence_lands_at_the_check(&controller, attempt()).await;
    told_as_not_shown_after(&control, &raced);
}

/// KR-REQ-09.09, the local door's answer for an attention change whose copy the store read from its
/// row and withheld: a row that cannot be decoded says that the action's row exists, and a fence
/// that lands once the store has met it stops it. The caller at this machine is told that what
/// became of the action is not shown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attention_change_a_store_withheld_is_told_at_the_local_door_as_not_shown() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let mutation = setting_quiet_hours(&temp);
    let admission = carried(&controller, connection_id);
    attention_answer(&controller, &actor_id, &mutation, admission)
        .await
        .into_answer_for_test()
        .expect("the window is set");
    let store =
        rusqlite::Connection::open(temp.environment().state_dir().join("attention.sqlite3"))
            .expect("opens the attention store");
    store
        .busy_timeout(Duration::from_secs(10))
        .expect("waits for the daemon's own writes");
    store
        .execute("UPDATE attention_actions SET recorded_at_ms = -1", [])
        .expect("the row cannot be decoded");
    let attempt = || {
        at_the_local_door(
            &controller,
            connection_id,
            &actor_id,
            &mutation,
            Method::AttentionQuietHours,
        )
    };
    let control = attempt().await;
    let raced = answered_after_a_fence_lands_at_the_check(&controller, attempt()).await;
    told_as_not_shown_after(&control, &raced);
}

/// KR-REQ-09.09, the local door's own search of the other stores for the identifier of a first
/// admission: the conflict it finds says that another request spent the identifier, which is
/// another attempt's word, so it goes back only under the authority the arrival still has, asked
/// once the search has found it. The control: with nothing owed the conflict is told. A fence that
/// lands once the arrival is past its look for a record is the answer instead. The fence lands at
/// the pause before the search, so the case shows that the check runs on the conflict, not when.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_identifier_another_method_spent_is_not_told_as_a_conflict_after_a_fence_lands() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let spent = setting_quiet_hours(&temp);
    let first = at_the_local_door(
        &controller,
        connection_id,
        &actor_id,
        &spent,
        Method::AttentionQuietHours,
    )
    .await;
    assert!(
        super::the_fence_at_every_effect::refusal(&first).is_none(),
        "the first method records its action: {first:?}"
    );
    let another = super::a_recorded_answer_another_copy_wrote::capability_request(
        &temp,
        Some(spent.action_id),
        None,
    );
    let attempt = || controller.perform(&actor_id, connection_id, None, another.clone());

    let control = attempt().await;
    let control = super::the_fence_at_every_effect::refusal(&control)
        .unwrap_or_else(|| panic!("an identifier another method spent is a conflict"));
    assert_eq!(control.code, ErrorCode::IdConflict, "{control:?}");

    let raced = answered_after_a_fence_lands_at_the_check(&controller, attempt()).await;
    refused_for_a_fence(
        super::the_fence_at_every_effect::refusal(&raced)
            .unwrap_or_else(|| panic!("a fence this host owes stops the conflict: {raced:?}")),
    );
}
