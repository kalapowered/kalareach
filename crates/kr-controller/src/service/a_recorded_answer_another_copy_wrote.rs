//! What an answer that another copy of an action recorded goes back under.
//!
//! The local door looks for a retained answer before it asks anything of a first admission, and
//! asks the authority check once the answer is in hand. A copy that finds nothing there goes on to
//! the service that performs the action, which looks again, and what another copy recorded in
//! between is found by that look and given back. Section 9 has the host check current authority
//! before any retained answer goes back, so the service's own look is owed the same check: a fence
//! this host owes, or the registration the copy arrived on withdrawn or replaced, stops the record
//! as it stops it at the door.
//!
//! Each case reaches one service as the late copy does, with the record already written by the
//! first copy or planted where the late copy finds it, and asks the service three things: the
//! control (nothing owed, the copy is given the record), a fence owed, and a registration gone.

use std::sync::Arc;
use std::time::Duration;

use kr_protocol::envelope::{MutationRequest, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, ActorId, ConnectionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, U64};

use super::the_fence_at_every_effect::{
    CountingSupervisor, accepted, admitted, another_devices_revocation_lands, carried, daemon,
    mutation_of, refusal, refused_for_a_fence,
};
use crate::authority::AdmittedMutation;
use crate::given::Given;
use crate::service::Controller;

/// The refusal a late copy is given while this host owes a fence it could not raise, asked again
/// once the fence is gone and the control has been shown by the case itself.
pub(super) async fn refused_for_the_fence(
    controller: &Controller,
    late: impl AsyncFn() -> Result<ParamsValue, ProtocolError>,
) {
    controller.hold_fence(true);
    let refused = late()
        .await
        .expect_err("a fence this host owes stops the recorded answer");
    refused_for_a_fence(&refused);
    controller.hold_fence(false);
}

/// The refusal a late copy is given once the registration it arrived on is gone.
async fn refused_for_the_registration(
    controller: &Controller,
    connection_id: ConnectionId,
    late: impl AsyncFn() -> Result<ParamsValue, ProtocolError>,
) {
    controller.admitted_write().remove(&connection_id);
    let refused = late()
        .await
        .expect_err("a registration that is gone stops the recorded answer");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(
        !refused.message.contains("fence"),
        "the refusal is the registration's, and not a fence this host owes: {refused:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// A repeated create
// ---------------------------------------------------------------------------------------------

/// KR-REQ-09.09, the repeated create: a create whose token already holds a reservation, found
/// when the create reaches the registry after the door's own look found none, is given what the
/// reservation leaves only under the authority the create arrived under, asked with it in hand.
/// The control: with nothing owed the repeat is given the answer as one read from the reservation.
/// While this host owes a fence, or once the revision the create was admitted under has been
/// replaced by another device's revocation, it is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeated_create_is_given_what_its_first_attempt_made_only_under_its_authority() {
    use kr_protocol::session::{LaunchProfile, Presentation, SessionCreateParams, ShellMode};

    let temp = kr_ipc::testing::TempHost::create();
    let mut setup = super::a_floor_owed_its_record::setup(&temp);
    setup.supervisor = Box::new(CountingSupervisor::default());
    let controller = Controller::start(setup).await.expect("the daemon starts");
    let (connection_id, actor_id) = admitted(&controller).await;
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
        &temp,
        Method::SessionCreate,
        ParamsValue::from_typed(&params).expect("encodes"),
    );
    // The first copy makes the reservation. The supervisor starts nothing, so what the reservation
    // leaves is the launch's failure.
    let first = controller
        .write_method(
            &actor_id,
            &mutation,
            Method::SessionCreate,
            connection_id,
            None,
            Some(accepted(&controller)),
            controller.admitted_revision(connection_id).ok(),
        )
        .await;
    assert!(
        refusal(&first).is_some_and(|error| error.code != ErrorCode::PermissionDenied),
        "the first copy's launch fails: {first:?}"
    );

    // The late copy reaches the create itself, as one does that began before the reservation was
    // written: nothing in front of it has looked for the token.
    let admission = carried(&controller, connection_id);
    let late = async || {
        controller
            .session_create(&actor_id, &mutation, admission)
            .await
    };
    let control = late().await;
    assert!(
        control.is_copied(),
        "the repeat is read from the reservation"
    );
    let kept = control
        .into_answer()
        .expect_err("what the reservation leaves is the launch's failure");
    assert_ne!(kept.code(), ErrorCode::PermissionDenied, "{kept}");

    controller.hold_fence(true);
    let refused = late()
        .await
        .into_answer()
        .expect_err("a fence this host owes stops the answer");
    refused_for_a_fence(&refused.to_protocol_error());
    controller.hold_fence(false);

    another_devices_revocation_lands(&controller).await;
    let refused = late()
        .await
        .into_answer()
        .expect_err("a revision that has been replaced stops the answer")
        .to_protocol_error();
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert_eq!(
        refused.message,
        crate::authority::AdmissionLapse::Revoked.to_string(),
        "the refusal is the replaced revision's"
    );
}

// ---------------------------------------------------------------------------------------------
// The project service
// ---------------------------------------------------------------------------------------------

/// A cancellation of an operation nobody started, under a fresh action identifier. The service
/// refuses it, and keeps the refusal as the action's answer.
fn cancellation(temp: &kr_ipc::testing::TempHost) -> MutationRequest {
    mutation_of(
        temp,
        Method::ProjectOperationCancel,
        ParamsValue::from_typed(&kr_protocol::project::ProjectOperationCancelParams {
            operation_action_id: ActionId::new(kr_ipc::new_uuid()),
            through_location_id: Nullable::null(),
        })
        .expect("encodes"),
    )
}

/// The project service's answer to `mutation`, asked as the daemon asks it: `begin` is the check a
/// first admission begins under, and the check a recorded answer is owed is the daemon's own.
async fn project_answer(
    controller: &Arc<Controller>,
    actor_id: &ActorId,
    mutation: &MutationRequest,
    admission: AdmittedMutation,
    begin: impl Fn() -> Result<(), ProtocolError> + Send + 'static,
) -> Given<Result<ParamsValue, ProtocolError>> {
    controller
        .project()
        .write(
            actor_id,
            mutation,
            Method::ProjectOperationCancel,
            begin,
            controller.retained_in_service(admission),
            None,
        )
        .await
}

/// The refusal the project service keeps for an action in the cases that plant one.
fn the_planted_refusal() -> kr_project::store::RetainedOutcome {
    kr_project::store::RetainedOutcome::Error {
        code: ErrorCode::InvalidArgument,
        detail: "planted".to_owned(),
    }
}

/// Writes the refusal another copy of `mutation` would have kept, where the project service's own
/// look finds it.
fn plant_a_project_refusal(
    controller: &Controller,
    actor_id: &ActorId,
    mutation: &MutationRequest,
) {
    let digest = kr_protocol::digest::mutation_digest(mutation, actor_id).expect("a digest");
    controller
        .project()
        .service()
        .record_action(
            actor_id,
            mutation.action_id.get(),
            Method::ProjectOperationCancel.as_str(),
            digest,
            &the_planted_refusal(),
        )
        .expect("the record is written");
}

/// What a deadline that has passed refuses a first admission with.
fn a_deadline_that_passed() -> ProtocolError {
    crate::error::ControllerError::WindowExpired {
        detail: "the deadline passed".to_owned(),
    }
    .to_protocol_error()
}

/// KR-REQ-09.09, the project service's first look: an action another copy recorded after the door's
/// own lookup is given back only under the authority the late copy arrived under, asked with the
/// record in hand. The control: with nothing owed the late copy is given the record as a copy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_project_action_recorded_before_a_late_attempts_look_is_not_given_back_while_a_fence_is_owed()
 {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let mutation = cancellation(&temp);
    let admission = carried(&controller, connection_id);
    let first = project_answer(
        &controller,
        &actor_id,
        &mutation,
        admission,
        controller.admission_in_service(admission),
    )
    .await;
    assert!(!first.is_copied(), "the first copy answers for itself");
    let first = first
        .into_answer()
        .expect_err("an operation nobody started is refused");

    let late = async || {
        project_answer(
            &controller,
            &actor_id,
            &mutation,
            admission,
            controller.admission_in_service(admission),
        )
        .await
        .into_answer()
    };
    let control = project_answer(
        &controller,
        &actor_id,
        &mutation,
        admission,
        controller.admission_in_service(admission),
    )
    .await;
    assert!(control.is_copied(), "the late copy reads the record");
    assert_eq!(
        control.into_answer().expect_err("the kept refusal"),
        first,
        "it is given what the first copy was told"
    );

    refused_for_the_fence(&controller, late).await;
    refused_for_the_registration(&controller, connection_id, late).await;
}

/// KR-REQ-09.09, the project service's admission: a copy whose admission refuses (the deadline has
/// passed) while another copy settles the action is given the record the journal then holds only
/// under the authority it arrived under. The control: with nothing owed it is given the record.
/// While this host owes a fence the record is not given back, the fence is the copy's answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_project_action_that_settles_while_its_admission_is_asked_is_not_given_back_while_a_fence_is_owed()
 {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let admission = carried(&controller, connection_id);
    // The record is written while the admission is asked, which refuses: the early look found
    // nothing and the journal holds the record when it is read after the refusal.
    let settling = |mutation: &MutationRequest| {
        let controller = Arc::clone(&controller);
        let (actor_id, mutation) = (actor_id.clone(), mutation.clone());
        move || {
            plant_a_project_refusal(&controller, &actor_id, &mutation);
            Err(a_deadline_that_passed())
        }
    };

    let mutation = cancellation(&temp);
    let control = project_answer(
        &controller,
        &actor_id,
        &mutation,
        admission,
        settling(&mutation),
    )
    .await;
    assert!(control.is_copied(), "the copy is given the settled record");
    assert_eq!(
        control
            .into_answer()
            .expect_err("the planted refusal")
            .message,
        "planted"
    );

    let mutation = cancellation(&temp);
    controller.hold_fence(true);
    let refused = project_answer(
        &controller,
        &actor_id,
        &mutation,
        admission,
        settling(&mutation),
    )
    .await
    .into_answer()
    .expect_err("a fence this host owes stops the record the journal then holds");
    refused_for_a_fence(&refused);
    controller.hold_fence(false);

    let mutation = cancellation(&temp);
    controller.admitted_write().remove(&connection_id);
    let refused = project_answer(
        &controller,
        &actor_id,
        &mutation,
        admission,
        settling(&mutation),
    )
    .await
    .into_answer()
    .expect_err("a registration that is gone stops it");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert_ne!(refused.message, "planted");
}

/// KR-REQ-09.09, a claim that is not settled: a copy whose admission refuses while the journal
/// holds a claim for its action with no outcome is told that what became of the action is not known
/// only under the authority it arrived under. The control: with nothing owed it is told so. While
/// this host owes a fence it is refused for the fence, and told nothing of the claim.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_project_action_whose_claim_is_open_is_not_told_while_a_fence_is_owed() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let admission = carried(&controller, connection_id);
    let store_path = kr_project::ProjectService::root_of(&controller.paths)
        .join(kr_project::store::STORE_FILE_NAME);
    let claiming = |mutation: &MutationRequest| {
        let store_path = store_path.clone();
        let (actor_id, mutation) = (actor_id.clone(), mutation.clone());
        move || {
            let digest =
                kr_protocol::digest::mutation_digest(&mutation, &actor_id).expect("a digest");
            let store = rusqlite::Connection::open(&store_path).expect("the store opens");
            store
                .busy_timeout(Duration::from_secs(10))
                .expect("waits for the daemon's own writes");
            store
                .execute(
                    "INSERT INTO actions (actor_id, action_id, method, payload_digest, subject,
                                          result, error_code, error_detail, recorded_at_ms)
                     VALUES (?1, ?2, ?3, ?4, NULL, NULL, NULL, NULL, 1)",
                    rusqlite::params![
                        actor_id.as_str(),
                        mutation.action_id.get().as_bytes().to_vec(),
                        Method::ProjectOperationCancel.as_str(),
                        digest.as_bytes().to_vec(),
                    ],
                )
                .expect("the claim is written");
            Err(a_deadline_that_passed())
        }
    };

    let mutation = cancellation(&temp);
    let control = project_answer(
        &controller,
        &actor_id,
        &mutation,
        admission,
        claiming(&mutation),
    )
    .await
    .into_answer()
    .expect_err("what became of the action is not known");
    assert_eq!(control.code, ErrorCode::OutcomeUnknown, "{control:?}");

    let mutation = cancellation(&temp);
    controller.hold_fence(true);
    let refused = project_answer(
        &controller,
        &actor_id,
        &mutation,
        admission,
        claiming(&mutation),
    )
    .await
    .into_answer()
    .expect_err("a fence this host owes is the answer");
    refused_for_a_fence(&refused);
    controller.hold_fence(false);
}

/// KR-REQ-09.09, the answer another copy recorded while this one performed: an attempt that finds
/// the action recorded when it comes to record its own answer (and wrote no claim) is given the
/// record only under the authority it arrived under. The record is written while the admission is
/// asked, which passes. The control: with nothing owed the attempt is given it as a copy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_project_action_another_copy_recorded_while_it_ran_is_not_given_back_while_a_fence_is_owed()
 {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let admission = carried(&controller, connection_id);
    let racing = |mutation: &MutationRequest| {
        let controller = Arc::clone(&controller);
        let (actor_id, mutation) = (actor_id.clone(), mutation.clone());
        move || {
            plant_a_project_refusal(&controller, &actor_id, &mutation);
            Ok(())
        }
    };

    let mutation = cancellation(&temp);
    let control = project_answer(
        &controller,
        &actor_id,
        &mutation,
        admission,
        racing(&mutation),
    )
    .await;
    assert!(
        control.is_copied(),
        "the attempt is given the record another copy wrote"
    );
    assert_eq!(
        control
            .into_answer()
            .expect_err("the planted refusal")
            .message,
        "planted"
    );

    let mutation = cancellation(&temp);
    controller.hold_fence(true);
    let refused = project_answer(
        &controller,
        &actor_id,
        &mutation,
        admission,
        racing(&mutation),
    )
    .await
    .into_answer()
    .expect_err("a fence this host owes stops the record");
    refused_for_a_fence(&refused);
    controller.hold_fence(false);
}

/// KR-REQ-09.09, a record that cannot be written: an attempt whose own record is refused by the
/// store reads the record another copy wrote, and is given it only under the authority it arrived
/// under. The control: with nothing owed the attempt is given it as a copy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_project_action_whose_record_cannot_be_written_is_given_the_other_copys_only_under_its_authority()
 {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let admission = carried(&controller, connection_id);
    let store_path = kr_project::ProjectService::root_of(&controller.paths)
        .join(kr_project::store::STORE_FILE_NAME);
    let store = rusqlite::Connection::open(&store_path).expect("the store opens");
    store
        .busy_timeout(Duration::from_secs(10))
        .expect("waits for the daemon's own writes");
    // The store keeps no refusal but the planted one, so the attempt's own cannot be written.
    store
        .execute_batch(
            "CREATE TRIGGER only_the_planted_refusal_is_kept BEFORE INSERT ON actions
             WHEN NEW.error_detail IS NOT 'planted'
             BEGIN SELECT RAISE(ABORT, 'the store keeps no other refusal'); END;",
        )
        .expect("the store is made to refuse the attempt's own record");
    let racing = |mutation: &MutationRequest| {
        let controller = Arc::clone(&controller);
        let (actor_id, mutation) = (actor_id.clone(), mutation.clone());
        move || {
            plant_a_project_refusal(&controller, &actor_id, &mutation);
            Ok(())
        }
    };

    let mutation = cancellation(&temp);
    let control = project_answer(
        &controller,
        &actor_id,
        &mutation,
        admission,
        racing(&mutation),
    )
    .await;
    assert!(
        control.is_copied(),
        "the attempt reads the record another copy wrote"
    );
    assert_eq!(
        control
            .into_answer()
            .expect_err("the planted refusal")
            .message,
        "planted"
    );

    let mutation = cancellation(&temp);
    controller.hold_fence(true);
    let refused = project_answer(
        &controller,
        &actor_id,
        &mutation,
        admission,
        racing(&mutation),
    )
    .await
    .into_answer()
    .expect_err("a fence this host owes stops the record");
    refused_for_a_fence(&refused);
    controller.hold_fence(false);
    store
        .execute_batch("DROP TRIGGER only_the_planted_refusal_is_kept;")
        .expect("the store is whole again");
}

// ---------------------------------------------------------------------------------------------
// The change-set service
// ---------------------------------------------------------------------------------------------

/// A materialisation of a version nobody captured, under a fresh action identifier. The service
/// refuses it, and keeps the refusal as the action's answer.
fn materialisation(temp: &kr_ipc::testing::TempHost) -> MutationRequest {
    mutation_of(
        temp,
        Method::ChangesetMaterialize,
        ParamsValue::from_typed(&kr_protocol::changeset::ChangesetMaterializeParams {
            change_set_id: kr_protocol::ids::ChangeSetId::new(
                kr_protocol::scalars::Uuid::from_bytes([0x6d; 16]),
            ),
            version: kr_protocol::ids::ChangeSetVersion::new(1),
            purpose: kr_protocol::changeset::MaterialisationPurpose::Test,
            label: "a version nobody captured".to_owned(),
        })
        .expect("encodes"),
    )
}

async fn changeset_answer(
    controller: &Arc<Controller>,
    actor_id: &ActorId,
    mutation: &MutationRequest,
    admission: AdmittedMutation,
) -> Given<Result<ParamsValue, ProtocolError>> {
    controller
        .changesets()
        .write(
            actor_id,
            mutation,
            Method::ChangesetMaterialize,
            admission,
            Arc::clone(controller),
            None,
        )
        .await
}

/// KR-REQ-09.09, the change-set service's first look: an action another copy recorded after the
/// door's own lookup is given back only under the authority the late copy arrived under, asked with
/// the record in hand. The control: with nothing owed the late copy is given the record as a copy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_set_action_recorded_before_a_late_attempts_look_is_not_given_back_while_a_fence_is_owed()
 {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let mutation = materialisation(&temp);
    let admission = carried(&controller, connection_id);
    let first = changeset_answer(&controller, &actor_id, &mutation, admission).await;
    assert!(!first.is_copied(), "the first copy answers for itself");
    let first = first
        .into_answer()
        .expect_err("a version nobody captured is refused");

    let late = async || {
        changeset_answer(&controller, &actor_id, &mutation, admission)
            .await
            .into_answer()
    };
    let control = changeset_answer(&controller, &actor_id, &mutation, admission).await;
    assert!(control.is_copied(), "the late copy reads the record");
    assert_eq!(
        control.into_answer().expect_err("the kept refusal"),
        first,
        "it is given what the first copy was told"
    );

    refused_for_the_fence(&controller, late).await;
    refused_for_the_registration(&controller, connection_id, late).await;
}

/// KR-REQ-09.09, the change-set service's claim: a copy that meets a claim another copy holds, with
/// nothing recorded yet, is told that what became of the action is not known only under the
/// authority it arrived under, asked with the answer in hand. A fence that lands once the copy has
/// the answer stops it. The control: with nothing owed the copy is told so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_set_action_whose_claim_another_copy_holds_is_not_told_after_a_fence_lands() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let admission = carried(&controller, connection_id);
    let claimed_by_another_copy = |mutation: &MutationRequest| {
        let digest = kr_protocol::digest::mutation_digest(mutation, &actor_id).expect("a digest");
        assert!(
            controller
                .changesets()
                .service()
                .claim_action(
                    &actor_id,
                    mutation.action_id.get(),
                    Method::ChangesetMaterialize.as_str(),
                    digest,
                    None,
                )
                .expect("the claim is written"),
            "the first claim of an action is the one that makes it"
        );
    };

    let mutation = materialisation(&temp);
    claimed_by_another_copy(&mutation);
    let control = changeset_answer(&controller, &actor_id, &mutation, admission).await;
    assert!(control.is_copied(), "the copy meets the other copy's claim");
    assert_eq!(
        control
            .into_answer()
            .expect_err("what became of the action is not known")
            .code,
        ErrorCode::OutcomeUnknown
    );

    // The copy has met the claim and read the answer when the fence lands.
    let mutation = materialisation(&temp);
    claimed_by_another_copy(&mutation);
    let (arrived, release) = controller.pause_retained_lookup();
    let mut late = tokio::spawn({
        let (controller, actor_id, mutation) =
            (Arc::clone(&controller), actor_id.clone(), mutation.clone());
        async move {
            changeset_answer(&controller, &actor_id, &mutation, admission)
                .await
                .into_answer()
        }
    });
    tokio::select! {
        reached = tokio::time::timeout(Duration::from_secs(30), arrived) => {
            reached
                .expect("the copy reaches the place it is stopped at")
                .expect("the pause is armed");
        }
        answered = &mut late => panic!(
            "the copy was answered without the check being asked with the answer in hand: \
             {answered:?}"
        ),
    }
    controller.hold_fence(true);
    release.send(()).expect("the copy goes on");
    let refused = late
        .await
        .expect("the copy finishes")
        .expect_err("a fence that landed once the copy had the answer stops it");
    refused_for_a_fence(&refused);
    controller.hold_fence(false);
}

// ---------------------------------------------------------------------------------------------
// The catalogue
// ---------------------------------------------------------------------------------------------

/// An admission that lets a fence land once its first check has passed, and asks the daemon's own
/// check otherwise.
struct FenceAfterTheFirstCheck {
    inner: crate::catalogue::DaemonAdmission,
    controller: Arc<Controller>,
    landing: std::sync::atomic::AtomicBool,
}

impl kr_plugin_catalogue::Authority for FenceAfterTheFirstCheck {
    fn check(&self) -> kr_plugin_catalogue::CatalogueResult<()> {
        let checked = self.inner.check();
        if self
            .landing
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            self.controller.hold_fence(true);
        }
        checked
    }

    fn commit(
        &self,
        effect: &kr_plugin_catalogue::Effect,
        commit: &mut dyn FnMut() -> kr_plugin_catalogue::CatalogueResult<()>,
    ) -> kr_plugin_catalogue::CatalogueResult<()> {
        self.inner.commit(effect, commit)
    }

    fn owner_confirmed(&self) -> bool {
        self.inner.owner_confirmed()
    }
}

impl crate::catalogue::Admission for FenceAfterTheFirstCheck {
    fn accepted_deadline_ms(&self) -> Option<u64> {
        self.inner.accepted_deadline_ms()
    }

    fn check_retained(&self) -> kr_plugin_catalogue::CatalogueResult<()> {
        self.inner.check_retained()
    }
}

/// KR-REQ-09.09, the catalogue's claim: a receipt another copy kept, found by the claim once the
/// early check has passed, is given back only under the authority the late copy arrived under,
/// asked with the receipt in hand. The control: with nothing owed the late copy is given the
/// receipt as a copy. A fence that lands once the early check has passed stops it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_catalogue_receipt_kept_before_a_late_attempts_claim_is_not_given_back_after_a_fence_lands()
 {
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
        let admission: Arc<dyn crate::catalogue::Admission> = Arc::new(FenceAfterTheFirstCheck {
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
    let first = attempt(false).await;
    assert!(!first.is_copied(), "the first copy answers for itself");
    let first = first
        .into_answer()
        .expect_err("a catalogue nobody enrolled is refused");
    assert_ne!(first.code, ErrorCode::PermissionDenied, "{first:?}");

    let control = attempt(false).await;
    assert!(control.is_copied(), "the late copy reads the receipt");
    assert_eq!(
        control.into_answer().expect_err("the kept refusal"),
        first,
        "it is given what the first copy was told"
    );

    let refused = attempt(true)
        .await
        .into_answer()
        .expect_err("a fence that landed after the early check stops the receipt");
    refused_for_a_fence(&refused);
    controller.hold_fence(false);
}

// ---------------------------------------------------------------------------------------------
// The attention store
// ---------------------------------------------------------------------------------------------

/// KR-REQ-09.09, the attention store's record: an action another copy recorded, returned by the
/// store before it asks the admission, is given back only under the authority the late copy arrived
/// under, asked with the record in hand. The control: with nothing owed the late copy is given the
/// record as a copy. A fence that lands once the entry check has passed and the late copy is at the
/// store stops it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attention_action_recorded_before_a_late_attempts_look_is_not_given_back_after_a_fence_lands()
 {
    use kr_protocol::attention::{AttentionQuietHoursParams, QuietHours};

    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let mutation = mutation_of(
        &temp,
        Method::AttentionQuietHours,
        ParamsValue::from_typed(&AttentionQuietHoursParams {
            quiet_hours: Nullable::some(QuietHours {
                start_minute: U64::new(22 * 60),
                end_minute: U64::new(7 * 60),
                zone: Nullable::null(),
            }),
        })
        .expect("encodes"),
    );
    let admission = carried(&controller, connection_id);
    let attempt = || {
        controller.attention().write(
            &controller,
            &crate::attention::Caller::Owner,
            &actor_id,
            &mutation,
            Method::AttentionQuietHours,
            &admission,
        )
    };
    let first = attempt().await;
    assert!(!first.is_copied(), "the first copy answers for itself");
    let first = first.into_answer().expect("the window is set");

    let control = attempt().await;
    assert!(control.is_copied(), "the late copy reads the record");
    assert_eq!(
        control.into_answer().expect("the record's answer"),
        first,
        "it is given what the first copy was told"
    );

    // The late copy has passed the entry check and is at the store when the fence lands.
    let (arrived, release) = controller.attention().pause_before_store();
    let mut late = tokio::spawn({
        let (controller, actor_id, mutation) =
            (Arc::clone(&controller), actor_id.clone(), mutation.clone());
        async move {
            controller
                .attention()
                .write(
                    &controller,
                    &crate::attention::Caller::Owner,
                    &actor_id,
                    &mutation,
                    Method::AttentionQuietHours,
                    &admission,
                )
                .await
                .into_answer()
        }
    });
    let reached =
        tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(30)));
    tokio::select! {
        reached = reached => {
            reached
                .expect("the wait finishes")
                .expect("the late copy reaches the place it is stopped at");
        }
        answered = &mut late => panic!("the late copy was answered before the store: {answered:?}"),
    }
    controller.hold_fence(true);
    release.send(()).expect("the late copy goes on");
    let refused = late
        .await
        .expect("the late copy finishes")
        .expect_err("a fence that landed at the store stops the record it returns");
    refused_for_a_fence(&refused);
    controller.hold_fence(false);
}

// ---------------------------------------------------------------------------------------------
// The automation journal
// ---------------------------------------------------------------------------------------------

/// KR-REQ-09.09, the automation journal's record: a workflow install that another copy of its
/// action recorded is read back by the journal, inside its own transaction and without asking the
/// admission, and is given to the late copy only under the authority it arrived under, asked once
/// the journal has answered. The late copy passes the daemon's own check and is stopped before the
/// journal's transaction, where a fence lands. The control: with nothing owed the late copy is
/// given what the first was told, as a copy of the record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_automation_action_another_copy_recorded_is_not_given_back_after_a_fence_lands() {
    use kr_protocol::automation::{
        WorkflowActionKind, WorkflowDeadlines, WorkflowDefinition, WorkflowInstallParams,
        WorkflowNode, WorkflowResourceScope, WorkflowTrigger,
    };
    use kr_protocol::grant::{
        EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector,
    };
    use kr_protocol::ids::{GrantId, WorkflowId};
    use kr_protocol::rights::ActionRight;
    use kr_protocol::scalars::{CanonicalSet, Uuid};

    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;

    // The grant the workflow acts under, with every right its node needs, as a person sharing a
    // session would have issued it.
    let device_id = kr_protocol::ids::DeviceId::new(temp.environment_id().get());
    let grant = Grant {
        grant_id: GrantId::new(Uuid::from_bytes([19; 16])),
        parent_grant_id: Nullable::null(),
        issuer_device_id: device_id,
        recipient_device_id: device_id,
        authority_revision: controller.policy().authority_revision(),
        environment_selector: EnvironmentSelector::Any,
        session_selector: SessionSelector::Any,
        actions: [
            ActionRight::AutomationManage,
            ActionRight::TerminalInput,
            ActionRight::SessionCreate,
            ActionRight::SessionClose,
            ActionRight::WorkspaceManage,
        ]
        .into_iter()
        .collect(),
        history: HistoryScope {
            lower_bound_ms: Nullable::null(),
            include_live_screen: false,
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
        },
        expiry: GrantExpiry::Never,
        organisation: Nullable::null(),
    };
    controller
        .sharing()
        .grants()
        .issue(
            &crate::grants::GrantRecord {
                grant: grant.clone(),
                session_id: None,
                issued_at_ms: 1_000,
                activated_at_ms: Some(1_000),
                revoked_at_ms: None,
                revoked_by_parent: None,
            },
            || Ok(()),
        )
        .expect("the grant is written");

    let definition = WorkflowDefinition {
        workflow_id: WorkflowId::new(Uuid::from_bytes([43; 16])),
        revision: U64::new(1),
        name: "recorded by another copy".to_owned(),
        description: Nullable::null(),
        trigger: WorkflowTrigger {
            event_type: "manual".to_owned(),
        },
        resource_scope: WorkflowResourceScope::default(),
        nodes: vec![WorkflowNode {
            node_id: "tests".to_owned(),
            action_kind: WorkflowActionKind::RunTests,
            action_params: serde_json::to_string(&kr_protocol::automation::RunTestsParams {
                suite: "unit".to_owned(),
                version: kr_protocol::changeset::VersionRef {
                    change_set_id: kr_protocol::ids::ChangeSetId::new(Uuid::from_bytes([0x5d; 16])),
                    version: kr_protocol::ids::ChangeSetVersion::new(1),
                },
            })
            .expect("a test node's typed parameters"),
            declared_environment: Nullable::null(),
        }],
        edges: Vec::new(),
        deadlines: WorkflowDeadlines::default(),
        grant_reference: grant.grant_id,
        enabled: false,
        explicit_recurrence: false,
    };
    let mutation = mutation_of(
        &temp,
        Method::WorkflowInstall,
        ParamsValue::from_typed(&WorkflowInstallParams {
            workflow_id: definition.workflow_id,
            revision: definition.revision,
            definition: definition.clone(),
            grant_reference: definition.grant_reference,
        })
        .expect("encodes"),
    );
    let admission = carried(&controller, connection_id);
    let attempt = || {
        controller.automation_mutation(
            &actor_id,
            &mutation,
            Method::WorkflowInstall,
            admission,
            None,
        )
    };
    let first = attempt().await;
    assert!(!first.is_copied(), "the first copy answers for itself");
    let first = first.into_answer().expect("the first copy installs it");

    let control = attempt().await;
    assert!(control.is_copied(), "the late copy reads the record");
    assert_eq!(
        control.into_answer().expect("the record's answer"),
        first,
        "it is given what the first copy was told"
    );

    // The late copy has passed the daemon's own check and is stopped before the journal when the
    // fence lands.
    let (arrived, release) = controller.pause_after_the_automation_admission();
    let mut late = tokio::spawn({
        let (controller, actor_id, mutation) =
            (Arc::clone(&controller), actor_id.clone(), mutation.clone());
        async move {
            controller
                .automation_mutation(
                    &actor_id,
                    &mutation,
                    Method::WorkflowInstall,
                    admission,
                    None,
                )
                .await
                .into_answer()
        }
    });
    tokio::select! {
        reached = tokio::time::timeout(Duration::from_secs(30), arrived) => {
            reached
                .expect("the late copy reaches the place it is stopped at")
                .expect("the pause is armed");
        }
        answered = &mut late => panic!("the late copy was answered before the journal: {answered:?}"),
    }
    controller.hold_fence(true);
    release.send(()).expect("the late copy goes on");
    let refused = late
        .await
        .expect("the late copy finishes")
        .expect_err("a fence that landed before the journal stops the record it gives back");
    refused_for_a_fence(&refused);
    controller.hold_fence(false);
}

// ---------------------------------------------------------------------------------------------
// The pairing door
// ---------------------------------------------------------------------------------------------

/// KR-REQ-09.09, a retained confirmation request: the challenge another copy of a request was
/// given, found by the owner's own look after the door's, is given back only under the authority
/// the late copy arrived under. The control: with nothing owed the repeat is given the challenge
/// as a copy. While this host owes a fence, or once the registration is gone, it is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_confirmation_request_another_copy_was_given_is_not_given_back_while_a_fence_is_owed() {
    use kr_protocol::confirmation::{ConfirmationSubject, OwnerConfirmationRequestParams};

    use super::an_owner_establishes_the_clock::{Door, distrusting};
    use crate::service::net::owner::Caller;

    let (temp, controller, ..) = distrusting().await;
    controller
        .update_policy(|policy| policy.set_exclusively_managed(true))
        .expect("the host is made exclusively organisation-managed");
    let door = Door::open(&temp, &controller).await;
    let request = door.mutation(
        Method::OwnerConfirmationRequest,
        ActionId::new(kr_ipc::new_uuid()),
        30_000,
        &OwnerConfirmationRequestParams {
            subject: ConfirmationSubject::SetExclusiveManagement { exclusive: false },
        },
    );
    let connection_id = door.connection_id();
    let revision = controller.admitted_revision(connection_id).ok();
    let deadline = Some(door.accepted().deadline);
    let attempt = async || {
        controller
            .pairing_write(
                Caller::local(door.actor_id().clone()),
                Method::OwnerConfirmationRequest,
                &request,
                controller.pairing_admission(connection_id, revision, deadline),
                controller.pairing_standing(connection_id, revision),
                controller.pairing_guard(connection_id, revision, deadline),
                controller.pairing_life(deadline),
            )
            .await
    };
    let first = attempt().await;
    assert!(!first.is_copied(), "the first copy answers for itself");
    let first = first.into_answer().expect("the first request is answered");

    let control = attempt().await;
    assert!(control.is_copied(), "the repeat reads the record");
    assert_eq!(
        control.into_answer().expect("the repeat is answered"),
        first,
        "with the challenge the first was given"
    );

    let late = async || {
        attempt()
            .await
            .into_answer()
            .map_err(|error| error.to_protocol_error())
    };
    refused_for_the_fence(&controller, late).await;
    refused_for_the_registration(&controller, connection_id, late).await;
}
