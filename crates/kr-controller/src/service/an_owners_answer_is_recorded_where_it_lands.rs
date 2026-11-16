//! Where an owner's answer to a confirmation lands.
//!
//! The record of the answer is written in one transaction. After the lookup it reads the signer's
//! standing from the rows of that transaction and verifies the confirmation again; it asks the
//! authority feed where that takes its locks, copies the bound of the local owner's lease, and asks
//! the footing's one question with the copy; where the bound ended or moved, the challenge's display
//! is decided again under the scope that no lease serves; the feed is asked once more with no lock;
//! and the record is written with nothing allocated or awaited between the question and the write.
//!
//! Each case stops the record at a wait and ends what it ends there: before the transaction begins,
//! which stands for the wait for the pairing records' write lock, or in the last wait, after the
//! feed was asked and before the bound is copied.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use kr_crypto::keys::AuthorisationKeyPair;
use kr_pairing::confirm::sign_confirmation;
use kr_protocol::confirmation::{
    ConfirmationDisplay, OwnerConfirmationCompleteParams, OwnerConfirmationCompleteResult,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, ActorId};
use kr_protocol::pairing::{ConfirmationChannel, SensitiveAction};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Digest256, Nullable};

use super::a_result_the_lease_ended_over::{
    Presenter, connected_under_a_lease_that_can_be_presented_again,
};
use super::an_owner_establishes_the_clock::{Door, paired, registry};
use crate::error::ControllerError;
use crate::service::Controller;
use crate::service::net::owner::{Caller, Resolved};

/// The host a case runs on.
#[derive(Clone, Copy, Debug)]
enum World {
    /// A host with no owner and no lease, on clocks the case moves.
    Plain,
    /// A host whose local owner holds a lease.
    Leased,
}

/// What ends where the record is stopped.
#[derive(Clone, Copy, Debug)]
enum Ends {
    /// Nothing: the control.
    Nothing,
    /// The lease's time passes in the last wait, inside the transaction.
    TheLeasesTime,
    /// The lease is presented again in the wait for the write lock, before the transaction.
    TheLeaseIsPresentedAgain,
    /// An owner is established in the wait for the write lock, which ends the terminal's standing.
    AnOwnerIsEstablished,
    /// The challenge's time passes in the last wait, inside the transaction: the pairing clock's
    /// wall reading moves past its expiry.
    TheChallengeExpires,
}

struct Found {
    answered: Result<OwnerConfirmationCompleteResult, ControllerError>,
    confirmation: kr_protocol::ids::ConfirmationId,
    copied: bool,
    answers: i64,
    actions: i64,
}

fn making_exclusive() -> ConfirmationDisplay {
    ConfirmationDisplay::ExclusiveManagement {
        exclusive: true,
        organisation_ids: Vec::new(),
    }
}

fn closed_refusal() -> String {
    Caller::local(ActorId::new("local:test").expect("a principal"))
        .confirming_recovery_only(true)
        .refusal_to_confirm()
        .to_string()
}

struct Parts {
    temp: kr_ipc::testing::TempHost,
    controller: Arc<Controller>,
    continuous: kr_transport::clock::ManualClock,
    presenter: Option<Presenter>,
}

async fn parts(world: World) -> Parts {
    match world {
        World::Plain => {
            let temp = kr_ipc::testing::TempHost::create();
            let (continuous, _wall, clocks) = crate::service::net::tests::manual_clocks();
            let controller = crate::service::net::tests::daemon_on(&temp, clocks).await;
            Parts {
                temp,
                controller,
                continuous,
                presenter: None,
            }
        }
        World::Leased => {
            let (temp, controller, continuous, presenter, _writer, _reader) =
                connected_under_a_lease_that_can_be_presented_again().await;
            Parts {
                temp,
                controller,
                continuous,
                presenter: Some(presenter),
            }
        }
    }
}

fn count(temp: &kr_ipc::testing::TempHost, sql: &str, id: &[u8]) -> i64 {
    registry(temp)
        .query_row(sql, [id], |row| row.get::<_, i64>(0))
        .expect("the records are read")
}

/// Asks for a challenge that the terminal can answer, then answers it, stopping the record of the
/// answer where `ends` says and ending what it names there. `landed` says whether the caller of the
/// answer carries a landing.
async fn answered_with(
    world: World,
    ends: Ends,
    display: ConfirmationDisplay,
    landed: bool,
) -> Found {
    let parts = parts(world).await;
    let controller = &parts.controller;
    let door = Door::open(&parts.temp, controller).await;
    let revision = controller.admitted_revision(door.connection_id()).ok();
    // A deadline an hour away, so that what a case ends is not the deadline.
    let deadline = controller
        .clock
        .now()
        .checked_add(Duration::from_secs(3600))
        .expect("a deadline");
    let landing = || controller.pairing_landing(door.connection_id(), revision, Some(deadline));
    let owner = Arc::clone(controller.owner_authority());
    let challenge = {
        let owner = Arc::clone(&owner);
        let caller = controller.local_caller(door.actor_id()).landed(landing());
        tokio::task::spawn_blocking(move || {
            owner.request(
                &caller,
                Resolved {
                    action: SensitiveAction::ChangeHostAuthority,
                    digest: Digest256::from_bytes([7; 32]),
                    destination: None,
                    rights: CanonicalSet::new(),
                    display,
                    bootstrap: true,
                },
                (
                    ActionId::new(kr_ipc::new_uuid()),
                    Digest256::from_bytes([8; 32]),
                ),
                &AtomicBool::new(false),
            )
        })
        .await
        .expect("the request ends")
        .expect("the terminal is asked")
    };
    let key = AuthorisationKeyPair::generate().expect("a key");
    let params = OwnerConfirmationCompleteParams {
        proof: sign_confirmation(
            &key,
            &challenge.request,
            ConfirmationChannel::LocalBootstrapTerminal,
        )
        .expect("a proof"),
        bootstrap_signer: Nullable::some(*key.public()),
    };
    let confirmation = challenge.request.confirmation_id;
    let action = (
        ActionId::new(kr_ipc::new_uuid()),
        Digest256::from_bytes([9; 32]),
    );
    let caller = controller.local_caller(door.actor_id());
    let caller = if landed {
        caller.landed(landing())
    } else {
        caller
    };
    let (arrived, go) = match ends {
        Ends::Nothing | Ends::TheLeasesTime | Ends::TheChallengeExpires => {
            controller.pause_after_the_record_asks_the_feed()
        }
        Ends::TheLeaseIsPresentedAgain | Ends::AnOwnerIsEstablished => {
            controller.pause_before_the_record_begins()
        }
    };
    let answering = tokio::task::spawn_blocking({
        let owner = Arc::clone(&owner);
        move || {
            let copied = AtomicBool::new(false);
            let answered = owner.complete(&caller, &params, action, &copied);
            (answered, copied.load(Ordering::Acquire))
        }
    });
    if landed {
        tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(30)))
            .await
            .expect("the wait ends")
            .expect("the record reaches the place it is stopped at");
        match ends {
            Ends::Nothing => {}
            Ends::TheLeasesTime => parts.continuous.advance(Duration::from_secs(16 * 60)),
            Ends::TheChallengeExpires => controller
                .owner_authority()
                .pass_the_wall(Duration::from_secs(3 * 60)),
            Ends::TheLeaseIsPresentedAgain => parts
                .presenter
                .as_ref()
                .expect("a leased host")
                .present(&[ActionRight::FilesRead]),
            Ends::AnOwnerIsEstablished => {
                registry(&parts.temp)
                    .execute(
                        "INSERT INTO host_owner (id, how, established_at_ms) VALUES (0, 'test', 0)",
                        [],
                    )
                    .expect("an owner is established");
            }
        }
        go.send(()).expect("the record goes on");
    }
    let (answered, copied) = answering.await.expect("the answer ends");
    Found {
        answered,
        confirmation,
        copied,
        answers: count(
            &parts.temp,
            "SELECT COUNT(*) FROM owner_confirmations WHERE confirmation_id = ?1",
            confirmation.get().as_bytes().as_slice(),
        ),
        actions: count(
            &parts.temp,
            "SELECT COUNT(*) FROM pairing_actions WHERE action_id = ?1",
            action.0.get().as_bytes().as_slice(),
        ),
    }
}

fn recorded(found: &Found) {
    let answered = found.answered.as_ref().expect("the answer is accepted");
    assert_eq!(answered.confirmation_id, found.confirmation);
    assert_eq!(
        answered.channel,
        ConfirmationChannel::LocalBootstrapTerminal
    );
    assert!(!found.copied, "the answer was recorded here, not copied");
    assert_eq!(found.answers, 1, "the acceptance is recorded once");
    assert_eq!(found.actions, 1, "the action is recorded once");
}

fn refused(found: &Found) -> &ControllerError {
    assert_eq!(found.answers, 0, "no acceptance is recorded");
    assert_eq!(found.actions, 0, "no action is recorded");
    found.answered.as_ref().expect_err("the answer is refused")
}

/// KR-REQ-17.54: where the bound of the lease stands, the answer is recorded, for a challenge that
/// the recovery set holds and for one it does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_whose_lease_stands_at_its_question_is_recorded() {
    let establishing = ConfirmationDisplay::EstablishClock;
    recorded(&answered_with(World::Leased, Ends::Nothing, establishing, true).await);
    recorded(&answered_with(World::Leased, Ends::Nothing, making_exclusive(), true).await);
}

/// KR-REQ-17.54: a lease that ends in the last wait is found by the question, and the challenge's
/// display is decided again under the scope that no lease serves: the confirmation of the clock is
/// recorded, and the one the recovery set does not hold is refused in the door's own words.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_whose_lease_ends_in_the_last_wait_is_decided_again_under_the_closed_scope() {
    let establishing = ConfirmationDisplay::EstablishClock;
    recorded(&answered_with(World::Leased, Ends::TheLeasesTime, establishing, true).await);
    let found = answered_with(World::Leased, Ends::TheLeasesTime, making_exclusive(), true).await;
    assert_eq!(refused(&found).to_string(), closed_refusal());
}

/// KR-REQ-17.54: a lease presented again in the wait for the write lock moves the bound to another
/// lineage, which counts as an ended lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_whose_bound_moves_before_its_transaction_is_decided_again_under_the_closed_scope()
 {
    let establishing = ConfirmationDisplay::EstablishClock;
    recorded(
        &answered_with(
            World::Leased,
            Ends::TheLeaseIsPresentedAgain,
            establishing,
            true,
        )
        .await,
    );
    let found = answered_with(
        World::Leased,
        Ends::TheLeaseIsPresentedAgain,
        making_exclusive(),
        true,
    )
    .await;
    assert_eq!(refused(&found).to_string(), closed_refusal());
}

/// KR-REQ-10.05: a terminal whose standing ends before the transaction reads the owner's rows,
/// because an owner was established meanwhile, confirms nothing: the answer is refused in the words
/// the consuming transaction uses, and nothing is recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_whose_signer_loses_its_standing_before_the_transaction_reads_it_is_refused() {
    let found = answered_with(
        World::Plain,
        Ends::AnOwnerIsEstablished,
        ConfirmationDisplay::EstablishClock,
        true,
    )
    .await;
    let ControllerError::Refused { code, detail } = refused(&found) else {
        panic!("the answer is refused as the owner's confirmation is required");
    };
    assert_eq!(*code, ErrorCode::OwnerConfirmationRequired);
    assert_eq!(
        detail,
        "this host has an owner, so the terminal bootstrap no longer confirms anything"
    );
}

/// A caller that no door landed is refused in the words of a mutation that carries no freshness,
/// and records nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_from_a_caller_with_no_landing_is_refused_and_records_nothing() {
    let found = answered_with(
        World::Plain,
        Ends::Nothing,
        ConfirmationDisplay::EstablishClock,
        false,
    )
    .await;
    let ControllerError::WindowExpired { detail } = refused(&found) else {
        panic!("a caller with no landing is refused as one that carries no freshness");
    };
    assert_eq!(
        detail,
        "this action carries no freshness, so it may be answered from what this host holds and \
         may not write"
    );
}

/// KR-REQ-10.05: a confirmation that expires in the last wait, after the feed's locked ask and
/// before the bound is copied, is verified again after that wait: the answer is refused as the
/// owner's confirmation is required, whole, and nothing is recorded. The control: where it has
/// not expired, the same answer is recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_whose_challenge_expires_in_the_last_wait_is_refused_and_records_nothing() {
    recorded(
        &answered_with(
            World::Plain,
            Ends::Nothing,
            ConfirmationDisplay::EstablishClock,
            true,
        )
        .await,
    );
    let found = answered_with(
        World::Plain,
        Ends::TheChallengeExpires,
        ConfirmationDisplay::EstablishClock,
        true,
    )
    .await;
    let ControllerError::Refused { code, detail } = refused(&found) else {
        panic!("the answer is refused as the owner's confirmation is required");
    };
    assert_eq!(*code, ErrorCode::OwnerConfirmationRequired);
    assert_eq!(detail, "this action needs a fresh owner confirmation");
}

/// Asks for a challenge and answers it, as a local caller, with the proof of an owner device that
/// this host holds; the answer's record is stopped in the last wait, where the authority feed's
/// refusal that removes every remote grant's standing is raised when `raised` says so. A local
/// connection has no grants for the feed to ask, so what refuses the device is the signer's own
/// standing, read after the wait.
async fn answered_by_an_owner_device(raised: bool) -> Found {
    let parts = parts(World::Plain).await;
    let controller = &parts.controller;
    let keys = kr_crypto::keys::DeviceKeys::generate().expect("keys");
    paired(
        controller,
        &keys,
        0x41,
        &[ActionRight::HostManage],
        kr_protocol::grant::GrantExpiry::Never,
    );
    let door = Door::open(&parts.temp, controller).await;
    let revision = controller.admitted_revision(door.connection_id()).ok();
    let deadline = controller
        .clock
        .now()
        .checked_add(Duration::from_secs(3600))
        .expect("a deadline");
    let landing = || controller.pairing_landing(door.connection_id(), revision, Some(deadline));
    let owner = Arc::clone(controller.owner_authority());
    let challenge = {
        let owner = Arc::clone(&owner);
        let caller = controller.local_caller(door.actor_id()).landed(landing());
        tokio::task::spawn_blocking(move || {
            owner.request(
                &caller,
                Resolved {
                    action: SensitiveAction::ChangeHostAuthority,
                    digest: Digest256::from_bytes([7; 32]),
                    destination: None,
                    rights: CanonicalSet::new(),
                    display: ConfirmationDisplay::EstablishClock,
                    bootstrap: false,
                },
                (
                    ActionId::new(kr_ipc::new_uuid()),
                    Digest256::from_bytes([8; 32]),
                ),
                &AtomicBool::new(false),
            )
        })
        .await
        .expect("the request ends")
        .expect("the challenge is issued")
    };
    let params = OwnerConfirmationCompleteParams {
        proof: sign_confirmation(
            &keys.authorisation,
            &challenge.request,
            ConfirmationChannel::OwnerDevicePresence,
        )
        .expect("a proof"),
        bootstrap_signer: Nullable::null(),
    };
    let confirmation = challenge.request.confirmation_id;
    let action = (
        ActionId::new(kr_ipc::new_uuid()),
        Digest256::from_bytes([9; 32]),
    );
    let caller = controller.local_caller(door.actor_id()).landed(landing());
    let (arrived, go) = controller.pause_after_the_record_asks_the_feed();
    let answering = tokio::task::spawn_blocking({
        let owner = Arc::clone(&owner);
        move || {
            let copied = AtomicBool::new(false);
            let answered = owner.complete(&caller, &params, action, &copied);
            (answered, copied.load(Ordering::Acquire))
        }
    });
    tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(30)))
        .await
        .expect("the wait ends")
        .expect("the record reaches the place it is stopped at");
    // The raise sets the refusal's word and then waits for every write to the pairing records that
    // is under way, and the paused record's transaction is one: the raise is started, the case
    // waits until the word is up, and the raise ends once the record has.
    let raising = raised.then(|| {
        let controller = Arc::clone(controller);
        tokio::spawn(async move {
            controller
                .move_a_feed_refusal(
                    crate::grants::RemoteRefusal::WITHDRAWAL_UNVERIFIED,
                    true,
                    crate::grants::HostPolicy::withdrawal_unverified,
                    crate::grants::HostPolicy::set_withdrawal_unverified,
                )
                .await;
        })
    });
    if raising.is_some() {
        tokio::time::timeout(Duration::from_secs(30), async {
            while !controller.policy().withdrawal_unverified() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the refusal's word is raised");
    }
    go.send(()).expect("the record goes on");
    let (answered, copied) = answering.await.expect("the answer ends");
    if let Some(raising) = raising {
        raising.await.expect("the raise ends once the record has");
    }
    Found {
        answered,
        confirmation,
        copied,
        answers: count(
            &parts.temp,
            "SELECT COUNT(*) FROM owner_confirmations WHERE confirmation_id = ?1",
            confirmation.get().as_bytes().as_slice(),
        ),
        actions: count(
            &parts.temp,
            "SELECT COUNT(*) FROM pairing_actions WHERE action_id = ?1",
            action.0.get().as_bytes().as_slice(),
        ),
    }
}

/// KR-REQ-09.12, KR-REQ-10.05: a local caller carries the proof of an owner device, and a refusal
/// that removes every remote grant's standing rises in the last wait. The feed's asks read nothing
/// for a local connection, so the signer's standing is read after that wait: the answer is refused
/// in the feed's words, whole, and nothing is recorded. The control: with no refusal raised, the
/// same answer is recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_with_an_owner_devices_proof_meets_a_feed_refusal_raised_in_the_last_wait() {
    let control = answered_by_an_owner_device(false).await;
    let answered = control.answered.as_ref().expect("the answer is accepted");
    assert_eq!(answered.confirmation_id, control.confirmation);
    assert_eq!(answered.channel, ConfirmationChannel::OwnerDevicePresence);
    assert_eq!(control.answers, 1, "the acceptance is recorded once");
    let found = answered_by_an_owner_device(true).await;
    let ControllerError::PermissionDenied { detail } = refused(&found) else {
        panic!("the answer is refused as the feed refuses the device's standing");
    };
    assert_eq!(
        detail,
        "this host's authority feed shows a revocation by an owner this host does not know, so it \
         refuses remote access until the owner at this machine has revoked what it names"
    );
}
