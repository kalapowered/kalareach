//! A share asked for while an earlier share of the same session to the same device is still being
//! made, and what a share that is no longer being made is answered.
//!
//! A second `grant.create` under a fresh action for the subject of one that is still running would
//! write a second grant and a second invitation if both reach their effect, and nothing can undo
//! that, so it is refused while the first runs. Once the first has ended this host reads what it
//! wrote from its own store: the share, when it wrote one, and otherwise that nothing was shared.
//! A share whose store could not say whether it wrote anything holds its subject until the host
//! restarts. The first share is held where it waits for the registry, which each case takes
//! itself, so nothing here is decided by a timer.

use std::future::Future;
use std::pin::Pin;

use kr_protocol::envelope::{ControlFrame, MutationRequest, Outcome, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::grant::{GrantExpiry, SessionSelector};
use kr_protocol::ids::{ActorId, DeviceId, GrantId, InvitationId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{DurationMs, Nullable, Uuid};
use kr_protocol::sharing::{
    AuthorityNotice, GrantCreateParams, GrantCreateResult, RoleSelection, SessionRole,
};

use super::a_share_a_device_holds::{paired as paired_with_no_session, share as held_share};
use super::a_share_that_names_a_current_decision::{
    Holding, grants_written, holding_grant, holds_question_reads, invitation_written, recipient,
    share, world,
};
use crate::error::ControllerError;
use crate::given::Given;
use crate::grants::ActionRecord;
use crate::service::a_close_a_worker_never_answers as fake;
use crate::service::a_read_that_meets_a_worker_on_its_way_out as scripted;
use crate::service::authority_changes::AuthorityCaller;

type Answer = Given<Result<ParamsValue, ControllerError>>;

/// A share that has been asked for and has not been polled.
type Running<'a> = Pin<Box<dyn Future<Output = Answer> + 'a>>;

/// The local owner, whose shares the cases make.
fn owner() -> ActorId {
    ActorId::new("local:test").expect("a principal")
}

/// A viewer's share of `session_id` to `to`, as action `action`.
fn viewing(
    world: &fake::Silent,
    session_id: SessionId,
    to: DeviceId,
    action: u8,
) -> MutationRequest {
    let selection = RoleSelection::plain(SessionRole::Viewer);
    MutationRequest {
        params: ParamsValue::from_typed(&GrantCreateParams {
            session_id,
            recipient_device_id: to,
            parent_grant_id: Nullable::null(),
            accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
            selection,
            lifetime_ms: Nullable::null(),
            owner_confirmation: Nullable::null(),
        })
        .expect("encodes"),
        ..share(
            world.environment_id,
            session_id,
            action,
            RoleSelection::plain(SessionRole::Viewer),
        )
    }
}

/// A second device this host is paired with, for a day, which a share can be made to.
fn paired(world: &fake::Silent, byte: u8) -> DeviceId {
    let (mut grant, _) = crate::service::net::tests::granted(
        kr_protocol::grant::GrantExpiry::At {
            expires_at_ms: kr_protocol::scalars::TimestampMs::new(
                kr_ipc::now_ms().get() + 24 * 3_600_000,
            ),
        },
        world.controller.policy().authority_revision(),
    );
    let device = DeviceId::new(Uuid::from_bytes([byte; 16]));
    grant.recipient_device_id = device;
    grant.issuer_device_id = device;
    holding_grant(&world.controller, byte, grant);
    device
}

/// A share by `actor` as `caller`, registered with the daemon and not yet polled. Every connection
/// a case needs is registered before it takes the registry, which registering one would wait for.
async fn starting<'a>(
    world: &'a fake::Silent,
    actor: &ActorId,
    caller: AuthorityCaller,
    mutation: &MutationRequest,
) -> Running<'a> {
    let carried = fake::admission(&world.controller, world.accepted).await;
    let (actor, mutation) = (actor.clone(), mutation.clone());
    Box::pin(async move {
        world
            .controller
            .authority_change(&actor, caller, &mutation, Method::GrantCreate, carried)
            .await
    })
}

/// What the daemon holds about `actor`'s action of `mutation`: its claim.
fn claim(
    world: &fake::Silent,
    actor: &ActorId,
    mutation: &MutationRequest,
) -> Option<ActionRecord> {
    let digest = kr_protocol::digest::mutation_digest(mutation, actor).expect("a digest");
    world
        .controller
        .sharing()
        .grants()
        .recorded_action(actor, mutation.action_id, &digest)
        .expect("the claim reads")
}

/// Polls `running` until it answers or its claim is written, whichever is first, and gives the
/// answer when there is one. A share that waits for the registry is left waiting.
async fn until_claimed(
    running: &mut Running<'_>,
    world: &fake::Silent,
    actor: &ActorId,
    mutation: &MutationRequest,
) -> Option<Answer> {
    tokio::select! {
        answer = running.as_mut() => Some(answer),
        () = async {
            while claim(world, actor, mutation).is_none() {
                tokio::task::yield_now().await;
            }
        } => None,
    }
}

/// The refusal an answer carries, or a panic naming what it carried.
fn refused(answer: &Answer) -> &ControllerError {
    match answer {
        Given::Fresh(Err(error)) | Given::Copied(Err(error)) | Given::Withheld(Err(error)) => error,
        Given::Fresh(Ok(value)) | Given::Copied(Ok(value)) | Given::Withheld(Ok(value)) => {
            panic!("the share was written: {value:?}")
        }
    }
}

/// The error a frame carries, or a panic naming what it carried.
fn refusal_in(frame: Option<ControlFrame>) -> ProtocolError {
    let Some(ControlFrame::Response(response)) = frame else {
        panic!("a repeat of an action this host claimed is answered: {frame:?}");
    };
    let Outcome::Error(error) = response.outcome else {
        panic!("the repeat is refused: {response:?}");
    };
    error
}

/// The share a frame carries, or a panic naming what it carried.
fn share_in(frame: Option<ControlFrame>) -> GrantCreateResult {
    let Some(ControlFrame::Response(response)) = frame else {
        panic!("a repeat of an action this host claimed is answered: {frame:?}");
    };
    let Outcome::Ok(value) = response.outcome else {
        panic!("the repeat is answered with a share: {response:?}");
    };
    value.to_typed().expect("a share result")
}

/// The identities a build before they were scoped to the actor gave a share of `action`.
fn earlier_identities(action: Uuid) -> (GrantId, InvitationId) {
    let derived = |purpose: &[u8]| {
        let digest =
            kr_cbor::sha256(&[b"kr-sharing/1".as_slice(), purpose, action.as_bytes()].concat());
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        Uuid::from_bytes(bytes)
    };
    (
        GrantId::new(derived(b"grant")),
        InvitationId::new(derived(b"invitation")),
    )
}

/// A connection to the registry's file beside the daemon's own, for what a case does to the store.
fn beside(world: &fake::Silent) -> rusqlite::Connection {
    let connection = rusqlite::Connection::open(world._temp.environment().registry_database())
        .expect("the registry opens beside the daemon's own handle");
    connection
        .busy_timeout(std::time::Duration::from_secs(10))
        .expect("waits for the daemon's own writes");
    connection
}

/// KR-REQ-23.24: a share under a fresh action is refused while an earlier share of the same actor,
/// session and device is still being made, even when it differs from it in what a request's digest
/// sees, and it is told so as its own answer, which a repeat of it is given again as a copy. The
/// earlier share's own repeat is told it has not finished, and a share of another session, to
/// another device or by another actor is not held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_24_a_fresh_share_is_refused_while_an_earlier_share_of_its_subject_runs() {
    let (world, _holding) = world(Holding::default(), holds_question_reads()).await;
    let owner = owner();
    let other_actor = ActorId::new("local:other").expect("a principal");
    let elsewhere = fake::open_session(&world.controller).await;
    let another = paired(&world, 0xd2);

    let first = viewing(&world, world.session_id, recipient(), 0x01);
    let mut replacement = viewing(&world, world.session_id, recipient(), 0x02);
    replacement.requested_ttl_ms = DurationMs::new(31_000);
    replacement.target.session_epoch = Nullable::null();
    let in_elsewhere = viewing(&world, elsewhere, recipient(), 0x03);
    let to_another = viewing(&world, world.session_id, another, 0x04);
    let by_other = viewing(&world, world.session_id, recipient(), 0x05);

    let mut running = starting(&world, &owner, AuthorityCaller::Owner, &first).await;
    let mut refusing = starting(&world, &owner, AuthorityCaller::Owner, &replacement).await;
    let mut held_elsewhere = starting(&world, &owner, AuthorityCaller::Owner, &in_elsewhere).await;
    let mut held_to_another = starting(&world, &owner, AuthorityCaller::Owner, &to_another).await;
    let mut held_by_other = starting(&world, &other_actor, AuthorityCaller::Owner, &by_other).await;

    let registry = world.controller.registry.lock().await;
    assert!(
        until_claimed(&mut running, &world, &owner, &first)
            .await
            .is_none(),
        "the first share waits for the registry"
    );
    assert_eq!(claim(&world, &owner, &first), Some(ActionRecord::InFlight));

    let answered = until_claimed(&mut refusing, &world, &owner, &replacement).await;
    let Some(ActionRecord::Refused { code, detail }) = claim(&world, &owner, &replacement) else {
        panic!(
            "the replacement was not refused while the first share runs: {:?}",
            claim(&world, &owner, &replacement)
        );
    };
    assert_eq!(code, ErrorCode::DraftConflict);
    assert!(
        detail.contains(&first.action_id.to_string()),
        "it names the share that holds it: {detail}"
    );
    let answered = answered.expect("a refusal is answered at the claim");
    assert!(
        !answered.is_copied(),
        "a refusal made now is not a copy of a record"
    );
    assert_eq!(refused(&answered).code(), ErrorCode::DraftConflict);

    // The running share's own repeat is told it has not finished, as it always was.
    assert_eq!(
        refusal_in(
            world
                .controller
                .retained_authority_answer(&owner, &first)
                .await
        )
        .code,
        ErrorCode::OutcomeUnknown
    );
    // The refused action's repeat is told what it was told.
    let again = refusal_in(
        world
            .controller
            .retained_authority_answer(&owner, &replacement)
            .await,
    );
    assert_eq!(again.code, ErrorCode::DraftConflict);

    // Another session, another device and another actor are not the subject of the running share.
    for (held, actor, mutation) in [
        (&mut held_elsewhere, &owner, &in_elsewhere),
        (&mut held_to_another, &owner, &to_another),
        (&mut held_by_other, &other_actor, &by_other),
    ] {
        assert!(until_claimed(held, &world, actor, mutation).await.is_none());
        assert_eq!(
            claim(&world, actor, mutation),
            Some(ActionRecord::InFlight),
            "a share that is not the running one's subject is admitted"
        );
    }

    // Every share waiting for the registry is polled together: the registry hands itself to each
    // waiter in turn, so one that is not polled would hold the others behind it.
    drop(registry);
    let (first_answer, in_elsewhere_answer, to_another_answer, by_other_answer) =
        tokio::join!(running, held_elsewhere, held_to_another, held_by_other);
    first_answer
        .into_answer()
        .expect("the first share is written");
    for answer in [in_elsewhere_answer, to_another_answer, by_other_answer] {
        answer.into_answer().expect("the share is written");
    }
    assert!(invitation_written(&world, 0x01));
    assert!(
        !invitation_written(&world, 0x02),
        "the refused share wrote nothing"
    );

    let copied = starting(&world, &owner, AuthorityCaller::Owner, &replacement)
        .await
        .await;
    assert!(copied.is_copied(), "the refused action's repeat is a copy");
    assert_eq!(refused(&copied).code(), ErrorCode::DraftConflict);
}

/// KR-REQ-23.24: the hold is the same for a paired device that delegates from a share it holds:
/// while its delegation runs, a delegation of the same session to the same device under a fresh
/// action is refused at the claim, as its own answer and a copy for its repeat; once the first has
/// ended, a delegation under a fresh action is admitted and written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_24_a_device_that_delegates_is_held_to_its_running_share_too() {
    let (world, _holding) = world(Holding::default(), holds_question_reads()).await;
    let delegating = paired_with_no_session(&world.controller, 0xd3, SessionSelector::None);
    let device = delegating.principal();
    let acting = AuthorityCaller::Device(delegating.device_id);
    let rights: Vec<_> = RoleSelection::plain(SessionRole::Owner)
        .actions()
        .iter()
        .copied()
        .collect();
    let parent = held_share(&world, &delegating, &rights, &[], true, GrantExpiry::Never);
    let to = paired(&world, 0xd2);
    let delegation = |action: u8| {
        let selection = RoleSelection::plain(SessionRole::Viewer);
        MutationRequest {
            params: ParamsValue::from_typed(&GrantCreateParams {
                session_id: world.session_id,
                recipient_device_id: to,
                parent_grant_id: Nullable::some(parent.grant_id),
                accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
                selection,
                lifetime_ms: Nullable::some(DurationMs::new(600_000)),
                owner_confirmation: Nullable::null(),
            })
            .expect("encodes"),
            ..share(
                world.environment_id,
                world.session_id,
                action,
                RoleSelection::plain(SessionRole::Viewer),
            )
        }
    };
    let (first, replacement, afterwards) = (delegation(0x11), delegation(0x12), delegation(0x13));

    let mut running = starting(&world, &device, acting, &first).await;
    let mut refusing = starting(&world, &device, acting, &replacement).await;
    let later = starting(&world, &device, acting, &afterwards).await;
    let registry = world.controller.registry.lock().await;
    assert!(
        until_claimed(&mut running, &world, &device, &first)
            .await
            .is_none()
    );
    let answered = until_claimed(&mut refusing, &world, &device, &replacement).await;
    let Some(ActionRecord::Refused { code, .. }) = claim(&world, &device, &replacement) else {
        panic!(
            "the device's replacement was not refused: {:?}",
            claim(&world, &device, &replacement)
        );
    };
    assert_eq!(code, ErrorCode::DraftConflict);
    let answered = answered.expect("a refusal is answered at the claim");
    assert!(!answered.is_copied());
    assert_eq!(refused(&answered).code(), ErrorCode::DraftConflict);

    drop(registry);
    running
        .await
        .into_answer()
        .expect("the device's delegation is written");
    assert_eq!(grants_written(&world), 2, "the parent and the delegation");
    later
        .await
        .into_answer()
        .expect("a delegation under a fresh action is admitted once the first has ended");
    assert_eq!(grants_written(&world), 3);

    let copied = starting(&world, &device, acting, &replacement).await.await;
    assert!(copied.is_copied(), "the refused action's repeat is a copy");
    assert_eq!(refused(&copied).code(), ErrorCode::DraftConflict);
}

/// KR-REQ-23.24: a share is held only while it runs. One that ends by its task being dropped lets
/// a fresh share of the subject be admitted and written, and so does one that ended having written
/// its share, which is then a second share of the same session to the same device.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_24_a_share_is_admitted_once_the_earlier_one_has_ended() {
    let (world, _holding) = world(Holding::default(), holds_question_reads()).await;
    let owner = owner();
    let first = viewing(&world, world.session_id, recipient(), 0x21);
    let second = viewing(&world, world.session_id, recipient(), 0x22);
    let third = viewing(&world, world.session_id, recipient(), 0x23);

    let mut running = starting(&world, &owner, AuthorityCaller::Owner, &first).await;
    let mut fresh = starting(&world, &owner, AuthorityCaller::Owner, &second).await;
    let registry = world.controller.registry.lock().await;
    assert!(
        until_claimed(&mut running, &world, &owner, &first)
            .await
            .is_none()
    );
    drop(running);
    assert!(
        until_claimed(&mut fresh, &world, &owner, &second)
            .await
            .is_none()
    );
    assert_eq!(
        claim(&world, &owner, &second),
        Some(ActionRecord::InFlight),
        "the share whose task was dropped no longer holds the subject"
    );
    drop(registry);
    fresh
        .await
        .into_answer()
        .expect("the share is written once the earlier one is gone");
    assert_eq!(grants_written(&world), 1);

    starting(&world, &owner, AuthorityCaller::Owner, &third)
        .await
        .await
        .into_answer()
        .expect("a share after one that wrote its share is written");
    assert_eq!(grants_written(&world), 2);
}

/// KR-REQ-23.24: a share whose task ended before it wrote anything is answered, to a repeat of its
/// action, that nothing was shared under it, and it is not performed again; the same after the
/// daemon restarts. Where the grants cannot be read that is not what a repeat is told, since the
/// share may have been written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_24_a_share_that_ended_before_it_wrote_anything_is_told_so() {
    let (world, _holding) = world(Holding::default(), holds_question_reads()).await;
    let owner = owner();
    let first = viewing(&world, world.session_id, recipient(), 0x31);

    let mut running = starting(&world, &owner, AuthorityCaller::Owner, &first).await;
    let registry = world.controller.registry.lock().await;
    assert!(
        until_claimed(&mut running, &world, &owner, &first)
            .await
            .is_none()
    );
    drop(running);
    drop(registry);
    assert_eq!(
        claim(&world, &owner, &first),
        Some(ActionRecord::Unfinished),
        "the attempt ended with nothing recorded"
    );

    let told = refusal_in(
        world
            .controller
            .retained_authority_answer(&owner, &first)
            .await,
    );
    assert_eq!(told.code, ErrorCode::DraftConflict, "{told:?}");
    assert!(
        told.message.contains("nothing was shared"),
        "it says nothing was shared: {told:?}"
    );
    assert_eq!(grants_written(&world), 0);

    let registry = beside(&world);
    registry
        .execute_batch("ALTER TABLE grants RENAME TO grants_aside;")
        .expect("the grants cannot be read");
    let unreadable = refusal_in(
        world
            .controller
            .retained_authority_answer(&owner, &first)
            .await,
    );
    registry
        .execute_batch("ALTER TABLE grants_aside RENAME TO grants;")
        .expect("the grants can be read again");
    assert_eq!(
        unreadable.code,
        ErrorCode::OutcomeUnknown,
        "a share that cannot be looked for is not one that was not made: {unreadable:?}"
    );
    drop(registry);

    let world = scripted::restarted(world).await;
    let after_a_restart = refusal_in(
        world
            .controller
            .retained_authority_answer(&owner, &first)
            .await,
    );
    assert_eq!(after_a_restart.code, ErrorCode::DraftConflict);
    assert!(after_a_restart.message.contains("nothing was shared"));
}

/// KR-REQ-23.24: a share that was written and whose result could not be kept is found by a repeat
/// and answered as written, also after a restart. Its store could not say whether it kept what it
/// was asked to, so it holds its subject until the host restarts, and a share of the subject after
/// that is admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_24_a_share_whose_result_cannot_be_kept_is_found_and_holds_its_subject() {
    let (world, _holding) = world(Holding::default(), holds_question_reads()).await;
    let owner = owner();
    let first = viewing(&world, world.session_id, recipient(), 0x41);
    let later = viewing(&world, world.session_id, recipient(), 0x42);

    let mut running = starting(&world, &owner, AuthorityCaller::Owner, &first).await;
    let refusing = starting(&world, &owner, AuthorityCaller::Owner, &later).await;
    let registry = world.controller.registry.lock().await;
    assert!(
        until_claimed(&mut running, &world, &owner, &first)
            .await
            .is_none()
    );
    let receipts = beside(&world);
    receipts
        .execute_batch("ALTER TABLE authority_receipts RENAME TO authority_receipts_aside;")
        .expect("the claims cannot be written");
    drop(registry);
    let answer = running.await;
    receipts
        .execute_batch("ALTER TABLE authority_receipts_aside RENAME TO authority_receipts;")
        .expect("the claims can be written again");
    drop(receipts);
    assert_eq!(
        refused(&answer).code(),
        ErrorCode::OutcomeUnknown,
        "the share was written and its result was not kept"
    );
    assert_eq!(grants_written(&world), 1);

    let written = share_in(
        world
            .controller
            .retained_authority_answer(&owner, &first)
            .await,
    );
    let (grant_id, _) = kr_protocol::sharing::share_identities(&owner, first.action_id.get());
    assert_eq!(written.grant.grant_id, grant_id);

    let held = refusing.await;
    assert_eq!(
        refused(&held).code(),
        ErrorCode::DraftConflict,
        "a share of the subject waits for the restart"
    );
    assert_eq!(grants_written(&world), 1);

    let world = scripted::restarted(world).await;
    let found = share_in(
        world
            .controller
            .retained_authority_answer(&owner, &first)
            .await,
    );
    assert_eq!(found.grant.grant_id, grant_id);
    let afresh = viewing(&world, world.session_id, recipient(), 0x43);
    starting(&world, &owner, AuthorityCaller::Owner, &afresh)
        .await
        .await
        .into_answer()
        .expect("a share of the subject is admitted after a restart");
    assert_eq!(grants_written(&world), 2);
}

/// KR-REQ-23.24: a store that fails while a share is being written has not said that nothing was
/// written, so the share is not called unperformed: its repeat is told the outcome is not known and
/// its subject stays held until the host restarts, which reads the store as it stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_24_a_share_whose_store_fails_while_it_is_written_holds_its_subject() {
    let (world, _holding) = world(Holding::default(), holds_question_reads()).await;
    let owner = owner();
    let first = viewing(&world, world.session_id, recipient(), 0x51);
    let second = viewing(&world, world.session_id, recipient(), 0x52);
    let third = viewing(&world, world.session_id, recipient(), 0x53);

    let store = beside(&world);
    store
        .execute_batch(
            "CREATE TRIGGER refuse_invitations BEFORE INSERT ON session_invitations
             BEGIN SELECT RAISE(ABORT, 'the store failed'); END;",
        )
        .expect("the store fails while a share is written");
    let failed = starting(&world, &owner, AuthorityCaller::Owner, &first)
        .await
        .await;
    assert_eq!(
        refused(&failed).code(),
        ErrorCode::OutcomeUnknown,
        "the caller is not told that nothing took effect, which a transient word says"
    );
    assert_eq!(grants_written(&world), 0);

    let unknown = refusal_in(
        world
            .controller
            .retained_authority_answer(&owner, &first)
            .await,
    );
    assert_eq!(
        unknown.code,
        ErrorCode::OutcomeUnknown,
        "it is not known whether the share was written: {unknown:?}"
    );
    let held = starting(&world, &owner, AuthorityCaller::Owner, &second)
        .await
        .await;
    assert_eq!(
        refused(&held).code(),
        ErrorCode::DraftConflict,
        "the subject stays held"
    );

    // The store is whole again, and a restart reads it as it stands.
    store
        .execute_batch("DROP TRIGGER refuse_invitations;")
        .expect("the store is whole");
    drop(store);
    let world = scripted::restarted(world).await;
    let told = refusal_in(
        world
            .controller
            .retained_authority_answer(&owner, &first)
            .await,
    );
    assert_eq!(told.code, ErrorCode::DraftConflict);
    assert!(told.message.contains("nothing was shared"), "{told:?}");
    starting(&world, &owner, AuthorityCaller::Owner, &third)
        .await
        .await
        .into_answer()
        .expect("a share of the subject is admitted after a restart");
    assert_eq!(grants_written(&world), 1);
}

/// KR-REQ-23.24: a store that fails before a share's transaction begins has written nothing, so
/// the share holds nothing: a repeat of it is told that nothing was shared, and a share of the
/// subject under a fresh action is admitted and written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_24_a_share_whose_store_fails_before_it_is_written_holds_nothing() {
    let (world, _holding) = world(Holding::default(), holds_question_reads()).await;
    let owner = owner();
    let first = viewing(&world, world.session_id, recipient(), 0x71);
    let second = viewing(&world, world.session_id, recipient(), 0x72);

    let store = beside(&world);
    store
        .execute_batch("ALTER TABLE grants RENAME TO grants_aside;")
        .expect("the grants cannot be read when the share is compiled");
    let failed = starting(&world, &owner, AuthorityCaller::Owner, &first)
        .await
        .await;
    store
        .execute_batch("ALTER TABLE grants_aside RENAME TO grants;")
        .expect("the grants can be read again");
    drop(store);
    assert_eq!(refused(&failed).code(), ErrorCode::StorageUnavailable);
    assert_eq!(grants_written(&world), 0);

    let told = refusal_in(
        world
            .controller
            .retained_authority_answer(&owner, &first)
            .await,
    );
    assert_eq!(told.code, ErrorCode::DraftConflict, "{told:?}");
    assert!(told.message.contains("nothing was shared"), "{told:?}");
    starting(&world, &owner, AuthorityCaller::Owner, &second)
        .await
        .await
        .into_answer()
        .expect("a share of the subject is admitted: the failed one held nothing");
    assert_eq!(grants_written(&world), 1);
}

/// KR-REQ-23.24: a share a build before identities were scoped to the actor wrote is not called
/// unperformed by its absence under the identities the actor derives now, since the host cannot say
/// whose it was: a claim that never recorded its answer, beside a share under the earlier
/// identities, is told that what became of the action is not known.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_24_a_share_written_under_earlier_identities_is_not_called_unperformed() {
    let (world, _holding) = world(Holding::default(), holds_question_reads()).await;
    let owner = owner();
    let first = viewing(&world, world.session_id, recipient(), 0x61);
    starting(&world, &owner, AuthorityCaller::Owner, &first)
        .await
        .await
        .into_answer()
        .expect("the share is written");

    let (grant_id, invitation_id) =
        kr_protocol::sharing::share_identities(&owner, first.action_id.get());
    let (earlier_grant, earlier_invitation) = earlier_identities(first.action_id.get());
    let registry = beside(&world);
    registry
        .execute(
            "UPDATE grants SET grant_id = ?1 WHERE grant_id = ?2",
            rusqlite::params![
                earlier_grant.get().as_bytes().as_slice(),
                grant_id.get().as_bytes().as_slice()
            ],
        )
        .expect("the grant keeps the identity an earlier build gave it");
    registry
        .execute(
            "UPDATE session_invitations SET invitation_id = ?1, grant_id = ?2
              WHERE invitation_id = ?3",
            rusqlite::params![
                earlier_invitation.get().as_bytes().as_slice(),
                earlier_grant.get().as_bytes().as_slice(),
                invitation_id.get().as_bytes().as_slice()
            ],
        )
        .expect("the invitation keeps the identity an earlier build gave it");
    registry
        .execute(
            "UPDATE authority_receipts SET result = NULL, recorded_at_ms = NULL
              WHERE actor_id = ?1 AND action_id = ?2",
            rusqlite::params![owner.as_str(), first.action_id.get().as_bytes().as_slice()],
        )
        .expect("the claim never recorded its answer");
    drop(registry);

    let told = refusal_in(
        world
            .controller
            .retained_authority_answer(&owner, &first)
            .await,
    );
    assert_eq!(
        told.code,
        ErrorCode::OutcomeUnknown,
        "what became of the action is not known: {told:?}"
    );
}

/// KR-REQ-23.24: a share under the earlier identities that cannot be read is not called
/// unperformed either. Nothing is under the identities the actor derives now, so the share is
/// absent there, and its grant sits under the earlier identities as a row that cannot be decoded:
/// the repeat is told that what became of the action is not known, not that nothing was shared.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_24_a_share_under_earlier_identities_that_cannot_be_read_is_not_called_unperformed()
 {
    let (world, _holding) = world(Holding::default(), holds_question_reads()).await;
    let owner = owner();
    let first = viewing(&world, world.session_id, recipient(), 0x71);
    starting(&world, &owner, AuthorityCaller::Owner, &first)
        .await
        .await
        .into_answer()
        .expect("the share is written");

    let (grant_id, invitation_id) =
        kr_protocol::sharing::share_identities(&owner, first.action_id.get());
    let (earlier_grant, earlier_invitation) = earlier_identities(first.action_id.get());
    let registry = beside(&world);
    registry
        .execute(
            "UPDATE grants SET grant_id = ?1, grant = X'00' WHERE grant_id = ?2",
            rusqlite::params![
                earlier_grant.get().as_bytes().as_slice(),
                grant_id.get().as_bytes().as_slice()
            ],
        )
        .expect("the grant keeps the identity an earlier build gave it, and cannot be decoded");
    registry
        .execute(
            "UPDATE session_invitations SET invitation_id = ?1, grant_id = ?2
              WHERE invitation_id = ?3",
            rusqlite::params![
                earlier_invitation.get().as_bytes().as_slice(),
                earlier_grant.get().as_bytes().as_slice(),
                invitation_id.get().as_bytes().as_slice()
            ],
        )
        .expect("the invitation keeps the identity an earlier build gave it");
    registry
        .execute(
            "UPDATE authority_receipts SET result = NULL, recorded_at_ms = NULL
              WHERE actor_id = ?1 AND action_id = ?2",
            rusqlite::params![owner.as_str(), first.action_id.get().as_bytes().as_slice()],
        )
        .expect("the claim never recorded its answer");
    drop(registry);

    let told = refusal_in(
        world
            .controller
            .retained_authority_answer(&owner, &first)
            .await,
    );
    assert_eq!(
        told.code,
        ErrorCode::OutcomeUnknown,
        "a share that cannot be read is not one that was not made: {told:?}"
    );
}

/// KR-REQ-23.24: a share that is there and cannot be read back is not called unperformed. The grant
/// is read and its invitation is not, so what the repeat finds says nothing of whether the share was
/// written: it is told that what became of the action is not known, and once the invitation can be
/// read it is told the share.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_24_a_share_that_cannot_be_read_back_is_not_called_unperformed() {
    let (world, _holding) = world(Holding::default(), holds_question_reads()).await;
    let owner = owner();
    let first = viewing(&world, world.session_id, recipient(), 0x81);
    starting(&world, &owner, AuthorityCaller::Owner, &first)
        .await
        .await
        .into_answer()
        .expect("the share is written");

    let registry = beside(&world);
    registry
        .execute(
            "UPDATE authority_receipts SET result = NULL, recorded_at_ms = NULL
              WHERE actor_id = ?1 AND action_id = ?2",
            rusqlite::params![owner.as_str(), first.action_id.get().as_bytes().as_slice()],
        )
        .expect("the claim never recorded its answer");
    registry
        .execute_batch("ALTER TABLE session_invitations RENAME TO session_invitations_aside;")
        .expect("the invitations cannot be read");
    let unreadable = refusal_in(
        world
            .controller
            .retained_authority_answer(&owner, &first)
            .await,
    );
    registry
        .execute_batch("ALTER TABLE session_invitations_aside RENAME TO session_invitations;")
        .expect("the invitations can be read again");
    drop(registry);
    assert_eq!(
        unreadable.code,
        ErrorCode::OutcomeUnknown,
        "a share that cannot be read back is not one that was not made: {unreadable:?}"
    );

    let (grant_id, _) = kr_protocol::sharing::share_identities(&owner, first.action_id.get());
    let found = share_in(
        world
            .controller
            .retained_authority_answer(&owner, &first)
            .await,
    );
    assert_eq!(found.grant.grant_id, grant_id);
}
