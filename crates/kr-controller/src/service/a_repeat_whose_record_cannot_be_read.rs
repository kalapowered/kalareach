//! What a repeat of an authority change is told when the record of its first attempt cannot be
//! read, at the two lookups that stand before an authority change is admitted.
//!
//! The registry keeps a claim for each authority change the host performed, and a repeat is answered
//! from it. A registry that cannot read the claim is not one that holds none: the change may have
//! been made, so the repeat is told that what became of it is not known, and not a transient word,
//! which says that nothing took effect and has the change sent again as though nothing had.

use kr_protocol::envelope::{ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, ActionWindowId, ActorId, GrantId, RequestId};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::scalars::{DurationMs, Nullable};
use kr_protocol::sharing::GrantRevokeParams;

use super::a_transfer_left_unanswered::daemon;

/// A `grant.revoke` under a fresh action.
fn revoke_request(temp: &kr_ipc::testing::TempHost) -> MutationRequest {
    MutationRequest {
        request_id: RequestId::new(1),
        method: Method::GrantRevoke.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget::environment(temp.environment_id()),
        expected: ParamsValue::empty(),
        action_window_id: ActionWindowId::new("local:test").expect("a window"),
        requested_ttl_ms: DurationMs::new(30_000),
        params: ParamsValue::from_typed(&GrantRevokeParams {
            grant_id: GrantId::new(kr_ipc::new_uuid()),
        })
        .expect("encodes"),
    }
}

/// The error a frame carries.
fn told(frame: Option<ControlFrame>) -> kr_protocol::error::ProtocolError {
    let Some(ControlFrame::Response(response)) = frame else {
        panic!("a repeat the registry cannot be asked about is answered: {frame:?}");
    };
    let Outcome::Error(error) = response.outcome else {
        panic!("the repeat is refused: {response:?}");
    };
    error
}

/// KR-REQ-09.09: a repeat asked of a registry that cannot read the claims is told the outcome is
/// unknown, by the lookup that waits for the freshness an authority change needs and by the one a
/// caller that cannot wait stands behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeat_of_an_authority_change_the_registry_cannot_be_asked_about_is_told_the_outcome_is_unknown()
 {
    let (temp, controller) = daemon().await;
    let actor_id = ActorId::new("local:test").expect("a principal");
    let mutation = revoke_request(&temp);

    let registry = rusqlite::Connection::open(temp.environment().registry_database())
        .expect("the registry opens beside the daemon's own handle");
    registry
        .busy_timeout(std::time::Duration::from_secs(10))
        .expect("waits for the daemon's own writes");
    registry
        .execute_batch("ALTER TABLE authority_receipts RENAME TO authority_receipts_aside;")
        .expect("the claims cannot be read");

    let waiting = told(
        controller
            .retained_authority_answer(&actor_id, &mutation)
            .await,
    );
    let not_waiting = told(controller.retained_authority_change(&actor_id, &mutation));
    registry
        .execute_batch("ALTER TABLE authority_receipts_aside RENAME TO authority_receipts;")
        .expect("the claims can be read again");
    assert_eq!(waiting.code, ErrorCode::OutcomeUnknown, "{waiting:?}");
    assert_eq!(
        not_waiting.code,
        ErrorCode::OutcomeUnknown,
        "{not_waiting:?}"
    );
}

/// A `voice.stop` under a fresh action.
fn voice_stop_request(temp: &kr_ipc::testing::TempHost) -> MutationRequest {
    MutationRequest {
        request_id: RequestId::new(1),
        method: Method::VoiceStop.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget::environment(temp.environment_id()),
        expected: ParamsValue::empty(),
        action_window_id: ActionWindowId::new("local:test").expect("a window"),
        requested_ttl_ms: DurationMs::new(30_000),
        params: ParamsValue::from_typed(&kr_protocol::voice::VoiceStopParams {
            voice_session_id: kr_protocol::ids::VoiceSessionId::new(kr_ipc::new_uuid()),
        })
        .expect("encodes"),
    }
}

/// KR-REQ-09.09: a repeat of a voice change asked of a store that cannot read the claim, or that
/// holds a result or a refusal it cannot read back, is told the outcome is unknown. The change may
/// have been made, and a transient word, or a refusal of the argument, would say it was not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeat_of_a_voice_change_whose_record_cannot_be_read_is_told_the_outcome_is_unknown() {
    let (temp, controller) = daemon().await;
    let actor_id = ActorId::new("local:test").expect("a principal");
    let mutation = voice_stop_request(&temp);
    let registry = rusqlite::Connection::open(temp.environment().registry_database())
        .expect("the registry opens beside the daemon's own handle");
    registry
        .busy_timeout(std::time::Duration::from_secs(10))
        .expect("waits for the daemon's own writes");

    registry
        .execute_batch("ALTER TABLE authority_receipts RENAME TO authority_receipts_aside;")
        .expect("the claims cannot be read");
    let unread = controller
        .voice_answered(&actor_id, &mutation)
        .await
        .expect_err("a claim that cannot be read does not answer the repeat");
    registry
        .execute_batch("ALTER TABLE authority_receipts_aside RENAME TO authority_receipts;")
        .expect("the claims can be read again");
    assert_eq!(unread.code(), ErrorCode::OutcomeUnknown, "{unread}");

    // The claim holds a result that is not an encoding of anything.
    let digest = kr_protocol::digest::mutation_digest(&mutation, &actor_id).expect("digests it");
    registry
        .execute(
            "INSERT INTO authority_receipts
                 (actor_id, action_id, payload_digest, claimed_at_ms, result, recorded_at_ms,
                  refusal_code, refusal_detail)
             VALUES (?1, ?2, ?3, 1, x'ff', 1, NULL, NULL)",
            rusqlite::params![
                actor_id.as_str(),
                mutation.action_id.get().as_bytes().to_vec(),
                digest.as_bytes().to_vec(),
            ],
        )
        .expect("the claim is written");
    let undecoded = controller
        .voice_answered(&actor_id, &mutation)
        .await
        .expect_err("a result that cannot be read back does not answer the repeat");
    assert_eq!(undecoded.code(), ErrorCode::OutcomeUnknown, "{undecoded}");

    // The claim holds a refusal under a code this build does not know.
    registry
        .execute(
            "UPDATE authority_receipts
                SET result = NULL, refusal_code = 'A_CODE_THIS_BUILD_LACKS', refusal_detail = 'no'",
            [],
        )
        .expect("the claim holds a refusal");
    let unknown_code = controller
        .voice_answered(&actor_id, &mutation)
        .await
        .expect_err("a refusal that cannot be read back does not answer the repeat");
    assert_eq!(
        unknown_code.code(),
        ErrorCode::OutcomeUnknown,
        "{unknown_code}"
    );
}

/// KR-REQ-09.09: a repeat of an authority change whose kept result is not an encoding of anything is
/// told the outcome is unknown, by both lookups. The change was made and its answer is lost; a
/// refusal of the argument would say that the request was malformed, which it was not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeat_of_an_authority_change_whose_kept_result_cannot_be_decoded_is_told_the_outcome_is_unknown()
 {
    let (temp, controller) = daemon().await;
    let actor_id = ActorId::new("local:test").expect("a principal");
    let mutation = revoke_request(&temp);
    let registry = rusqlite::Connection::open(temp.environment().registry_database())
        .expect("the registry opens beside the daemon's own handle");
    registry
        .busy_timeout(std::time::Duration::from_secs(10))
        .expect("waits for the daemon's own writes");
    let digest = kr_protocol::digest::mutation_digest(&mutation, &actor_id).expect("digests it");
    registry
        .execute(
            "INSERT INTO authority_receipts
                 (actor_id, action_id, payload_digest, claimed_at_ms, result, recorded_at_ms,
                  refusal_code, refusal_detail)
             VALUES (?1, ?2, ?3, 1, x'ff', 1, NULL, NULL)",
            rusqlite::params![
                actor_id.as_str(),
                mutation.action_id.get().as_bytes().to_vec(),
                digest.as_bytes().to_vec(),
            ],
        )
        .expect("the claim is written with a result that is not an encoding");

    let waiting = told(
        controller
            .retained_authority_answer(&actor_id, &mutation)
            .await,
    );
    let not_waiting = told(controller.retained_authority_change(&actor_id, &mutation));
    assert_eq!(waiting.code, ErrorCode::OutcomeUnknown, "{waiting:?}");
    assert_eq!(
        not_waiting.code,
        ErrorCode::OutcomeUnknown,
        "{not_waiting:?}"
    );
}

/// KR-REQ-09.09: a voice change that found no record of its action at the early look, and then meets
/// a claim that cannot be read where it claims the action, is told the outcome is unknown. A copy
/// of the change may have claimed in between and carried it out; the claim's own transaction cannot
/// tell a first change from a repeat, and a transient word would say that nothing took effect.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_voice_change_whose_claim_cannot_be_read_where_it_is_made_is_told_the_outcome_is_unknown()
{
    let (temp, controller) = daemon().await;
    let actor_id = ActorId::new("local:test").expect("a principal");
    let mutation = voice_stop_request(&temp);
    let registry = rusqlite::Connection::open(temp.environment().registry_database())
        .expect("the registry opens beside the daemon's own handle");
    registry
        .busy_timeout(std::time::Duration::from_secs(10))
        .expect("waits for the daemon's own writes");
    let accepted = kr_transport::window::AcceptedDeadline {
        deadline: controller
            .clock
            .now()
            .checked_add(std::time::Duration::from_secs(30))
            .expect("a deadline half a minute out"),
        bound: kr_transport::window::DeadlineBound::RequestedTtl,
    };
    let carried = super::a_close_a_worker_never_answers::admission(&controller, accepted).await;
    let revision = controller.policy().authority_revision();

    // The change has looked for a record and found none; the claims then cannot be read where it
    // claims the action.
    let (arrived, go) = controller.before_a_voice_change_claims.arm();
    let making = tokio::spawn({
        let controller = std::sync::Arc::clone(&controller);
        let mutation = mutation.clone();
        async move {
            controller
                .voice_mutation(
                    super::voice_actions::VoiceIngress {
                        actor_id,
                        actor: crate::voice::VoiceActor::Owner,
                        route: None,
                    },
                    &mutation,
                    Method::VoiceStop,
                    revision,
                    carried,
                )
                .await
        }
    });
    arrived.await.expect("the change has looked for a record");
    registry
        .execute_batch("ALTER TABLE authority_receipts RENAME TO authority_receipts_aside;")
        .expect("the claims cannot be read");
    let _ = go.send(());
    let given = making.await.expect("the change ran");
    registry
        .execute_batch("ALTER TABLE authority_receipts_aside RENAME TO authority_receipts;")
        .expect("the claims can be read again");
    let unread = given
        .into_answer()
        .expect_err("a claim that cannot be read is not one this change may be made under");
    assert_eq!(unread.code(), ErrorCode::OutcomeUnknown, "{unread}");
}

/// KR-REQ-09.09: a voice change whose claim cannot even be begun, because another writer holds the
/// store where the claim's transaction opens, is told the outcome is unknown. The claim's
/// transaction is where a copy that found no record at the early look meets one it cannot read, and
/// that is as true of a transaction that never opened as of a read that failed in it. A claim that
/// cannot be written is another matter, and keeps the storage word.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_voice_change_whose_claim_cannot_be_begun_is_told_the_outcome_is_unknown() {
    let (temp, controller) = daemon().await;
    let actor_id = ActorId::new("local:test").expect("a principal");
    let mutation = voice_stop_request(&temp);
    let registry = rusqlite::Connection::open(temp.environment().registry_database())
        .expect("the registry opens beside the daemon's own handle");
    registry
        .busy_timeout(std::time::Duration::from_secs(10))
        .expect("waits for the daemon's own writes");
    let accepted = kr_transport::window::AcceptedDeadline {
        deadline: controller
            .clock
            .now()
            .checked_add(std::time::Duration::from_secs(30))
            .expect("a deadline half a minute out"),
        bound: kr_transport::window::DeadlineBound::RequestedTtl,
    };
    let carried = super::a_close_a_worker_never_answers::admission(&controller, accepted).await;
    let revision = controller.policy().authority_revision();

    let (arrived, go) = controller.before_a_voice_change_claims.arm();
    let making = tokio::spawn({
        let controller = std::sync::Arc::clone(&controller);
        let mutation = mutation.clone();
        async move {
            controller
                .voice_mutation(
                    super::voice_actions::VoiceIngress {
                        actor_id,
                        actor: crate::voice::VoiceActor::Owner,
                        route: None,
                    },
                    &mutation,
                    Method::VoiceStop,
                    revision,
                    carried,
                )
                .await
        }
    });
    arrived.await.expect("the change has looked for a record");
    // Another writer holds the store, and the claim's transaction does not wait for it.
    controller
        .sharing()
        .grants()
        .wait_for_storage_up_to(std::time::Duration::ZERO)
        .expect("the store waits no time for another writer");
    registry
        .execute_batch("BEGIN IMMEDIATE")
        .expect("another writer holds the store");
    let _ = go.send(());
    let given = making.await.expect("the change ran");
    registry
        .execute_batch("ROLLBACK")
        .expect("the other writer lets the store go");
    controller
        .sharing()
        .grants()
        .wait_for_storage_up_to(std::time::Duration::from_secs(5))
        .expect("the store waits as it does");
    let unbegun = given
        .into_answer()
        .expect_err("a claim that cannot be begun is not one this change may be made under");
    assert_eq!(unbegun.code(), ErrorCode::OutcomeUnknown, "{unbegun}");
}

/// A `grant.create` under a fresh action. The repeat of an unfinished one reads what the first
/// attempt wrote and never looks at the request's parameters, so they are left empty.
fn grant_create_request(temp: &kr_ipc::testing::TempHost) -> MutationRequest {
    MutationRequest {
        method: Method::GrantCreate.into(),
        params: ParamsValue::empty(),
        ..revoke_request(temp)
    }
}

/// Writes a claim for `mutation` with nothing recorded under it: an attempt that began and has no
/// outcome, which no attempt is carrying out.
fn an_unfinished_claim(
    registry: &rusqlite::Connection,
    actor_id: &ActorId,
    mutation: &MutationRequest,
) {
    let digest = kr_protocol::digest::mutation_digest(mutation, actor_id).expect("digests it");
    registry
        .execute(
            "INSERT INTO authority_receipts
                 (actor_id, action_id, payload_digest, claimed_at_ms, result, recorded_at_ms,
                  refusal_code, refusal_detail)
             VALUES (?1, ?2, ?3, 1, NULL, NULL, NULL, NULL)",
            rusqlite::params![
                actor_id.as_str(),
                mutation.action_id.get().as_bytes().to_vec(),
                digest.as_bytes().to_vec(),
            ],
        )
        .expect("the claim is written with nothing recorded under it");
}

/// KR-REQ-09.09: a repeat of a `grant.create` whose claim is unfinished, asked of a registry that
/// cannot read what the first attempt wrote, or that holds a row for the share it cannot decode, is
/// told the outcome is unknown, by both lookups. The claim shows the first attempt began, and a
/// transient word would say that nothing took effect and have the share sent again as though
/// nothing had, while a refusal of the argument would say that the request was malformed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeat_of_an_unfinished_share_whose_grants_cannot_be_read_is_told_the_outcome_is_unknown()
 {
    let (temp, controller) = daemon().await;
    let actor_id = ActorId::new("local:test").expect("a principal");
    let mutation = grant_create_request(&temp);
    let registry = rusqlite::Connection::open(temp.environment().registry_database())
        .expect("the registry opens beside the daemon's own handle");
    registry
        .busy_timeout(std::time::Duration::from_secs(10))
        .expect("waits for the daemon's own writes");
    an_unfinished_claim(&registry, &actor_id, &mutation);

    registry
        .execute_batch("ALTER TABLE grants RENAME TO grants_aside;")
        .expect("the grants cannot be read");
    let waiting = told(
        controller
            .retained_authority_answer(&actor_id, &mutation)
            .await,
    );
    let not_waiting = told(controller.retained_authority_change(&actor_id, &mutation));
    registry
        .execute_batch("ALTER TABLE grants_aside RENAME TO grants;")
        .expect("the grants can be read again");
    assert_eq!(waiting.code, ErrorCode::OutcomeUnknown, "{waiting:?}");
    assert_eq!(
        not_waiting.code,
        ErrorCode::OutcomeUnknown,
        "{not_waiting:?}"
    );

    // The row the first attempt wrote for the share is not an encoding of a grant.
    let (grant_id, _invitation_id) =
        kr_protocol::sharing::share_identities(&actor_id, mutation.action_id.get());
    registry
        .execute(
            "INSERT INTO grants (grant_id, recipient_device_id, grant, issued_at_ms)
             VALUES (?1, x'00', x'ff', 1)",
            rusqlite::params![grant_id.get().as_bytes().to_vec()],
        )
        .expect("the row is written");
    let waiting = told(
        controller
            .retained_authority_answer(&actor_id, &mutation)
            .await,
    );
    let not_waiting = told(controller.retained_authority_change(&actor_id, &mutation));
    assert_eq!(waiting.code, ErrorCode::OutcomeUnknown, "{waiting:?}");
    assert_eq!(
        not_waiting.code,
        ErrorCode::OutcomeUnknown,
        "{not_waiting:?}"
    );
}

/// KR-REQ-09.09: a repeat of an unfinished revocation, asked of a registry that cannot read the
/// grants its records are compared with, is told the outcome is unknown. The claim shows the first
/// attempt began and the grants are what say whether it withdrew anything, so a transient word
/// would say that nothing took effect.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeat_of_an_unfinished_revocation_whose_grants_cannot_be_read_is_told_the_outcome_is_unknown()
 {
    let (temp, controller) = daemon().await;
    let actor_id = ActorId::new("local:test").expect("a principal");
    let mutation = revoke_request(&temp);
    let registry = rusqlite::Connection::open(temp.environment().registry_database())
        .expect("the registry opens beside the daemon's own handle");
    registry
        .busy_timeout(std::time::Duration::from_secs(10))
        .expect("waits for the daemon's own writes");
    an_unfinished_claim(&registry, &actor_id, &mutation);

    registry
        .execute_batch("ALTER TABLE grants RENAME TO grants_aside;")
        .expect("the grants cannot be read");
    let waiting = told(
        controller
            .retained_authority_answer(&actor_id, &mutation)
            .await,
    );
    registry
        .execute_batch("ALTER TABLE grants_aside RENAME TO grants;")
        .expect("the grants can be read again");
    assert_eq!(waiting.code, ErrorCode::OutcomeUnknown, "{waiting:?}");
}
