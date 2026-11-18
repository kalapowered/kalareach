//! What the owner and a paired device are told when the host carried an action out and the record
//! of what it came to cannot be written.
//!
//! A transient word says nothing took effect, so it is not the word for an action that was carried
//! out. A service performs the action and then records its answer, and a worker that closes a
//! session hands its closure over for the daemon to record; a store that refuses the record leaves
//! the action done and the answer unkept, and the caller is told the outcome is unknown.

use kr_protocol::envelope::ParamsValue;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::ActorId;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;

use super::a_copy_from_a_services_record::{EVERY_RIGHT, mutation_of};
use super::write_boundary::paired_connection;
use crate::service::a_close_a_worker_never_answers as fake;

/// KR-REQ-09.09: the project service performs `project.init` and records its answer in a second
/// write. With the store refusing the write that records an answer, the owner is told the
/// outcome is unknown, and the repository exists; with the store whole, the same request is answered.
///
/// A repository is made with Git, which a Windows host does not run: there the request is refused
/// before anything is made, as the Windows case below shows, and the project service's own leg of
/// this rule has no case on Windows. The rule that an action performed whose answer could not be
/// kept is told as of an unknown outcome is shown on every platform by
/// `kr_req_23_24_a_share_whose_result_cannot_be_kept_is_found_and_holds_its_subject` in
/// `a_share_beside_one_that_runs`.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_project_action_performed_and_not_recorded_is_told_the_outcome_is_unknown() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let (connection, _) = paired_connection(controller, 79, EVERY_RIGHT);
    let parent = world._temp.root().join("repositories");
    std::fs::create_dir(&parent).expect("a directory to make the repositories in");
    let actor = ActorId::new("local:501").expect("an actor");
    let store = rusqlite::Connection::open(
        kr_project::ProjectService::root_of(&controller.paths)
            .join(kr_project::store::STORE_FILE_NAME),
    )
    .expect("the project store opens beside the service's own handle");

    for refused in [false, true] {
        let name = if refused { "unrecorded" } else { "recorded" };
        let mutation = mutation_of(
            &world,
            &connection,
            Method::ProjectInit,
            91,
            ParamsValue::from_typed(&kr_protocol::project::ProjectInitParams {
                destination: kr_protocol::project::DestinationRequest {
                    environment_id: world.environment_id,
                    parent: kr_protocol::project::DestinationParent::Host {
                        path: parent.to_string_lossy().into_owned(),
                    },
                    name: name.to_owned(),
                },
                label: name.to_owned(),
                initial_branch: Nullable::some("main".to_owned()),
            })
            .expect("encodes"),
        );
        if refused {
            // The write that keeps an answer carries one; the writes that claim the action and
            // settle it do not insert a row with a result.
            store
                .execute_batch(
                    "CREATE TRIGGER the_answer_is_not_kept BEFORE INSERT ON actions
                     WHEN NEW.result IS NOT NULL
                     BEGIN SELECT RAISE(ABORT, 'the store keeps no answer'); END;",
                )
                .expect("the store is made to refuse the write that keeps an answer");
        }
        let given = controller
            .project()
            .write(
                &actor,
                &mutation,
                Method::ProjectInit,
                || Ok(()),
                || Ok(()),
                None,
            )
            .await;
        let answer = given.into_answer_for_test();
        if refused {
            let told = answer.expect_err("the answer cannot be kept");
            assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");
            assert!(
                parent.join(name).join(".git").is_dir(),
                "the repository was made before the answer could not be kept"
            );
        } else {
            answer.expect("with the store whole the repository is made and the answer given");
        }
    }
    world.serving.abort();
}

/// KR-REQ-09.09: a platform that runs no Git refuses `project.init` before anything is made, with
/// the word of a host that is not set up for the work, so no repository exists for an answer that
/// is not kept to leave unknown.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_project_action_that_needs_git_is_refused_where_no_git_is_run() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let (connection, _) = paired_connection(controller, 79, EVERY_RIGHT);
    let parent = world._temp.root().join("repositories");
    std::fs::create_dir(&parent).expect("a directory to make the repositories in");
    let actor = ActorId::new("local:501").expect("an actor");
    let mutation = mutation_of(
        &world,
        &connection,
        Method::ProjectInit,
        91,
        ParamsValue::from_typed(&kr_protocol::project::ProjectInitParams {
            destination: kr_protocol::project::DestinationRequest {
                environment_id: world.environment_id,
                parent: kr_protocol::project::DestinationParent::Host {
                    path: parent.to_string_lossy().into_owned(),
                },
                name: "refused".to_owned(),
            },
            label: "refused".to_owned(),
            initial_branch: Nullable::some("main".to_owned()),
        })
        .expect("encodes"),
    );
    let given = controller
        .project()
        .write(
            &actor,
            &mutation,
            Method::ProjectInit,
            || Ok(()),
            || Ok(()),
            None,
        )
        .await;
    let told = given
        .into_answer_for_test()
        .expect_err("a platform that runs no Git refuses the request");
    assert_eq!(told.code, ErrorCode::HostNotConfigured, "{told:?}");
    assert!(
        told.message.contains("Git is not run on this platform"),
        "the word says why: {told:?}"
    );
    assert!(
        !parent.join("refused").exists(),
        "nothing was made before the refusal"
    );
    world.serving.abort();
}

/// KR-REQ-09.09: a close the worker answers with the closure of the session it has ended. The
/// answer is the worker's, and the daemon writes the record on a task of its own: with the registry
/// refusing the write that records it, the device is still told that the session closed, with the
/// closure the worker gave, and the worker has the close; a repeat of the close is answered from
/// what the daemon knows without asking the worker again, while the registry still refuses; once
/// the registry takes the write, the closure is recorded durably.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_whose_closure_cannot_be_recorded_is_answered_and_recorded_when_the_registry_takes_it()
 {
    use kr_protocol::envelope::{ActionTarget, ControlFrame, Outcome, Response};
    use kr_protocol::session::{Durability, SessionCloseResult};

    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{
        self as scripted, Scripted, recorded,
    };

    for refused in [false, true] {
        let script = Scripted::new();
        script.accepts_with_its_closure();
        let world = scripted::scripted(&script).await;
        let controller = &world.controller;
        let (connection, _) = paired_connection(controller, 36, EVERY_RIGHT);
        let close = |action: u64| {
            let mut close = mutation_of(
                &world,
                &connection,
                Method::SessionClose,
                action,
                ParamsValue::from_typed(&kr_protocol::session::SessionCloseParams {
                    session_id: world.session_id,
                })
                .expect("encodes"),
            );
            close.target = ActionTarget {
                environment_id: world.environment_id,
                session_id: Nullable::some(world.session_id),
                session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            };
            close
        };
        let registry = || {
            rusqlite::Connection::open(controller.paths.registry_database())
                .expect("the registry opens beside the daemon's own handle")
        };
        // What a close answers with, and the closure it carries, which is the worker's own.
        let closure_in = |answered: &super::decision::Answered| -> SessionCloseResult {
            let ControlFrame::Response(Response {
                outcome: Outcome::Ok(value),
                ..
            }) = answered.frame()
            else {
                panic!(
                    "the close is answered with a result: {:?}",
                    answered.frame()
                );
            };
            value.to_typed().expect("decodes")
        };
        if refused {
            registry()
                .execute_batch(
                    "CREATE TRIGGER the_closure_is_not_kept BEFORE INSERT ON tombstones
                     BEGIN SELECT RAISE(ABORT, 'the registry keeps no closure'); END;",
                )
                .expect("the registry is made to refuse the write that records a closure");
        }

        let answered = connection
            .answer_now(ControlFrame::Mutation(Box::new(close(91))))
            .await
            .expect("the close is answered");
        let first = closure_in(&answered);
        assert_eq!(
            first.closure.0.as_ref().map(|record| record.durability),
            Some(Durability::Durable),
            "the closure the worker gave is in the answer, refused {refused}: {first:?}"
        );
        assert_eq!(
            script.forwarded().len(),
            1,
            "the close reached the worker, refused {refused}"
        );
        if refused {
            // The registry still refuses the write, so the closure is known and not recorded: the
            // repeat is answered from what the daemon knows, whichever way the retries run.
            let repeated = connection
                .answer_now(ControlFrame::Mutation(Box::new(close(92))))
                .await
                .expect("the repeat is answered");
            let again = closure_in(&repeated);
            assert_eq!(again.durability, Durability::Durable, "{again:?}");
            assert_eq!(
                again.closure.0.as_ref().map(|record| record.session_id),
                Some(world.session_id),
                "{again:?}"
            );
            assert_eq!(
                script.forwarded().len(),
                1,
                "the repeat is answered from what the daemon knows and does not reach the worker"
            );
            registry()
                .execute_batch("DROP TRIGGER the_closure_is_not_kept;")
                .expect("the registry takes a closure again");
        }
        // The write is tried again when the closure is asked about, so a close sent now is
        // answered whichever write is running, and the closure is recorded.
        let mut action = 93;
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            while !recorded(&world).await {
                if refused {
                    connection
                        .answer_now(ControlFrame::Mutation(Box::new(close(action))))
                        .await
                        .expect("a repeat is answered");
                    action += 1;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("the closure was never recorded, refused {refused}"));
        let record = controller
            .registry
            .lock()
            .await
            .closure(world.session_id)
            .expect("the registry answers")
            .expect("the closure is recorded");
        assert_eq!(
            record.durability,
            Durability::Durable,
            "the record is durable, refused {refused}"
        );
        world.serving.abort();
    }
}
