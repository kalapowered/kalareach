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

use super::a_copy_from_a_services_record::{EVERY_RIGHT, mutation_of, refusal_of};
use super::write_boundary::paired_connection;
use crate::service::a_close_a_worker_never_answers as fake;

/// KR-REQ-09.09: the project service performs `project.init` and records its answer in a second
/// write. With the store refusing the write that records an answer, the owner is told the
/// outcome is unknown, and the repository exists; with the store whole, the same request is answered.
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

/// KR-REQ-09.09: a close the worker answers with the closure of the session it has ended. The
/// daemon records that closure before it passes the answer on. With the registry refusing the write
/// that records it, the device is told the outcome is unknown, and the worker has the close; with
/// the registry whole the same close is answered and the closure is recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_whose_closure_cannot_be_recorded_is_told_the_outcome_is_unknown() {
    use kr_protocol::envelope::{ActionTarget, ControlFrame, Outcome, Response};

    use crate::service::a_read_that_meets_a_worker_on_its_way_out::{self as scripted, Scripted};

    for refused in [false, true] {
        let script = Scripted::new();
        script.accepts_with_its_closure();
        let world = scripted::scripted(&script).await;
        let controller = &world.controller;
        let (connection, _) = paired_connection(controller, 36, EVERY_RIGHT);
        let mut close = mutation_of(
            &world,
            &connection,
            Method::SessionClose,
            91,
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
        if refused {
            rusqlite::Connection::open(controller.paths.registry_database())
                .expect("the registry opens beside the daemon's own handle")
                .execute_batch(
                    "CREATE TRIGGER the_closure_is_not_kept BEFORE INSERT ON tombstones
                     BEGIN SELECT RAISE(ABORT, 'the registry keeps no closure'); END;",
                )
                .expect("the registry is made to refuse the write that records a closure");
        }

        let answered = connection
            .answer_now(ControlFrame::Mutation(Box::new(close)))
            .await
            .expect("the close is answered");
        assert_eq!(
            script.forwarded().len(),
            1,
            "the close reached the worker, refused {refused}"
        );
        if refused {
            let told = refusal_of(&answered);
            assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");
        } else {
            assert!(
                matches!(
                    answered.frame(),
                    ControlFrame::Response(Response {
                        outcome: Outcome::Ok(_),
                        ..
                    })
                ),
                "with the registry whole the close is answered: {:?}",
                answered.frame()
            );
        }
        world.serving.abort();
    }
}
