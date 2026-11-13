//! The walks over the method table that hold the local door's routes.
//!
//! A mutation that arrives on a local connection is a local write when the registry lists it as a
//! write with the local ingress. Each has one route (`LocalWrite::of`), and the route's kind says
//! what its answer is labelled. These walks fail for a method added to the table without a route,
//! for a route the envelope does not agree with, and for a method the registry keeps a record of
//! that a route says keeps none.

use kr_protocol::authority::{EffectClass, IdempotencyBehaviour};
use kr_protocol::envelope::ParamsValue;
use kr_protocol::method::Method;

use super::routes::NO_ADMISSION;
use super::the_fence_at_every_effect::{accepted, admitted, daemon, mutation_of, refusal};
use super::writes::LocalWrite;

/// The words that say a mutation is not one this daemon serves.
const NOT_SERVED: &str = "is not a mutation this daemon serves";

/// The local writes that neither a daemon module nor a worker's request table serves, and that the
/// envelope refuses by name: the terminal palette and the root editor's frames.
const NOT_ON_THE_WORKERS_TABLE: [Method; 6] = [
    Method::TerminalPaletteSet,
    Method::RootEditorEnter,
    Method::RootEditorLeave,
    Method::RootEditorFence,
    Method::RootEofDetach,
    Method::RootCommandAccepted,
];

/// Whether the registry holds `method` as a write a local caller makes.
fn is_a_local_write(method: Method) -> bool {
    let entry = method.entry();
    entry.effect == EffectClass::Write
        && entry
            .ingress
            .contains(&kr_protocol::actor::ActorIngress::LocalIpc)
}

/// Whether a module of this daemon serves `method` as a local write.
fn served_by_a_module(method: Method) -> bool {
    super::net::methods::serves(method)
        || crate::transfer::TransferModule::serves(method)
        || crate::voice::VoiceModule::serves(method)
        || crate::catalogue::CatalogueModule::serves(method)
        || crate::project::ProjectModule::serves(method)
        || crate::automation::AutomationModule::serves(method)
        || crate::attention::AttentionModule::serves(method)
        || crate::changeset::ChangeSetModule::serves(method)
}

/// KR-REQ-09.09, 09.12 and 26.16: every local write in the method table has one route, the routes
/// agree with the envelope about which writes this daemon serves, and a route is never the one that
/// says a method is not served for a method the daemon performs. A method added to the table
/// without a route fails here, instead of being refused by name at run time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_local_write_in_the_method_table_has_one_route() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let captured = controller
        .admitted_revision(connection_id)
        .expect("the connection is registered");

    let unrouted: Vec<Method> = Method::ALL
        .iter()
        .copied()
        .filter(|method| LocalWrite::of(*method).is_some() != is_a_local_write(*method))
        .collect();
    assert!(
        unrouted.is_empty(),
        "a local write has a route, and nothing else has: {unrouted:?}"
    );
    for listed in NO_ADMISSION {
        assert!(
            LocalWrite::of(listed).is_some_and(|kind| kind != LocalWrite::NotServed),
            "{listed:?} is held to the fence by name and has no route that performs it"
        );
    }

    let mut not_served = Vec::new();
    for method in Method::ALL.iter().copied() {
        let Some(kind) = LocalWrite::of(method) else {
            continue;
        };
        let received_at = controller.clock.now();
        let envelope = controller
            .check_envelope(
                connection_id,
                &mutation_of(&temp, method, ParamsValue::empty()),
                method,
                received_at,
            )
            .map(|_| ())
            .map_err(|refused| crate::error::ControllerError::from(refused).to_string());
        let says_not_served = envelope
            .as_ref()
            .err()
            .is_some_and(|message| message.contains(NOT_SERVED));
        if kind == LocalWrite::NotServed {
            assert!(
                says_not_served,
                "{method:?} has no daemon route, and the envelope does not refuse it by name: \
                 {envelope:?}"
            );
            assert!(
                (kr_protocol::worker_surface::serves(method)
                    || NOT_ON_THE_WORKERS_TABLE.contains(&method))
                    && !served_by_a_module(method),
                "{method:?} is refused as not served, and a worker or a module serves it"
            );
            not_served.push(method);
            continue;
        }
        assert!(
            !says_not_served,
            "{method:?} has a route, and the envelope refuses it as not served"
        );
        let answered = controller
            .write_method(
                &actor_id,
                &mutation_of(&temp, method, ParamsValue::empty()),
                method,
                connection_id,
                None,
                Some(accepted(&controller)),
                Some(captured),
            )
            .await
            .into_answer_for_test();
        assert!(
            refusal(&answered).is_none_or(|error| !error.message.contains(NOT_SERVED)),
            "{method:?} has a route, and the route refuses it as not served: {answered:?}"
        );
    }
    println!("local writes this daemon does not serve: {not_served:?}");
    assert!(
        not_served.contains(&Method::SessionAttach),
        "the worker's own writes are among them"
    );
}

/// KR-REQ-09.09: a route agrees with the registry about records. A method the registry says is
/// deduplicated by its action is never routed as one that keeps no record of its action; every
/// route that says its answer derives from older records, or that keeps none, says why.
#[test]
fn a_route_agrees_with_the_registry_about_records() {
    for method in Method::ALL.iter().copied() {
        let Some(kind) = LocalWrite::of(method) else {
            continue;
        };
        match kind {
            // The worker keeps these records: `session.attach` is deduplicated and is not the
            // daemon's to record. The walk above holds the set.
            LocalWrite::NotServed => {}
            LocalWrite::Unrecorded(reason) => {
                assert!(
                    method.entry().idempotency != IdempotencyBehaviour::ActionDeduplicated,
                    "{method:?} is deduplicated by its action and is routed as keeping no record"
                );
                assert!(
                    !reason.is_empty(),
                    "{method:?} is unrecorded and says no why"
                );
                println!("{method:?} is unrecorded: {reason}");
            }
            LocalWrite::Derived(reason) => {
                assert!(!reason.is_empty(), "{method:?} is derived and says no why");
                println!("{method:?} is derived: {reason}");
            }
            _ => {}
        }
    }
}
