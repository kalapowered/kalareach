//! A phone opens a paired host's sessions: the host's half.
//!
//! One real daemon on the loopback network, started the way a host starts one, and the workers it
//! adopts: each worker's own service on its own socket, with its journal, its spool, its shell,
//! its question ledger and its broker, run in this process. The only thing a test supplies in
//! place of the product is an agent's upstream, the transport the broker hands a prompt to.
//!
//! Devices pair over the network and speak to the daemon through the client library, so what each
//! test asserts is read from the daemon's answer to a device.

mod net_support;

use std::sync::Arc;

use kr_protocol::agent::{
    AgentCapabilitiesParams, AgentCapabilitiesResult, AgentMutationTarget, AgentPromptParams,
    AgentSnapshotParams, AgentSnapshotResult, PromptText,
};
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::ids::{AgentBindingRevision, SessionEpoch};
use kr_protocol::method::Method;
use kr_protocol::recovery::{EventsSnapshotParams, EventsSnapshotResult};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{DurationMs, Nullable, TimestampMs};

use net_support::worker::{Adopted, Upstream, Worker};
use net_support::{Device, connect, pair_with, proposal};

/// The target of an agent mutation on a worker's session.
fn target(
    adopted: &Adopted,
    worker: &Worker,
    instance: kr_protocol::ids::ApplicationInstanceId,
) -> ActionTarget {
    ActionTarget {
        environment_id: adopted.environment_id(),
        session_id: Nullable::some(worker.session_id),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::some(instance),
        agent_binding_revision: Nullable::some(Worker::BINDING),
    }
}

/// A daemon reaches a worker's agent: the device finds the instance in the session's snapshot,
/// reads its capabilities and conversation, and its prompt reaches the upstream the broker
/// dispatches on.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_device_reads_and_prompts_an_agent_on_a_worker_the_daemon_adopted() {
    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let upstream = Arc::new(Upstream::default());
    let instance = worker.register_agent(Arc::clone(&upstream));
    worker
        .service
        .broker()
        .observe(
            instance,
            "message",
            "ready when you are",
            TimestampMs::new(2),
        )
        .expect("the agent has said something");

    let device = Device::create().await;
    let mut whole = proposal(&[ActionRight::SessionView, ActionRight::AgentPrompt]);
    whole.history.lower_bound_ms = Nullable::some(TimestampMs::new(0));
    let record = pair_with(&adopted.host, &device, &adopted.owner, whole).await;
    let session = connect(&adopted.host, &device, &record).await;

    let snapshot: EventsSnapshotResult = session
        .read(
            Method::EventsSnapshot,
            &EventsSnapshotParams {
                session_id: worker.session_id,
                agent_resources_from: Nullable::null(),
            },
        )
        .await
        .expect("the snapshot is read");
    let found: Vec<_> = snapshot
        .agent_instances
        .instances
        .iter()
        .map(|found| found.application_instance_id)
        .collect();
    assert_eq!(found, vec![instance]);

    let subject = kr_worker::broker::subject(worker.session_id, instance);
    let capabilities: AgentCapabilitiesResult = session
        .read(
            Method::AgentCapabilities,
            &AgentCapabilitiesParams { subject },
        )
        .await
        .expect("the capabilities are read");
    assert_eq!(
        capabilities.binding.binding_revision,
        AgentBindingRevision::new(1)
    );
    let conversation: AgentSnapshotResult = session
        .read(
            Method::AgentSnapshot,
            &AgentSnapshotParams {
                subject,
                from_node: Nullable::null(),
            },
        )
        .await
        .expect("the conversation is read");
    assert_eq!(conversation.entries.len(), 1);

    let settled = session
        .mutate(
            Method::AgentPromptSubmit,
            target(&adopted, worker, instance),
            None,
            &ParamsValue::empty(),
            &AgentPromptParams {
                target: AgentMutationTarget {
                    subject,
                    binding_revision: AgentBindingRevision::new(1),
                },
                draft_id: Nullable::null(),
                text: Nullable::some(PromptText::new("run the tests").expect("a prompt")),
            },
            DurationMs::new(60_000),
        )
        .await
        .expect("the prompt is admitted");
    let result: kr_protocol::agent::AgentMutationResult = settled
        .to_typed()
        .expect("the prompt is answered with its result");
    assert_eq!(
        result.provenance,
        kr_protocol::broker::ActionProvenance::UpstreamTypedRpc
    );
    assert_eq!(upstream.prompts(), vec!["run the tests".to_owned()]);

    session.close();
    adopted.stop().await;
}
