//! An agent's semantic history and privacy mode, read the way a paired device reads it.
//!
//! One real daemon on the loopback network and a real worker it adopts: the worker's own broker
//! holds the agent's semantic history, and a device paired with the right to view the session
//! reads it with `agent.snapshot` over its own connection.
//!
//! Section 24: privacy mode disables content-history retention prospectively, removes what was
//! retained when it is enabled, and when it is disabled starts new retention from that point
//! without reconstructing what was omitted.

#![cfg(unix)]

mod net_support;

use std::sync::Arc;

use kr_protocol::agent::{AgentSnapshotParams, AgentSnapshotResult};
use kr_protocol::ids::ApplicationInstanceId;
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Nullable, TimestampMs};
use net_support::worker::{Adopted, Upstream};
use net_support::{Device, RawDevice, pair_with, proposal};

/// What a device paired with the right to view the session reads of the agent's history, as the
/// texts of its entries and whether the daemon reports that history is missing.
async fn read_history(
    adopted: &Adopted,
    device: &Device,
    record: &kr_controller::service::net::devices::DeviceRecord,
    instance: ApplicationInstanceId,
) -> (Vec<String>, bool) {
    let connection = RawDevice::connect(&adopted.host, device, record).await;
    let snapshot: AgentSnapshotResult = connection
        .read(
            Method::AgentSnapshot,
            &AgentSnapshotParams {
                subject: kr_worker::broker::subject(adopted.workers[0].session_id, instance),
                from_node: Nullable::null(),
            },
        )
        .await
        .expect("the snapshot is read")
        .to_typed()
        .expect("decodes");
    connection.close();
    let texts = snapshot
        .entries
        .iter()
        .map(|entry| entry.text.clone())
        .collect();
    (texts, snapshot.history_gap)
}

/// KR-REQ-24.27 and KR-REQ-15.20: privacy mode removes an agent's retained semantic history when
/// it is enabled, records none while it is on, and records again from the moment it is disabled. A
/// device that reads the agent's history after the change finds only what happened after it, and
/// is told that earlier history is missing; the control is the same read before the change.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn privacy_mode_removes_an_agents_semantic_history_and_records_none_while_it_is_on() {
    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let instance = worker.register_agent(Arc::new(Upstream::default()));
    let broker = worker.service.broker();
    broker
        .observe(instance, "message", "before", TimestampMs::new(10))
        .expect("the agent has said something");

    let device = Device::create().await;
    let mut grant = proposal(&[ActionRight::SessionView]);
    grant.history.lower_bound_ms = Nullable::some(TimestampMs::new(0));
    let record = pair_with(&adopted.host, &device, &adopted.owner, grant).await;

    let (control, _) = read_history(&adopted, &device, &record, instance).await;
    assert_eq!(control, vec!["before".to_owned()]);

    adopted.set_privacy(true).await;
    broker
        .observe(instance, "message", "during", TimestampMs::new(11))
        .expect("the agent said something while privacy mode was on");
    let (private, _) = read_history(&adopted, &device, &record, instance).await;
    assert!(private.is_empty(), "{private:?}");

    adopted.set_privacy(false).await;
    broker
        .observe(instance, "message", "after", TimestampMs::new(12))
        .expect("the agent said something after");
    let (after, gap) = read_history(&adopted, &device, &record, instance).await;
    assert_eq!(after, vec!["after".to_owned()]);
    assert!(gap, "history before the change is reported missing");
    adopted.stop().await;
}
