//! How long a paired device is without a connection to this host, measured by the host and reported
//! by `host.doctor`.
//!
//! The counting itself, which is a matter of the clock and of the order connections come and go
//! in, is the unit cases of `net/reconnects.rs`. What is shown here is that a real daemon on the
//! network counts it: a device that connects, goes and comes back is a gap in the report its owner
//! reads, and the first connection of a device is not.

mod net_support;

use kr_crypto::keys::DeviceKeys;
use kr_protocol::hostinfo::HostDoctorResult;
use kr_protocol::method::Method;
use kr_protocol::metrics::{Attempt, Environment, MetricOutcome};
use kr_protocol::rights::ActionRight;
use net_support::{Device, Host, connect, pair_with, proposal};

/// A grant that sees a session and nothing more: all a device needs to hold a connection.
const VIEWER: &[ActionRight] = &[ActionRight::SessionView];

/// How many times a device is sent away and brought back before the case gives up waiting for the
/// host to have counted its connection as ended.
const CYCLES: usize = 40;

async fn doctor(host: &Host) -> HostDoctorResult {
    let mut client = host.client().await;
    client
        .request(Method::HostDoctor, &())
        .await
        .expect("the call reaches the daemon")
        .expect("host.doctor is served on the local socket")
        .to_typed()
        .expect("a result of the declared shape")
}

/// KR-REQ-26.43: a device that connects, goes and comes back is one reconnection in what the host
/// reports about itself, with how it reached the host and which attempt it was, and its first
/// connection is none.
///
/// The host counts a connection as ended when it has noticed the control stream go, which the
/// device's own close does not wait for, so a device that comes back at once can arrive before the
/// host has seen it leave and is then not reconnecting yet. The case goes round until a gap shows,
/// and fails if forty rounds of the same race all lose it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_26_43_a_device_that_comes_back_is_a_reconnection_in_what_the_host_reports() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = Device::create().await;
    let record = pair_with(&host, &device, &owner, proposal(VIEWER)).await;

    let mut session = connect(&host, &device, &record).await;
    assert!(
        doctor(&host).await.metrics.reconnect_time.is_empty(),
        "a device's first connection since the host started has no gap before it"
    );

    for _ in 0..CYCLES {
        session.close();
        session = connect(&host, &device, &record).await;
        if !doctor(&host).await.metrics.reconnect_time.is_empty() {
            break;
        }
    }
    let report = doctor(&host).await.metrics;
    assert!(
        !report.reconnect_time.is_empty(),
        "the host counted none of the {CYCLES} times the device came back"
    );
    for series in &report.reconnect_time {
        assert_eq!(series.outcome, MetricOutcome::Ok, "{series:?}");
        assert_eq!(series.attempt, Attempt::One, "{series:?}");
        assert_eq!(series.environment, Environment::Development, "{series:?}");
        assert!(series.count.get() >= 1);
        assert!(series.longest_ms.get() <= series.total_ms.get());
    }
    assert_eq!(
        report.terminal_parse_fault.len() + report.adapter_failure.len(),
        0,
        "nothing else was measured here"
    );

    session.close();
    host.stop().await;
}
