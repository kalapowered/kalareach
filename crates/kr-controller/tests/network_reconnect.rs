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
use kr_protocol::metrics::{
    Environment, HostMetrics, MetricOutcome, MetricsReport, ReconnectAttempt,
};
use kr_protocol::rights::ActionRight;
use net_support::{Device, Host, MovedClocks, connect, pair_with, paired_dial, proposal};

/// A grant that sees a session and nothing more: all a device needs to hold a connection.
const VIEWER: &[ActionRight] = &[ActionRight::SessionView];

/// How many times a device is sent away and brought back before the case gives up waiting for the
/// host to have counted its connection as ended.
const CYCLES: usize = 40;

/// What the host says it counted, to its owner at the machine.
async fn counted(host: &Host) -> MetricsReport {
    let mut client = host.client().await;
    let result: HostDoctorResult = client
        .request(Method::HostDoctor, &())
        .await
        .expect("the call reaches the daemon")
        .expect("host.doctor is served on the local socket")
        .to_typed()
        .expect("a result of the declared shape");
    match result.metrics {
        Some(HostMetrics::Counted(report)) => report,
        other => panic!("the owner at the machine is given the report: {other:?}"),
    }
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
        counted(&host).await.reconnect_time.is_empty(),
        "a device's first connection since the host started has no gap before it"
    );

    for _ in 0..CYCLES {
        session.close();
        session = connect(&host, &device, &record).await;
        // The host counts a connection when it admits it, which is after the transport's handshake
        // that `connect` waits for; a request it answers is one it has admitted.
        session
            .read::<_, kr_protocol::hostinfo::HostInfoResult>(Method::HostInfo, &())
            .await
            .expect("the host answers the device that came back");
        if !counted(&host).await.reconnect_time.is_empty() {
            break;
        }
    }
    let report = counted(&host).await;
    assert!(
        !report.reconnect_time.is_empty(),
        "the host counted none of the {CYCLES} times the device came back"
    );
    // The round that showed the first gap is the round that counted it, once: the loop ends there.
    assert_eq!(report.reconnect_time.len(), 1, "{report:?}");
    for series in &report.reconnect_time {
        assert_eq!(series.outcome, MetricOutcome::Ok, "{series:?}");
        assert_eq!(series.attempt, ReconnectAttempt::One, "{series:?}");
        assert_eq!(series.environment, Environment::Development, "{series:?}");
        assert_eq!(series.count.get(), 1, "{series:?}");
        assert_eq!(series.longest_ms, series.total_ms, "{series:?}");
    }
    assert_eq!(
        report.terminal_parse_fault.len() + report.adapter_failure.len(),
        0,
        "nothing else was measured here"
    );

    session.close();
    host.stop().await;
}

/// KR-REQ-09.17 and KR-REQ-26.43: a device that comes back after its grant ran out, in a run that
/// had anchored the grant, is refused at admission and counted refused in what the host reports,
/// and not admitted and counted ok before the grant's own watch ends it. The host has seen its
/// first connection end before the clock moves, so the return is a reconnection, and no one has
/// observed the end: the anchor is answered from memory.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_09_17_a_device_that_comes_back_after_its_anchored_grant_ran_out_is_counted_refused()
{
    let owner = DeviceKeys::generate().expect("owner keys");
    let moved = MovedClocks::new();
    let host = Host::start_on_clocks(&owner, moved.clocks()).await;
    let device = Device::create().await;
    let record = pair_with(&host, &device, &owner, proposal(VIEWER)).await;

    // The first connection anchors the grant, and ends.
    let first = connect(&host, &device, &record).await;
    first
        .read::<_, kr_protocol::hostinfo::HostInfoResult>(Method::HostInfo, &())
        .await
        .expect("the host answers the device");
    first.close();
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        while host.controller().network_connections_served() > 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the host sees the connection end");

    // The grant is a day's: two days on, on both clocks, it has run out, and nothing has observed
    // that.
    moved.advance(std::time::Duration::from_secs(2 * 24 * 60 * 60));
    if let Ok(transport) = paired_dial(&host, &device, &record).try_dial().await {
        let session =
            kr_client::session::Session::start(std::sync::Arc::new(transport)).expect("a session");
        session
            .read::<_, kr_protocol::hostinfo::HostInfoResult>(Method::HostInfo, &())
            .await
            .expect_err("the host turns a device with no grant away");
    }
    let report = counted(&host).await;
    assert!(
        report
            .reconnect_time
            .iter()
            .any(|series| series.outcome == MetricOutcome::Refused),
        "the return is counted refused: {report:?}"
    );
    assert!(
        report
            .reconnect_time
            .iter()
            .all(|series| series.outcome != MetricOutcome::Ok),
        "and not admitted: {report:?}"
    );
    host.stop().await;
}
