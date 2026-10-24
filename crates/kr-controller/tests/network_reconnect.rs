//! How long a paired device is without a connection to this host, measured by the host and reported
//! by `host.doctor`.
//!
//! The counting itself, which is a matter of the clock and of the order connections come and go
//! in, is the unit cases of `net/reconnects.rs`. What is shown here is that a real daemon on the
//! network counts it: a device that connects, goes and comes back is a gap in the report its owner
//! reads, the first connection of a device is not, and a connection the host turns away after a
//! gap is a refused attempt, whichever of the host's refusals turns it away.

mod net_support;

use kr_controller::service::net::devices::DeviceRecord;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::hostinfo::{HostDoctorResult, HostInfoResult};
use kr_protocol::method::Method;
use kr_protocol::metrics::{
    Environment, HostMetrics, MetricOutcome, MetricsReport, ReconnectAttempt,
};
use kr_protocol::rights::ActionRight;
use net_support::{Device, Host, Moved, connect, pair_with, paired_dial, proposal};

/// A grant that sees a session and nothing more: all a device needs to hold a connection.
const VIEWER: &[ActionRight] = &[ActionRight::SessionView];

/// How long the host is given to do what a case waits for, which it does without being asked
/// again: a liveness bound, not a measurement.
const LIVENESS: std::time::Duration = std::time::Duration::from_secs(120);

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

/// A device the host has served and that has gone, and the host has recorded that its connection
/// ended: the next connection of it is a reconnection, and the host has seen no attempt of it since.
async fn a_device_that_has_come_and_gone(
    host: &Host,
    owner: &DeviceKeys,
) -> (Device, DeviceRecord) {
    let device = Device::create().await;
    let record = pair_with(host, &device, owner, proposal(VIEWER)).await;
    let session = connect(host, &device, &record).await;
    session
        .read::<_, HostInfoResult>(Method::HostInfo, &())
        .await
        .expect("the host serves the device");
    assert!(
        counted(host).await.reconnect_time.is_empty(),
        "a device's first connection since the host started has no gap before it"
    );
    session.close();
    let started = tokio::time::Instant::now();
    while host.connections_of(&record) != 0 {
        assert!(
            started.elapsed() < LIVENESS,
            "the host never recorded that the connection ended"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    (device, record)
}

/// The series the report holds, as outcome, attempt and how many gaps each counts.
fn reconnections(report: &MetricsReport) -> Vec<(MetricOutcome, ReconnectAttempt, u64)> {
    let mut series: Vec<_> = report
        .reconnect_time
        .iter()
        .map(|series| {
            assert_eq!(series.environment, Environment::Development, "{series:?}");
            (series.outcome, series.attempt, series.count.get())
        })
        .collect();
    series.sort_by_key(|(outcome, attempt, _)| (outcome.as_str(), attempt.as_str()));
    series
}

/// Has the connection the host is holding go on, and says what the device was told: the host
/// refused it. The host counts a refusal before it says so.
async fn refused(held: &kr_client::session::Session) {
    tokio::time::timeout(
        LIVENESS,
        held.read::<_, HostInfoResult>(Method::HostInfo, &()),
    )
    .await
    .expect("the host answers the connection it turned away")
    .expect_err("a connection the host refused is served nothing");
}

/// KR-REQ-26.43: a device that connects, goes and comes back is one reconnection in what the host
/// reports about itself, with how it reached the host and which attempt it was, and its first
/// connection is none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_26_43_a_device_that_comes_back_is_a_reconnection_in_what_the_host_reports() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (device, record) = a_device_that_has_come_and_gone(&host, &owner).await;

    let session = connect(&host, &device, &record).await;
    // The host counts a connection when it admits it, which is after the transport's handshake
    // that `connect` waits for; a request it answers is one it has admitted.
    session
        .read::<_, HostInfoResult>(Method::HostInfo, &())
        .await
        .expect("the host answers the device that came back");
    let report = counted(&host).await;
    assert_eq!(
        reconnections(&report),
        vec![(MetricOutcome::Ok, ReconnectAttempt::One, 1)]
    );
    for series in &report.reconnect_time {
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

/// KR-REQ-26.43: a connection the host turns away after the device has been gone is a refused
/// attempt, and the connection that follows it is the second.
///
/// The host is made to refuse at its registration of the connection: the authority the transport
/// authorised it under is withdrawn while the host holds it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_26_43_a_connection_the_host_does_not_register_is_a_refused_attempt() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (device, record) = a_device_that_has_come_and_gone(&host, &owner).await;

    let (arrived, release) = host.controller().pause_connection_registration();
    let held = connect(&host, &device, &record).await;
    arrived
        .await
        .expect("the host holds the connection before it registers it");
    host.controller()
        .revoke_authority()
        .await
        .expect("the revocation is recorded");
    release
        .send(())
        .expect("the host is still holding the connection");
    refused(&held).await;
    assert_eq!(
        reconnections(&counted(&host).await),
        vec![(MetricOutcome::Refused, ReconnectAttempt::One, 1)]
    );
    held.close();

    let admitted = connect(&host, &device, &record).await;
    admitted
        .read::<_, HostInfoResult>(Method::HostInfo, &())
        .await
        .expect("a connection authorised after the withdrawal is served");
    assert_eq!(
        reconnections(&counted(&host).await),
        vec![
            (MetricOutcome::Ok, ReconnectAttempt::TwoToThree, 1),
            (MetricOutcome::Refused, ReconnectAttempt::One, 1)
        ],
        "the host admitted the second connection after it turned the first away"
    );
    admitted.close();
    host.stop().await;
}

/// KR-REQ-26.43: a connection the host turns away because it cannot say whether the device's grant
/// still stands is a refused attempt too. A grant that ends is decided against the clock, and a
/// host whose clock lost its continuity cannot decide it, so it serves no expiring grant until its
/// owner establishes the clock again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_26_43_a_connection_whose_grant_the_clock_cannot_vouch_for_is_a_refused_attempt() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (device, record) = a_device_that_has_come_and_gone(&host, &owner).await;

    let (arrived, release) = host.controller().pause_connection_registration();
    let held = connect(&host, &device, &record).await;
    arrived
        .await
        .expect("the host holds the connection before it registers it");
    host.controller().utc_floor().lose_continuity();
    release
        .send(())
        .expect("the host is still holding the connection");
    refused(&held).await;
    host.controller().utc_floor().establish_continuity();
    assert_eq!(
        reconnections(&counted(&host).await),
        vec![(MetricOutcome::Refused, ReconnectAttempt::One, 1)]
    );
    held.close();

    let admitted = connect(&host, &device, &record).await;
    admitted
        .read::<_, HostInfoResult>(Method::HostInfo, &())
        .await
        .expect("the owner establishing the clock lets the grant stand");
    assert_eq!(
        reconnections(&counted(&host).await),
        vec![
            (MetricOutcome::Ok, ReconnectAttempt::TwoToThree, 1),
            (MetricOutcome::Refused, ReconnectAttempt::One, 1)
        ]
    );
    admitted.close();
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
    let (moved, clocks) = Moved::new();
    let host = Host::start_on_clocks(&owner, clocks).await;
    // The first connection anchors the grant, and ends.
    let (device, record) = a_device_that_has_come_and_gone(&host, &owner).await;

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
