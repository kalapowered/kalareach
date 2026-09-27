//! How long a handover of plugin admissions may hold a connection: every part sent and every part
//! of the report has its own time, so a slow worker holds the connection for one part's time and a
//! long report whose parts each come in time is read whole. These tests drive a real socket with a
//! worker that answers at the pace the test sets.

#![cfg(unix)]

use std::time::Duration;

use kr_ipc::IpcError;
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::framed::split;
use kr_protocol::admission::{FrameId, PluginAdmissions, PluginAdmissionsAck, RevocationPolicy};
use kr_protocol::envelope::ControlFrame;
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::{ActionWindow, PROTOCOL_VERSION, ReceiveLimits};
use kr_protocol::ids::{
    ActionWindowId, BootEpoch, BuildId, ConnectionId, ControllerGeneration, EnvironmentId,
    SessionId,
};
use kr_protocol::local::{LocalClientKind, LocalHelloAck, LocalPeer, LocalRole};
use kr_protocol::scalars::{CanonicalSet, DurationMs, Nullable, TimestampMs, U64, Uuid};

/// The time each part has in these tests.
const PER_PART: Duration = Duration::from_millis(400);

/// How long a test waits for an exchange that must have ended by then.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(20);

fn frame() -> FrameId {
    FrameId {
        generation: ControllerGeneration::new(1),
        revision: U64::new(1),
        round: U64::new(1),
    }
}

fn snapshot() -> Vec<PluginAdmissions> {
    vec![PluginAdmissions {
        environment_id: EnvironmentId::new(Uuid::NIL),
        frame: frame(),
        part: 1,
        parts: 1,
        policy: RevocationPolicy::WarnOnly,
        packages: Vec::new(),
        releases: Vec::new(),
    }]
}

fn report_part(part: u32, parts: u32) -> ControlFrame {
    ControlFrame::PluginAdmissionsAck(Box::new(PluginAdmissionsAck {
        session_id: SessionId::new(Uuid::NIL),
        frame: frame(),
        report_seq: U64::new(1),
        part,
        parts,
        bindings: Vec::new(),
        refusals: Vec::new(),
    }))
}

/// A worker that takes the snapshot's parts and then writes each report part after its delay,
/// and afterwards holds the connection open.
struct Worker {
    _tree: kr_ipc::testing::TempHost,
    endpoint: kr_ipc::paths::Endpoint,
    serving: tokio::task::JoinHandle<()>,
}

impl Worker {
    fn start(snapshot_parts: usize, report: Vec<(Duration, ControlFrame)>) -> Self {
        let tree = kr_ipc::testing::TempHost::create();
        let endpoint = tree
            .environment()
            .controller_endpoint()
            .expect("an endpoint path");
        let listener = Listener::bind(&endpoint).expect("a local endpoint");
        let environment_id = tree.environment_id();
        let serving = tokio::spawn(async move {
            serve(listener, environment_id, snapshot_parts, report).await;
        });
        Self {
            _tree: tree,
            endpoint,
            serving,
        }
    }

    async fn client(&self) -> LocalClient {
        LocalClient::connect(
            &self.endpoint,
            LocalClientKind::Cli,
            BuildId::new("kr-ipc-tests").expect("a literal build identifier"),
        )
        .await
        .expect("the worker answered the opening frame")
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

async fn serve(
    listener: Listener,
    environment_id: EnvironmentId,
    snapshot_parts: usize,
    report: Vec<(Duration, ControlFrame)>,
) {
    let Ok((connection, peer)) = listener.accept().await else {
        return;
    };
    let (mut reader, mut writer) = split(connection, StreamKind::Control);
    let Ok(ControlFrame::Hello(_)) = reader.read_message::<ControlFrame>().await else {
        return;
    };
    let connection_id = ConnectionId::new(kr_ipc::new_uuid());
    let acknowledgement = LocalHelloAck {
        selected_version: PROTOCOL_VERSION,
        role: LocalRole::Controller,
        connection_id,
        environment_id,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        peer: LocalPeer {
            uid: U64::new(u64::from(peer.uid)),
            gid: U64::new(u64::from(peer.gid)),
            pid: Nullable::null(),
        },
        action_window: ActionWindow {
            action_window_id: ActionWindowId::new("window-1").expect("a window identifier"),
            connection_id,
            boot_epoch: BootEpoch::new(1),
            issued_at_ms: TimestampMs::new(0),
            valid_for_ms: DurationMs::new(60_000),
        },
        capabilities: CanonicalSet::new(),
        max_receive: ReceiveLimits::default(),
        build: None,
    };
    if writer
        .write_message(&ControlFrame::HelloAck(Box::new(acknowledgement)))
        .await
        .is_err()
    {
        return;
    }
    for _ in 0..snapshot_parts {
        let Ok(ControlFrame::PluginAdmissions(_)) = reader.read_message::<ControlFrame>().await
        else {
            return;
        };
    }
    for (delay, frame) in report {
        tokio::time::sleep(delay).await;
        if writer.write_message(&frame).await.is_err() {
            return;
        }
    }
    std::future::pending::<()>().await;
}

/// A report whose parts each come within a part's time is read whole, however long all of them
/// take together.
#[tokio::test]
async fn a_report_whose_parts_each_come_in_time_is_read_whole() {
    let pace = PER_PART / 2;
    let worker = Worker::start(
        1,
        vec![
            (pace, report_part(1, 3)),
            (pace, report_part(2, 3)),
            (pace, report_part(3, 3)),
        ],
    );
    let mut client = worker.client().await;
    let report = tokio::time::timeout(
        LIVENESS_DEADLINE,
        client.exchange_admissions(snapshot(), PER_PART),
    )
    .await
    .expect("the exchange ended")
    .expect("every part came in time");
    assert_eq!(report.len(), 3);
}

/// A worker that stops part way holds the connection for one part's time, and the exchange says
/// the part did not come in time.
#[tokio::test]
async fn a_part_that_does_not_come_in_time_ends_the_exchange() {
    let worker = Worker::start(1, vec![(Duration::ZERO, report_part(1, 3))]);
    let mut client = worker.client().await;
    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(
        LIVENESS_DEADLINE,
        client.exchange_admissions(snapshot(), PER_PART),
    )
    .await
    .expect("the exchange ended");
    assert!(
        matches!(outcome, Err(IpcError::IdentityUnavailable { .. })),
        "{outcome:?}"
    );
    assert!(started.elapsed() < PER_PART * 4, "{:?}", started.elapsed());
}

/// A report that announces more parts than a report may have is refused at its first part.
#[tokio::test]
async fn a_report_of_more_parts_than_the_bound_is_refused() {
    let too_many = kr_protocol::limits::MAX_ADMISSION_PARTS + 1;
    let worker = Worker::start(1, vec![(Duration::ZERO, report_part(1, too_many))]);
    let mut client = worker.client().await;
    let outcome = tokio::time::timeout(
        LIVENESS_DEADLINE,
        client.exchange_admissions(snapshot(), PER_PART),
    )
    .await
    .expect("the exchange ended");
    assert!(
        matches!(outcome, Err(IpcError::UnexpectedMessage(_))),
        "{outcome:?}"
    );
}

/// A worker that sends only its subscription's events never moves the part it owes: the exchange
/// ends within about one part's time however many events come.
#[tokio::test]
async fn events_do_not_extend_the_time_a_part_has() {
    let pace = PER_PART / 4;
    let events: Vec<(Duration, ControlFrame)> = (0..40).map(|n| (pace, event(n))).collect();
    let worker = Worker::start(1, events);
    let mut client = worker.client().await;
    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(
        LIVENESS_DEADLINE,
        client.exchange_admissions(snapshot(), PER_PART),
    )
    .await
    .expect("the exchange ended");
    assert!(
        matches!(outcome, Err(IpcError::IdentityUnavailable { .. })),
        "{outcome:?}"
    );
    assert!(started.elapsed() < PER_PART * 3, "{:?}", started.elapsed());
}

/// One event on this connection's subscription.
fn event(sequence: u64) -> ControlFrame {
    ControlFrame::Notification(kr_protocol::envelope::Notification {
        stream_id: kr_protocol::ids::StreamId::new("session.output").expect("a stream name"),
        sequence: kr_protocol::ids::EventSequence::new(sequence + 1),
        event_type: kr_protocol::ids::EventType::new("session.output").expect("an event type"),
        payload: kr_protocol::envelope::ParamsValue::from_typed(&"x".repeat(64))
            .expect("a payload"),
    })
}
