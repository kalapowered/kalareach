//! A local connection whose peer stops reading.
//!
//! The loop that serves a local connection writes a keepalive and a replacement window between
//! reads, and while it waits for a peer to take one it reads nothing. These tests make a peer that
//! connects and then never reads, let the loop write until the socket takes no more, and read back
//! that the connection ends and its registration goes, rather than the loop holding for ever; and
//! that a peer that does read keeps its connection.

use std::sync::Arc;
use std::time::Duration;

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_protocol::envelope::{ControlEvent, ControlFrame};
use kr_protocol::local::LocalClientKind;

use crate::service::Controller;

/// How long a test waits for something it is waiting for by condition, and fails after. Nothing
/// is decided by it: a loop that holds for ever is the one thing that runs it out.
const WAIT: Duration = Duration::from_secs(60);

/// The bound a write waits for a peer in these tests. Only how soon the connection ends depends on
/// it; that it ends does not.
const BOUND: Duration = Duration::from_millis(200);

/// A daemon serving its local endpoint, with the pace it writes unasked at chosen by the test.
async fn serving(
    renewal: Duration,
    keepalive: Duration,
) -> (
    kr_ipc::testing::TempHost,
    Arc<Controller>,
    kr_ipc::paths::Endpoint,
) {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = Controller::start(super::a_floor_owed_its_record::setup(&temp))
        .await
        .expect("the daemon starts");
    controller.pace_local_connections(renewal, keepalive, BOUND);
    let endpoint = temp
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    tokio::spawn(Arc::clone(&controller).serve_clients(listener));
    (temp, controller, endpoint)
}

/// Connects a client, and waits until the daemon has registered its connection.
async fn connected(controller: &Controller, endpoint: &kr_ipc::paths::Endpoint) -> LocalClient {
    let client = LocalClient::connect(
        endpoint,
        LocalClientKind::Cli,
        kr_protocol::ids::BuildId::new("kr-test/0").expect("a build identifier"),
    )
    .await
    .expect("connects");
    until("the connection is registered", || {
        !controller.admitted_table().is_empty()
    })
    .await;
    client
}

/// Waits until `done` holds, and fails the test after [`WAIT`].
async fn until(what: &str, done: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !done() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what} did not happen within {WAIT:?}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// The two things a loop writes unasked, one at a time: `which` is paced fast and the other so
/// slowly it never fires.
async fn a_peer_that_never_reads(which: &str) {
    let hour = Duration::from_secs(3_600);
    let (renewal, keepalive) = match which {
        "renewal" => (Duration::from_millis(1), hour),
        _ => (hour, Duration::from_millis(1)),
    };
    let (_temp, controller, endpoint) = serving(renewal, keepalive).await;
    let _silent = connected(&controller, &endpoint).await;

    // The loop writes until the socket takes no more, and that write is the one that must end.
    until("a write waited for the peer", || {
        controller.local_writes_blocked() >= 1
    })
    .await;
    until("the connection ended", || {
        controller.admitted_table().is_empty()
    })
    .await;
}

/// A peer that stops reading does not hold the loop that writes its keepalive: the write that finds
/// the socket full ends after its bound, and the connection with its registration goes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_keepalive_to_a_peer_that_stopped_reading_ends_the_connection() {
    a_peer_that_never_reads("keepalive").await;
}

/// The same for the replacement window the loop writes at half its validity.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replacement_window_to_a_peer_that_stopped_reading_ends_the_connection() {
    a_peer_that_never_reads("renewal").await;
}

/// The control: a peer that reads what it is sent keeps its connection however long the loop goes
/// on writing, and the loop never has to wait for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_reads_keeps_its_connection() {
    let (_temp, controller, endpoint) =
        serving(Duration::from_millis(1), Duration::from_millis(1)).await;
    let (mut reader, _writer, _acknowledgement) =
        connected(&controller, &endpoint).await.into_halves();

    let mut keepalives = 0;
    let mut renewals = 0;
    while keepalives < 200 || renewals < 20 {
        let frame: ControlFrame = tokio::time::timeout(WAIT, reader.read_message())
            .await
            .expect("the daemon keeps writing")
            .expect("the connection stands");
        match frame {
            ControlFrame::Event(ControlEvent::Keepalive) => keepalives += 1,
            ControlFrame::Event(ControlEvent::ActionWindowRenewed(_)) => renewals += 1,
            other => panic!("the daemon wrote something unasked that is not a beat: {other:?}"),
        }
    }
    assert!(
        !controller.admitted_table().is_empty(),
        "the connection is still registered"
    );
    assert_eq!(
        controller.local_writes_blocked(),
        0,
        "no write waited for a peer that reads"
    );
}
