//! A local connection whose serving loop is ended while the daemon is still held.
//!
//! Ending the loop that serves the daemon's clients ends the task of each connection it serves, at
//! whatever it is waiting for. A daemon something else still holds (an operation that has started,
//! a suite that keeps its handle) must not keep what the connection was admitted under: its
//! registration is authority nothing could revoke, and its windows could first-admit a request
//! through a connection that no longer exists.

use std::sync::Arc;
use std::time::Duration;

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_protocol::local::LocalClientKind;

use crate::service::Controller;

/// How long the test gives the runtime to cut the connection off, and fails after. Nothing is
/// decided by it: a connection whose cleanup never runs is the one thing that runs it out.
const WAIT: Duration = Duration::from_secs(30);

/// A connection cut off by the end of the loop that serves it leaves neither its registration nor
/// its windows behind, though the daemon is still held.
///
/// The daemon is kept by this test, so nothing about it is let go: what is looked at is what the
/// connection's own end takes away. The connection is cut off wherever its task is, here at its
/// wait for the peer's next frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_cut_off_with_its_loop_leaves_no_registration_or_window() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = Controller::start(super::a_floor_owed_its_record::setup(&temp))
        .await
        .expect("the daemon starts");
    let endpoint = temp
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let serving = tokio::spawn(
        Arc::clone(&controller)
            .serve_clients(Listener::bind(&endpoint).expect("binds the endpoint")),
    );
    let _client = LocalClient::connect(
        &endpoint,
        LocalClientKind::Cli,
        kr_protocol::ids::BuildId::new("kr-test/0").expect("a build identifier"),
    )
    .await
    .expect("connects");
    // The hello was answered, so the daemon has registered the connection and issued its window.
    assert_eq!(
        controller.admitted_read().len(),
        1,
        "the connection is registered"
    );
    assert!(
        controller.windows.outstanding() >= 1,
        "its window is outstanding"
    );

    serving.abort();
    let _ = serving.await;

    // The connection's task is cancelled at the runtime's next turns, so the test gives it them
    // until the condition holds.
    let cut_off = tokio::time::timeout(WAIT, async {
        while !controller.admitted_read().is_empty() || controller.windows.outstanding() > 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        cut_off.is_ok(),
        "registrations left: {}, windows left: {}",
        controller.admitted_read().len(),
        controller.windows.outstanding()
    );
}
