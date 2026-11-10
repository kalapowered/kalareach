//! What a daemon lets go of when its owner stops it while a device and a local client are still
//! connected.
//!
//! A connection holds the daemon for as long as it lasts, and the daemon owns the network
//! listener that serves the network ones, so a daemon whose owner only let go of it would keep its
//! controller, its pairing service and the stores they hold open for as long as its peers stayed
//! connected: a stop followed by a start in one process then meets the previous daemon's open
//! stores. The stop is ending the loop that serves the daemon's clients. These cases run the real
//! daemon on the loopback network with a paired device on its own authorised connection and a
//! local client on its socket, stop it that way, and look at what is left.
//!
//! Nothing here waits a length of time for something to happen. What ends a connection's task is
//! cancelled at the next turn of the runtime, so the cases wait on the condition itself (a handle
//! that can no longer be upgraded, a connection that has closed) and the bound they give it only
//! keeps a daemon that does not let go from holding the suite for ever.

mod net_support;

use std::future::Future;
use std::sync::{Arc, Weak};
use std::time::Duration;

use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::ParamsValue;
use kr_protocol::hostinfo::HostDoctorResult;
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use net_support::Host;

/// How long a condition the daemon is expected to reach is given before the case calls it
/// unreached. A bound on a hang, never a measure of how long letting go takes. It is shorter than
/// the time a connection nobody closed takes to time out (thirty seconds), so a peer that was
/// never told its connection is closed does not pass for one that was.
const LIVENESS: Duration = Duration::from_secs(15);

fn typed<T: kr_protocol::wire::WireMessage>(value: &ParamsValue) -> T {
    value.to_typed().expect("a result of the declared shape")
}

/// Whether `condition` was reached within the bound.
async fn reached(condition: impl Future<Output = ()>) -> bool {
    tokio::time::timeout(LIVENESS, condition).await.is_ok()
}

/// Gives the runtime its turns until `held` can no longer be upgraded.
async fn until_let_go<T>(held: &Weak<T>) {
    while held.upgrade().is_some() {
        tokio::task::yield_now().await;
    }
}

/// Reads from a local client until its connection has closed.
async fn until_closed(local: &mut kr_ipc::client::LocalClient) {
    while local.recv().await.is_ok() {}
}

/// A daemon whose owner stops it lets go of its controller and its pairing service at once,
/// though a paired device and a local client are still connected; each of them sees its
/// connection close, and each was answered as usual while the daemon ran.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stopped_daemon_lets_go_of_its_controller_and_its_pairing_service() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (_device, session) =
        net_support::paired_device(&host, &owner, &[ActionRight::SessionView]).await;
    let mut local = host.client().await;

    // While the daemon runs, each door answers as it always did.
    let owners: HostDoctorResult = typed(
        &local
            .request(Method::HostDoctor, &())
            .await
            .expect("the call reaches the daemon")
            .expect("host.doctor is served on the local socket"),
    );
    let devices: HostDoctorResult = typed(
        &session
            .read(Method::HostDoctor, &())
            .await
            .expect("host.doctor is served to the device"),
    );
    assert_eq!(devices.healthy, owners.healthy);

    let controller = Arc::downgrade(host.controller());
    let pairing = Arc::downgrade(host.network().pairing());
    assert!(controller.upgrade().is_some() && pairing.upgrade().is_some());

    host.dropped().await;

    let (device_closed, client_closed, controller_let_go, pairing_let_go) = tokio::join!(
        reached(session.closed()),
        reached(until_closed(&mut local)),
        reached(until_let_go(&controller)),
        reached(until_let_go(&pairing)),
    );
    assert!(
        device_closed && client_closed && controller_let_go && pairing_let_go,
        "after the stop, within the bound: the device's connection closed: {device_closed}; \
         the local client's connection closed: {client_closed}; the controller was let go: \
         {controller_let_go}; the pairing service was let go: {pairing_let_go}"
    );
}
