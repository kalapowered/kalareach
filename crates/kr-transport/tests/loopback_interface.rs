//! The interface list the network library reads before it keeps a relay connection through a
//! network change.

use std::net::{IpAddr, Ipv4Addr};

/// The list names the IPv4 loopback, which is where the loopback front listens, so a relay session
/// through the front is kept when the network changes and not redialled. A platform whose list
/// omits the loopback fails here, and each real network change on it then costs one redial, which
/// writes nothing the verdict forbids.
///
/// This is a platform guard: it holds on a platform that lists its loopback and can fail on one
/// that does not.
///
/// Covers KR-REQ-10.02.
#[tokio::test]
async fn the_interface_list_the_network_library_reads_names_the_loopback() {
    let state = netwatch::interfaces::State::new().await;
    assert!(
        state
            .local_addresses
            .loopback
            .contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)),
        "the loopback is not among {:?}",
        state.local_addresses.loopback
    );
}
