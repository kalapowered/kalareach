//! This computer asks the managed service to admit it through a relay as it dials a host.
//!
//! The device is this crate's own [`Device`], made from the parts a test gives, with the managed
//! service the stand-in the other suites use, held to the Worker's source. What is under test is
//! the construction the application's own parts make: the link carries the admission service, the
//! device's authorisation key signs the request, and the service it is addressed to is the one
//! whose relays the device names to it. The relay admission itself, and the cache around it, are
//! `kr-client`'s own suite.
#![cfg(desktop)]

#[path = "../../../../crates/kr-controller/tests/net_support/mod.rs"]
mod net_support;
mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use companion_tauri::device::{Device, ManagedService};
use kr_client::pairing::BoxFuture;
use kr_client::pairing::candidate::CandidateRoom;
use kr_client::pairing::link::HostLink;
use kr_client::pairing::room::{RoomError, RoomSocket};
use kr_crypto::store::{MemoryStore, SecretStore};
use kr_protocol::pairing::{Locator, NetworkConfig, NetworkHint, RendezvousOrigin};
use kr_protocol::scalars::{EndpointKey, Nullable};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use kr_service_stand_in::ServiceWeb;

/// A room that serves nothing: nothing here pairs.
struct NoRoom;

impl CandidateRoom for NoRoom {
    fn open<'a>(
        &'a self,
        origin: &'a RendezvousOrigin,
        _locator: &'a Locator,
    ) -> BoxFuture<'a, Result<RoomSocket, RoomError>> {
        Box::pin(async move {
            Err(RoomError::Unreachable {
                origin: origin.as_str().to_owned(),
                reason: "a test room that serves nothing".to_owned(),
            })
        })
    }
}

fn network(relay: &str) -> NetworkConfig {
    NetworkConfig {
        relay_urls: vec![NetworkHint::new(relay).expect("a hint")],
        pkarr_publisher_url: Nullable::null(),
        pkarr_resolver_url: Nullable::null(),
        dns_origin: Nullable::null(),
        direct_addresses: Vec::new(),
    }
}

/// KR-REQ-10.39: the device the application builds from its parts asks the managed service for an
/// admission, signed by its own key, for the relay of the service it is about to dial, and names no
/// relay of any other service to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn this_computer_asks_the_managed_service_to_admit_it_as_it_dials_a_host() {
    // The service answers from a loopback origin, so the relay it carries is one on this machine and
    // the dial that follows the request ends at once with nothing to reach.
    let service = Arc::new(ServiceWeb::at("http://127.0.0.1:9"));
    let origin = GatewayOrigin::new(service.origin()).expect("an origin");
    let reaching: Arc<Mutex<Option<Arc<dyn HostLink>>>> = Arc::new(Mutex::new(None));
    let kept = Arc::clone(&reaching);
    let mut parts = support::parts(
        Arc::new(MemoryStore::new()) as Arc<dyn SecretStore>,
        Arc::new(NoRoom),
    );
    parts.managed = Some(ManagedService {
        origin,
        http: Arc::clone(&service) as _,
    });
    parts.link = Some(Box::new(move |own| {
        *kept.lock().expect("the link") = Some(Arc::clone(&own));
        own
    }));
    let data = tempfile::tempdir().expect("a directory");
    let device = Device::with(data.path(), parts, || {}).expect("the device opens");
    let link = reaching
        .lock()
        .expect("the link")
        .clone()
        .expect("the device was given its link");
    let host = EndpointKey::from_bytes([0x11; 32]);

    // A relay of another service: nothing is asked.
    let _ = tokio::time::timeout(
        Duration::from_secs(4),
        link.dial(&network("https://relay.other.invalid/"), &host),
    )
    .await;
    assert!(
        service.relay_admission_requests().is_empty(),
        "a relay that is not the service's was named to it"
    );

    // A relay of the service: it is asked, with this device's own key. The stand-in lists a request
    // for an admission only when it accepted the credential.
    let _ = tokio::time::timeout(
        Duration::from_secs(4),
        link.dial(&network("http://127.0.0.1:9/"), &host),
    )
    .await;
    let asked = service.relay_admission_requests();
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert_eq!(asked[0].host, host);
    assert_eq!(
        asked[0].candidate,
        *device.identity().keys.transport.public()
    );
    assert_eq!(
        asked[0].relay_url.trim_end_matches('/'),
        "http://127.0.0.1:9"
    );

    // The request was signed as an installation by this device's own authorisation key: the stand-in
    // keeps the kind and the key each request arrived signed with, and the one that was accepted is
    // the only one.
    let signed = service
        .arrived()
        .into_iter()
        .filter(|arrived| arrived.path == "/api/relay/admission")
        .map(|arrived| arrived.signed_by)
        .collect::<Vec<_>>();
    assert_eq!(
        signed,
        vec![Some((
            ServiceRequestSigner::Installation,
            *device.identity().keys.authorisation.public()
        ))]
    );
}
