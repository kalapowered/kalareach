//! Which way the command line reaches a host.
//!
//! Section 4: the command line is a local IPC client, and remote application access uses
//! `kr-client` over iroh. Neither half is this crate's to implement. Reaching a host on this
//! machine is `kr-ipc`'s socket or named pipe, and reaching one anywhere else is `kr-client`'s
//! connection, which is why this crate depends on both and on no transport at all.

use kr_ipc::client::LocalClient;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::WorkerProfile;
use kr_protocol::ids::{SessionEpoch, SessionId};
use kr_protocol::scalars::{TimestampMs, Uuid};
use kr_protocol::session::DisplayNumber;
use kr_protocol::worker::WorkerDescriptor;

/// A descriptor naming an endpoint nothing is listening on.
///
/// Everything but the endpoint is beside the point here: the connection fails before a descriptor's
/// claims are acted on, which is itself the contract — nothing in one is believed until the worker
/// behind it has answered a challenge.
fn descriptor_for(endpoint: &kr_ipc::paths::Endpoint) -> WorkerDescriptor {
    WorkerDescriptor {
        session_id: SessionId::new(Uuid::from_bytes([1; 16])),
        session_epoch: SessionEpoch::V1,
        environment_id: kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([2; 16])),
        display_number: DisplayNumber::new(1),
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        process_start_identity: kr_ipc::identity::current_process_start_identity()
            .expect("a process identity"),
        protocol_version: PROTOCOL_VERSION,
        endpoint: endpoint.as_text(),
        worker_public_key: *kr_crypto::keys::AuthorisationKeyPair::generate()
            .expect("a key pair")
            .public(),
        worker_profile: WorkerProfile::HeadlessUser,
        published_at_ms: TimestampMs::new(0),
    }
}

#[tokio::test]
async fn reaching_a_session_on_this_machine_is_a_local_ipc_client() {
    let tree = kr_ipc::testing::TempHost::create();
    let endpoint = tree
        .paths()
        .environment(tree.environment_id())
        .controller_endpoint()
        .expect("an endpoint path");
    let descriptor = descriptor_for(&endpoint);

    // The annotation is the assertion: the command's path to a session answers with a
    // `kr_ipc::client::LocalClient` and with nothing else. A path that reached a worker over a
    // network connection would not produce one, and this would stop compiling.
    let opened: kr_cli::Result<LocalClient> =
        kr_cli::resolve::open_worker(&descriptor, kr_cli::build_id()).await;

    // Nothing is listening there, so it fails the way a local endpoint fails: the host could not
    // be reached, naming the session it was looking for.
    let error = opened.expect_err("nothing is listening at that endpoint");
    assert!(
        matches!(error, kr_cli::CliError::HostUnavailable(_)),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .contains(&descriptor.session_id.to_string())
    );
}

#[test]
fn the_command_line_carries_no_transport_of_its_own() {
    // Its two ways to reach a host are the two the specification names, and both belong to other
    // crates: `kr-ipc` for a host on this machine and `kr-client` for one anywhere else. A
    // dependency on iroh or on the transport crate here would be a third way, or a second copy of
    // one of these two, which is exactly what section 4 says the contracts do not need.
    let manifest = include_str!("../Cargo.toml");
    let declarations: String = manifest
        .lines()
        .take_while(|line| !line.starts_with("[dev-dependencies]"))
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<&str>>()
        .join("\n");
    assert!(declarations.contains("kr-ipc.workspace = true"));
    assert!(declarations.contains("kr-client.workspace = true"));
    for transport in ["iroh", "kr-transport", "quinn", "tokio-rustls"] {
        assert!(
            !declarations.contains(transport),
            "the command line declares {transport}; reaching a host is kr-ipc's or kr-client's"
        );
    }
}
