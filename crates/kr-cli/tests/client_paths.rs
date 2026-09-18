//! Which way the command line reaches a host.
//!
//! Section 4: the command line is a local IPC client, and remote application access uses
//! `kr-client` over iroh. Neither half is this crate's to implement. Reaching a host on this
//! machine is `kr-ipc`'s socket or named pipe, and reaching one anywhere else is `kr-client`'s
//! connection, which is why this crate depends on both and on no transport at all.

use kr_ipc::client::LocalClient;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::WorkerProfile;
use kr_protocol::ids::{SessionEpoch, SessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{TimestampMs, Uuid};
use kr_protocol::session::DisplayNumber;
use kr_protocol::worker::WorkerDescriptor;

/// A descriptor naming an endpoint nothing is listening on.
///
/// Everything but the endpoint is beside the point here: the connection fails before a descriptor's
/// claims are acted on, which is itself the contract: nothing in one is believed until the worker
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

#[tokio::test]
async fn reaching_the_control_daemon_is_a_round_trip_over_the_local_socket() {
    // The other half of the local path: the daemon this machine's own commands talk to. A fake one
    // here, because what is under test is the command's side of the exchange, which is the opening
    // frames it sends, the acknowledgement it reads and the request it correlates, rather than what
    // a real daemon would answer.
    let tree = kr_ipc::testing::TempHost::create();
    let paths = tree.environment();
    let endpoint = paths.controller_endpoint().expect("an endpoint path");
    let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("a local endpoint");
    let serving = tokio::spawn(serve_one_local_caller(listener, tree.environment_id()));

    let mut client: LocalClient = kr_cli::resolve::open_controller(&paths, kr_cli::build_id())
        .await
        .expect("the daemon answered");

    // A request goes over the socket and is answered.
    let answer = client
        .request(Method::SessionList, &Empty {})
        .await
        .expect("a round trip")
        .expect("a result");
    assert_eq!(
        answer.to_typed::<SessionList>().expect("a listing"),
        SessionList { count: 2 }
    );

    // The connection carries the host's own stamp of who it authenticated and which environment
    // this is, which is what a local endpoint has instead of a device proof.
    let (_, _, acknowledgement) = client.into_halves();
    assert_eq!(acknowledgement.environment_id, tree.environment_id());
    assert_eq!(
        acknowledgement.peer.uid.get(),
        u64::from(kr_ipc::paths::current_uid())
    );
    assert_eq!(
        acknowledgement.role,
        kr_protocol::local::LocalRole::Controller
    );

    serving.abort();
}

#[test]
fn the_command_line_carries_no_transport_of_its_own() {
    // Its two ways to reach a host are the two the specification names, and both belong to other
    // crates: `kr-ipc` for a host on this machine and `kr-client` for one anywhere else. A
    // dependency on iroh or on the transport crate here would be a third way, or a second copy of
    // one of these two, which is exactly what section 4 says the contracts do not need.
    //
    // Every section that declares dependencies is read, including the per-platform ones, because a
    // transport added for one operating system is still a transport.
    let manifest = include_str!("../Cargo.toml");
    let mut in_dependencies = false;
    let mut declarations = String::new();
    for line in manifest.lines() {
        let line = line.trim_end();
        if let Some(section) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            in_dependencies =
                section.ends_with("dependencies") && !section.ends_with("dev-dependencies");
            continue;
        }
        if in_dependencies && !line.trim_start().starts_with('#') {
            declarations.push_str(line);
            declarations.push('\n');
        }
    }
    assert!(declarations.contains("kr-ipc"), "{declarations}");
    assert!(declarations.contains("kr-client"), "{declarations}");
    for transport in ["iroh", "kr-transport", "quinn", "rustls"] {
        assert!(
            !declarations.contains(transport),
            "the command line declares {transport}; reaching a host is kr-ipc's or kr-client's"
        );
    }
}

/// Answers one local caller: the opening exchange, then every request it sends.
async fn serve_one_local_caller(
    listener: kr_ipc::endpoint::Listener,
    environment_id: kr_protocol::ids::EnvironmentId,
) {
    let Ok((connection, peer)) = listener.accept().await else {
        return;
    };
    let (mut reader, mut writer) =
        kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
    let Ok(ControlFrame::Hello(hello)) = reader.read_message::<ControlFrame>().await else {
        return;
    };
    // The command presents itself as a command line, which says how to frame the conversation and
    // confers nothing.
    assert_eq!(hello.client, kr_protocol::local::LocalClientKind::Cli);
    let connection_id = kr_protocol::ids::ConnectionId::new(Uuid::from_bytes([42; 16]));
    let acknowledgement = kr_protocol::local::LocalHelloAck {
        selected_version: PROTOCOL_VERSION,
        role: kr_protocol::local::LocalRole::Controller,
        connection_id,
        environment_id,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        peer: kr_protocol::local::LocalPeer {
            uid: kr_protocol::scalars::U64::new(u64::from(peer.uid)),
            gid: kr_protocol::scalars::U64::new(u64::from(peer.gid)),
            pid: kr_protocol::scalars::Nullable::null(),
        },
        action_window: kr_protocol::hello::ActionWindow {
            action_window_id: kr_protocol::ids::ActionWindowId::new("window-1")
                .expect("a literal window identifier"),
            connection_id,
            boot_epoch: kr_protocol::ids::BootEpoch::new(1),
            issued_at_ms: kr_protocol::scalars::TimestampMs::new(0),
            valid_for_ms: kr_protocol::scalars::DurationMs::new(60_000),
        },
        capabilities: kr_protocol::scalars::CanonicalSet::new(),
        max_receive: hello.max_receive,
    };
    if writer
        .write_message(&ControlFrame::HelloAck(Box::new(acknowledgement)))
        .await
        .is_err()
    {
        return;
    }
    while let Ok(frame) = reader.read_message::<ControlFrame>().await {
        let ControlFrame::Request(request) = frame else {
            continue;
        };
        let answer = ControlFrame::Response(kr_protocol::envelope::Response {
            request_id: request.request_id,
            outcome: kr_protocol::envelope::Outcome::Ok(
                kr_protocol::envelope::ParamsValue::from_typed(&SessionList { count: 2 })
                    .expect("a result"),
            ),
        });
        if writer.write_message(&answer).await.is_err() {
            return;
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
struct SessionList {
    count: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct Empty {}
