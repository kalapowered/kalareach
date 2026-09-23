//! The local listener, bridge registration and the binary a live binding is pinned to.

use kr_protocol::broker::{BinaryIdentity, IntegrationMode};
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{ApplicationInstanceId, LaunchProfileId, SessionId};
use kr_protocol::scalars::{Digest256, TimestampMs, Uuid};
#[cfg(unix)]
use kr_worker::broker::BoundEndpoint;
use kr_worker::broker::{
    BoundBinary, BridgeHello, Broker, BrokerTransport, Credential, ListenerAddress, ManagedProcess,
    PeerIdentity, Registration, TransportHandle, listener::BROWSER_HEADERS,
};

const CREDENTIAL: [u8; 32] = [9; 32];

fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([1; 16]))
}

fn instance() -> ApplicationInstanceId {
    ApplicationInstanceId::new(Uuid::from_bytes([2; 16]))
}

fn process(pid: u64, start: u64) -> ProcessStartIdentity {
    ProcessStartIdentity::new(pid, ProcessStartSource::MacosProcBsdInfo, start)
}

fn managed(identity: ProcessStartIdentity) -> ManagedProcess {
    ManagedProcess::new(
        instance(),
        identity.clone(),
        TransportHandle {
            transport: BrokerTransport::PrivateSocket,
            application_instance_id: instance(),
            executable_digest: Digest256::from_bytes([3; 32]),
            process: identity,
        },
        Credential::from_bytes(CREDENTIAL),
        true,
        TimestampMs::new(1),
    )
}

fn registration(address: ListenerAddress) -> Registration {
    registration_for(address, process(41, 900))
}

fn registration_for(address: ListenerAddress, expected: ProcessStartIdentity) -> Registration {
    Registration::new(
        address,
        LaunchProfileId::new("lp-1").expect("valid"),
        instance(),
        expected,
    )
}

/// A private runtime directory, made owner-only the way the host makes one.
#[cfg(unix)]
fn private_directory() -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let name: String = kr_ipc::new_uuid()
        .to_string()
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(8)
        .collect();
    let directory = std::env::temp_dir().join(format!("kr-l-{name}"));
    std::fs::create_dir_all(&directory).expect("the directory is created");
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
        .expect("the directory is made private");
    directory
}

/// The identity this test process actually has, which is what the kernel will report.
#[cfg(unix)]
fn this_process() -> ProcessStartIdentity {
    kr_ipc::identity::current_process_start_identity().expect("this process is identifiable")
}

fn hello() -> BridgeHello {
    BridgeHello {
        credential: kr_crypto::secret::SecretVec::new(CREDENTIAL.to_vec()),
        process: process(41, 900),
        environment_session_id: Some("KR_SESSION=abc".to_owned()),
    }
}

/// KR-REQ-12.14: the listener is private, refuses a browser and an unauthenticated request, is
/// never an address a relay could carry, and keeps credentials out of what anybody reads.
#[test]
fn kr_req_12_14_the_address_is_private_browsers_are_refused_and_nothing_printed_carries_a_credential()
 {
    let name: String = kr_ipc::new_uuid()
        .to_string()
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(8)
        .collect();
    let directory = std::env::temp_dir().join(format!("kr-l-{name}"));
    std::fs::create_dir_all(&directory).expect("the directory is created");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("the directory is made private");
    }

    // Private where the platform has one, loopback with a credential where it does not. Either
    // way the address is local, and it is refused before it is published if it is not.
    let address = ListenerAddress::for_launch(&directory, 49_152).expect("an address is chosen");
    assert!(address.is_local());
    address.require_local().expect("it is local");
    assert!(
        ListenerAddress::Loopback {
            address: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            port: 49_152,
        }
        .require_local()
        .is_err(),
        "an address something else could reach is never published"
    );
    if cfg!(unix) {
        assert!(matches!(address, ListenerAddress::PrivateSocket(_)));
    } else {
        assert!(matches!(address, ListenerAddress::Loopback { .. }));
    }

    // Nothing a browser sends gets in.
    for header in BROWSER_HEADERS {
        assert!(
            kr_worker::broker::reject_browser_origin([(*header, "https://example.test")]).is_err(),
            "{header} disqualifies a connection"
        );
    }
    kr_worker::broker::reject_browser_origin([("content-type", "application/json")])
        .expect("a native client's own headers are fine");

    // An unauthenticated request is refused.
    let registration = registration(address.clone());
    let managed = managed(process(41, 900));
    let unauthenticated = BridgeHello {
        credential: kr_crypto::secret::SecretVec::new(Vec::new()),
        process: process(41, 900),
        environment_session_id: None,
    };
    assert!(
        registration
            .authenticate(
                &unauthenticated,
                &PeerIdentity::presented(Some(process(41, 900)), true),
                &managed
            )
            .is_err()
    );

    // And what a failure logs carries no credential either.
    let rendered = format!("{:?}", hello());
    assert!(rendered.contains("credential: \"<redacted>\""));
    assert!(
        !rendered.contains("09, 09"),
        "{rendered} carries the credential it received"
    );

    // And nothing a person or a diagnostic reads carries the credential.
    let diagnostic = address.for_diagnostics();
    let file = registration.to_file();
    for rendering in [&diagnostic, &file] {
        assert!(!rendering.contains("0909"), "{rendering} carries a secret");
        assert!(!rendering.to_ascii_lowercase().contains("credential"));
        assert!(
            !rendering.contains('@'),
            "a credential never travels in a URL"
        );
    }
    let _ = std::fs::remove_dir_all(&directory);
}

/// KR-REQ-11.43 and KR-REQ-12.14: registration authenticates against the launch and process
/// binding and a private exchange, on an endpoint this host actually bound.
///
/// The endpoint is real, so the peer's ownership and process identity are the kernel's reading of
/// the connection rather than anything the connecting side said about itself. That is the whole
/// difference between deciding who may connect and knowing who did.
// Unix only: the kernel names a peer only on a private socket, and Windows has no managed gateway.
#[cfg(unix)]
#[tokio::test]
async fn kr_req_11_43_registration_needs_the_launch_binding_and_the_private_exchange_together() {
    let directory = private_directory();
    let endpoint = BoundEndpoint::bind(&directory).expect("the endpoint binds");
    let address = endpoint.address().clone();
    address.require_local().expect("a bound endpoint is local");

    // The launch this host made is this process, because this process is what will connect.
    let launched = this_process();
    let registration = registration_for(address.clone(), launched.clone());
    let managed = managed(launched.clone());

    let connecting = match address.clone() {
        ListenerAddress::PrivateSocket(path) => tokio::spawn(async move {
            tokio::net::UnixStream::connect(&path)
                .await
                .expect("the bridge connects")
        }),
        ListenerAddress::Loopback { address, port } => tokio::spawn(async move {
            let _ = tokio::net::TcpStream::connect((address, port))
                .await
                .expect("the bridge connects");
            unreachable!("this platform prefers a private socket in these tests")
        }),
    };
    let accepted = endpoint.accept().await.expect("the connection is accepted");
    assert!(
        accepted.peer.from_operating_system(),
        "a private socket names its peer"
    );
    assert_eq!(
        accepted.peer.process().expect("the kernel named it"),
        &launched,
        "the identity is read from the kernel and not from the hello"
    );

    // Both halves, on a connection the kernel vouched for.
    registration
        .authenticate(
            &BridgeHello {
                credential: kr_crypto::secret::SecretVec::new(CREDENTIAL.to_vec()),
                process: launched.clone(),
                environment_session_id: Some("KR_SESSION=abc".to_owned()),
            },
            &accepted.peer,
            &managed,
        )
        .expect("both halves are there");

    // The session identifier from the environment, and nothing else.
    assert!(
        registration
            .authenticate(
                &BridgeHello {
                    credential: kr_crypto::secret::SecretVec::new(Vec::new()),
                    process: launched.clone(),
                    environment_session_id: Some("KR_SESSION=abc".to_owned()),
                },
                &accepted.peer,
                &managed,
            )
            .is_err(),
        "an environment-variable session identifier is not authentication"
    );

    // A bridge that names somebody else's process is refused by the kernel's reading, not by its
    // own honesty: the hello below claims the launch and the connection is a different process.
    let stranger = registration_for(address.clone(), process(77, 900));
    assert!(
        stranger
            .authenticate(
                &BridgeHello {
                    credential: kr_crypto::secret::SecretVec::new(CREDENTIAL.to_vec()),
                    process: process(77, 900),
                    environment_session_id: None,
                },
                &accepted.peer,
                &managed,
            )
            .is_err(),
        "the process the kernel named is the one that is compared"
    );

    // Another operating-system user is refused before anything else is read.
    assert!(
        registration
            .authenticate(
                &BridgeHello {
                    credential: kr_crypto::secret::SecretVec::new(CREDENTIAL.to_vec()),
                    process: launched.clone(),
                    environment_session_id: None,
                },
                &PeerIdentity::presented(Some(launched.clone()), false),
                &managed,
            )
            .is_err()
    );

    // And where the kernel does name the peer, an identity it did not name is not admitted: the
    // loopback path exists for a platform that has no private socket, not as a way past this one.
    if cfg!(unix) {
        assert!(
            registration
                .authenticate(
                    &BridgeHello {
                        credential: kr_crypto::secret::SecretVec::new(CREDENTIAL.to_vec()),
                        process: launched.clone(),
                        environment_session_id: None,
                    },
                    &PeerIdentity::presented(Some(launched), true),
                    &managed,
                )
                .is_err()
        );
    }

    // The registration file is the small file section 11 prefers: where to connect and which
    // launch, and nothing that speaks to the listener.
    let file = registration.to_file();
    assert!(file.contains(&address.for_diagnostics()));
    assert!(file.lines().count() >= 5);
    assert!(!file.to_ascii_lowercase().contains("credential"));

    drop(connecting.await.expect("the connecting task finishes"));
    drop(endpoint);
    let _ = std::fs::remove_dir_all(&directory);
}

/// KR-REQ-12.15: an executable upgrade affects new launches; an existing binding keeps the binary
/// identity it was bound to.
#[test]
fn kr_req_12_15_a_bound_binary_identity_is_the_one_a_running_binding_acts_under() {
    let original = BinaryIdentity {
        resolved_path: "/usr/local/bin/codex".to_owned(),
        digest: Digest256::from_bytes([3; 32]),
        version: "0.9.1".to_owned(),
        distribution: "homebrew".to_owned(),
    };
    let upgraded = BinaryIdentity {
        digest: Digest256::from_bytes([4; 32]),
        version: "0.9.2".to_owned(),
        ..original.clone()
    };

    let bound = BoundBinary::pin(original.clone(), process(41, 900));
    assert_eq!(
        bound.identity_for(&upgraded).version,
        "0.9.1",
        "a running binding acts under the identity it was bound to"
    );
    assert!(bound.differs_from_installed(&upgraded));
    assert!(!bound.differs_from_installed(&original));
    assert_eq!(bound.pinned.digest, Digest256::from_bytes([3; 32]));
    assert_eq!(BoundBinary::for_new_launch(&upgraded).version, "0.9.2");

    // And the live broker agrees: the connection the running process authenticated is still its
    // own after the file on disk changed.
    let broker = Broker::open(None, session()).expect("the broker opens");
    broker
        .register_instance(
            instance(),
            IntegrationMode::Gateway,
            Some(LaunchProfileId::new("lp-1").expect("valid")),
            Some(managed(process(41, 900))),
        )
        .expect("the instance is registered");
    broker.invalidate_capabilities(
        kr_protocol::broker::InstanceInvalidation::BinaryChanged,
        "the executable was upgraded",
        TimestampMs::new(5),
    );
    assert_eq!(
        broker
            .binding_state(instance())
            .expect("the instance is still bound")
            .binding_revision,
        kr_protocol::ids::AgentBindingRevision::new(1),
        "an upgrade on disk does not move a running binding"
    );
}
