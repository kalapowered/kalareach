//! A control daemon speaks to a worker only at a compatibility level its release retains.
//!
//! A worker outlives the daemon that started it, so a daemon can meet a worker of another build.
//! The worker states its build in its answer to the hello, and a daemon's connection is refused
//! there, before the worker's challenge is read and before any generation is presented, when that
//! build is at a level this release does not retain; this release retains its own. These tests
//! drive a real endpoint with a worker that states what the test chooses.

#![cfg(unix)]

use std::time::Duration;

use kr_ipc::IpcError;
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::framed::split;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::error::ErrorCode;
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::{
    ActionWindow, PACKAGE_VERSION, PROTOCOL_VERSION, PackageVersion, ReceiveLimits,
};
use kr_protocol::ids::{ActionWindowId, BootEpoch, BuildId, ConnectionId};
use kr_protocol::local::{LocalBuild, LocalClientKind, LocalHelloAck, LocalPeer, LocalRole};
use kr_protocol::scalars::{CanonicalSet, DurationMs, Nullable, TimestampMs, U64};
use kr_protocol::worker::GenerationChallenge;

/// How long a wait tolerates nothing happening at all.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// A worker on a real endpoint that states `stated` in its answer and records what it is sent.
struct Worker {
    _tree: kr_ipc::testing::TempHost,
    endpoint: kr_ipc::paths::Endpoint,
    /// What the client sent after its hello, once the connection has ended.
    sent_after_hello: tokio::task::JoinHandle<Vec<ControlFrame>>,
}

impl Worker {
    fn start(stated: Option<LocalBuild>) -> Self {
        let tree = kr_ipc::testing::TempHost::create();
        let endpoint = tree
            .environment()
            .controller_endpoint()
            .expect("an endpoint path");
        let listener = Listener::bind(&endpoint).expect("a local endpoint");
        let environment_id = tree.environment_id();
        let sent_after_hello = tokio::spawn(async move {
            let mut received = Vec::new();
            let Ok((connection, peer)) = listener.accept().await else {
                return Vec::new();
            };
            let (mut reader, mut writer) = split(connection, StreamKind::Control);
            let Ok(ControlFrame::Hello(_)) = reader.read_message::<ControlFrame>().await else {
                return Vec::new();
            };
            let connection_id = ConnectionId::new(kr_ipc::new_uuid());
            let acknowledgement = LocalHelloAck {
                selected_version: PROTOCOL_VERSION,
                role: LocalRole::Worker,
                connection_id,
                environment_id,
                boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
                peer: LocalPeer {
                    uid: U64::new(u64::from(peer.uid)),
                    gid: U64::new(u64::from(peer.gid)),
                    pid: Nullable::null(),
                },
                action_window: ActionWindow {
                    action_window_id: ActionWindowId::new("worker:level").expect("a window"),
                    connection_id,
                    boot_epoch: BootEpoch::new(1),
                    issued_at_ms: TimestampMs::new(0),
                    valid_for_ms: DurationMs::new(60_000),
                },
                capabilities: CanonicalSet::new(),
                max_receive: ReceiveLimits::default(),
                build: stated,
            };
            // What a worker sends a daemon at once: its answer, and its generation challenge.
            let _ = writer
                .write_message(&ControlFrame::HelloAck(Box::new(acknowledgement)))
                .await;
            let _ = writer
                .write_message(&ControlFrame::GenerationChallenge(GenerationChallenge {
                    nonce: kr_ipc::verify::fresh_challenge()
                        .expect("a challenge")
                        .nonce,
                }))
                .await;
            while let Ok(frame) = reader.read_message::<ControlFrame>().await {
                received.push(frame);
            }
            received
        });
        Self {
            _tree: tree,
            endpoint,
            sent_after_hello,
        }
    }

    async fn connect(&self, kind: LocalClientKind) -> kr_ipc::Result<LocalClient> {
        LocalClient::connect(
            &self.endpoint,
            kind,
            BuildId::new("kr-controller/0").expect("a build identifier"),
        )
        .await
    }

    /// What the client sent after its hello, once it has let go of the connection.
    async fn sent_after_hello(self) -> Vec<ControlFrame> {
        tokio::time::timeout(LIVENESS_DEADLINE, self.sent_after_hello)
            .await
            .expect("the connection ends")
            .expect("the worker's task ends")
    }
}

fn stating(version: PackageVersion) -> Option<LocalBuild> {
    Some(LocalBuild {
        build_id: BuildId::new("kr-worker/0.1.0").expect("a build identifier"),
        protocol_version: version,
    })
}

/// A version at another compatibility level than this build's.
fn another_level() -> PackageVersion {
    if PACKAGE_VERSION.major == 0 {
        PackageVersion::new(0, PACKAGE_VERSION.minor + 1, 0)
    } else {
        PackageVersion::new(PACKAGE_VERSION.major + 1, 0, 0)
    }
}

/// KR-REQ-26.08: a daemon's connection to a worker of another level, or to one that states no
/// build, is refused before anything but the hello is sent; a worker at this build's level is met,
/// a patch number apart included.
#[tokio::test(flavor = "multi_thread")]
async fn a_daemon_meets_only_a_worker_at_a_level_its_release_retains() {
    // The controls: this build's own version, and one a patch number apart, are met.
    for version in [
        PACKAGE_VERSION,
        PackageVersion::new(
            PACKAGE_VERSION.major,
            PACKAGE_VERSION.minor,
            PACKAGE_VERSION.patch + 1,
        ),
    ] {
        let worker = Worker::start(stating(version));
        let client = worker
            .connect(LocalClientKind::Controller)
            .await
            .unwrap_or_else(|error| panic!("a worker at {version} is met: {error}"));
        drop(client);
        assert!(worker.sent_after_hello().await.is_empty());
    }
    for stated in [stating(another_level()), None] {
        let worker = Worker::start(stated.clone());
        let refused = worker
            .connect(LocalClientKind::Controller)
            .await
            .expect_err("a worker at another level is refused");
        assert!(
            matches!(refused, IpcError::UnretainedLevel { .. }),
            "{refused}"
        );
        assert_eq!(refused.code(), ErrorCode::UnsupportedSchema);
        let said = refused.to_string();
        match &stated {
            Some(build) => assert!(
                said.contains(&format!(
                    "kr-worker/0.1.0 with protocol {}",
                    build.protocol_version
                )),
                "{said}"
            ),
            None => assert!(said.contains("states no protocol version"), "{said}"),
        }
        assert!(
            worker.sent_after_hello().await.is_empty(),
            "nothing but the hello reached the worker: no challenge and no generation"
        );
    }
}

/// A client that is not a control daemon is not refused by this rule: `kr attach` checks the
/// worker's build itself, and a read that needs no frame of another level may go on.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_is_not_a_daemon_is_not_refused_by_the_daemon_s_rule() {
    let worker = Worker::start(stating(another_level()));
    let client = worker
        .connect(LocalClientKind::Cli)
        .await
        .expect("a command-line client reaches the worker");
    assert_eq!(
        client
            .acknowledgement()
            .build
            .as_ref()
            .map(|build| build.protocol_version),
        Some(another_level())
    );
}
