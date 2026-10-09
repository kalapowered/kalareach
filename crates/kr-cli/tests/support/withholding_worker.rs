//! A worker's endpoint that answers a hello and withholds its proof until the test lets it give it.
//!
//! An update classes every worker an environment's registry names by challenging it for the key its
//! session was given. This peer speaks the real protocol on a real local socket, states a build of
//! this level in its answer to the hello, and holds the challenge: the update is then inside its
//! classification, after its check of the stores and before its switch, for as long as the test
//! wants it there. It counts the connections it is given, so a test can say that the one challenge it
//! saw was the classification's.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use kr_ipc::endpoint::Listener;
use kr_ipc::paths::EnvironmentPaths;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::ids::{ConnectionId, SessionEpoch, SessionId};
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs};
use kr_protocol::session::DisplayNumber;
use tokio::sync::{mpsc, watch};

/// The worker of one session, and what the test can do with it.
pub struct Withholding {
    identity: Arc<WorkerIdentity>,
    endpoint: String,
    challenged: mpsc::UnboundedReceiver<()>,
    release: watch::Sender<bool>,
    connections: Arc<AtomicUsize>,
    serving: tokio::task::JoinHandle<()>,
}

impl Withholding {
    /// Binds the endpoint a worker of `session` in `environment` has and serves it.
    pub fn start(
        environment: &EnvironmentPaths,
        display: DisplayNumber,
        session: SessionId,
    ) -> Self {
        let endpoint = environment.worker_endpoint(display).expect("an endpoint");
        let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
        let process =
            kr_ipc::identity::current_process_start_identity().expect("a process identity");
        let identity = Arc::new(
            WorkerIdentity::generate(
                session,
                SessionEpoch::V1,
                boot.clone(),
                process,
                PROTOCOL_VERSION,
            )
            .expect("a worker identity"),
        );
        let listener = Listener::bind(&endpoint).expect("binds the worker's endpoint");
        let (challenged_to, challenged) = mpsc::unbounded_channel();
        let (release, released) = watch::channel(false);
        let connections = Arc::new(AtomicUsize::new(0));
        let serving = tokio::spawn(serve(
            listener,
            Served {
                identity: Arc::clone(&identity),
                endpoint: endpoint.as_text(),
                environment_id: environment.environment_id(),
                boot,
                challenged: challenged_to,
                released,
                connections: Arc::clone(&connections),
            },
        ));
        Self {
            identity,
            endpoint: endpoint.as_text(),
            challenged,
            release,
            connections,
            serving,
        }
    }

    /// The key the worker's session was given, which the registry records.
    pub fn key(&self) -> kr_protocol::scalars::AuthorisationKey {
        *self.identity.public_key()
    }

    /// The endpoint text the registry records.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Waits until the worker has been challenged.
    pub async fn challenged(&mut self) {
        self.challenged
            .recv()
            .await
            .expect("the worker is challenged");
    }

    /// Lets the worker give its proof, to the challenge it holds and to any later one.
    pub fn prove(&self) {
        let _ = self.release.send(true);
    }

    /// How many connections the worker has been given.
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

impl Drop for Withholding {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

/// What every connection to the worker needs.
#[derive(Clone)]
struct Served {
    identity: Arc<WorkerIdentity>,
    endpoint: String,
    environment_id: kr_protocol::ids::EnvironmentId,
    boot: kr_protocol::identity::BootIdentity,
    challenged: mpsc::UnboundedSender<()>,
    released: watch::Receiver<bool>,
    connections: Arc<AtomicUsize>,
}

async fn serve(listener: Listener, served: Served) {
    while let Ok((connection, peer)) = listener.accept().await {
        served.connections.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(serve_one(connection, peer, served.clone()));
    }
}

async fn serve_one(
    connection: kr_ipc::endpoint::Connection,
    peer: kr_ipc::peer::PeerIdentity,
    mut served: Served,
) {
    let (mut reader, mut writer) = kr_ipc::framed::split(connection, StreamKind::Control);
    let Ok(ControlFrame::Hello(hello)) = reader.read_message::<ControlFrame>().await else {
        return;
    };
    let connection_id = ConnectionId::new(kr_ipc::new_uuid());
    let acknowledgement = kr_protocol::local::LocalHelloAck {
        selected_version: PROTOCOL_VERSION,
        role: kr_protocol::local::LocalRole::Worker,
        connection_id,
        environment_id: served.environment_id,
        boot_identity: served.boot.clone(),
        peer: kr_protocol::local::LocalPeer {
            uid: kr_protocol::scalars::U64::new(u64::from(peer.uid)),
            gid: kr_protocol::scalars::U64::new(u64::from(peer.gid)),
            pid: Nullable::null(),
        },
        action_window: kr_protocol::hello::ActionWindow {
            action_window_id: kr_protocol::ids::ActionWindowId::new("window-1")
                .expect("a window identifier"),
            connection_id,
            boot_epoch: kr_protocol::ids::BootEpoch::new(1),
            issued_at_ms: TimestampMs::new(kr_ipc::now_ms().get()),
            valid_for_ms: kr_protocol::scalars::DurationMs::new(60_000),
        },
        capabilities: CanonicalSet::new(),
        max_receive: hello.max_receive,
        // A worker of this level states the build, and the update reads the level it retains from it.
        build: Some(kr_protocol::local::LocalBuild::this(
            kr_protocol::ids::BuildId::new("kr-worker/0.1.0+aaaaaaaaaaaa")
                .expect("a build identifier"),
        )),
    };
    if writer
        .write_message(&ControlFrame::HelloAck(Box::new(acknowledgement)))
        .await
        .is_err()
    {
        return;
    }
    while let Ok(frame) = reader.read_message::<ControlFrame>().await {
        if let ControlFrame::VerifyChallenge(challenge) = frame {
            let _ = served.challenged.send(());
            while !*served.released.borrow_and_update() {
                if served.released.changed().await.is_err() {
                    return;
                }
            }
            let proof = served
                .identity
                .answer(&challenge, &served.endpoint)
                .expect("a proof");
            if writer
                .write_message(&ControlFrame::VerifyProof(proof))
                .await
                .is_err()
            {
                return;
            }
        }
    }
}
