//! A daemon that starts again in the boot it already ran in, after it left a session of an earlier
//! boot as it was.
//!
//! A session of an earlier boot is closed as the host's restart when the daemon starts in a new
//! boot. Where another recovery holds one of them, the daemon leaves it, and what it leaves must
//! never reach the sessions the boot it runs in has made since: those are running, and a restart
//! of the daemon finds them running.
//!
//! The daemon is the product's own, on a temporary host tree, and the session of the boot it runs
//! in is a worker's own service in this process, adopted at the daemon's start the way a daemon
//! that restarted adopts the workers it left running.

mod net_support;

use std::time::Duration;

use kr_controller::archive::ArchiveService;
use kr_controller::registry::{Registry, WorkerRecord};
use kr_crypto::keys::{AuthorisationKeyPair, DeviceKeys};
use kr_protocol::identity::{
    BootIdentity, BootIdentitySource, DesktopBinding, ProcessStartIdentity, WorkerProfile,
};
use kr_protocol::ids::{AuthorityRevision, SessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::Bytes;
use kr_protocol::session::{DisplayNumber, SessionReadParams, SessionReadResult, SessionState};
use net_support::Host;
use net_support::worker::Worker;

/// How long a condition is waited for before the test gives up on it.
const PATIENCE: Duration = Duration::from_secs(60);

/// The display of the session of the earlier boot.
const EARLIER: u64 = 2;

/// The display of the session of the boot the daemon runs in.
const CURRENT: u64 = 1;

/// Reads one session's state at the daemon's local socket.
async fn state_of(host: &Host, session_id: SessionId) -> SessionState {
    let mut client = host.client().await;
    let read: SessionReadResult = client
        .request(Method::SessionRead, &SessionReadParams { session_id })
        .await
        .expect("the call reaches the daemon")
        .expect("the session reads")
        .to_typed()
        .expect("decodes");
    read.session.state
}

/// Records, as an earlier boot left it, a worker whose process has ended, and returns its session.
fn recorded_ended_worker(
    environment: &kr_ipc::paths::EnvironmentPaths,
    ended: &ProcessStartIdentity,
) -> SessionId {
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let display_number = DisplayNumber::new(EARLIER);
    let mut registry = Registry::open(
        environment.registry_database(),
        environment.environment_id(),
    )
    .expect("the registry");
    registry
        .adopt_worker(
            &WorkerRecord {
                session_id,
                display_number,
                public_key: *AuthorisationKeyPair::generate().expect("a key").public(),
                process_identity: ended.clone(),
                endpoint: environment
                    .worker_endpoint(display_number)
                    .expect("an endpoint")
                    .as_text(),
                profile: WorkerProfile::HeadlessUser,
                state: SessionState::Live,
                acknowledged_revision: AuthorityRevision::new(0),
            },
            Some(&DesktopBinding::none()),
        )
        .expect("the worker is recorded");
    session_id
}

/// KR-REQ-24.18: a restart in the boot the daemon already runs in does not close the sessions
/// that boot has made, whatever an earlier start left undone of the boot before it.
///
/// The first start finds a session of an earlier boot that another recovery holds and leaves it.
/// A session is then made in this boot, and the daemon starts again, with that recovery still
/// holding the first. The second start must find the session of this boot running, as it was
/// left, and serve it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restart_in_the_boot_after_a_deferred_recovery_leaves_the_boots_own_session_running() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let stopped = Host::start(&owner).await.shut_down().await;
    let environment = stopped.tree().environment();

    // The environment's last start was in another boot, and a session of it has a worker that has
    // ended.
    let earlier_boot = BootIdentity {
        source: BootIdentitySource::BootTime,
        value: Bytes::new(vec![0x5c; 16]),
    };
    kr_ipc::paths::write_owner_only_file(
        &environment
            .state_dir()
            .join(kr_controller::service::BOOT_FILE),
        &kr_cbor::to_canonical_vec(&earlier_boot).expect("encodes"),
    )
    .expect("the record of the last boot is written");
    let ended = kr_ipc::identity::ended_process_identity(4_000_003);
    let earlier = recorded_ended_worker(&environment, &ended);

    // Another recovery holds that session, so the daemon cannot close it yet.
    let recovery = ArchiveService::new(environment.clone())
        .take_ownership(earlier, DisplayNumber::new(EARLIER), &ended)
        .expect("another recovery holds the session");
    let settings = stopped.settings().clone();
    let host = stopped.start(settings.clone()).await;
    let stopped = host.shut_down().await;

    // A session of this boot, running, and the daemon again.
    let worker = Worker::start(stopped.tree(), CURRENT).await;
    let host = stopped.start(settings).await;

    let deadline = tokio::time::Instant::now() + PATIENCE;
    loop {
        let state = state_of(&host, worker.session_id).await;
        assert_ne!(
            state,
            SessionState::Closed,
            "a session of this boot, whose worker runs, was closed by a restart in this boot"
        );
        if state == SessionState::Live {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the daemon never served the running session: {state:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    drop(recovery);
    host.stop().await;
}
