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
use kr_controller::registry::{LaunchPhase, Registry, WorkerRecord};
use kr_crypto::keys::{AuthorisationKeyPair, DeviceKeys};
use kr_protocol::identity::{
    BootIdentity, BootIdentitySource, DesktopBinding, ProcessStartIdentity, WorkerProfile,
};
use kr_protocol::ids::{ActorId, AuthorityRevision, SessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Bytes, Digest256};
use kr_protocol::session::{
    ClosureReason, ClosureRecord, DisplayNumber, SessionReadParams, SessionReadResult, SessionState,
};
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

/// Records a session whose worker has ended, as it is left in the boot the daemon runs in, with a
/// complete registration (a reservation and a worker) and a journal holding the worker's record of
/// its processes, which names the boot the worker says it ran in.
fn recorded_worker_with_a_record(
    environment: &kr_ipc::paths::EnvironmentPaths,
    ended: &ProcessStartIdentity,
    boot: &BootIdentity,
) -> (SessionId, DisplayNumber) {
    let mut registry = Registry::open(
        environment.registry_database(),
        environment.environment_id(),
    )
    .expect("the registry");
    let reservation = registry
        .reserve(
            &ActorId::new("local:test").expect("a principal"),
            kr_ipc::new_uuid(),
            Digest256::from_bytes([ended.pid.get().to_be_bytes()[7]; 32]),
            b"",
            kr_ipc::now_ms(),
        )
        .expect("reserves")
        .reservation;
    registry
        .record_launch(reservation.reservation_id, ended)
        .expect("records the launcher");
    registry
        .set_phase(reservation.reservation_id, LaunchPhase::Spawned)
        .expect("spawned");
    let key = *AuthorisationKeyPair::generate().expect("a key").public();
    registry
        .claim_rendezvous(reservation.reservation_id, key)
        .expect("claims");
    registry
        .record_worker(
            reservation.reservation_id,
            &WorkerRecord {
                session_id: reservation.session_id,
                display_number: reservation.display_number,
                public_key: key,
                process_identity: ended.clone(),
                endpoint: environment
                    .worker_endpoint(reservation.display_number)
                    .expect("an endpoint")
                    .as_text(),
                profile: WorkerProfile::HeadlessUser,
                state: SessionState::Live,
                acknowledged_revision: AuthorityRevision::new(0),
            },
            &DesktopBinding::none(),
        )
        .expect("records the worker");
    let path = environment.journal_database(reservation.session_id);
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the journal directory");
    kr_worker::journal::Journal::open(&path)
        .expect("opens")
        .record_owned(
            reservation.session_id,
            &kr_worker::ownership::OwnedRecord {
                boot: Some(boot.clone()),
                root: ended.clone(),
                processes: vec![ended.clone()],
                cgroup: None,
                boundary: "the terminal's process group".to_owned(),
                limits: Vec::new(),
                backends: Vec::new(),
            },
        )
        .expect("records what the session owned");
    (reservation.session_id, reservation.display_number)
}

/// The closure a read of the session answers with, which closes the session of a worker that has
/// ended when nothing has yet.
async fn closure_of(host: &Host, session_id: SessionId) -> ClosureRecord {
    let mut client = host.client().await;
    let read: SessionReadResult = client
        .request(Method::SessionRead, &SessionReadParams { session_id })
        .await
        .expect("the call reaches the daemon")
        .expect("the session reads")
        .to_typed()
        .expect("decodes");
    read.session
        .closure
        .0
        .expect("a session whose worker has ended is closed")
}

/// The registry's closure for the session, read while no daemon runs.
fn recorded_closure(
    environment: &kr_ipc::paths::EnvironmentPaths,
    session_id: SessionId,
) -> Option<ClosureRecord> {
    Registry::open(
        environment.registry_database(),
        environment.environment_id(),
    )
    .expect("the registry")
    .closure(session_id)
    .expect("the registry answers")
}

/// KR-REQ-24.18: a worker that went with an earlier boot is closed as the host's restart by a
/// daemon that started again in the boot, which has forgotten that it left the session: the worker's
/// own record of its processes names the boot it ran in.
///
/// The first start finds the session of an earlier boot held by another recovery and leaves it. The
/// daemon stops, the recovery lets go, and the daemon starts again in the same boot, where it runs
/// no pass over the sessions of an earlier boot. Two sessions that a crash in this boot left are
/// beside it as controls: one whose worker's record names this boot, and one whose record names a
/// boot of another kind, which this host cannot compare with its own. Both close as the crashes they
/// are.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restart_in_the_boot_closes_a_worker_of_an_earlier_boot_as_the_hosts_restart() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let stopped = Host::start(&owner).await.shut_down().await;
    let environment = stopped.tree().environment();

    // The environment's last start was in an earlier boot of this host's kind, and a session of it
    // has a worker that has ended.
    let here = kr_ipc::identity::boot_identity().expect("this boot");
    let mut earlier_value = here.value.as_slice().to_vec();
    earlier_value[0] ^= 0xff;
    let earlier_boot = BootIdentity {
        source: here.source,
        value: Bytes::new(earlier_value),
    };
    kr_ipc::paths::write_owner_only_file(
        &environment
            .state_dir()
            .join(kr_controller::service::BOOT_FILE),
        &kr_cbor::to_canonical_vec(&earlier_boot).expect("encodes"),
    )
    .expect("the record of the last boot is written");
    let ended_earlier = kr_ipc::identity::ended_process_identity(4_000_003);
    let (earlier, earlier_display) =
        recorded_worker_with_a_record(&environment, &ended_earlier, &earlier_boot);

    // Another recovery holds that session for as long as the first daemon runs.
    let recovery = ArchiveService::new(environment.clone())
        .take_ownership(earlier, earlier_display, &ended_earlier)
        .expect("another recovery holds the session");
    let settings = stopped.settings().clone();
    let host = stopped.start(settings.clone()).await;
    let stopped = host.shut_down().await;
    drop(recovery);
    assert!(
        recorded_closure(&environment, earlier).is_none(),
        "the first daemon left the session it could not take"
    );

    // A crash in this boot leaves two more, and the daemon starts again in this boot.
    let ended_here = kr_ipc::identity::ended_process_identity(4_000_004);
    let (here_session, _) = recorded_worker_with_a_record(&environment, &ended_here, &here);
    let ended_unlike = kr_ipc::identity::ended_process_identity(4_000_005);
    let unlike = BootIdentity {
        source: if here.source == BootIdentitySource::BootTime {
            BootIdentitySource::LinuxBootId
        } else {
            BootIdentitySource::BootTime
        },
        value: Bytes::new(vec![0x5c; 16]),
    };
    let (unlike_session, _) = recorded_worker_with_a_record(&environment, &ended_unlike, &unlike);
    let host = stopped.start(settings).await;

    let went_with_the_boot = closure_of(&host, earlier).await;
    assert_eq!(
        went_with_the_boot.reason,
        ClosureReason::HostShutdown,
        "a worker whose record names an earlier boot went with it, whatever this daemon remembers"
    );
    assert!(
        went_with_the_boot.surviving.is_empty(),
        "and owned nothing that outlived the boot: {went_with_the_boot:?}"
    );
    assert_eq!(
        closure_of(&host, here_session).await.reason,
        ClosureReason::WorkerCrash,
        "control: a worker of this boot that ended is a crash"
    );
    assert_eq!(
        closure_of(&host, unlike_session).await.reason,
        ClosureReason::WorkerCrash,
        "control: a record of a boot this host cannot compare with its own is not an earlier boot"
    );
    host.stop().await;
}
