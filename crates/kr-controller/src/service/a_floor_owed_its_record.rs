//! What a workflow's grant is decided on while this host's clock floor is owed its record.

use std::sync::Arc;

use kr_protocol::actor::ActorIngress;
use kr_protocol::grant::{EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{BuildId, DeviceId, GrantId};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs};

use crate::grants::GrantRecord;
use crate::service::{Controller, ControllerSetup};
use crate::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};

/// A supervisor that starts nothing. Deciding a grant needs no worker.
#[derive(Debug)]
struct NoWorkers;

impl WorkerSupervisor for NoWorkers {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> &'static str {
        "a supervisor that starts nothing"
    }
}

pub(super) async fn daemon(temp: &kr_ipc::testing::TempHost) -> Arc<Controller> {
    Controller::start(setup(temp))
        .await
        .expect("the daemon starts")
}

/// How long a test waits for the debt pass, or for a daemon to take the environment over.
pub(super) const WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// Starts a daemon as [`daemon`] does, whose debt pass looks again only when the test sends
/// it a pass, or when a change leaves it a debt.
pub(super) async fn daemon_passing_by_hand(
    temp: &kr_ipc::testing::TempHost,
) -> (Arc<Controller>, tokio::sync::mpsc::UnboundedSender<()>) {
    let (passes, schedule) = tokio::sync::mpsc::unbounded_channel();
    let controller = Controller::start_passing(
        setup(temp),
        crate::service::Clocks::system(),
        crate::service::barrier::PassSchedule::ByHand(schedule),
        std::sync::Arc::new(crate::quiet::RealTimer),
    )
    .await
    .expect("the daemon starts");
    (controller, passes)
}

/// Waits until `done` holds, and fails the test after [`WAIT`].
pub(super) async fn until(what: &str, mut done: impl AsyncFnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !done().await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what} did not happen within {WAIT:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

/// What [`daemon`] starts a daemon with.
pub(super) fn setup(temp: &kr_ipc::testing::TempHost) -> ControllerSetup {
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let secrets = environment.secrets_dir();
    ControllerSetup {
        paths: environment,
        environment_id,
        identity: Box::new(move || {
            let store = kr_crypto::store::open_store_in(&secrets)
                .expect("a secret store for the test environment");
            Ok(kr_ipc::verify::ControllerIdentity::open(
                store.store.as_ref(),
                environment_id,
                false,
            )
            .expect("an identity"))
        }),
        secret_store: kr_crypto::store::StoreSelection::File,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(NoWorkers),
        worker_program: temp.root().join("kr-worker"),
        build_id: BuildId::new("kr-test/0").expect("a build identifier"),
        release: "0".to_owned(),
        shell_packages: None,
        terminal: Box::new(crate::supervision::NoTerminal),
    }
}

/// A personal grant a workflow runs under, held by a device that reaches this host remotely.
fn held(controller: &Controller, expiry: GrantExpiry) -> GrantRecord {
    let device_id = DeviceId::new(kr_ipc::new_uuid());
    let record = GrantRecord {
        grant: Grant {
            grant_id: GrantId::new(kr_ipc::new_uuid()),
            parent_grant_id: Nullable::null(),
            issuer_device_id: controller.sharing().host_device_id(),
            recipient_device_id: device_id,
            authority_revision: controller.policy().authority_revision(),
            environment_selector: EnvironmentSelector::Any,
            session_selector: SessionSelector::Any,
            actions: [ActionRight::SessionView].into_iter().collect(),
            history: HistoryScope {
                lower_bound_ms: Nullable::null(),
                include_live_screen: false,
                named_questions: CanonicalSet::new(),
                named_approvals: CanonicalSet::new(),
            },
            expiry,
            organisation: Nullable::null(),
        },
        session_id: None,
        issued_at_ms: 1,
        activated_at_ms: Some(1),
        revoked_at_ms: None,
        revoked_by_parent: None,
    };
    // Written into the grant store, as a grant a workflow names is.
    controller
        .sharing()
        .grants()
        .issue(&record, || Ok(()))
        .expect("the grant is written");
    record
}

/// A workflow's grant is decided at a reading no older than the policy's lock it is decided
/// under: the caller's reading carried forward by the time it waited, and never earlier than
/// the wall clock read once the lock is held. With the wall clock past the grant's expiry and
/// the caller's reading short of it, the node is refused. The control: with the wall clock
/// short of the expiry, it is permitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_workflow_decision_reads_the_wall_clock_once_its_lock_is_held() {
    for passed in [false, true] {
        let temp = kr_ipc::testing::TempHost::create();
        let (_continuous, wall, clocks) = crate::service::net::tests::manual_clocks();
        let controller = crate::service::net::tests::daemon_on(&temp, clocks).await;
        let now = wall.load(std::sync::atomic::Ordering::SeqCst);
        let expiring = held(
            &controller,
            GrantExpiry::At {
                expires_at_ms: TimestampMs::new(now + 60_000),
            },
        );
        controller
            .decide_for_workflow(
                &expiring,
                ActorIngress::PairedDevice,
                now,
                controller.continuous_now(),
            )
            .expect("anchored and in force");
        if passed {
            wall.store(now + 60_000, std::sync::atomic::Ordering::SeqCst);
        }
        let decided = controller.decide_for_workflow(
            &expiring,
            ActorIngress::PairedDevice,
            now,
            controller.continuous_now(),
        );
        assert_eq!(decided.is_err(), passed, "{decided:?}");
        drop(controller);
    }
}

/// While the floor is owed its record, a workflow's grant that reads the clock is not decided,
/// and a personal grant that never expires, under no time bound of this host's policy, is
/// decided as before. Once the floor is written down, the expiring grant is decided again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_grant_that_never_expires_is_decided_while_the_floor_is_owed() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = daemon(&temp).await;
    let registry = rusqlite::Connection::open(temp.environment().registry_database())
        .expect("opens the registry");
    registry
        .busy_timeout(std::time::Duration::from_secs(5))
        .expect("waits for the daemon's writes");
    registry
        .execute_batch(
            "CREATE TRIGGER refuse_policy BEFORE INSERT ON host_authority
                 WHEN NEW.key = 'policy'
                 BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("the fault is in place");
    // A lapse this host found and could not write down.
    controller.keep_lapse(kr_ipc::now_ms().get());

    let now_ms = kr_ipc::now_ms().get();
    let lasting = held(&controller, GrantExpiry::Never);
    controller
        .decide_for_workflow(
            &lasting,
            ActorIngress::PairedDevice,
            now_ms,
            controller.continuous_now(),
        )
        .expect("a personal grant that never expires reads no clock");
    let expiring = held(
        &controller,
        GrantExpiry::At {
            expires_at_ms: TimestampMs::new(now_ms + 60 * 60 * 1000),
        },
    );
    let refused = controller
        .decide_for_workflow(
            &expiring,
            ActorIngress::PairedDevice,
            now_ms,
            controller.continuous_now(),
        )
        .expect_err("a grant that expires is not decided while the floor is owed");
    assert!(
        matches!(
            refused,
            kr_automation::AutomationError::AuthorityUnavailable(_)
        ),
        "{refused:?}"
    );

    registry
        .execute_batch("DROP TRIGGER refuse_policy;")
        .expect("the fault is cleared");
    controller
        .decide_for_workflow(
            &expiring,
            ActorIngress::PairedDevice,
            kr_ipc::now_ms().get(),
            controller.continuous_now(),
        )
        .expect("once the floor is written down, the grant is decided on its merits");
}
