//! An action identifier one method spent is spent for every method of the same actor.
//!
//! One real daemon with a real worker it adopts, and the owner at its own socket. The stores of the
//! daemon each keep the actions they performed, and each compares an arriving mutation with its own
//! records alone; the local door asks the others before a first admission, so an identifier a
//! mutation of one store spent is refused to a mutation of another before anything is done.

#![cfg(unix)]

mod net_support;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use kr_controller::catalogue::TestingPoint;
use kr_ipc::client::LocalClient;
use kr_protocol::attention::{VisitAcknowledgeParams, VisitAcknowledgeResult};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::privacy::{PrivacyReport, PrivacySetParams, PrivacyStatusParams};
use kr_protocol::project::{DestinationRequest, ProjectInitParams, ProjectInitResult};
use kr_protocol::scalars::{Nullable, U64};
use net_support::Host;
use net_support::pairing::mutate_as;
use net_support::worker::Adopted;

fn identifier(byte: u8) -> ActionId {
    ActionId::new(kr_protocol::scalars::Uuid::from_bytes([byte; 16]))
}

/// Acknowledges a visit to the session: a mutation the attention store keeps.
async fn visit(
    host: &Host,
    client: &mut LocalClient,
    session_id: SessionId,
    action: ActionId,
) -> Result<VisitAcknowledgeResult, kr_protocol::error::ProtocolError> {
    mutate_as(
        host.environment_id,
        client,
        action,
        Method::VisitAcknowledge,
        &VisitAcknowledgeParams {
            session_id,
            acknowledged_cursor: U64::new(0),
            views: Vec::new(),
        },
    )
    .await
}

/// Sets privacy mode: a mutation the grant store keeps.
async fn privacy(
    host: &Host,
    client: &mut LocalClient,
    enabled: bool,
    action: ActionId,
) -> Result<PrivacyReport, kr_protocol::error::ProtocolError> {
    mutate_as(
        host.environment_id,
        client,
        action,
        Method::PrivacySet,
        &PrivacySetParams { enabled },
    )
    .await
}

/// Starts a repository in a directory of its own: a mutation the project store keeps.
async fn project(
    host: &Host,
    client: &mut LocalClient,
    work: &kr_ipc::testing::PrivateTempDir,
    name: &str,
    action: ActionId,
) -> Result<ProjectInitResult, kr_protocol::error::ProtocolError> {
    mutate_as(
        host.environment_id,
        client,
        action,
        Method::ProjectInit,
        &ProjectInitParams {
            destination: DestinationRequest {
                environment_id: host.environment_id,
                parent: kr_protocol::project::DestinationParent::Host {
                    path: work.path().display().to_string(),
                },
                name: name.to_owned(),
            },
            label: name.to_owned(),
            initial_branch: Nullable::some("main".to_owned()),
        },
    )
    .await
}

async fn privacy_is_on(host: &Host) -> bool {
    let mut client = host.client().await;
    let report: PrivacyReport = client
        .request(Method::PrivacyStatus, &PrivacyStatusParams {})
        .await
        .expect("the call reaches the daemon")
        .expect("privacy mode's report")
        .to_typed()
        .expect("decodes");
    report.enabled
}

fn is_a_reuse<T: std::fmt::Debug>(outcome: Result<T, kr_protocol::error::ProtocolError>) -> bool {
    matches!(outcome, Err(ref error) if error.code == ErrorCode::IdConflict)
}

/// KR-REQ-09.07: an identifier a mutation of one store spent is refused to a mutation of another,
/// whichever way round, and the refused mutation does nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_identifier_spent_in_one_store_is_refused_to_a_mutation_of_another() {
    let Adopted { host, workers, .. } = Adopted::start(1).await;
    let session_id = workers[0].session_id;
    let work = kr_ipc::testing::PrivateTempDir::create();
    let mut client = host.client().await;

    // The project store spends it, and the attention store is refused, and the other way round.
    let first = identifier(0x41);
    project(&host, &mut client, &work, "first", first)
        .await
        .expect("the repository is started");
    assert!(is_a_reuse(
        visit(&host, &mut client, session_id, first).await
    ));
    let second = identifier(0x42);
    visit(&host, &mut client, session_id, second)
        .await
        .expect("the visit is acknowledged");
    assert!(is_a_reuse(
        project(&host, &mut client, &work, "second", second).await
    ));
    assert!(
        !work.path().join("second").exists(),
        "the refused mutation did not run"
    );

    // The attention store spends it, and the grant store is refused, and the other way round.
    assert!(is_a_reuse(privacy(&host, &mut client, true, second).await));
    assert!(
        !privacy_is_on(&host).await,
        "the refused mutation did not run"
    );
    let third = identifier(0x43);
    privacy(&host, &mut client, true, third)
        .await
        .expect("privacy mode turns on");
    assert!(is_a_reuse(
        visit(&host, &mut client, session_id, third).await
    ));

    // A repeat of the mutation that spent it is still answered from its own store.
    project(&host, &mut client, &work, "first", first)
        .await
        .expect("a repeat of the first is answered");
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.07: an identifier spent before a restart is spent after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_identifier_spent_before_a_restart_is_spent_after_it() {
    let Adopted { host, workers, .. } = Adopted::start(1).await;
    let session_id = workers[0].session_id;
    let spent = identifier(0x51);
    {
        let mut client = host.client().await;
        visit(&host, &mut client, session_id, spent)
            .await
            .expect("the visit is acknowledged");
    }
    let stopped = host.shut_down().await;
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;

    let mut client = host.client().await;
    assert!(is_a_reuse(privacy(&host, &mut client, true, spent).await));
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.07: an identifier that a mutation is being performed under is refused to a mutation of
/// another store that arrives meanwhile, before the first has written anything.
///
/// The first mutation is stopped inside its store, where it holds the registry and has written no
/// record, so the stores hold nothing under the identifier for the second to find. Only the
/// identifier the daemon is performing can refuse the second, and the second is refused without
/// waiting for the registry the first holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_identifier_being_performed_is_refused_to_a_mutation_of_another_store_arriving_meanwhile()
 {
    let Adopted { host, workers, .. } = Adopted::start(1).await;
    let session_id = workers[0].session_id;
    let shared = identifier(0x61);
    let mut client = host.client().await;
    let (arrived, release) = host.controller().attention().pause_before_store();
    let host = Arc::new(host);
    let visiting = {
        let host = Arc::clone(&host);
        tokio::spawn(async move {
            let mut client = host.client().await;
            visit(&host, &mut client, session_id, shared).await.is_ok()
        })
    };
    // Bounded, because the module keeps the other end of this channel: a mutation that answered
    // without reaching the pause would leave an unbounded wait rather than a failure.
    tokio::task::spawn_blocking(move || {
        arrived
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the visit reached its store")
    })
    .await
    .expect("the wait ends");

    let refused = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        privacy(&host, &mut client, true, shared),
    )
    .await
    .expect("the second mutation is answered without waiting for the first");
    assert!(
        is_a_reuse(refused),
        "the identifier being performed is refused to the other mutation"
    );
    release.send(()).expect("the visit is let go");
    assert!(
        visiting.await.expect("the visit task ends"),
        "the first mutation is performed"
    );
    assert!(
        !privacy_is_on(&host).await,
        "the refused mutation did not run"
    );
    Arc::try_unwrap(host)
        .unwrap_or_else(|_| panic!("the task has ended"))
        .stop()
        .await;
    drop(workers);
}

/// KR-REQ-09.07: an attempt that claimed its action and was left unfinished is answered as its own
/// retry and not refused as a reuse.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_attempt_left_unfinished_is_not_refused_as_a_reuse_of_its_own_identifier() {
    use kr_protocol::digest::mutation_digest;

    let Adopted { host, workers, .. } = Adopted::start(1).await;
    let mut client = host.client().await;
    let action = identifier(0x71);
    let mutation = client
        .compose(
            Method::PrivacySet,
            action,
            kr_protocol::envelope::ActionTarget::environment(host.environment_id),
            &PrivacySetParams { enabled: true },
        )
        .await
        .expect("the mutation is composed");
    let owner = kr_protocol::ids::ActorId::new(format!("local:{}", kr_ipc::paths::current_uid()))
        .expect("an actor");
    let digest = mutation_digest(&mutation, &owner).expect("a digest");
    let claim = host
        .controller()
        .sharing()
        .grants()
        .claim_action(&owner, action, &digest, kr_ipc::now_ms().get())
        .expect("the claim is written");
    assert!(matches!(
        claim,
        kr_controller::grants::ActionClaim::Claimed { .. }
    ));
    drop(claim);

    let answered = client
        .repeat(&mutation)
        .await
        .expect("the daemon answers the call");
    assert!(
        !matches!(&answered, Err(error) if error.code == ErrorCode::IdConflict),
        "the retry of an unfinished attempt is not a reuse: {answered:?}"
    );
    host.stop().await;
    drop(workers);
}

/// KR-REQ-09.07: a catalogue operation that is under way holds up no mutation of another store.
///
/// The check reads the catalogue's records through a connection of its own. A read that took the
/// catalogue's lock would wait for the operation, which here waits for the mutation to answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_catalogue_operation_under_way_holds_up_no_mutation_of_another_store() {
    let Adopted { host, workers, .. } = Adopted::start(1).await;
    let (entered, entered_signal) = std::sync::mpsc::channel::<()>();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let released = Mutex::new(released);
    let timed_out = Arc::new(AtomicBool::new(false));
    host.controller().catalogue().at_testing_point({
        let timed_out = Arc::clone(&timed_out);
        let entered = Mutex::new(entered);
        move |point| {
            if point == TestingPoint::Records {
                let _ = entered
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .send(());
                let answered = released
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .recv_timeout(std::time::Duration::from_secs(60));
                if matches!(answered, Err(std::sync::mpsc::RecvTimeoutError::Timeout)) {
                    timed_out.store(true, Ordering::SeqCst);
                }
            }
        }
    });
    let operation = {
        let host = host.controller().clone();
        tokio::spawn(async move {
            let _ = host
                .catalogue()
                .installed_within(tokio::time::Instant::now() + std::time::Duration::from_secs(120))
                .await;
        })
    };
    tokio::task::spawn_blocking(move || entered_signal.recv())
        .await
        .expect("the wait ends")
        .expect("the operation reached the catalogue's records");

    let mut client = host.client().await;
    visit(&host, &mut client, workers[0].session_id, identifier(0x81))
        .await
        .expect("a mutation of another store is answered while the catalogue is held");
    release
        .send(())
        .expect("the operation is waiting to be released");
    operation.await.expect("the operation ends");
    assert!(
        !timed_out.load(Ordering::SeqCst),
        "the mutation waited for the catalogue operation"
    );
    host.stop().await;
    drop(workers);
}
