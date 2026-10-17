//! What this daemon sends a session worker about its host's local owner, and when.
//!
//! The worker here is a recording one that stands for each worker a daemon can meet: one that
//! acknowledges the statement of what the local owner may do and one whose first exchange fails. A
//! test reads what the worker was sent, in the order it arrived.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use kr_ipc::endpoint::Listener;
use kr_ipc::framed::split;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::frame::StreamKind;
use kr_protocol::ids::{BuildId, CapabilityId, ConnectionId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::CanonicalSet;
use kr_protocol::worker::{AuthorityRevisionAck, LocalAccessAck};

use super::Reach;
use super::a_close_a_worker_never_answers::{self as world, Silent};

/// How long a test waits for something it waits for by condition, and fails after. Nothing is
/// decided by it: a daemon that never gets there is the one thing that runs it out.
const WAIT: Duration = Duration::from_secs(60);

/// Every frame a recording worker was sent after its handshake, in arrival order, with the number
/// of the connection that carried it.
type Heard = Arc<std::sync::Mutex<Vec<(u64, ControlFrame)>>>;

/// How a recording worker behaves.
#[derive(Clone, Copy)]
struct Behaviour {
    /// Whether it ends the link that carries the first such statement without answering it.
    fails_the_first_statement: bool,
}

/// A recording worker that answers what it is sent as a worker of `behaviour` does.
fn recording(
    behaviour: Behaviour,
    recorded: Heard,
) -> impl FnOnce(Listener, Arc<WorkerIdentity>, String) -> tokio::task::JoinHandle<()> {
    move |listener, identity, endpoint_text| {
        let failing = Arc::new(AtomicBool::new(behaviour.fails_the_first_statement));
        let links = Arc::new(AtomicU64::new(0));
        let stated: CanonicalSet<CapabilityId> =
            [CapabilityId::new(kr_protocol::local::LOCAL_ACCESS).expect("a capability")]
                .into_iter()
                .collect();
        tokio::spawn(async move {
            loop {
                let Ok((connection, peer)) = listener.accept().await else {
                    return;
                };
                let identity = Arc::clone(&identity);
                let endpoint_text = endpoint_text.clone();
                let recorded = Arc::clone(&recorded);
                let failing = Arc::clone(&failing);
                let stated = stated.clone();
                let link = links.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let (mut reader, mut writer) = split(connection, StreamKind::Control);
                    let connection_id = ConnectionId::new(kr_ipc::new_uuid());
                    while let Ok(frame) = reader.read_message::<ControlFrame>().await {
                        // The statements are what this worker is here to record, so they are
                        // not answered with the rest of the handshake.
                        let handshaking = if matches!(frame, ControlFrame::LocalAccess(_)) {
                            None
                        } else {
                            world::handshake(
                                &frame,
                                &identity,
                                &endpoint_text,
                                connection_id,
                                &peer,
                                &stated,
                            )
                        };
                        if let Some(answers) = handshaking {
                            for answer in answers {
                                if writer.write_message(&answer).await.is_err() {
                                    return;
                                }
                            }
                            continue;
                        }
                        recorded
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push((link, frame.clone()));
                        let answer = match frame {
                            ControlFrame::LocalAccess(access) => {
                                if failing.swap(false, Ordering::SeqCst) {
                                    return;
                                }
                                ControlFrame::LocalAccessAck(LocalAccessAck {
                                    sequence: access.sequence,
                                })
                            }
                            ControlFrame::AuthorityRevision(notice) => {
                                ControlFrame::AuthorityRevisionAck(AuthorityRevisionAck {
                                    session_id: identity.session_id(),
                                    revision: notice.revision,
                                    fence: None,
                                })
                            }
                            _ => continue,
                        };
                        if writer.write_message(&answer).await.is_err() {
                            return;
                        }
                    }
                });
            }
        })
    }
}

/// A daemon with one recording worker in its directory.
async fn with(behaviour: Behaviour) -> (Silent, Heard) {
    let recorded: Heard = Arc::default();
    let silent = world::fake_world(recording(behaviour, Arc::clone(&recorded))).await;
    (silent, recorded)
}

/// The frames the worker has been sent, in arrival order.
fn heard(recorded: &Heard) -> Vec<ControlFrame> {
    heard_on(recorded)
        .into_iter()
        .map(|(_, frame)| frame)
        .collect()
}

/// The same, with the connection each came on.
fn heard_on(recorded: &Heard) -> Vec<(u64, ControlFrame)> {
    recorded
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Waits until `done` holds, and fails the test after [`WAIT`].
async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !done() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what} did not happen within {WAIT:?}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// The registry's row for the fake worker of `silent`, as a worker that reported itself has one.
fn row_of(silent: &Silent) -> crate::registry::WorkerRecord {
    let descriptor = &silent.worker.descriptor;
    crate::registry::WorkerRecord {
        session_id: silent.session_id,
        display_number: descriptor.display_number,
        public_key: descriptor.worker_public_key,
        process_identity: descriptor.process_start_identity.clone(),
        endpoint: descriptor.endpoint.clone(),
        profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        state: kr_protocol::session::SessionState::Live,
        acknowledged_revision: kr_protocol::ids::AuthorityRevision::new(0),
    }
}

/// The sessions the host counts as unable to be told what the local owner may do.
async fn lacking(silent: &Silent) -> Vec<SessionId> {
    let registry = silent.controller.registry.lock().await;
    silent
        .controller
        .workers_without_local_enforcement_in(&registry)
        .expect("the registry answers")
}

/// KR-REQ-17.54: a barrier tells a worker what the local owner may do before it announces the
/// revision, over the link it announces on, so the worker acknowledges the revision only once it
/// holds the bound in force.
///
/// The daemon's link to the worker was opened and used before, while the host was not exclusive. A
/// restriction then commits, and the publisher has not yet repeated its pass. The barrier's own
/// statement is the only thing that can put the new bound in front of the revision on that link.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_barrier_tells_a_worker_what_its_local_owner_may_do_before_it_announces_the_revision() {
    use kr_protocol::worker::LocalBound;

    let (silent, recorded) = with(Behaviour {
        fails_the_first_statement: false,
    })
    .await;
    let controller = &silent.controller;
    world::acknowledged(controller, silent.session_id);
    controller.tell_workers().await;
    assert!(
        heard(&recorded)
            .iter()
            .any(|frame| matches!(frame, ControlFrame::LocalAccess(_))),
        "the worker was told while the host was not exclusive"
    );

    // The restriction commits; nothing wakes the publisher.
    controller
        .policy
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .set_exclusively_managed(true);
    let debt = controller
        .owe_debt("a change that restricts", Reach::Host)
        .expect("written");
    let own = controller.publish_debts(&[(debt, Reach::Host)]);
    controller.barrier(own).await.expect("a barrier");

    let frames = heard_on(&recorded);
    let (link, announced) = frames
        .iter()
        .enumerate()
        .find_map(|(at, (link, frame))| {
            matches!(frame, ControlFrame::AuthorityRevision(_)).then_some((*link, at))
        })
        .expect("the worker was sent the revision");
    let told = frames[..announced]
        .iter()
        .rev()
        .find_map(|(carried_on, frame)| match frame {
            ControlFrame::LocalAccess(access) if *carried_on == link => Some(*access),
            _ => None,
        })
        .expect("the link the revision came on carried a statement before it");
    assert_eq!(
        told.bound,
        LocalBound::Closed,
        "and it was the bound in force, not the one the link was last told: {frames:?}"
    );
    silent.serving.abort();
}

/// KR-REQ-17.54: a worker whose level cannot read the statement is sent none, and the link it was
/// told on goes on. Such a worker is counted as one that cannot be told, which is what the
/// enablement of exclusive management refuses to pass over.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_whose_level_cannot_read_the_statement_is_sent_none_and_its_link_goes_on() {
    let (silent, recorded) = with(Behaviour {
        fails_the_first_statement: false,
    })
    .await;
    let controller = &silent.controller;
    world::acknowledged(controller, silent.session_id);
    controller
        .registry
        .lock()
        .await
        .adopt_worker(
            &row_of(&silent),
            Some(&kr_protocol::identity::DesktopBinding::none()),
        )
        .expect("the registry records the worker");
    // A level whose frames have no statement of what the local owner may do.
    let level = kr_protocol::retained::a_level_of_the_tests_own(
        |definitions| {
            definitions["ControlFrame"]["oneOf"]
                .as_array_mut()
                .expect("variants")
                .retain(|variant| variant["properties"].get("local_access").is_none());
        },
        &[],
    );
    let mut link = kr_ipc::client::BoundLink::connect_at(
        &silent.worker.endpoint,
        controller.build_id.clone(),
        level,
    )
    .await
    .expect("the link is made");

    for _ in 0..2 {
        assert_eq!(
            controller
                .tell_link(silent.session_id, &mut link)
                .await
                .expect("a worker that cannot be told is not an error, and its link goes on"),
            None
        );
    }
    assert!(
        !heard(&recorded)
            .iter()
            .any(|frame| matches!(frame, ControlFrame::LocalAccess(_))),
        "no statement reached a worker that cannot read one"
    );
    assert_eq!(
        lacking(&silent).await,
        vec![silent.session_id],
        "and the host counts it as one that cannot be told"
    );
    silent.serving.abort();
}

/// KR-REQ-17.54: a worker whose first statement failed is told again by the publisher alone, with
/// no wake and no new link asked for: the daemon repeats until the worker acknowledges.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_statement_a_worker_did_not_acknowledge_is_sent_again_by_the_publisher_alone() {
    let (silent, recorded) = with(Behaviour {
        fails_the_first_statement: true,
    })
    .await;
    // The first statement ends its link without an answer; the publisher sends the same statement
    // again on a link of its own, with nobody asking it to.
    until("the worker is sent the statement a second time", || {
        heard_on(&recorded)
            .iter()
            .filter(|(_, frame)| matches!(frame, ControlFrame::LocalAccess(_)))
            .map(|(link, _)| *link)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            >= 2
    })
    .await;
    silent.serving.abort();
}

/// KR-REQ-17.54: the host counts as unable to be told every recorded worker it has not reached or
/// whose level cannot read the statement, and every claimed launch that this run of the daemon did
/// not make, because its worker may be alive and serving its local caller without the hold. A
/// worker it has told is not counted. Making the host exclusively organisation-managed is refused
/// while the count is not empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_host_counts_the_workers_it_cannot_tell_and_not_those_it_has_told() {
    let (silent, _recorded) = with(Behaviour {
        fails_the_first_statement: false,
    })
    .await;
    let controller = &silent.controller;
    controller
        .registry
        .lock()
        .await
        .adopt_worker(
            &row_of(&silent),
            Some(&kr_protocol::identity::DesktopBinding::none()),
        )
        .expect("the registry records the worker");

    // A recorded worker that has not been reached counts as one that cannot be told.
    assert_eq!(lacking(&silent).await, vec![silent.session_id]);

    // Once it has been reached and told, it does not.
    controller.tell_workers().await;
    assert!(lacking(&silent).await.is_empty());

    // A claimed launch this run of the daemon did not make may have a worker alive.
    let claim = super::a_create_that_launches_nothing::seed_claim_as(
        controller,
        &silent.actor.actor_id,
        kr_protocol::identity::WorkerProfile::HeadlessUser,
        |_| {
            *kr_crypto::keys::AuthorisationKeyPair::generate()
                .expect("a key")
                .public()
        },
    )
    .await;
    assert_eq!(lacking(&silent).await, vec![claim.session_id]);
    silent.serving.abort();
}

/// KR-REQ-17.54: a claim the daemon recovers is recorded before the worker is told anything, and
/// the worker is told what is in force when it is published, not what was drawn before a
/// restriction committed.
///
/// The worker is real and starts closed, as one the daemon launched does. The daemon stops with the
/// statement drawn and not yet sent; at that moment the registry already holds the worker, so any
/// restriction from here on counts it, and the worker is not visible. A restriction commits there.
/// Once the tell ends, the worker holds the restriction, and only then is it published.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_recovered_claim_is_recorded_before_it_is_told_and_published_on_what_is_in_force() {
    use super::a_link_that_is_not_given_back::Served;

    let (world, _reservation) = Served::claimed().await;
    let controller = &world.controller;
    let session_id = world.session_id;
    world.service().hold_local_access_until_told();
    let (drawn, go) = controller.after_the_local_access_is_drawn.arm();

    let recovering = tokio::spawn({
        let controller = Arc::clone(controller);
        async move { controller.recover_claims().await }
    });
    tokio::time::timeout(WAIT, drawn)
        .await
        .expect("the daemon draws what it will tell the worker")
        .expect("the pause is armed");

    assert!(
        controller
            .registry
            .lock()
            .await
            .workers()
            .expect("the registry answers")
            .iter()
            .any(|row| row.session_id == session_id),
        "the worker has its row before it is told anything, so every barrier counts it"
    );
    assert!(
        controller.directory.lock().await.get(session_id).is_none(),
        "and nothing can find it yet"
    );
    refused_for_the_lease(
        &read_as_the_owner(&world).await,
        "not yet told",
        "the worker has been told nothing, and serves its local owner nothing that is held",
    );

    // A restriction commits after the statement was drawn and before it is sent.
    controller
        .policy
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .set_exclusively_managed(true);
    go.send(()).expect("the tell is waiting");
    tokio::time::timeout(WAIT, recovering)
        .await
        .expect("the recovery ends")
        .expect("the task ends")
        .expect("the claim is recovered");

    assert!(
        controller.directory.lock().await.get(session_id).is_some(),
        "the worker is published"
    );
    refused_for_the_lease(
        &read_as_the_owner(&world).await,
        "not live",
        "and it holds the restriction that committed meanwhile, not the answer drawn before it",
    );
}

/// A read of the worker's session by the host's local owner, on the worker's own socket as
/// `kr attach` makes it.
async fn read_as_the_owner(
    world: &super::a_link_that_is_not_given_back::Served,
) -> Result<(), kr_protocol::error::ProtocolError> {
    let mut client = kr_ipc::client::LocalClient::connect(
        &world.worker.endpoint,
        kr_protocol::local::LocalClientKind::Cli,
        BuildId::new("kr-test/0").expect("a build identifier"),
    )
    .await
    .expect("connects to the worker");
    client
        .request(
            Method::SessionRead,
            &kr_protocol::session::SessionReadParams {
                session_id: world.session_id,
            },
        )
        .await
        .expect("the worker answers")
        .map(|_| ())
}

/// Asserts that a read was refused for the local owner's lease, in the words that name `why`.
fn refused_for_the_lease(
    answer: &Result<(), kr_protocol::error::ProtocolError>,
    why: &str,
    what: &str,
) {
    let error = answer.as_ref().expect_err(what);
    assert_eq!(
        error.code,
        kr_protocol::error::ErrorCode::PermissionDenied,
        "{what}: {error:?}"
    );
    assert!(error.message.contains(why), "{what}: {error:?}");
}
