//! What this daemon sends a session worker about its host's local owner, and when.
//!
//! The worker here is a recording one that stands for each worker a daemon can meet: one that
//! states it can be told what the local owner may do and acknowledges the statement, one that
//! states nothing, as a worker of an earlier release does, and one whose first exchange fails. A
//! test reads what the worker was sent, in the order it arrived.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use kr_ipc::endpoint::Listener;
use kr_ipc::framed::split;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::frame::StreamKind;
use kr_protocol::ids::{CapabilityId, ConnectionId, SessionId};
use kr_protocol::scalars::CanonicalSet;
use kr_protocol::worker::{AuthorityRevisionAck, LocalAccessAck};

use super::Reach;
use super::a_close_a_worker_never_answers::{self as world, Recorded, Silent};

/// How long a test waits for something it waits for by condition, and fails after. Nothing is
/// decided by it: a daemon that never gets there is the one thing that runs it out.
const WAIT: Duration = Duration::from_secs(60);

/// How a recording worker behaves.
#[derive(Clone, Copy)]
struct Behaviour {
    /// Whether it states that it can be told what the local owner may do.
    states: bool,
    /// Whether it ends the link that carries the first such statement without answering it.
    fails_the_first_statement: bool,
}

/// A recording worker that answers what it is sent as a worker of `behaviour` does.
fn recording(
    behaviour: Behaviour,
    recorded: Recorded,
) -> impl FnOnce(Listener, Arc<WorkerIdentity>, String) -> tokio::task::JoinHandle<()> {
    move |listener, identity, endpoint_text| {
        let failing = Arc::new(AtomicBool::new(behaviour.fails_the_first_statement));
        let stated: CanonicalSet<CapabilityId> = if behaviour.states {
            [CapabilityId::new(kr_protocol::local::LOCAL_ACCESS).expect("a capability")]
                .into_iter()
                .collect()
        } else {
            CanonicalSet::new()
        };
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
                tokio::spawn(async move {
                    let (mut reader, mut writer) = split(connection, StreamKind::Control);
                    let connection_id = ConnectionId::new(kr_ipc::new_uuid());
                    while let Ok(frame) = reader.read_message::<ControlFrame>().await {
                        if let Some(answers) = world::handshake(
                            &frame,
                            &identity,
                            &endpoint_text,
                            connection_id,
                            &peer,
                            &stated,
                        ) {
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
                            .push(frame.clone());
                        let answer = match frame {
                            ControlFrame::LocalAccess(access) => {
                                // A worker that does not state the capability ends the link that
                                // carries one, as a worker of an earlier release does.
                                if !behaviour.states || failing.swap(false, Ordering::SeqCst) {
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
async fn with(behaviour: Behaviour) -> (Silent, Recorded) {
    let recorded: Recorded = Arc::default();
    let silent = world::fake_world(recording(behaviour, Arc::clone(&recorded))).await;
    (silent, recorded)
}

/// The frames the worker has been sent, in arrival order.
fn heard(recorded: &Recorded) -> Vec<ControlFrame> {
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

/// What the worker of `session_id` has acknowledged, as the daemon records it.
fn acknowledged(silent: &Silent, session_id: SessionId) -> u64 {
    silent
        .controller
        .local_access
        .worker(session_id)
        .acknowledged
}

/// KR-REQ-17.54: a barrier tells a worker what the local owner may do before it announces the
/// revision, so the worker acknowledges the revision only once it holds the bound in force.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_barrier_tells_a_worker_what_its_local_owner_may_do_before_it_announces_the_revision() {
    let (silent, recorded) = with(Behaviour {
        states: true,
        fails_the_first_statement: false,
    })
    .await;
    let controller = &silent.controller;
    world::acknowledged(controller, silent.session_id);

    let debt = controller
        .owe_debt("a change that restricts", Reach::Host)
        .expect("written");
    let own = controller.publish_debts(&[(debt, Reach::Host)]);
    controller.barrier(own).await.expect("a barrier");

    let frames = heard(&recorded);
    let told = frames
        .iter()
        .position(|frame| matches!(frame, ControlFrame::LocalAccess(_)))
        .expect("the worker was told what the local owner may do");
    let announced = frames
        .iter()
        .position(|frame| matches!(frame, ControlFrame::AuthorityRevision(_)))
        .expect("the worker was sent the revision");
    assert!(
        told < announced,
        "the statement comes before the revision: {frames:?}"
    );
    silent.serving.abort();
}

/// KR-REQ-17.54: a worker that states no capability is sent no statement: it would end the link
/// that carried one, as a worker of an earlier release does. Such a worker is counted as one that
/// cannot be told, which is what the enablement of exclusive management refuses to pass over.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_that_states_no_capability_is_sent_no_statement_and_counts_as_one_that_cannot_be_told()
 {
    let (silent, recorded) = with(Behaviour {
        states: false,
        fails_the_first_statement: false,
    })
    .await;
    let controller = &silent.controller;
    world::acknowledged(controller, silent.session_id);

    controller.tell_workers().await;
    let debt = controller
        .owe_debt("a change that restricts", Reach::Host)
        .expect("written");
    let own = controller.publish_debts(&[(debt, Reach::Host)]);
    controller.barrier(own).await.expect("a barrier");

    assert_eq!(
        controller.local_access.worker(silent.session_id).states,
        Some(false),
        "the worker's hello said it cannot be told"
    );
    assert!(
        !heard(&recorded)
            .iter()
            .any(|frame| matches!(frame, ControlFrame::LocalAccess(_))),
        "no statement reached a worker that cannot take one"
    );
    silent.serving.abort();
}

/// KR-REQ-17.54: a worker whose first statement failed is told again by the publisher alone, with
/// no wake and no new link asked for: the daemon repeats until the worker acknowledges.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_statement_a_worker_did_not_acknowledge_is_sent_again_by_the_publisher_alone() {
    let (silent, recorded) = with(Behaviour {
        states: true,
        fails_the_first_statement: true,
    })
    .await;
    let session_id = silent.session_id;
    until("the worker acknowledges a statement", || {
        acknowledged(&silent, session_id) >= 1
    })
    .await;
    let statements = heard(&recorded)
        .iter()
        .filter(|frame| matches!(frame, ControlFrame::LocalAccess(_)))
        .count();
    assert!(
        statements >= 2,
        "the first statement failed and the worker was sent it again: {statements}"
    );
    silent.serving.abort();
}
