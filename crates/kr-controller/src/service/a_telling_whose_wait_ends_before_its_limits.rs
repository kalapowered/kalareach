//! A telling's wait for the registry between two notices, which ends before the limits around it.
//!
//! An ask that has a deadline is bounded three times at that instant: the wait for the registry
//! between two notices, the limit of the telling, and the bound of the ask itself. A link that goes
//! out of its holder's hand with no answer given back stops the renewal of the worker's lease, so
//! which of those timers the runtime sees first must decide nothing: the wait ends a whole
//! exchange's time before the deadline, where no further notice can begin, and gives the link back
//! there, with nothing on the wire. The write the wait is for may still finish after it, until the
//! deadline, before the next caller has the link.
//!
//! The worker here answers a notice only when a test lets it, so a test holds the registry before
//! the first answer arrives and learns what the daemon did from its own records: the slot, the lease
//! issuer and the registry's row of the worker.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use kr_ipc::endpoint::Listener;
use kr_ipc::framed::split;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::frame::StreamKind;
use kr_protocol::ids::{AuthorityRevision, ConnectionId, SessionId};
use kr_protocol::scalars::U64;

use super::a_close_a_worker_never_answers::{self as world, Silent};
use super::barrier::Asked;
use crate::service::Controller;

/// How long a test waits for something it waits for by condition, and fails after. Nothing is
/// decided by it: a daemon that never gets there is the one thing that runs it out.
const WAIT: Duration = Duration::from_secs(30);

/// How long the ask of each case has: the first notice begins at once, with time for two exchanges,
/// and the wait for the registry ends five seconds before this.
const ASK: Duration = Duration::from_secs(10);

/// What the worker has been sent, and when it may answer.
#[derive(Debug)]
struct Heard {
    frames: AtomicUsize,
    connections: AtomicUsize,
    /// One permit lets the worker answer one announcement.
    answer: tokio::sync::Semaphore,
}

/// An endpoint that proves itself as a worker and acknowledges each announcement it is sent, with a
/// fence that names nothing and has nothing more to say, once a test lets it answer.
fn answering(
    heard: Arc<Heard>,
) -> impl FnOnce(Listener, Arc<WorkerIdentity>, String) -> tokio::task::JoinHandle<()> {
    move |listener, identity, endpoint_text| {
        tokio::spawn(async move {
            loop {
                let Ok((connection, peer)) = listener.accept().await else {
                    return;
                };
                heard.connections.fetch_add(1, Ordering::SeqCst);
                let identity = Arc::clone(&identity);
                let endpoint_text = endpoint_text.clone();
                let heard = Arc::clone(&heard);
                tokio::spawn(async move {
                    let (mut reader, mut writer) = split(connection, StreamKind::Control);
                    let connection_id = ConnectionId::new(kr_ipc::new_uuid());
                    while let Ok(frame) = reader.read_message::<ControlFrame>().await {
                        let answers = world::handshake(
                            &frame,
                            &identity,
                            &endpoint_text,
                            connection_id,
                            &peer,
                            &kr_protocol::scalars::CanonicalSet::new(),
                        );
                        if let Some(answers) = answers {
                            for answer in answers {
                                if writer.write_message(&answer).await.is_err() {
                                    return;
                                }
                            }
                            continue;
                        }
                        let ControlFrame::AuthorityRevision(notice) = &frame else {
                            continue;
                        };
                        let revision = notice.revision;
                        heard.frames.fetch_add(1, Ordering::SeqCst);
                        let Ok(permit) = heard.answer.acquire().await else {
                            return;
                        };
                        permit.forget();
                        let ack = ControlFrame::AuthorityRevisionAck(
                            kr_protocol::worker::AuthorityRevisionAck {
                                session_id: identity.session_id(),
                                revision,
                                fence: Some(kr_protocol::action::FenceEvidence {
                                    rejected_actions: Vec::new(),
                                    possibly_executed: Vec::new(),
                                    remaining: U64::ZERO,
                                    omitted: U64::ZERO,
                                }),
                            },
                        );
                        if writer.write_message(&ack).await.is_err() {
                            return;
                        }
                    }
                });
            }
        })
    }
}

/// A daemon with one answering worker in its directory, which has acknowledged the revision in
/// force, so its lease renews, and which would be told its revisions in several notices.
async fn answered() -> (Silent, Arc<Heard>) {
    let heard = Arc::new(Heard {
        frames: AtomicUsize::new(0),
        connections: AtomicUsize::new(0),
        answer: tokio::sync::Semaphore::new(0),
    });
    let silent = world::fake_world_reached(answering(Arc::clone(&heard))).await;
    let controller = &silent.controller;
    // Two barriers for changes that reach more grants than one notice names, raised while the
    // worker is not in the directory, so that a daemon that has recorded nothing of the worker
    // tells it its revisions in at least two notices.
    controller.directory.lock().await.remove(silent.session_id);
    let bound = u32::try_from(kr_protocol::worker::MAX_REVISION_REACH_NAMES).expect("fits");
    let mut newest = AuthorityRevision::new(0);
    for first in [1_u32, 100_000] {
        let grants: std::collections::BTreeSet<_> = (first..first + bound / 2 + 1)
            .map(|number| {
                let mut bytes = [0_u8; 16];
                bytes[..4].copy_from_slice(&number.to_be_bytes());
                kr_protocol::ids::GrantId::new(kr_protocol::scalars::Uuid::from_bytes(bytes))
            })
            .collect();
        let reach = crate::service::Reach::Grants {
            holding_leases: grants.clone(),
            grants,
        };
        let debt = controller
            .owe_debt("a change", reach.clone())
            .expect("written");
        let own = controller.publish_debts(&[(debt, reach)]);
        controller.barrier(own).await.expect("a barrier");
        newest = controller
            .registry
            .lock()
            .await
            .authority_revision()
            .expect("readable");
    }
    assert!(
        controller
            .revision_notices(newest, AuthorityRevision::new(0), 0)
            .len()
            >= 2,
        "the worker is told in several notices"
    );
    world::acknowledged(controller, silent.session_id);
    controller
        .directory
        .lock()
        .await
        .insert(silent.worker.clone(), None);
    (silent, heard)
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

/// What the daemon holds in the worker's slot: a link, or nothing.
async fn slot_holds_a_link(controller: &Controller, session_id: SessionId) -> bool {
    let slot = Arc::clone(
        controller
            .connections
            .lock()
            .await
            .get(&session_id)
            .expect("the daemon has a slot for the worker"),
    );
    slot.lock().await.is_some()
}

/// The registry's row for the fake worker of `silent`, as a worker that reported itself has one,
/// which a write of its acknowledged revision needs.
async fn record_the_worker(silent: &Silent) {
    let descriptor = &silent.worker.descriptor;
    silent
        .controller
        .registry
        .lock()
        .await
        .adopt_worker(
            &crate::registry::WorkerRecord {
                session_id: silent.session_id,
                display_number: descriptor.display_number,
                public_key: descriptor.worker_public_key,
                process_identity: descriptor.process_start_identity.clone(),
                endpoint: descriptor.endpoint.clone(),
                profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
                state: kr_protocol::session::SessionState::Live,
                acknowledged_revision: AuthorityRevision::new(0),
            },
            Some(&kr_protocol::identity::DesktopBinding::none()),
        )
        .expect("the registry records the worker");
}

/// The revision the registry records the worker as having acknowledged.
async fn acknowledged_in_the_row(
    controller: &Controller,
    session_id: SessionId,
) -> AuthorityRevision {
    controller
        .registry
        .lock()
        .await
        .workers()
        .expect("readable")
        .into_iter()
        .find(|worker| worker.session_id == session_id)
        .expect("the worker has a row")
        .acknowledged_revision
}

/// What a telling that gave its link back, with nothing on the wire, leaves behind: one notice was
/// sent, the worker's lease goes on renewing, and the link is in its slot, so that no other link was
/// opened for the next caller.
async fn the_link_went_back_whole(silent: &Silent, heard: &Heard) {
    let controller = &silent.controller;
    assert_eq!(
        heard.frames.load(Ordering::SeqCst),
        1,
        "only the first notice went to the worker"
    );
    assert!(
        !controller.leases.is_fenced(silent.session_id),
        "the renewal of the worker's lease was not stopped"
    );
    assert!(
        controller
            .leases
            .renew(silent.session_id, controller.generation, &*controller.clock)
            .expect("a decision")
            .is_ok()
    );
    assert!(
        slot_holds_a_link(controller, silent.session_id).await,
        "the link went back whole"
    );
    assert_eq!(
        heard.connections.load(Ordering::SeqCst),
        1,
        "no other link was opened"
    );
}

/// KR-REQ-09.12: a limit around an ask's telling that ends before the deadline finds the link given
/// back, so the order of the timers decides nothing.
///
/// The first notice is answered at once, and the registry is held, so the write for it waits. A limit
/// that cuts the ask a second before its deadline stands in for a runtime that sees the outer timers
/// before the wait's own: with the wait ending at the deadline, that limit comes first and drops the
/// link with the lease's renewal; with it ending five seconds before, the link is already back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_limit_that_ends_near_the_deadline_finds_the_link_already_given_back() {
    let (silent, heard) = answered().await;
    let controller = Arc::clone(&silent.controller);
    let session_id = silent.session_id;
    let (let_go, held_until) = tokio::sync::oneshot::channel::<()>();
    let holder = tokio::spawn({
        let controller = Arc::clone(&controller);
        let heard = Arc::clone(&heard);
        async move {
            until("the first notice reached the worker", || {
                heard.frames.load(Ordering::SeqCst) >= 1
            })
            .await;
            let held = controller.registry.lock().await;
            heard.answer.add_permits(1);
            let _ = held_until.await;
            drop(held);
        }
    });
    let until_when = tokio::time::Instant::now() + ASK;
    let asked = tokio::time::timeout_at(
        until_when - Duration::from_secs(1),
        controller.ask_worker_revision(session_id, Some(until_when)),
    )
    .await;
    let _ = let_go.send(());
    holder.await.expect("the holder ended");
    assert!(
        asked.is_err(),
        "the limit around the ask ended it, before the deadline"
    );
    the_link_went_back_whole(&silent, &heard).await;
    silent.serving.abort();
}

/// KR-REQ-09.12: the write that a wait for the registry is for finishes when the registry is let
/// go after the wait ended, and leaves the row as the acknowledgement of the first notice.
///
/// The wait ends five seconds before the deadline, and the registry is let go three seconds later,
/// two before the deadline. The link has gone back by then, and the write is made with the slot still
/// held, so that the next caller of the link finds it recorded. The ask, which could send no more,
/// answers `Failed`.
///
/// The worker has a row, so it is pending, and the daemon's own pass would ask it too, and send a
/// notice of its own that the count of frames and the slot would take for this ask's. The pass's
/// asks are held for the case.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_that_finishes_after_the_wait_ended_leaves_the_row_right() {
    let (silent, heard) = answered().await;
    silent.controller.hold_the_pass_asks_for_tests(true);
    record_the_worker(&silent).await;
    let controller = Arc::clone(&silent.controller);
    let session_id = silent.session_id;
    let held_at_first = acknowledged_in_the_row(&controller, session_id).await;
    let newest = controller
        .registry
        .lock()
        .await
        .authority_revision()
        .expect("readable");
    let first = controller
        .revision_notices(newest, held_at_first, 0)
        .first()
        .expect("a notice")
        .revision;
    let until_when = tokio::time::Instant::now() + ASK;
    let holder = tokio::spawn({
        let controller = Arc::clone(&controller);
        let heard = Arc::clone(&heard);
        async move {
            until("the first notice reached the worker", || {
                heard.frames.load(Ordering::SeqCst) >= 1
            })
            .await;
            let held = controller.registry.lock().await;
            heard.answer.add_permits(1);
            tokio::time::sleep_until(until_when - Duration::from_secs(2)).await;
            drop(held);
        }
    });
    let asked = controller
        .ask_worker_revision(session_id, Some(until_when))
        .await;
    holder.await.expect("the holder ended");
    assert_eq!(
        asked.unwrap_or(Asked::Failed),
        Asked::Failed,
        "no further notice could begin"
    );
    assert_eq!(
        acknowledged_in_the_row(&controller, session_id).await,
        first,
        "the row records the acknowledgement of the first notice"
    );
    the_link_went_back_whole(&silent, &heard).await;
    silent.serving.abort();
}
