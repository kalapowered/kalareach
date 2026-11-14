//! What this daemon does when a worker tells a link it has just opened that a later connection
//! holds its authority.
//!
//! The worker here stands for one of an earlier build, which gives a role to the connection whose
//! presentation it decides last, so that a link this daemon opened and gave up on can take the
//! authority from the one it opened after it. It answers the first statement a link carries with
//! the words a worker says that in, on the first links it is asked, and acknowledges the rest.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use kr_ipc::endpoint::Listener;
use kr_ipc::framed::split;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::envelope::{ControlFrame, Outcome, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::StreamKind;
use kr_protocol::ids::{CapabilityId, ConnectionId, RequestId};
use kr_protocol::scalars::CanonicalSet;
use kr_protocol::worker::LocalAccessAck;
use kr_worker::service::LATER_CONNECTION_HOLDS_AUTHORITY;

use super::a_close_a_worker_never_answers as world;

/// How long a case waits for the daemon to answer, and fails after. Nothing is decided by it.
const WAIT: Duration = Duration::from_secs(60);

/// A worker that refuses the first statement of its first links with `refusals`, one for each
/// link in the order they are opened, as a worker whose connection was displaced does, and
/// acknowledges the first statement of every link after them. `links` counts the connections it
/// has accepted.
fn worker(
    refusals: &'static [&'static str],
    links: Arc<AtomicU64>,
) -> impl FnOnce(Listener, Arc<WorkerIdentity>, String) -> tokio::task::JoinHandle<()> {
    move |listener, identity, endpoint_text| {
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
                let stated = stated.clone();
                let link = usize::try_from(links.fetch_add(1, Ordering::SeqCst))
                    .expect("a link number fits");
                tokio::spawn(async move {
                    let (mut reader, mut writer) = split(connection, StreamKind::Control);
                    let connection_id = ConnectionId::new(kr_ipc::new_uuid());
                    while let Ok(frame) = reader.read_message::<ControlFrame>().await {
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
                        let answer = match frame {
                            ControlFrame::LocalAccess(access) => match refusals.get(link) {
                                Some(words) => ControlFrame::Response(Response {
                                    request_id: RequestId::new(0),
                                    outcome: Outcome::Error(
                                        ProtocolError::new(ErrorCode::PermissionDenied, *words)
                                            .for_a_fenced_link(),
                                    ),
                                }),
                                None => ControlFrame::LocalAccessAck(LocalAccessAck {
                                    sequence: access.sequence,
                                }),
                            },
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

/// KR-REQ-02.05: a link whose first exchange is refused with the words that a later connection
/// holds the worker's authority is replaced by one more link, and the request that wanted it goes
/// on with that one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_displaced_before_its_first_exchange_is_opened_once_more_for_the_request() {
    let links = Arc::new(AtomicU64::new(0));
    let silent = world::fake_world_reached(worker(
        &[LATER_CONNECTION_HOLDS_AUTHORITY],
        Arc::clone(&links),
    ))
    .await;
    let link = tokio::time::timeout(WAIT, silent.controller.worker_client(&silent.worker))
        .await
        .expect("the daemon answers")
        .expect("the request is given a link");
    assert_eq!(
        links.load(Ordering::SeqCst),
        2,
        "the displaced link and the one that replaced it"
    );
    drop(link);
}

/// KR-REQ-02.05: the daemon opens one further link and no more: a second refusal with the same
/// words is the request's answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_displacement_is_the_requests_answer() {
    let links = Arc::new(AtomicU64::new(0));
    let silent = world::fake_world_reached(worker(
        &[
            LATER_CONNECTION_HOLDS_AUTHORITY,
            LATER_CONNECTION_HOLDS_AUTHORITY,
            LATER_CONNECTION_HOLDS_AUTHORITY,
        ],
        Arc::clone(&links),
    ))
    .await;
    let answered = tokio::time::timeout(WAIT, silent.controller.worker_client(&silent.worker))
        .await
        .expect("the daemon answers");
    assert!(answered.is_err(), "the request is refused");
    assert_eq!(
        links.load(Ordering::SeqCst),
        2,
        "one further link and no other"
    );
}

/// KR-REQ-02.05: only that refusal opens a further link: a link refused for any other reason is
/// the request's answer at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_of_another_kind_opens_no_further_link() {
    let links = Arc::new(AtomicU64::new(0));
    let silent = world::fake_world_reached(worker(
        &["this worker holds no statement for this host"],
        Arc::clone(&links),
    ))
    .await;
    let answered = tokio::time::timeout(WAIT, silent.controller.worker_client(&silent.worker))
        .await
        .expect("the daemon answers");
    assert!(answered.is_err(), "the request is refused");
    assert_eq!(links.load(Ordering::SeqCst), 1, "no further link");
}
