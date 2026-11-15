//! Terminal input from a client, through the host's door, to a real worker.
//!
//! The client is the library's own input lane over a real connection to the daemon, and the worker
//! is the real one: nothing between them is scripted. A case types through the client's lane, waits
//! for the host's acknowledgements, and sends a release as the client does, with the barrier the
//! lane marked. What each case asserts is what the worker took, what the host refused, and what the
//! client read back.
//!
//! A worker that states the input lane is served on its lane; one that does not is served one call
//! at a time, and its client is told what an older worker gives: no count of what the end of its
//! lease discarded.

#![cfg(unix)]

mod net_support;

use std::sync::Arc;
use std::time::Duration;

use kr_client::error::ClientError;
use kr_client::input::InputEvent;
use kr_client::session::Session;
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult,
    SessionDetachParams, SessionDetachResult,
};
use kr_protocol::envelope::ParamsValue;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{AttachmentId, InputLeaseEpoch};
use kr_protocol::input::{
    InputAcquireParams, InputAcquireResult, InputBarrier, InputLeaseResult, InputReleaseParams,
};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{DurationMs, Nullable, U64};
use kr_worker::input_domain::InputShared;

use net_support::typing::Typing;
use net_support::worker::Adopted;
use net_support::{Device, connect, pair_with, proposal};

/// What a case waits at most for the host or the worker to do what the case says. A host that does
/// it answers at once: the bound only ends a case that would hang.
const WAIT: Duration = Duration::from_secs(60);

/// A paired device that types, connected to a daemon that has adopted one real worker, attached to
/// the worker's session and holding the input lease, with the client's input lane open.
struct Client {
    adopted: Adopted,
    session: Session,
    _typist: Device,
    attachment: AttachmentId,
    epoch: InputLeaseEpoch,
    typing: Typing,
}

impl Client {
    /// A client of a worker that states the input lane when `states_the_lane` is true, and of one
    /// that leaves it out of its answer to the hello, as a worker of an earlier release does,
    /// when it is false.
    async fn start(states_the_lane: bool) -> Self {
        let adopted = Adopted::start(1).await;
        if !states_the_lane {
            adopted.workers[0]
                .service
                .withhold_capability(kr_protocol::local::INPUT_LANE);
        }
        let host = &adopted.host;
        let worker = &adopted.workers[0];
        let typist = Device::create().await;
        let record = pair_with(
            host,
            &typist,
            &adopted.owner,
            proposal(&[ActionRight::SessionView, ActionRight::TerminalInput]),
        )
        .await;
        let session = connect(host, &typist, &record).await;
        let attached: SessionAttachResult = session
            .mutate(
                Method::SessionAttach,
                worker.target(host.environment_id),
                None,
                &ParamsValue::empty(),
                &SessionAttachParams {
                    session_id: worker.session_id,
                    mode: AttachMode::Semantic,
                    claim_geometry: false,
                    dimensions: Nullable::null(),
                    terminal_profile_id: Nullable::null(),
                    requested: [
                        AttachmentCapability::ObserveTerminal,
                        AttachmentCapability::Input,
                    ]
                    .into_iter()
                    .collect(),
                },
                DurationMs::new(120_000),
            )
            .await
            .expect("the attach is settled")
            .to_typed()
            .expect("an attachment");
        let attachment = attached.attachment.attachment_id;
        let acquired: InputAcquireResult = session
            .mutate(
                Method::InputAcquire,
                worker.target(host.environment_id),
                None,
                &ParamsValue::empty(),
                &InputAcquireParams {
                    session_id: worker.session_id,
                    attachment_id: attachment,
                    expected_epoch: Nullable::null(),
                },
                DurationMs::new(120_000),
            )
            .await
            .expect("the lease is settled")
            .to_typed()
            .expect("a lease");
        let typing = Typing::open(&session, host.environment_id, worker.session_id, attachment)
            .await
            .expect("the input lane opens");
        Self {
            adopted,
            session,
            _typist: typist,
            attachment,
            epoch: acquired.lease.epoch,
            typing,
        }
    }

    async fn stop(self) {
        drop(self.typing);
        self.session.close();
        self.adopted.stop().await;
    }

    /// Types each of `keys` as a frame of its own and returns once the host has accepted all of
    /// them.
    async fn type_keys(&mut self, keys: &[&[u8]]) {
        for key in keys {
            self.typing
                .type_bytes(self.epoch, key)
                .await
                .expect("the host accepts the typing");
        }
    }

    /// The real worker's input domain, which a case reads the bound lanes, the lease and the
    /// terminal's writes from.
    fn worker_input(&self) -> Arc<InputShared> {
        Arc::clone(self.adopted.workers[0].runtime().input())
    }

    /// How many frames of its epoch the worker's lease has accepted.
    fn workers_count(&self) -> u64 {
        let input = self.worker_input();
        input.lock().lease().next_sequence.get()
    }

    /// Whether the worker's lease is held by the client's attachment.
    fn holds_the_lease(&self) -> bool {
        let input = self.worker_input();
        let holder = input.lock().lease().holder.0;
        holder == Some(self.attachment)
    }

    /// How many lanes the worker has bound.
    fn workers_lanes(&self) -> usize {
        let input = self.worker_input();
        input.lock().lane_count()
    }

    /// What the worker's terminal took of the lease's typing, in the order it took it.
    fn typed_at_the_terminal(&self) -> Vec<u8> {
        self.worker_input()
            .terminal_writes()
            .into_iter()
            .filter(|write| write.of_a_lease)
            .flat_map(|write| write.bytes)
            .collect()
    }

    /// How many requests the host's own record of the typing has refused.
    fn host_refusals(&self) -> u64 {
        self.adopted
            .host
            .network()
            .input_stages()
            .counts()
            .position_refusals
    }

    /// Waits until the host has accepted the typing that `barrier` names, as the client does before
    /// it sends the request.
    async fn until_reached(&mut self, barrier: &InputBarrier) {
        tokio::time::timeout(WAIT, async {
            loop {
                match self.typing.events().recv().await {
                    Some(InputEvent::Reached(reached)) if &reached == barrier => return,
                    Some(InputEvent::NotReached { reason, .. }) => {
                        panic!("the host did not accept the typing: {reason:?}");
                    }
                    Some(_) => {}
                    None => panic!("the lane ended before the barrier was reached"),
                }
            }
        })
        .await
        .expect("the host accepts the typing in time");
    }

    /// Waits for the host's notice that the lease of the client's epoch ended, and returns the
    /// count of bytes it says the end discarded.
    async fn the_count_the_notice_gives(&mut self) -> u64 {
        tokio::time::timeout(WAIT, async {
            loop {
                match self.typing.events().recv().await {
                    Some(InputEvent::EpochEnded {
                        epoch,
                        fenced_bytes,
                        ..
                    }) if epoch == self.epoch => return fenced_bytes,
                    Some(_) => {}
                    None => panic!("the lane ended before the lease's end was told"),
                }
            }
        })
        .await
        .expect("the host tells the end of the lease in time")
    }

    /// Sends a release of the client's attachment as the client does, with `barrier` as given.
    async fn release(
        &self,
        barrier: Option<InputBarrier>,
    ) -> Result<InputLeaseResult, ClientError> {
        let host = &self.adopted.host;
        let worker = &self.adopted.workers[0];
        let settled = self
            .session
            .mutate(
                Method::InputRelease,
                worker.target(host.environment_id),
                None,
                &ParamsValue::empty(),
                &InputReleaseParams {
                    session_id: worker.session_id,
                    attachment_id: self.attachment,
                    epoch: self.epoch,
                    after_input: barrier,
                    fenced_report: self.typing.lane().fenced_report(),
                },
                DurationMs::new(120_000),
            )
            .await?;
        Ok(settled.to_typed().expect("a lease result"))
    }
}

impl Client {
    /// Sends a detach of the client's attachment as the client does, with `barrier` as given.
    async fn detach(
        &self,
        barrier: Option<InputBarrier>,
    ) -> Result<SessionDetachResult, ClientError> {
        let host = &self.adopted.host;
        let worker = &self.adopted.workers[0];
        let settled = self
            .session
            .mutate(
                Method::SessionDetach,
                worker.target(host.environment_id),
                None,
                &ParamsValue::empty(),
                &SessionDetachParams {
                    attachment_id: Nullable::some(self.attachment),
                    line_token: Nullable::null(),
                    after_input: barrier,
                    fenced_report: self.typing.lane().fenced_report(),
                },
                DurationMs::new(120_000),
            )
            .await?;
        Ok(settled.to_typed().expect("a detach result"))
    }
}

/// The barrier that names one frame more than the lane marked: typing that has not all arrived.
fn one_frame_beyond(barrier: &InputBarrier) -> InputBarrier {
    InputBarrier {
        count: U64::new(barrier.count.get() + 1),
        ..barrier.clone()
    }
}

/// Waits until `condition` holds.
async fn until(what: &str, condition: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !condition() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "it never came to be that {what}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Typing from the client's lane reaches the worker on a lane of its own, in order, and the
/// acknowledgements come back through the host: the client's accepted set and the worker's count
/// of the typing are one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn typed_text_from_a_client_reaches_the_workers_lane_in_order_and_is_acknowledged() {
    let mut client = Client::start(true).await;
    client.type_keys(&[b"a", b"b", b"c"]).await;
    assert_eq!(
        client.workers_lanes(),
        1,
        "the host bound a lane on the worker"
    );
    until("the worker's terminal took the three keys", || {
        client.typed_at_the_terminal() == b"abc"
    })
    .await;
    assert_eq!(client.workers_count(), 3);
    let sets = client.typing.lane().sets().expect("an epoch");
    assert_eq!(sets.accepted.frames, 3, "the client was told of all three");
    client.stop().await;
}

/// A release whose barrier the host has accepted all the typing of is taken by the worker, and the
/// count the client reads, in the answer and in the notice of the lease's end, is the worker's: the
/// writer holds the first batch, so the five bytes are accepted and none is written, and the worker
/// says it fenced five.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_release_whose_barrier_is_reached_is_taken_and_the_client_reads_the_workers_count() {
    let mut client = Client::start(true).await;
    let (stopped, go) = client.worker_input().writer_hold().arm();
    client.type_keys(&[b"abc"]).await;
    stopped.await.expect("the writer took the batch");
    client.type_keys(&[b"de"]).await;
    let barrier = client.typing.lane().mark(None).expect("a barrier");
    client.until_reached(&barrier).await;
    let released = client
        .release(Some(barrier))
        .await
        .expect("the release is taken");
    assert_eq!(
        released.fenced_bytes,
        Some(U64::new(5)),
        "the worker's count"
    );
    assert!(!client.holds_the_lease(), "the lease ended");
    assert_eq!(client.the_count_the_notice_gives().await, 5);
    assert_eq!(client.host_refusals(), 0);
    drop(go);
    client.stop().await;
}

/// A release whose barrier names typing that has not all arrived is refused by the host with
/// nothing forwarded: a definite refusal, the lease stays, and the worker's count is what it was.
/// The client sends the release again with no position, as it does after a refusal, and it is
/// taken with the worker's count.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_release_whose_barrier_is_not_reached_is_refused_and_the_lease_stays() {
    let mut client = Client::start(true).await;
    let (stopped, go) = client.worker_input().writer_hold().arm();
    client.type_keys(&[b"abc"]).await;
    stopped.await.expect("the writer took the batch");
    client.type_keys(&[b"de"]).await;
    let barrier = client.typing.lane().mark(None).expect("a barrier");
    client.until_reached(&barrier).await;
    let refused = client
        .release(Some(one_frame_beyond(&barrier)))
        .await
        .expect_err("the position is not reached");
    assert_eq!(refused.code(), ErrorCode::DraftConflict);
    assert_eq!(client.host_refusals(), 1, "the host refused it");
    assert!(client.holds_the_lease(), "the refusal changed nothing");
    assert_eq!(client.workers_count(), 2);
    let released = client
        .release(None)
        .await
        .expect("the resend with no position is taken");
    assert_eq!(
        released.fenced_bytes,
        Some(U64::new(5)),
        "the worker's count"
    );
    assert_eq!(client.the_count_the_notice_gives().await, 5);
    drop(go);
    client.stop().await;
}

/// The host holds no record of a stream that has ended. A release that follows it with a position
/// that the worker has not reached is forwarded and refused by the worker, with the same refusal
/// and the lease standing, and the resend with no position is taken.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_worker_refuses_a_position_that_the_host_holds_no_record_of() {
    let mut client = Client::start(true).await;
    client.type_keys(&[b"a", b"b", b"c"]).await;
    let barrier = client.typing.lane().mark(None).expect("a barrier");
    client.until_reached(&barrier).await;
    let mut ended = client.adopted.host.network().input_tasks_ended();
    client.typing.lane().finish();
    tokio::time::timeout(WAIT, ended.changed())
        .await
        .expect("the stream task ends")
        .expect("the count stands");
    let refused = client
        .release(Some(one_frame_beyond(&barrier)))
        .await
        .expect_err("the worker has accepted three frames");
    assert_eq!(refused.code(), ErrorCode::DraftConflict);
    assert_eq!(
        client.host_refusals(),
        0,
        "the host had nothing to judge by"
    );
    assert!(client.holds_the_lease(), "the refusal changed nothing");
    client
        .release(None)
        .await
        .expect("the resend with no position is taken");
    client.stop().await;
}

/// A worker that states no lane is served one call at a time: the typing reaches it in order and
/// is acknowledged, and a release with a reached barrier is taken. The client is told what an older
/// worker gives, which is no count: the answers carry none, and the host ends the stream of such a
/// worker at the detach with no notice of the lease's end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_of_a_worker_without_the_lane_types_and_is_told_no_count() {
    let mut client = Client::start(false).await;
    client.type_keys(&[b"a", b"b", b"c"]).await;
    assert_eq!(client.workers_lanes(), 0, "no lane was bound on the worker");
    until("the worker's terminal took the three keys", || {
        client.typed_at_the_terminal() == b"abc"
    })
    .await;
    assert_eq!(client.workers_count(), 3);
    let barrier = client.typing.lane().mark(None).expect("a barrier");
    client.until_reached(&barrier).await;
    let released = client
        .release(Some(barrier.clone()))
        .await
        .expect("the release is taken");
    assert_eq!(
        released.fenced_bytes, None,
        "an older worker gives no count"
    );
    assert!(!client.holds_the_lease(), "the lease ended");
    let detached = client
        .detach(Some(barrier))
        .await
        .expect("the detach is taken");
    assert_eq!(
        detached.fenced_bytes, None,
        "an older worker gives no count"
    );
    tokio::time::timeout(WAIT, async {
        loop {
            match client.typing.events().recv().await {
                Some(InputEvent::EpochEnded { .. }) => {
                    panic!("a count that nothing the worker said gave was told");
                }
                Some(InputEvent::Ended { .. }) => return,
                Some(_) => {}
                None => panic!("the events ended with no end of the lane"),
            }
        }
    })
    .await
    .expect("the host ends the stream at the detach");
    client.stop().await;
}

/// For a worker without the lane the host's record is the only check of the position: a barrier
/// that names typing the host has not accepted is refused there with the lease standing, and the
/// resend with no position is taken.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_release_whose_barrier_is_not_reached_is_refused_for_a_worker_without_the_lane() {
    let mut client = Client::start(false).await;
    client.type_keys(&[b"a", b"b", b"c"]).await;
    let barrier = client.typing.lane().mark(None).expect("a barrier");
    client.until_reached(&barrier).await;
    let refused = client
        .release(Some(one_frame_beyond(&barrier)))
        .await
        .expect_err("the position is not reached");
    assert_eq!(refused.code(), ErrorCode::DraftConflict);
    assert_eq!(client.host_refusals(), 1, "the host refused it");
    assert!(client.holds_the_lease(), "the refusal changed nothing");
    client
        .release(None)
        .await
        .expect("the resend with no position is taken");
    client.stop().await;
}
