//! A paired device's keys, through the control daemon, beside the requests it sends on its own
//! connection.
//!
//! One real daemon on the loopback network, a real worker it adopts (the worker's own service over
//! a real pseudo-terminal, with its journal), and a paired device that sends its own frames. The
//! application in the session keeps what it reads in a file, so what reached it is read without the
//! worker. A client sends its keys, its viewport reports and its reads on one connection, and the
//! daemon used to answer them one at a time, so a key sent behind a request waited for the
//! request's round trip to the worker. These cases stop the worker's next journal commit, which
//! holds the request, and show where the key is meanwhile.
//!
//! The cases decide by what reached the application and in what order, never by how long anything
//! took. `remote_input_forwarding_latency` is the measurement: it records how long a key takes, and
//! is run by name.

#![cfg(unix)]

mod net_support;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use kr_controller::service::net::devices::DeviceRecord;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, AttachmentViewportParams, SessionAttachParams,
    SessionAttachResult, SessionDetachParams,
};
use kr_protocol::envelope::Outcome;
use kr_protocol::error::ErrorCode;
use kr_protocol::grant::SessionSelector;
use kr_protocol::ids::{
    ActionId, AttachmentId, InputLeaseEpoch, InputSequence, RequestId, SessionId,
};
use kr_protocol::input::{InputAcquireParams, InputAcquireResult, InputContent, InputWriteParams};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Bytes, Nullable};
use kr_protocol::session::{ClosureReason, Dimensions};
use kr_protocol::sharing::{GrantRedeemParams, RoleSelection, SessionRole};

use net_support::worker::Worker;
use net_support::{Device, Host, RawDevice, on_the_host, pair_with, proposal, share_with};

/// How long a test waits for something that must happen while the work it follows is stopped.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(30);

/// When a watchdog lets the stalled work go, so a regression fails by naming the wait and does not
/// hang the suite.
const WATCHDOG: Duration = Duration::from_secs(5);

/// The application: raw mode, bracketed paste on (so a lone Escape is held as a prefix), a file
/// that says it is ready, and everything it reads kept in a second file.
fn application(kept: &std::path::Path) -> String {
    format!(
        "stty raw -echo; printf '\\033[?2004hkr-ready.'; touch '{}'; exec tee '{}'",
        kept.join("ready").display(),
        kept.join("received").display()
    )
}

/// A daemon with an adopted worker and a paired device attached to its session, holding the input
/// lease, on a connection that sends its own frames.
struct Rig {
    host: Host,
    worker: Worker,
    device: RawDevice,
    paired: (Device, DeviceRecord),
    attachment: AttachmentId,
    epoch: InputLeaseEpoch,
    sequence: u64,
    /// What the application has been typed so far, in the order it was sent.
    typed: Vec<u8>,
    received: PathBuf,
    /// A session the device may reach that this connection is not attached to, which no worker
    /// serves.
    elsewhere: SessionId,
    _kept: tempfile::TempDir,
}

/// A daemon whose one session's worker runs the application, and the keys of its owner.
async fn environment() -> (Host, Worker, DeviceKeys, tempfile::TempDir) {
    let kept = tempfile::tempdir().expect("a directory for what the application keeps");
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let stopped = host.shut_down().await;
    let worker = Worker::start_running(stopped.tree(), 1, &application(kept.path())).await;
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;
    until_adopted(&host, &worker).await;
    until_the_application_is_ready(kept.path()).await;
    (host, worker, owner, kept)
}

impl Rig {
    /// A device paired with the rights to view and to type over any session, attached and holding
    /// the lease.
    async fn start() -> Self {
        Self::start_reaching(false, &[]).await
    }

    /// As [`Self::start`], for a device that may also manage the host, which the catalogue's
    /// methods ask for.
    async fn start_managing() -> Self {
        Self::start_reaching(false, &[ActionRight::HostManage]).await
    }

    /// As [`Self::start`], for a device whose pairing grant reaches the attached session only, and
    /// which holds a viewer's share of a session no worker serves.
    async fn start_shared() -> Self {
        Self::start_reaching(true, &[]).await
    }

    async fn start_reaching(only_here: bool, also: &[ActionRight]) -> Self {
        let (host, worker, owner, kept) = environment().await;
        let device = Device::create().await;
        let rights: Vec<ActionRight> = [ActionRight::SessionView, ActionRight::TerminalInput]
            .into_iter()
            .chain(also.iter().copied())
            .collect();
        let mut grant = proposal(&rights);
        if only_here {
            grant.session_selector = SessionSelector::These {
                session_ids: [worker.session_id].into_iter().collect(),
            };
        }
        let record = pair_with(&host, &device, &owner, grant).await;
        let connection = RawDevice::connect(&host, &device, &record).await;
        let elsewhere = net_support::an_open_session(&host).0;
        if only_here {
            let share = share_with(
                &host,
                elsewhere,
                record.device_id,
                RoleSelection::plain(SessionRole::Viewer),
                None,
            )
            .await
            .expect("the other session is shared");
            connection
                .mutate(
                    Method::GrantRedeem,
                    ActionId::new(kr_ipc::new_uuid()),
                    on_the_host(&host),
                    &GrantRedeemParams {
                        invitation_id: share.preview.invitation_id,
                    },
                )
                .await
                .expect("the share is redeemed");
        }
        let target = worker.target(host.environment_id);
        let attached: SessionAttachResult = connection
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                target.clone(),
                &SessionAttachParams {
                    session_id: worker.session_id,
                    mode: AttachMode::Terminal,
                    claim_geometry: false,
                    dimensions: Nullable::some(Dimensions::new(80, 24)),
                    terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                    requested: [
                        AttachmentCapability::ObserveTerminal,
                        AttachmentCapability::Input,
                    ]
                    .into_iter()
                    .collect(),
                },
            )
            .await
            .expect("the device attaches")
            .to_typed()
            .expect("an attachment");
        let attachment = attached.attachment.attachment_id;
        let lease: InputAcquireResult = connection
            .mutate(
                Method::InputAcquire,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                &InputAcquireParams {
                    session_id: worker.session_id,
                    attachment_id: attachment,
                    expected_epoch: Nullable::null(),
                },
            )
            .await
            .expect("the device takes the input lease")
            .to_typed()
            .expect("a lease");
        Self {
            host,
            worker,
            device: connection,
            paired: (device, record),
            attachment,
            epoch: lease.lease.epoch,
            sequence: 0,
            typed: Vec::new(),
            received: kept.path().join("received"),
            elsewhere,
            _kept: kept,
        }
    }

    fn target(&self) -> kr_protocol::envelope::ActionTarget {
        self.worker.target(self.host.environment_id)
    }

    /// What the application has received.
    fn received(&self) -> Vec<u8> {
        std::fs::read(&self.received).unwrap_or_default()
    }

    /// Waits until the application has received everything typed so far, and says when that was.
    async fn until_everything_typed_arrived(&self) -> Option<Instant> {
        tokio::time::timeout(LIVENESS_DEADLINE, async {
            loop {
                if self.received() == self.typed {
                    return Instant::now();
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .ok()
    }

    /// Sends one `input.write` on the device's connection without waiting for its answer, and
    /// returns the request and the instant before the frame was written, which is no later than
    /// its arrival at the daemon.
    async fn send_key(&mut self, bytes: &[u8]) -> (RequestId, Instant) {
        self.typed.extend_from_slice(bytes);
        self.send_key_naming(self.worker.session_id, bytes).await
    }

    /// As [`Self::send_key`], for a key that names `session_id`, which the application is not
    /// expected to receive when it is not the attached session.
    async fn send_key_naming(
        &mut self,
        session_id: SessionId,
        bytes: &[u8],
    ) -> (RequestId, Instant) {
        let params = InputWriteParams {
            session_id,
            attachment_id: self.attachment,
            epoch: self.epoch,
            sequence: InputSequence::new(self.sequence),
            input: InputContent::Bytes {
                bytes: Bytes::new(bytes.to_vec()),
            },
        };
        self.sequence += 1;
        let began = Instant::now();
        let id = self.device.submit_read(Method::InputWrite, &params).await;
        (id, began)
    }

    /// Sends one mutation on the device's connection without waiting for its answer.
    async fn send_mutation<T: serde::Serialize>(&self, method: Method, params: &T) -> RequestId {
        self.device
            .submit(
                method,
                ActionId::new(kr_ipc::new_uuid()),
                self.target(),
                params,
            )
            .await
    }

    /// A viewport report at the size the device attached with, which changes nothing and is
    /// journalled like any mutation.
    fn viewport_report(&self) -> AttachmentViewportParams {
        AttachmentViewportParams {
            attachment_id: self.attachment,
            dimensions: Dimensions::new(80, 24),
            position: Nullable::null(),
            column: kr_protocol::scalars::U64::new(0),
        }
    }

    /// Stops the commit of the next dispatch marker in the worker's journal.
    fn arm_stall(&self) -> Stall {
        let (reached, release) = {
            let mut session = self.worker.runtime().session();
            let journal = session.journal_mut().expect("this session keeps a journal");
            journal.stall_next_marker()
        };
        Stall {
            reached: Some(reached),
            release,
        }
    }

    /// Stops the commit of the next marker, sends the mutation `method` on the device's connection,
    /// and returns once the mutation is stopped in that commit.
    async fn stall_own<T: serde::Serialize>(
        &self,
        method: Method,
        params: &T,
    ) -> (Stall, RequestId) {
        let mut stall = self.arm_stall();
        let id = self.send_mutation(method, params).await;
        stall.until_reached(method).await;
        (stall, id)
    }

    /// What a lone Escape that follows work on the device's connection comes to: the hold, once the
    /// application has it and its answer has been read, with the work still stopped.
    ///
    /// The watchdog lets the stall go after five seconds at the latest, so a regression fails
    /// naming the wait and does not hang.
    async fn an_escape_meets(
        &mut self,
        stall: &Stall,
        answers: &mut Answers,
        what: &str,
    ) -> (RequestId, Duration) {
        let letting_go = LetGo::after(stall.release.clone(), WATCHDOG);
        let (escape, began) = self.send_key(b"\x1b").await;
        let arrived = self.until_everything_typed_arrived().await;
        let answer = answers.until(&self.device, escape, LIVENESS_DEADLINE).await;
        let had_to_be_let_go = letting_go.finish();
        let arrived = arrived.unwrap_or_else(|| {
            panic!(
                "{what}: the application never received the Escape: {:?}",
                self.received()
            )
        });
        let hold = arrived.duration_since(began);
        eprintln!("{what}: the Escape was received {hold:?} after the write began");
        assert!(
            !had_to_be_let_go,
            "{what}: the Escape was kept waiting until the work on its own connection was let go \
             ({hold:?})"
        );
        assert!(
            matches!(answer, Some(Outcome::Ok(_))),
            "{what}: the Escape was answered {answer:?}"
        );
        (escape, hold)
    }

    async fn close(self) {
        self.device.close();
        self.worker
            .runtime()
            .close(ClosureReason::CloseRequested)
            .1
            .release();
        self.host.stop().await;
    }
}

/// Waits until the daemon serves the worker's session.
async fn until_adopted(host: &Host, worker: &Worker) {
    let deadline = tokio::time::Instant::now() + LIVENESS_DEADLINE * 2;
    loop {
        let mut client = host.client().await;
        let read = client
            .request(
                Method::SessionRead,
                &kr_protocol::session::SessionReadParams {
                    session_id: worker.session_id,
                },
            )
            .await
            .expect("the call reaches the daemon");
        if read.is_ok() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the daemon never reached the worker: {read:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Waits until the application is in raw mode with bracketed paste on. Before then the line
/// discipline holds what is typed until a newline.
async fn until_the_application_is_ready(kept: &std::path::Path) {
    let ready = kept.join("ready");
    tokio::time::timeout(LIVENESS_DEADLINE * 2, async {
        while !ready.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the application became ready");
}

/// Work stopped in the worker's journal, and the means to let it go.
struct Stall {
    reached: Option<tokio::sync::oneshot::Receiver<()>>,
    release: std::sync::mpsc::Sender<()>,
}

impl Stall {
    async fn until_reached(&mut self, what: Method) {
        let reached = self.reached.take().expect("the stall is waited for once");
        tokio::time::timeout(LIVENESS_DEADLINE, reached)
            .await
            .unwrap_or_else(|_| panic!("{what:?}: the mutation did not reach its stall"))
            .unwrap_or_else(|_| panic!("{what:?}: the stall was dropped before it was reached"));
    }

    fn let_go(&self) {
        let _ = self.release.send(());
    }
}

/// Lets a stall go after a time, unless it is finished first.
struct LetGo {
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
    let_go: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: std::thread::JoinHandle<()>,
}

impl LetGo {
    fn after(release: std::sync::mpsc::Sender<()>, after: Duration) -> Self {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let (done, let_go) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        );
        let thread = {
            let (done, let_go) = (Arc::clone(&done), Arc::clone(&let_go));
            std::thread::spawn(move || {
                let began = Instant::now();
                while began.elapsed() < after {
                    if done.load(Ordering::Acquire) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                if !done.load(Ordering::Acquire) {
                    let_go.store(true, Ordering::Release);
                    let _ = release.send(());
                }
            })
        };
        Self {
            done,
            let_go,
            thread,
        }
    }

    /// Stops the watchdog, and says whether it had let the stall go.
    fn finish(self) -> bool {
        self.done.store(true, std::sync::atomic::Ordering::Release);
        self.thread.join().expect("the watchdog ends");
        self.let_go.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// What the device's connection has been answered, by request, and in which order.
#[derive(Default)]
struct Answers {
    outcomes: std::collections::BTreeMap<RequestId, Outcome>,
    order: Vec<RequestId>,
}

impl Answers {
    /// Reads the connection until `id` has been answered, or until `within` has passed.
    async fn until(
        &mut self,
        device: &RawDevice,
        id: RequestId,
        within: Duration,
    ) -> Option<Outcome> {
        let deadline = tokio::time::Instant::now() + within;
        while !self.outcomes.contains_key(&id) {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            let (answered, outcome) = device.next_answer(remaining).await?;
            self.order.push(answered);
            self.outcomes.insert(answered, outcome);
        }
        self.outcomes.get(&id).cloned()
    }
}

/// KR-PERF-002: a lone Escape that follows a journalled mutation on the device's connection reaches
/// the application while that mutation is stopped in its commit at the worker.
///
/// The daemon answered a device's frames one at a time, so the Escape waited in the daemon for the
/// mutation's round trip to the worker, and then for the recogniser's deadline. The clock starts
/// before the Escape is written, which is no later than its arrival at the daemon.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_lone_escape_sent_after_a_mutation_on_its_own_connection_reaches_the_application_while_the_mutation_is_stalled()
 {
    let mut rig = Rig::start().await;
    let report = rig.viewport_report();
    let (stall, viewport) = rig.stall_own(Method::AttachmentViewport, &report).await;
    let mut answers = Answers::default();
    let (escape, _) = rig
        .an_escape_meets(&stall, &mut answers, "a stalled viewport report")
        .await;
    assert!(
        !answers.outcomes.contains_key(&viewport),
        "the stalled mutation was answered before its stall was let go"
    );

    stall.let_go();
    let answer = answers
        .until(&rig.device, viewport, LIVENESS_DEADLINE)
        .await;
    assert!(
        matches!(answer, Some(Outcome::Ok(_))),
        "the viewport report was answered {answer:?}"
    );
    assert_eq!(
        answers.order,
        vec![escape, viewport],
        "the Escape was not answered ahead of the mutation it followed"
    );
    rig.close().await;
}

/// Sends a second mutation behind the stalled one on the device's connection, and asks for a copy of
/// it from another connection of the same device, in the window the first connection holds, until
/// the host tells that copy the outcome is unknown. Returns what the copy was last told, the second
/// mutation's request and the other connection.
///
/// The bound is the watchdog's, well under the 30 s the daemon waits for the worker's answer to the
/// stopped mutation, so that the second mutation has not claimed its route during the poll. The
/// poll covers the time the second mutation takes to reach the daemon, which no answer shows.
async fn the_copy_of_a_second_mutation_behind(
    rig: &Rig,
) -> (kr_protocol::error::ProtocolError, RequestId, RawDevice) {
    let report = rig.viewport_report();
    // The window the second mutation carries, which no answer has renewed while the first is
    // stopped.
    let window = rig.device.action_window_id();
    let behind = ActionId::new(kr_ipc::new_uuid());
    let held = rig
        .device
        .submit(Method::AttachmentViewport, behind, rig.target(), &report)
        .await;
    let (device, record) = &rig.paired;
    let other = RawDevice::connect(&rig.host, device, record).await;

    let deadline = Instant::now() + WATCHDOG;
    let told = loop {
        let refused = other
            .try_mutate_in(
                window.clone(),
                Method::AttachmentViewport,
                behind,
                rig.target(),
                &report,
            )
            .await
            .expect("the host answers on an open control stream")
            .expect_err("a window that is not this connection's admits nothing");
        if refused.code == ErrorCode::OutcomeUnknown || Instant::now() >= deadline {
            break refused;
        }
    };
    // The second mutation has claimed no route, so what told the copy is what the daemon holds of
    // the call and not a route, which only the daemon's own wait for the stopped mutation would
    // give it.
    assert!(
        rig.host
            .controller()
            .devices()
            .action_route(&record.principal(), behind)
            .expect("the routes are readable")
            .is_none(),
        "the second mutation had claimed its route when the copy was refused"
    );
    (told, held, other)
}

/// KR-REQ-23.49: a mutation the daemon has read ahead of the request it is answering, and holds
/// behind it, is on this host and will be carried out when its turn comes. A copy of it that
/// another connection of the same device sends meanwhile, in the window the first connection holds,
/// is refused on the daemon's own account, and is told the outcome is unknown, as the copy of any
/// call that has not yet claimed the route of its action is: the held mutation may still run.
///
/// The connection's first mutation is stopped in its commit at the worker and a second follows it,
/// which the daemon reads ahead and holds, since keys go ahead of a viewport report. Both are then
/// let through and answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_copy_of_a_mutation_held_behind_a_stalled_request_is_told_the_outcome_is_unknown() {
    let rig = Rig::start().await;
    let report = rig.viewport_report();
    let (stall, viewport) = rig.stall_own(Method::AttachmentViewport, &report).await;
    let (told, held, other) = the_copy_of_a_second_mutation_behind(&rig).await;
    stall.let_go();
    assert_eq!(
        told.code,
        ErrorCode::OutcomeUnknown,
        "the copy was refused as {told:?}, although the held mutation will run"
    );

    let mut answers = Answers::default();
    for request in [viewport, held] {
        let answer = answers.until(&rig.device, request, LIVENESS_DEADLINE).await;
        assert!(
            matches!(answer, Some(Outcome::Ok(_))),
            "the mutation was answered {answer:?}"
        );
    }
    drop(other);
    rig.close().await;
}

/// KR-REQ-23.49: a mutation that waits in the transport's queue for the request the connection is
/// answering is on this host as much as one the connection has read ahead: the daemon has read it
/// from the device's stream, and it will be carried out when its turn comes. A copy of it that
/// another connection of the same device sends meanwhile is told the outcome is unknown.
///
/// The connection's first mutation is a detach, which keys wait for, so the daemon reads nothing
/// more from the stream while it is stopped in its commit at the worker, and the second mutation
/// stays in the queue. Both are then let through and answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_copy_of_a_mutation_in_the_transport_queue_is_told_the_outcome_is_unknown() {
    let rig = Rig::start().await;
    let detach = SessionDetachParams {
        attachment_id: Nullable::some(rig.attachment),
        line_token: Nullable::null(),
    };
    let (stall, detach_id) = rig.stall_own(Method::SessionDetach, &detach).await;
    let (told, queued, other) = the_copy_of_a_second_mutation_behind(&rig).await;
    stall.let_go();
    assert_eq!(
        told.code,
        ErrorCode::OutcomeUnknown,
        "the copy was refused as {told:?}, although the queued mutation will run"
    );

    // The detach is answered, and so is the mutation behind it, whatever the detach left it to
    // meet.
    let mut answers = Answers::default();
    for request in [detach_id, queued] {
        let answer = answers.until(&rig.device, request, LIVENESS_DEADLINE).await;
        assert!(
            answer.is_some(),
            "the mutation {request:?} was not answered"
        );
    }
    drop(other);
    rig.close().await;
}

/// KR-PERF-002: a lone Escape that follows a read on the device's connection reaches the
/// application while that read waits at the worker for a session another connection's mutation is
/// holding.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_lone_escape_sent_after_a_read_waiting_for_the_session_reaches_the_application_while_it_is_held()
 {
    let mut rig = Rig::start().await;
    // Another connection of the same device attaches, and its marker commit is stopped with the
    // session held.
    let (device, record) = &rig.paired;
    let other = RawDevice::connect(&rig.host, device, record).await;
    let mut stall = rig.arm_stall();
    let attaching = other
        .submit(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            rig.target(),
            &SessionAttachParams {
                session_id: rig.worker.session_id,
                mode: AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(Dimensions::new(80, 24)),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                requested: [AttachmentCapability::ObserveTerminal]
                    .into_iter()
                    .collect(),
            },
        )
        .await;
    stall.until_reached(Method::SessionAttach).await;

    let read = rig
        .device
        .submit_read(
            Method::SessionRead,
            &kr_protocol::session::SessionReadParams {
                session_id: rig.worker.session_id,
            },
        )
        .await;
    let mut answers = Answers::default();
    let (escape, _) = rig
        .an_escape_meets(&stall, &mut answers, "a read waiting for the session")
        .await;
    assert!(
        !answers.outcomes.contains_key(&read),
        "the read was answered while the session was held"
    );

    stall.let_go();
    let answer = answers.until(&rig.device, read, LIVENESS_DEADLINE).await;
    assert!(
        matches!(answer, Some(Outcome::Ok(_))),
        "the read was answered {answer:?}"
    );
    assert_eq!(
        answers.order,
        vec![escape, read],
        "the Escape was not answered ahead of the read it followed"
    );
    let _ = attaching;
    other.close();
    rig.close().await;
}

/// KR-PERF-002: a key that follows a mutation which can change what the key meets still waits for
/// it.
///
/// A device that sends `session.detach` and then a key for the attachment has the key refused,
/// because the detach is applied first. The key is not answered while the detach is stopped in its
/// commit, and nothing reaches the application.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_key_sent_after_a_detach_on_its_own_connection_waits_for_it_and_is_refused() {
    let mut rig = Rig::start().await;
    let detach = SessionDetachParams {
        attachment_id: Nullable::some(rig.attachment),
        line_token: Nullable::null(),
    };
    let (stall, detach_id) = rig.stall_own(Method::SessionDetach, &detach).await;
    let (key, _) = rig.send_key(b"x").await;
    let mut answers = Answers::default();
    assert!(
        answers
            .until(&rig.device, key, Duration::from_millis(300))
            .await
            .is_none(),
        "the key was answered while the detach it follows was stopped in its commit"
    );

    stall.let_go();
    let detached = answers
        .until(&rig.device, detach_id, LIVENESS_DEADLINE)
        .await;
    assert!(
        matches!(detached, Some(Outcome::Ok(_))),
        "the detach was answered {detached:?}"
    );
    match answers.until(&rig.device, key, LIVENESS_DEADLINE).await {
        Some(Outcome::Error(error)) => assert_eq!(error.code, ErrorCode::AmbiguousAttachment),
        other => panic!("the key after the detach was answered {other:?}"),
    }
    assert_eq!(answers.order, vec![detach_id, key]);
    assert!(
        rig.received().is_empty(),
        "the key reached the application: {:?}",
        rig.received()
    );
    rig.close().await;
}

/// KR-PERF-002: every frame sent around a mutation is answered once and the keys arrive in order.
///
/// Keys and viewport reports are interleaved while a viewport report is stopped in its commit,
/// more of the reports than the daemon reads ahead of a key. Each request is answered once, every
/// key is accepted, and the application has the keys in the order they were sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_frames_sent_around_a_mutation_on_its_own_connection_are_each_answered_once_and_the_keys_stay_in_order()
 {
    let mut rig = Rig::start().await;
    let report = rig.viewport_report();
    let (stall, first) = rig.stall_own(Method::AttachmentViewport, &report).await;
    // A watchdog: while nothing is read ahead, the frames below wait behind the stall, which has to
    // be let go for them to be answered.
    let letting_go = LetGo::after(stall.release.clone(), WATCHDOG);
    let mut keys = Vec::new();
    let mut reports = vec![first];
    keys.push(rig.send_key(b"a").await.0);
    for _ in 0..10 {
        reports.push(rig.send_mutation(Method::AttachmentViewport, &report).await);
    }
    keys.push(rig.send_key(b"b").await.0);
    for _ in 0..10 {
        reports.push(rig.send_mutation(Method::AttachmentViewport, &report).await);
    }
    keys.push(rig.send_key(b"c").await.0);
    let mut answers = Answers::default();
    let _ = answers.until(&rig.device, keys[1], WATCHDOG).await;
    let _ = letting_go.finish();
    stall.let_go();

    for id in keys.iter().chain(&reports) {
        let answer = answers.until(&rig.device, *id, LIVENESS_DEADLINE).await;
        assert!(
            matches!(answer, Some(Outcome::Ok(_))),
            "request {id:?} was answered {answer:?}"
        );
    }
    let mut seen = answers.order.clone();
    seen.sort();
    seen.dedup();
    assert_eq!(
        seen.len(),
        answers.order.len(),
        "a request was answered twice: {:?}",
        answers.order
    );
    assert_eq!(answers.order.len(), keys.len() + reports.len());
    assert!(
        rig.until_everything_typed_arrived().await.is_some(),
        "the application did not receive the keys in the order they were sent: {:?}",
        rig.received()
    );
    rig.close().await;
}

/// KR-PERF-002: a read of another session, and a key that names it, keep their place behind a
/// mutation that is stopped in its commit.
///
/// Deciding a request over a session the connection does not act for selects another share, and
/// the share is then noted on the connection, so that its revocation ends the connection. A key
/// must not land ahead of that, so neither the read nor the keys behind it are answered while the
/// viewport report before them is, and all are answered in the order they were sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_read_of_another_session_and_the_keys_behind_it_keep_their_place_behind_a_stalled_mutation()
 {
    let mut rig = Rig::start_shared().await;
    let report = rig.viewport_report();
    let (stall, viewport) = rig.stall_own(Method::AttachmentViewport, &report).await;
    let read = rig
        .device
        .submit_read(
            Method::SessionRead,
            &kr_protocol::session::SessionReadParams {
                session_id: rig.elsewhere,
            },
        )
        .await;
    let (key_here, _) = rig.send_key(b"x").await;
    let elsewhere = rig.elsewhere;
    let (key_there, _) = rig.send_key_naming(elsewhere, b"y").await;
    let mut answers = Answers::default();
    // Nothing is answered while the mutation is stopped: the wait is bounded and a frame answered
    // late is not a pass of this case, only a failure it cannot see.
    assert!(
        answers
            .until(&rig.device, key_there, Duration::from_millis(500))
            .await
            .is_none(),
        "a key was answered ahead of the frames before it"
    );
    assert!(
        answers.order.is_empty(),
        "a frame was answered while the mutation before it was stopped: {:?}",
        answers.order
    );

    stall.let_go();
    for id in [viewport, read, key_here, key_there] {
        assert!(
            answers
                .until(&rig.device, id, LIVENESS_DEADLINE)
                .await
                .is_some(),
            "request {id:?} was never answered"
        );
    }
    assert_eq!(
        answers.order,
        vec![viewport, read, key_here, key_there],
        "the frames were not answered in the order they were sent"
    );
    rig.close().await;
}

/// KR-PERF-002: a key that names another session keeps its place behind a mutation that is stopped
/// in its commit, and so does the key behind it.
///
/// Deciding a key over a session the connection does not act for selects the share that admits that
/// session and notes it on the connection before the key is refused, so the key must not be
/// answered ahead of the frames before it. Both are answered once the mutation is, in the order
/// they were sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_key_that_names_another_session_keeps_its_place_behind_a_stalled_mutation() {
    let mut rig = Rig::start_shared().await;
    let report = rig.viewport_report();
    let (stall, viewport) = rig.stall_own(Method::AttachmentViewport, &report).await;
    let elsewhere = rig.elsewhere;
    let (key_there, _) = rig.send_key_naming(elsewhere, b"y").await;
    let (key_here, _) = rig.send_key(b"x").await;
    let mut answers = Answers::default();
    assert!(
        answers
            .until(&rig.device, key_here, Duration::from_millis(500))
            .await
            .is_none(),
        "a key was answered ahead of the mutation before it"
    );
    assert!(
        answers.order.is_empty(),
        "a frame was answered while the mutation before it was stopped: {:?}",
        answers.order
    );

    stall.let_go();
    for id in [viewport, key_there, key_here] {
        assert!(
            answers
                .until(&rig.device, id, LIVENESS_DEADLINE)
                .await
                .is_some(),
            "request {id:?} was never answered"
        );
    }
    assert_eq!(
        answers.order,
        vec![viewport, key_there, key_here],
        "the frames were not answered in the order they were sent"
    );
    rig.close().await;
}

// ---------------------------------------------------------------------------------------------
// What a paired device's key costs end to end through the daemon (a measurement)
// ---------------------------------------------------------------------------------------------

/// How many keys each reading sends.
const SAMPLES: usize = 1_000;

impl Rig {
    /// Attaches a second, watching attachment that is sent the session's output as it is written,
    /// subscribes it, and waits for what it is first sent to stop, so that the readings that follow
    /// time keys and not a screen being drawn. The attachment that types is a terminal one, which
    /// is sent the screen as it changes and not the bytes.
    async fn subscribed(&self) {
        let watching: SessionAttachResult = self
            .device
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                self.target(),
                &SessionAttachParams {
                    session_id: self.worker.session_id,
                    mode: AttachMode::Semantic,
                    claim_geometry: false,
                    dimensions: Nullable::null(),
                    terminal_profile_id: Nullable::null(),
                    requested: [AttachmentCapability::ObserveTerminal]
                        .into_iter()
                        .collect(),
                },
            )
            .await
            .expect("the device attaches to watch")
            .to_typed()
            .expect("an attachment");
        self.device
            .read(
                Method::EventsSubscribe,
                &kr_protocol::recovery::EventsSubscribeParams {
                    session_id: self.worker.session_id,
                    attachment_id: watching.attachment.attachment_id,
                    streams: [kr_protocol::recovery::EventStream::Output]
                        .into_iter()
                        .collect(),
                    from_cursor: Nullable::null(),
                },
            )
            .await
            .expect("the device subscribes");
        while self
            .device
            .next_frame(Duration::from_millis(300))
            .await
            .is_some()
        {}
    }

    /// Sends one key, and returns how long it was from the key's write until the application had
    /// it, and until the application's echo of it reached the device as output. `behind_a_report`
    /// writes a viewport report on the same connection first, which is not timed.
    async fn times_of_a_key(&mut self, behind_a_report: bool) -> (Duration, Duration) {
        use kr_protocol::envelope::ControlFrame;

        // The application's own file is watched on a thread of its own, polled every 50 µs, so the
        // figure is a ceiling with a step of about that and the timer's slack, and it neither waits
        // on the runtime's timer nor starts late: the report and the key are written once the
        // watcher has read the file.
        let (path, wanted) = (self.received.clone(), self.typed.len() as u64 + 1);
        let (watching, ready) = tokio::sync::oneshot::channel();
        let had_it = tokio::task::spawn_blocking(move || {
            let until = Instant::now() + LIVENESS_DEADLINE;
            let mut watching = Some(watching);
            while std::fs::metadata(&path).map_or(0, |file| file.len()) < wanted {
                if let Some(watching) = watching.take() {
                    let _ = watching.send(());
                }
                assert!(Instant::now() < until, "the application never had the key");
                std::thread::sleep(Duration::from_micros(50));
            }
            Instant::now()
        });
        ready
            .await
            .expect("the application had a byte before the key was sent");
        let report = self.viewport_report();
        let report = if behind_a_report {
            Some(
                self.send_mutation(Method::AttachmentViewport, &report)
                    .await,
            )
        } else {
            None
        };
        let (_, began) = self.send_key(b"k").await;
        let deadline = tokio::time::Instant::now() + LIVENESS_DEADLINE;
        let (mut echoed, mut report_answered) = (None, report.is_none());
        // The report is answered before the next key is written, so that each key is timed right
        // behind one report and not behind the queue of reports a faster sender would build.
        while echoed.is_none() || !report_answered {
            let frame = self
                .device
                .next_frame(deadline.saturating_duration_since(tokio::time::Instant::now()))
                .await
                .expect("the echo of the key and the answer to the report reached the device");
            match frame {
                ControlFrame::Response(response) if Some(response.request_id) == report => {
                    report_answered = true;
                }
                ControlFrame::Notification(notification)
                    if echoed.is_none() && notification.event_type.as_str() == "session.output" =>
                {
                    let event: kr_protocol::recovery::OutputEvent =
                        notification.payload.to_typed().expect("an output event");
                    if event.bytes.as_slice().contains(&b'k') {
                        echoed = Some(Instant::now());
                    }
                }
                _ => {}
            }
        }
        let had_it = had_it
            .await
            .expect("the watch of the application's file ends");
        (
            had_it.saturating_duration_since(began),
            echoed.expect("the echo arrived").duration_since(began),
        )
    }

    /// The times of each of a reading's keys: until the application had it, and until its echo
    /// reached the device. Each list is sorted.
    async fn keys_timed(&mut self, behind_a_report: bool) -> (Vec<Duration>, Vec<Duration>) {
        let (mut had_it, mut echoed) = (Vec::new(), Vec::new());
        for _ in 0..SAMPLES {
            let (to_the_application, to_the_device) = self.times_of_a_key(behind_a_report).await;
            had_it.push(to_the_application);
            echoed.push(to_the_device);
        }
        had_it.sort();
        echoed.sort();
        (had_it, echoed)
    }
}

/// Prints one reading with the conditions it was taken under.
fn report(what: &str, until: &str, timed: &[Duration]) {
    let at = |fraction: f64| {
        let index = ((timed.len() as f64) * fraction).ceil() as usize;
        timed[index.saturating_sub(1).min(timed.len() - 1)]
    };
    eprintln!(
        "KR-PERF-001 remote, {what}, until {until}: {} keys, p50 {:?}, p95 {:?}, p99 {:?}, \
         max {:?}; {} logical processors, {}",
        timed.len(),
        at(0.50),
        at(0.95),
        at(0.99),
        timed[timed.len() - 1],
        std::thread::available_parallelism().map_or(0, std::num::NonZero::get),
        if cfg!(debug_assertions) {
            "a debug build"
        } else {
            "a release build"
        },
    );
}

/// KR-PERF-001: the time from a paired device's write of one byte until the application has it, and
/// until the application's echo of it reaches the device as output, through the daemon, idle and
/// with each key written right behind a viewport report on the same connection.
///
/// The echo figure includes the device's own link to the daemon, the application's read and echo
/// and the output path back, as the worker's bench for the local socket
/// (`added_input_forwarding_latency`, run beside this one) includes the application and the output
/// path, so both are upper bounds on what the host adds. Section 27 states the bound for the local
/// path, so this is recorded beside it and asserts nothing about time. The clock starts at the
/// key's write, after the report's, and the next key waits for the report's answer, so that each
/// key is timed behind one report and not behind the queue a faster sender would build. The time
/// until the application has the key is the one that shows the key going ahead of the report, as
/// the echo also waits for the output path. It is run by name in a release build.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "a measurement, run by name in a release build"]
async fn remote_input_forwarding_latency() {
    let mut rig = Rig::start().await;
    rig.subscribed().await;
    // Warm: the first keys pay for the connection's first use of each path.
    let _ = rig.keys_timed(false).await;
    let (had_it, echoed) = rig.keys_timed(false).await;
    report("idle", "the application had the key", &had_it);
    report("idle", "its echo reached the device", &echoed);
    let (had_it, echoed) = rig.keys_timed(true).await;
    report(
        "each key right behind a viewport report",
        "the application had the key",
        &had_it,
    );
    report(
        "each key right behind a viewport report",
        "its echo reached the device",
        &echoed,
    );
    rig.close().await;
}

/// The catalogue's own builder of signed generations, for a repository of ten thousand entries.
#[allow(dead_code)]
#[path = "../../kr-plugin-catalogue/tests/support/mod.rs"]
mod generations;

/// How many of a change's commits the case holds, and types a key at each.
const HELD_COMMITS: usize = 2;

/// KR-REQ-11.14 and KR-ACC-017: a key typed in a session reaches its application while a sync and
/// an installation of a repository of ten thousand entries hold the catalogue, each held in the
/// middle of its durable work.
///
/// The daemon runs a catalogue change in a task of its own beside every session's tasks. A change
/// that did its blocking work on its worker thread kept the tasks queued on that worker waiting,
/// and the runtime here has one worker, so a key could not reach the application until the change
/// was done. A change also holds its connection's registration standing for the length of each
/// commit, and a key is decided under the same table of registrations, which it must not wait
/// behind, whether or not another connection comes or goes meanwhile. The case holds the change
/// inside two of its commits, with the registration held, connects a second device and lets it go,
/// types a key and waits for the application to have it, and only then lets the change go on; a
/// change that held the worker or the table is let go by the watchdog five seconds later, which
/// fails the case. It decides by what reached the application, never by how long anything took.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_key_reaches_the_application_while_a_sync_and_an_installation_of_ten_thousand_entries_hold_the_catalogue()
 {
    use kr_plugin_catalogue::{CapabilityCeiling, Enrolment, RepositoryId, RepositoryKind};
    use kr_protocol::catalogue as wire;
    use kr_protocol::scalars::U64;

    let mut rig = Rig::start_managing().await;
    let home = tempfile::tempdir().expect("a temporary directory");
    let generation = generations::Generation::build(
        home.path(),
        generations::GenerationSpec {
            listed_only: generations::synthetic_index(9_999).entries,
            ..generations::GenerationSpec::default()
        },
    )
    .await;
    let package = kr_protocol::ids::PluginId::new("kalareach/example-declarative")
        .expect("a plugin identifier");
    let catalogue = rig.host.controller().catalogue();
    catalogue
        .catalogue()
        .lock()
        .await
        .enrol(
            Enrolment::new(
                RepositoryId::new("crowded").expect("a repository identifier"),
                RepositoryKind::Community,
                generation.metadata_url(),
                generation.targets_url(),
                generation.root_bytes(),
                kr_plugin_sdk::limits::RepositoryBudgets::defaults(),
                CapabilityCeiling::default_ceiling(),
            )
            .expect("an enrollable repository"),
            true,
        )
        .expect("the owner adopted the root");

    // The change stops at its commits while the budget lasts, says so, and waits to be let go.
    let holds = Holds::on(catalogue);

    // The catalogue's changes go on a second connection of the device. A key never goes ahead of a
    // catalogue mutation sent before it on its own connection, which is the protocol's order, and
    // a person at a terminal does not wait for a synchronisation that another connection runs.
    let (device, record) = &rig.paired;
    let other = RawDevice::connect(&rig.host, device, record).await;
    let mut answers = Answers::default();
    let environment_id = rig.host.environment_id;
    let synced: wire::CatalogueSyncResult = holds
        .change(
            &mut rig,
            &other,
            &mut answers,
            Method::CatalogueSync,
            &wire::CatalogueSyncParams {
                environment_id,
                catalogue_id: "crowded".to_owned(),
            },
        )
        .await
        .to_typed()
        .expect("a sync result");
    assert_eq!(synced.entries, U64::new(10_000));
    let _: wire::PluginInstallResult = holds
        .change(
            &mut rig,
            &other,
            &mut answers,
            Method::PluginInstall,
            &wire::PluginInstallParams {
                environment_id,
                catalogue_id: "crowded".to_owned(),
                plugin_id: package,
                version: "0.1.0".to_owned(),
                package_digest: generation.manifest_digest().to_string(),
                grant: Vec::new(),
                owner_confirmation: Nullable::null(),
            },
        )
        .await
        .to_typed()
        .expect("an installation result");
    other.close();
    rig.close().await;
}

/// Which of a change's commits are held: the first `pass` go by, and the next `held` are each held.
#[derive(Clone, Copy)]
struct Plan {
    pass: usize,
    held: usize,
}

impl Plan {
    /// A change that nothing holds.
    const NONE: Self = Self { pass: 0, held: 0 };
}

/// Where a catalogue change is held, and what lets it go.
struct Holds {
    /// How many more commits go by before the next one is held.
    passing: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// How many more commits are held.
    budget: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// How many commits the change has reached.
    seen: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// Says that the change is held at a commit.
    waiting: std::sync::Arc<std::sync::Mutex<std::sync::mpsc::Receiver<()>>>,
    /// Lets the change go on.
    go: std::sync::mpsc::Sender<()>,
    /// Whether the watchdog, and not the case, let a change go.
    let_go: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Holds {
    /// Holds the commits the changes of `catalogue` make, as each change's plan says.
    fn on(catalogue: &kr_controller::catalogue::CatalogueModule) -> Self {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        use kr_controller::catalogue::TestingPoint;

        let (reached, waiting) = std::sync::mpsc::channel::<()>();
        let (go, going) = std::sync::mpsc::channel::<()>();
        let (reached, going) = (Mutex::new(reached), Mutex::new(going));
        let waiting = Arc::new(Mutex::new(waiting));
        let passing = Arc::new(AtomicUsize::new(0));
        let budget = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(AtomicUsize::new(0));
        let let_go_by_the_watchdog = Arc::new(AtomicBool::new(false));
        {
            let (passing, budget, seen, let_go) = (
                Arc::clone(&passing),
                Arc::clone(&budget),
                Arc::clone(&seen),
                Arc::clone(&let_go_by_the_watchdog),
            );
            catalogue.at_testing_point(move |point| {
                if point != TestingPoint::Commit {
                    return;
                }
                seen.fetch_add(1, Ordering::SeqCst);
                let takes = |count: &AtomicUsize| {
                    count
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                            left.checked_sub(1)
                        })
                        .is_ok()
                };
                if takes(&passing) || !takes(&budget) {
                    return;
                }
                let _ = reached.lock().expect("the signal").send(());
                if going
                    .lock()
                    .expect("the release")
                    .recv_timeout(WATCHDOG)
                    .is_err()
                {
                    let_go.store(true, Ordering::SeqCst);
                }
            });
        }
        Self {
            passing,
            budget,
            seen,
            waiting,
            go,
            let_go: let_go_by_the_watchdog,
        }
    }

    /// Sends one catalogue change on `via`, a connection of the device, and at each of its first
    /// `HELD_COMMITS` commits types a key on the connection the device attached on and waits for
    /// the application to have it before the change goes on. Returns the change's result.
    async fn change<P: serde::Serialize>(
        &self,
        rig: &mut Rig,
        via: &RawDevice,
        answers: &mut Answers,
        method: Method,
        params: &P,
    ) -> kr_protocol::envelope::ParamsValue {
        let plan = Plan {
            pass: 0,
            held: HELD_COMMITS,
        };
        let (answer, _) = self
            .hold(
                rig,
                via,
                answers,
                &format!("{method:?}"),
                method,
                params,
                plan,
            )
            .await;
        let Outcome::Ok(result) = answer else {
            panic!("{method:?} was answered {answer:?}");
        };
        result
    }

    /// Sends one catalogue change on `via`, lets the first `plan.pass` of its commits go by, and
    /// at each of the next `plan.held` types a key on the connection the device attached on and
    /// waits for the application to have it before the change goes on. Returns the change's
    /// answer and how many commits it made in all; `what` names the change where the case fails.
    // The change, the connection it goes on and where it is held are each one argument.
    #[allow(clippy::too_many_arguments)]
    async fn hold<P: serde::Serialize>(
        &self,
        rig: &mut Rig,
        via: &RawDevice,
        answers: &mut Answers,
        what: &str,
        method: Method,
        params: &P,
        plan: Plan,
    ) -> (Outcome, usize) {
        use std::sync::atomic::Ordering;

        self.seen.store(0, Ordering::SeqCst);
        self.passing.store(plan.pass, Ordering::SeqCst);
        self.budget.store(plan.held, Ordering::SeqCst);
        let change = via
            .submit(
                method,
                ActionId::new(kr_ipc::new_uuid()),
                on_the_host(&rig.host),
                params,
            )
            .await;
        for held in 1..=plan.held {
            let signal = std::sync::Arc::clone(&self.waiting);
            let reached = tokio::task::spawn_blocking(move || {
                signal
                    .lock()
                    .expect("the signal")
                    .recv_timeout(LIVENESS_DEADLINE)
            })
            .await
            .expect("the wait ended");
            if reached.is_err() {
                let answer = answers.until(via, change, Duration::from_secs(1)).await;
                panic!(
                    "{what}: the change never reached its commit {}; its answer: {answer:?}",
                    plan.pass + held
                );
            }
            // A device that connects and goes while the change is inside its commit, before the
            // key is typed.
            let (device, record) = &rig.paired;
            RawDevice::connect(&rig.host, device, record).await.close();
            rig.send_key(b"k").await;
            let arrived = rig.until_everything_typed_arrived().await;
            assert!(
                arrived.is_some() && !self.let_go.load(Ordering::SeqCst),
                "{what}: the key typed while the change was held at its commit {} did not reach \
                 the application until the watchdog let the change go",
                plan.pass + held
            );
            self.go.send(()).expect("the change is waiting");
        }
        let Some(answer) = answers.until(via, change, LIVENESS_DEADLINE).await else {
            panic!("{what} was not answered");
        };
        (answer, self.seen.load(Ordering::SeqCst))
    }
}

/// KR-REQ-11.14 and KR-ACC-017: a key typed in a session reaches its application while the
/// catalogue of a repository of ten thousand entries meets a full mirror's limit, fails an update
/// part way and refuses a rollback.
///
/// The daemon runs a change in a task of its own beside every session's tasks (the case above
/// states why a key must not wait behind one). That holds for the changes that stop as much as for
/// the ones that finish, since a person types through all of them. Each leg holds one change
/// inside commits it makes, with its registration held, and types a key at each; a change that did
/// its blocking work on the one worker of this runtime would keep the key out until the watchdog
/// let it go, which fails the case. Once a change is let go the case checks by what the daemon
/// answered that the event happened, and by what the catalogue still reads and has installed that
/// the last usable generation and the installed release stayed usable. Nothing here decides by
/// how long anything took.
///
/// 1. A full mirror whose payload budget this repository does not fit, meeting a second
///    generation: the sync refuses with that resource limit and the first generation stays the
///    one in use. The commit that keeps the generation's trust goes by; the held commits are the
///    time checkpoint the sync keeps after the limit refused the mirror and the admission
///    revision's raise that follows a change that stopped.
/// 2. An update whose second release signs a length shorter than its presentation's bytes: the
///    second generation is synchronised, and the installation caches the manifest, stops at the
///    presentation and is unwound. The held commits are the manifest's cache write, made before
///    the update stopped, and the admission revision's raise after it.
/// 3. A repository that publishes an older generation again, under metadata versions newer than
///    the ones this host accepted, so that every signature and version holds and the generation
///    number alone refuses it. The held commits are the one that keeps the generation's trust,
///    made before the refusal, and the admission revision's raise after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_key_reaches_the_application_while_the_catalogue_meets_a_mirror_limit_fails_an_update_and_refuses_a_rollback()
 {
    use kr_plugin_catalogue::{CapabilityCeiling, Enrolment, RepositoryId, RepositoryKind};
    use kr_protocol::catalogue as wire;
    use kr_protocol::scalars::U64;

    let mut rig = Rig::start_managing().await;
    let home = tempfile::tempdir().expect("a temporary directory");
    let listed = generations::synthetic_index(9_999).entries;
    let crowded = |generation: u64, version: &str, keys: Option<generations::KeySet>| {
        generations::GenerationSpec {
            generation,
            package_version: version.to_owned(),
            keys,
            listed_only: listed.clone(),
            ..generations::GenerationSpec::default()
        }
    };
    let first = generations::Generation::build(home.path(), crowded(1, "0.1.0", None)).await;
    let repository = RepositoryId::new("crowded").expect("a repository identifier");
    let package = kr_protocol::ids::PluginId::new("kalareach/example-declarative")
        .expect("a plugin identifier");
    rig.host
        .controller()
        .catalogue()
        .catalogue()
        .lock()
        .await
        .enrol(
            Enrolment::new(
                repository.clone(),
                RepositoryKind::Community,
                first.metadata_url(),
                first.targets_url(),
                first.root_bytes(),
                kr_plugin_sdk::limits::RepositoryBudgets::defaults(),
                CapabilityCeiling::default_ceiling(),
            )
            .expect("an enrollable repository"),
            true,
        )
        .expect("the owner adopted the root");
    let holds = Holds::on(rig.host.controller().catalogue());

    // The catalogue's changes go on a second connection of the device, as in the case above.
    let (device, record) = &rig.paired;
    let other = RawDevice::connect(&rig.host, device, record).await;
    let mut answers = Answers::default();
    let environment_id = rig.host.environment_id;
    let sync = wire::CatalogueSyncParams {
        environment_id,
        catalogue_id: "crowded".to_owned(),
    };
    let install = |version: &str, digest: String| wire::PluginInstallParams {
        environment_id,
        catalogue_id: "crowded".to_owned(),
        plugin_id: package.clone(),
        version: version.to_owned(),
        package_digest: digest,
        grant: Vec::new(),
        owner_confirmation: Nullable::null(),
    };

    // The repository is synchronised and its release installed, with nothing held: the state the
    // three events find.
    let (answer, _) = holds
        .hold(
            &mut rig,
            &other,
            &mut answers,
            "the first sync",
            Method::CatalogueSync,
            &sync,
            Plan::NONE,
        )
        .await;
    let synced: wire::CatalogueSyncResult = ok(answer).to_typed().expect("a sync result");
    assert_eq!(synced.entries, U64::new(10_000));
    let first_release = first.manifest_digest();
    let (answer, _) = holds
        .hold(
            &mut rig,
            &other,
            &mut answers,
            "the first installation",
            Method::PluginInstall,
            &install("0.1.0", first_release.to_string()),
            Plan::NONE,
        )
        .await;
    let _: wire::PluginInstallResult = ok(answer).to_typed().expect("an installation result");

    // The repository publishes a second release whose signed length for its presentation is
    // shorter than the presentation's bytes, and the second generation that lists it. Nothing has
    // read it yet: the first leg refuses to synchronise it, and the second leg synchronises it and
    // fails to install its release.
    let second = generations::Generation::build(
        &home.path().join("second"),
        generations::GenerationSpec {
            understated_presentation: Some(presentation_length(&first, &package) - 10),
            ..crowded(2, "0.2.0", Some(first.keys()))
        },
    )
    .await;
    first.replace_with(&second);

    // 1. The owner turns the full mirror on with a payload budget that no part of this repository
    // fits, and the sync of the second generation is refused for it. A reclaim that must make room
    // waits for every worker to say what it holds at the revision the installation raised, so the
    // case lets each report first: the refusal it meets is the budget's.
    until_every_worker_has_reported(&rig).await;
    set_budgets(&rig, &repository, |budgets| {
        budgets.full_offline_mirror = true;
        budgets.payload_cache_bytes = U64::new(64);
    })
    .await;
    let (answer, commits) = holds
        .hold(
            &mut rig,
            &other,
            &mut answers,
            "a sync past the full mirror's payload budget",
            Method::CatalogueSync,
            &sync,
            Plan { pass: 1, held: 2 },
        )
        .await;
    let said = stopped_on(answer, ErrorCode::QuotaExceeded);
    assert!(
        said.contains("payload_cache_bytes"),
        "the refusal names the budget: {said}"
    );
    assert_eq!(
        commits, 3,
        "the held commits are the last ones the change makes"
    );
    still_serves(&rig, &repository, 1, first_release, &package).await;
    set_budgets(&rig, &repository, |budgets| {
        *budgets = kr_plugin_sdk::limits::RepositoryBudgets::defaults();
    })
    .await;

    // 2. The second generation verifies; its release does not install.
    let (answer, _) = holds
        .hold(
            &mut rig,
            &other,
            &mut answers,
            "the second sync",
            Method::CatalogueSync,
            &sync,
            Plan::NONE,
        )
        .await;
    let synced: wire::CatalogueSyncResult = ok(answer).to_typed().expect("a sync result");
    assert_eq!(synced.entries, U64::new(10_000));
    let (answer, commits) = holds
        .hold(
            &mut rig,
            &other,
            &mut answers,
            "an update whose second release overruns its signed length",
            Method::PluginInstall,
            &install("0.2.0", second.manifest_digest().to_string()),
            Plan { pass: 0, held: 2 },
        )
        .await;
    let said = stopped_on(answer, ErrorCode::AttachmentIntegrity);
    assert!(said.contains("longer than"), "the refusal says why: {said}");
    assert_eq!(commits, 2, "the held commits are all the update makes");
    still_serves(&rig, &repository, 2, first_release, &package).await;

    // 3. The repository publishes generation one again, signed under newer metadata versions than
    // generation two was accepted at.
    let replayed = generations::Generation::build(
        &home.path().join("replayed"),
        generations::GenerationSpec {
            metadata_version: Some(3),
            ..crowded(1, "0.1.0", Some(first.keys()))
        },
    )
    .await;
    first.replace_with(&replayed);
    let (answer, commits) = holds
        .hold(
            &mut rig,
            &other,
            &mut answers,
            "a sync of a generation older than the one in use",
            Method::CatalogueSync,
            &sync,
            Plan { pass: 0, held: 2 },
        )
        .await;
    let said = stopped_on(answer, ErrorCode::RepositoryUntrusted);
    assert!(
        said.contains("older than the accepted generation"),
        "the generation number refused it: {said}"
    );
    assert_eq!(commits, 2, "the held commits are all the sync makes");
    still_serves(&rig, &repository, 2, first_release, &package).await;

    other.close();
    rig.close().await;
}

/// Changes the budgets the repository is enrolled with, as the owner at the host would.
async fn set_budgets(
    rig: &Rig,
    repository: &kr_plugin_catalogue::RepositoryId,
    edit: impl FnOnce(&mut kr_plugin_sdk::limits::RepositoryBudgets),
) {
    let mut catalogue = rig.host.controller().catalogue().catalogue().lock().await;
    let mut enrolment = catalogue
        .repository(repository)
        .expect("readable")
        .expect("enrolled");
    edit(&mut enrolment.budgets);
    catalogue
        .update_enrolment(enrolment, false)
        .expect("a mirror setting enlarges no trust");
}

/// The result of a change the case expects to succeed.
fn ok(answer: Outcome) -> kr_protocol::envelope::ParamsValue {
    match answer {
        Outcome::Ok(result) => result,
        Outcome::Error(error) => panic!("the change was refused: {error:?}"),
    }
}

/// The text of the answer to a change that committed part of its work and then stopped on `code`,
/// which is how the daemon answers it: as an action that stopped part way, naming what stopped it.
fn stopped_on(answer: Outcome, code: ErrorCode) -> String {
    let Outcome::Error(error) = answer else {
        panic!("the change was answered {answer:?}, and not as one that stopped");
    };
    assert_eq!(error.code, ErrorCode::OutcomeUnknown, "{error:?}");
    assert!(
        error.message.contains(code.as_str()),
        "the change did not stop on {}: {}",
        code.as_str(),
        error.message
    );
    error.message
}

/// What the case checks after each event: the catalogue still reads `generation` of the
/// repository offline, in whole, and the release installed from the first generation is the one
/// installed, with every file its manifest declares where it was put.
async fn still_serves(
    rig: &Rig,
    repository: &kr_plugin_catalogue::RepositoryId,
    generation: u64,
    installed: kr_plugin_sdk::digest::PayloadDigest,
    plugin: &kr_protocol::ids::PluginId,
) {
    let catalogue = rig.host.controller().catalogue().catalogue().lock().await;
    let index = catalogue
        .index(repository)
        .expect("the active generation is read offline");
    assert_eq!(index.generation.get(), generation);
    assert_eq!(index.entries.len(), 10_000);
    let release = catalogue
        .installation(rig.host.environment_id, plugin)
        .expect("readable")
        .expect("installed");
    assert_eq!(release.package_digest, installed);
    let complete = catalogue
        .store_of(&release)
        .check_package(installed, kr_plugin_catalogue::PackageLimits::format())
        .expect("a readable store");
    assert!(
        matches!(complete, kr_plugin_catalogue::PackageCheck::Complete(_)),
        "the installed release's files are not all where they were put: {complete:?}"
    );
}

/// Waits until every worker has said what it holds at the catalogue's admission revision, which a
/// change that installs a package raises, and which a reclaim that must make room waits for.
async fn until_every_worker_has_reported(rig: &Rig) {
    let deadline = tokio::time::Instant::now() + LIVENESS_DEADLINE;
    loop {
        let pending = rig
            .host
            .controller()
            .pending_admissions()
            .await
            .expect("the admission revision is readable");
        if pending.is_empty() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the workers did not report at the admission revision: {pending:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The length the release of `plugin` in `generation` declares for its presentation.
fn presentation_length(
    generation: &generations::Generation,
    plugin: &kr_protocol::ids::PluginId,
) -> u64 {
    let index: kr_plugin_sdk::catalogue::CatalogueIndex = serde_json::from_slice(
        &std::fs::read(generation.targets_dir().join("index.json")).expect("an index"),
    )
    .expect("a readable index");
    index
        .entries
        .iter()
        .find(|entry| &entry.plugin_id == plugin)
        .expect("the release is listed")
        .payloads
        .iter()
        .find(|payload| payload.path.as_str() == kr_plugin_sdk::package::PRESENTATION_FILE)
        .expect("a presentation")
        .size_bytes
        .get()
}

/// The keys of a burst, as a device sends them and as the host answered them.
struct Burst {
    /// The frames the device wrote to its connection.
    sent: usize,
    /// The answers that came back, by outcome.
    answered_ok: usize,
    answered_otherwise: usize,
    /// The most frames the device had written and not yet seen answered, at any time: no less than
    /// the frames the host held for its handler, and more by the frames still on their way.
    most_unanswered: usize,
    /// The frame at which a write failed, and the error, when the connection was lost.
    cut: Option<(usize, String)>,
    /// How the connection's reader ended, when it ended on an error.
    ended: Option<String>,
    /// What the application has of the keys written, and whether that is all of them or a
    /// beginning of them.
    received: usize,
    written: usize,
    clean_prefix: bool,
    /// A request that is not a key, whose answer is kept apart from the keys' while the burst is
    /// counted, and the answer it got.
    watched: Option<RequestId>,
    watched_outcome: Option<Outcome>,
    /// The first answer that was not a success, as the daemon said it.
    first_refusal: Option<String>,
}

impl Burst {
    fn new(watched: Option<RequestId>) -> Self {
        Self {
            sent: 0,
            answered_ok: 0,
            answered_otherwise: 0,
            most_unanswered: 0,
            cut: None,
            ended: None,
            received: 0,
            written: 0,
            clean_prefix: true,
            watched,
            watched_outcome: None,
            first_refusal: None,
        }
    }

    /// Counts one answer: of a key by its outcome, or of the request watched.
    fn counted(&mut self, id: RequestId, outcome: Outcome) {
        if self.watched == Some(id) {
            self.watched_outcome = Some(outcome);
        } else if matches!(outcome, Outcome::Ok(_)) {
            self.answered_ok += 1;
        } else {
            self.answered_otherwise += 1;
            if self.first_refusal.is_none() {
                let said = format!("{outcome:?}");
                self.first_refusal = Some(said.chars().take(200).collect());
            }
        }
    }

    fn kept(&self) -> bool {
        self.cut.is_none() && self.ended.is_none()
    }

    fn whole(&self) -> bool {
        self.kept()
            && self.answered_ok == self.sent
            && self.answered_otherwise == 0
            && self.received == self.written
    }

    fn line(&self, what: &str, run: usize) -> String {
        format!(
            "{what}, run {run}: {} written, {} answered ok, {} otherwise ({:?}), at most {} \
             unanswered; the application has {} of {} bytes ({}); {}",
            self.sent,
            self.answered_ok,
            self.answered_otherwise,
            self.first_refusal,
            self.most_unanswered,
            self.received,
            self.written,
            if self.received == self.written {
                "all"
            } else if self.clean_prefix {
                "a clean prefix"
            } else {
                "NOT a prefix"
            },
            match (&self.cut, &self.ended) {
                (None, None) => "the connection stayed".to_owned(),
                (cut, ended) =>
                    format!("the connection was lost: write failed at {cut:?}, reader {ended:?}"),
            }
        )
    }
}

impl Rig {
    /// Writes one `input.write` without waiting for its answer, and says why it could not be
    /// written when the connection is gone. What is written is typed: the application is expected
    /// to have it, in order.
    async fn try_send_key(&mut self, bytes: &[u8]) -> Result<(), kr_client::ClientError> {
        let params = InputWriteParams {
            session_id: self.worker.session_id,
            attachment_id: self.attachment,
            epoch: self.epoch,
            sequence: InputSequence::new(self.sequence),
            input: InputContent::Bytes {
                bytes: Bytes::new(bytes.to_vec()),
            },
        };
        self.device
            .try_submit_read(Method::InputWrite, &params)
            .await?;
        self.sequence += 1;
        self.typed.extend_from_slice(bytes);
        Ok(())
    }

    /// Reads, without waiting, every answer the device's connection has already heard, and counts
    /// them.
    async fn count_answers_heard(&self, burst: &mut Burst) {
        while let Some((id, outcome)) = self.device.next_answer(Duration::ZERO).await {
            burst.counted(id, outcome);
        }
    }

    /// What the application has once it has everything typed, or has taken nothing more for a
    /// while: after a lost connection or a refusal, what the host had already put to it is still
    /// being read.
    async fn settled_received(&self) -> Vec<u8> {
        let deadline = tokio::time::Instant::now() + LIVENESS_DEADLINE;
        let mut last = self.received();
        let mut since = tokio::time::Instant::now();
        while last != self.typed
            && since.elapsed() < Duration::from_millis(1500)
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let now = self.received();
            if now.len() != last.len() {
                since = tokio::time::Instant::now();
            }
            last = now;
        }
        last
    }

    /// Reads the answers still to come until every frame written has one, the connection ends, or
    /// the wait runs out, and then looks at what the application has.
    async fn finish_burst(&self, mut burst: Burst) -> Burst {
        let deadline = tokio::time::Instant::now() + LIVENESS_DEADLINE;
        while burst.answered_ok + burst.answered_otherwise < burst.sent
            || (burst.watched.is_some() && burst.watched_outcome.is_none())
        {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match self.device.next_answer(remaining).await {
                Some((id, outcome)) => burst.counted(id, outcome),
                None => break,
            }
        }
        let received = self.settled_received().await;
        burst.clean_prefix = self.typed.starts_with(&received);
        burst.received = received.len();
        burst.written = self.typed.len();
        burst.ended = self.device.how_it_ended();
        burst
    }
}

/// A burst: `frames` written one after another with no wait between them, as a client writes what
/// it held back while its link was stalled.
async fn burst_of(rig: &mut Rig, frames: &[Vec<u8>]) -> Burst {
    let mut burst = Burst::new(None);
    for (number, frame) in frames.iter().enumerate() {
        if let Err(error) = rig.try_send_key(frame).await {
            burst.cut = Some((number, format!("{error:?}")));
            break;
        }
        burst.sent += 1;
        rig.count_answers_heard(&mut burst).await;
        burst.most_unanswered = burst
            .most_unanswered
            .max(burst.sent - burst.answered_ok - burst.answered_otherwise);
    }
    rig.finish_burst(burst).await
}

/// `count` frames of `size` bytes each, every frame of one letter and no two neighbours alike, so
/// that what the application has says which frames it has and in what order.
fn frames_of(count: usize, size: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|number| vec![b'a' + u8::try_from(number % 26).expect("a letter"); size])
        .collect()
}

/// How many times each burst is made.
const BURST_RUNS: usize = 10;

/// KR-REQ-09.22 (provisional): a device that writes keys back to back, as a paste divided into
/// frames or the keys a client held while its link was stalled, keeps its connection, and the
/// application has every byte once and in order.
///
/// The daemon keeps 64 frames for a handler that has not read them and ends the connection at the
/// next, and a client has no limit on the keys it has written and not seen answered. No request
/// waits at the worker here: the keys alone are the load, and each is a round trip to the worker.
/// Every burst is made on a connection of its own, ten times. The case records for each burst how
/// many of the runs kept the connection and what the application had, and fails when a run lost the
/// connection or a byte.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_device_that_writes_a_burst_of_keys_keeps_its_connection_and_the_application_has_every_byte()
 {
    let bursts: Vec<(&str, Vec<Vec<u8>>)> = vec![
        ("64 KiB in 8 KiB frames", frames_of(8, 8 * 1024)),
        ("256 KiB in 8 KiB frames", frames_of(32, 8 * 1024)),
        ("512 KiB in 8 KiB frames", frames_of(64, 8 * 1024)),
        ("1 MiB in 8 KiB frames", frames_of(128, 8 * 1024)),
        ("64 keys of one byte", frames_of(64, 1)),
        ("65 keys of one byte", frames_of(65, 1)),
        ("128 keys of one byte", frames_of(128, 1)),
        ("256 keys of one byte", frames_of(256, 1)),
    ];
    let mut lost = Vec::new();
    for (what, frames) in &bursts {
        let mut kept = 0;
        for run in 1..=BURST_RUNS {
            let mut rig = Rig::start().await;
            let burst = burst_of(&mut rig, frames).await;
            eprintln!("{}", burst.line(what, run));
            if burst.whole() {
                kept += 1;
            } else {
                lost.push(burst.line(what, run));
            }
            rig.close().await;
        }
        eprintln!("{what}: {kept} of {BURST_RUNS} runs kept the connection and every byte");
    }
    assert!(
        lost.is_empty(),
        "{} of {} runs lost the connection or a byte:\n{}",
        lost.len(),
        bursts.len() * BURST_RUNS,
        lost.join("\n")
    );
}

/// How long a mutation is held in the worker's commit, and how fast a key repeats meanwhile.
const HELD_FOR: Duration = Duration::from_secs(3);
const REPEAT_EVERY: Duration = Duration::from_millis(33);

/// KR-REQ-09.22 (provisional): a device that holds a key down while a mutation of its session is
/// slow at the worker keeps its connection, the mutation is answered, and the application has
/// every key once and in order.
///
/// The mutation is a second attachment of the session, which a key does not go ahead of, held in
/// the worker's commit for three seconds: the commit of a journal on a busy disk. The key repeats
/// every 33 milliseconds, thirty a second, on the same connection. The daemon reads nothing ahead
/// of a frame it does not let a key pass, so the keys wait in its queue of 64; the case records the
/// key and the time at which the connection was lost, if it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_key_held_down_while_a_mutation_of_its_session_is_slow_at_the_worker_keeps_the_connection()
 {
    let mut rig = Rig::start().await;
    let second = SessionAttachParams {
        session_id: rig.worker.session_id,
        mode: AttachMode::Terminal,
        claim_geometry: false,
        dimensions: Nullable::some(Dimensions::new(80, 24)),
        terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
        requested: [AttachmentCapability::ObserveTerminal]
            .into_iter()
            .collect(),
    };
    let (stall, attach) = rig.stall_own(Method::SessionAttach, &second).await;
    let mut burst = Burst::new(Some(attach));
    let began = Instant::now();
    let mut ticks = tokio::time::interval(REPEAT_EVERY);
    let mut lost_at = None;
    while began.elapsed() < HELD_FOR {
        ticks.tick().await;
        let key = [b'a' + u8::try_from(burst.sent % 26).expect("a letter")];
        if let Err(error) = rig.try_send_key(&key).await {
            lost_at = Some((burst.sent, began.elapsed()));
            burst.cut = Some((burst.sent, format!("{error:?}")));
            break;
        }
        burst.sent += 1;
        rig.count_answers_heard(&mut burst).await;
        burst.most_unanswered = burst
            .most_unanswered
            .max(burst.sent - burst.answered_ok - burst.answered_otherwise);
    }
    let keys_answered_while_held = burst.answered_ok + burst.answered_otherwise;
    stall.let_go();
    let burst = rig.finish_burst(burst).await;
    let attached = burst.watched_outcome.clone();
    eprintln!(
        "held for {HELD_FOR:?} at {REPEAT_EVERY:?} a key: {} keys written, {keys_answered_while_held} \
         answered while the mutation was held, the mutation answered {attached:?}; lost at {lost_at:?}; {}",
        burst.sent,
        burst.line("the held key", 1)
    );
    rig.close().await;
    assert!(
        burst.whole() && matches!(attached, Some(Outcome::Ok(_))),
        "the connection did not stay, a key was lost, or the mutation was not answered: {}; the \
         mutation was answered {attached:?}",
        burst.line("the held key", 1)
    );
}
