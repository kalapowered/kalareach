//! A paired device's keys, through the control daemon, beside the requests it sends on its own
//! connection (KR-PERF-002).
//!
//! One real daemon on the loopback network, a real worker it adopts (the worker's own service over
//! a real pseudo-terminal, with its journal), and a paired device that sends its own frames. The
//! application in the session keeps what it reads in a file, so what reached it is read without the
//! worker. A client sends its keys, its viewport reports and its reads on one connection, and the
//! daemon used to answer them one at a time, so a key sent behind a request waited for the
//! request's round trip to the worker. These cases stop the worker's next journal commit, which
//! holds the request, and show where the key is meanwhile.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-PERF-002 | the cases here |

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
use kr_protocol::input::{InputAcquireParams, InputAcquireResult, InputWriteParams};
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
        Self::start_reaching(false).await
    }

    /// As [`Self::start`], for a device whose pairing grant reaches the attached session only, and
    /// which holds a viewer's share of a session no worker serves.
    async fn start_shared() -> Self {
        Self::start_reaching(true).await
    }

    async fn start_reaching(only_here: bool) -> Self {
        let (host, worker, owner, kept) = environment().await;
        let device = Device::create().await;
        let mut grant = proposal(&[ActionRight::SessionView, ActionRight::TerminalInput]);
        if only_here {
            grant.session_selector = SessionSelector::These {
                session_ids: [worker.session_id].into_iter().collect(),
            };
        }
        let record = pair_with(&host, &device, &owner, grant).await;
        let connection = RawDevice::connect(&host, &device, &record).await;
        let elsewhere = SessionId::new(kr_ipc::new_uuid());
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
            bytes: Bytes::new(bytes.to_vec()),
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
// KR-PERF-001: what a paired device's key costs end to end through the daemon (a measurement)
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
        ready.await.expect("the watcher read the file");
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
