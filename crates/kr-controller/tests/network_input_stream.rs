//! Terminal input on a stream of its own, at the host's door.
//!
//! A paired device opens a stream that carries typing and nothing else, and the host forwards each
//! frame to the session's worker over a lane of its own, within the credit the worker gives. The
//! device is real, on its authorised connection; the worker's lane is scripted
//! ([`net_support::lane::ScriptedLane`]), so every stage between the two is held where a case wants
//! it. What each case asserts is what reaches the lane and what the device is told.

#![cfg(unix)]

mod net_support;

use std::sync::Arc;
use std::time::Duration;

use kr_controller::service::net::devices::DeviceRecord;
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult, SessionDetachParams,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::frame::{StreamHeader, StreamKind, StreamResource};
use kr_protocol::ids::{ActionId, AttachmentId, InputLeaseEpoch, InputSequence, SessionId};
use kr_protocol::input::{InputAck, InputAcquireParams, InputAcquireResult, InputFrame};
use kr_protocol::local::{InputLaneReady, LaneEnded, LaneWindow};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Bytes, Nullable, U64};
use kr_protocol::session::Dimensions;
use kr_transport::streams::DataStream;

use net_support::lane::ScriptedLane;
use net_support::worker::{Adopted, Worker};
use net_support::{Device, RawDevice, pair_with, proposal};

/// What a case waits at most for an acknowledgement or a reset. A host that does what the case says
/// answers at once: the bound only ends a case that would hang.
const WAIT: Duration = Duration::from_secs(60);

/// The most frames the client has written and not had accepted: the window `Ready` names.
const CLIENT_WINDOW: u64 = 32;

/// Parameters of a method that takes none.
#[derive(serde::Serialize)]
struct NoParams {}

/// A daemon with an adopted worker, a paired device attached to its session and holding the input
/// lease, and a scripted lane for the host to carry that attachment's typing over.
struct Rig {
    adopted: Adopted,
    device: Arc<RawDevice>,
    _paired: (Device, DeviceRecord),
    session: SessionId,
    attachment: AttachmentId,
    epoch: InputLeaseEpoch,
    lane: ScriptedLane,
}

fn attach_params(session: SessionId, requested: &[AttachmentCapability]) -> SessionAttachParams {
    SessionAttachParams {
        session_id: session,
        mode: AttachMode::Terminal,
        claim_geometry: false,
        dimensions: Nullable::some(Dimensions::new(80, 24)),
        terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
        requested: requested.iter().copied().collect(),
    }
}

impl Rig {
    async fn start() -> Self {
        let adopted = Adopted::start(1).await;
        let host = &adopted.host;
        let worker: &Worker = &adopted.workers[0];
        let device = Device::create().await;
        let record = pair_with(
            host,
            &device,
            &adopted.owner,
            proposal(&[ActionRight::SessionView, ActionRight::TerminalInput]),
        )
        .await;
        let connection = RawDevice::connect(host, &device, &record).await;
        connection.claim();
        let target = worker.target(host.environment_id);
        let attached: SessionAttachResult = connection
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                target.clone(),
                &attach_params(
                    worker.session_id,
                    &[
                        AttachmentCapability::ObserveTerminal,
                        AttachmentCapability::Input,
                    ],
                ),
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
        let epoch = lease.lease.epoch;
        let lane = ScriptedLane::start(InputLaneReady {
            epoch,
            holder: true,
            frames: 64,
            bytes: U64::new(512 * 1024),
        });
        host.network().use_input_lane_at(lane.endpoint());
        Self {
            session: worker.session_id,
            adopted,
            device: Arc::new(connection),
            _paired: (device, record),
            attachment,
            epoch,
            lane,
        }
    }

    fn header(&self) -> StreamHeader {
        StreamHeader {
            kind: StreamKind::TerminalInput,
            connection_id: self.device.connection_id(),
            stream_id: Nullable::null(),
            resource: StreamResource {
                environment_id: self.adopted.host.environment_id,
                session_id: Nullable::some(self.session),
                attachment_id: Nullable::some(self.attachment),
                transfer_id: Nullable::null(),
            },
        }
    }

    /// Opens the attachment's input stream and reads the host's `Ready`.
    async fn open(&self) -> DataStream {
        let mut stream = self.device.open_stream(self.header()).await;
        match next(&mut stream).await {
            Some(InputAck::Ready { window }) => {
                assert_eq!(u64::from(window.frames), CLIENT_WINDOW);
            }
            other => panic!("the host was to say Ready, and it said {other:?}"),
        }
        stream
    }

    /// The frame of `bytes` at `sequence` of this rig's epoch.
    fn frame(&self, sequence: u64, bytes: &[u8]) -> InputFrame {
        InputFrame {
            epoch: self.epoch,
            sequence: InputSequence::new(sequence),
            bytes: Bytes::new(bytes.to_vec()),
        }
    }

    async fn stop(self) {
        self.device.close();
        self.adopted.host.stop().await;
    }
}

/// The next acknowledgement, or `None` when the host ended the stream.
async fn next(stream: &mut DataStream) -> Option<InputAck> {
    tokio::time::timeout(WAIT, stream.read_message::<InputAck>())
        .await
        .expect("the host answers or ends the stream in time")
        .unwrap_or(None)
}

/// The next acknowledgement, a clean end of the stream as `Ok(None)`, and a reset as an error.
async fn next_or_reset(stream: &mut DataStream) -> kr_transport::Result<Option<InputAck>> {
    tokio::time::timeout(WAIT, stream.read_message::<InputAck>())
        .await
        .expect("the host answers or ends the stream in time")
}

/// Waits for a hold to say that what it holds has arrived.
async fn arrived(at: tokio::sync::oneshot::Receiver<()>) {
    tokio::time::timeout(WAIT, at)
        .await
        .expect("the host reached the hold in time")
        .expect("the hold is armed");
}

/// Writes `frames` as the epoch's frames 0 to `n - 1` within the client's window and returns every
/// acknowledgement, up to the one that accepts the last.
async fn send_all(rig: &Rig, stream: &mut DataStream, frames: &[Vec<u8>]) -> Vec<InputAck> {
    let mut acks = Vec::new();
    let mut written: u64 = 0;
    let mut accepted: u64 = 0;
    while accepted < frames.len() as u64 {
        if written < frames.len() as u64 && written - accepted < CLIENT_WINDOW {
            stream
                .write_message(&rig.frame(written, &frames[written as usize]))
                .await
                .expect("the frame is written");
            written += 1;
            continue;
        }
        let ack = next(stream)
            .await
            .expect("the stream stays open while frames are outstanding");
        if let InputAck::Accepted { epoch, through } = &ack {
            assert_eq!(*epoch, rig.epoch);
            accepted = through.get() + 1;
        }
        assert!(
            !matches!(ack, InputAck::Refused { .. } | InputAck::EpochEnded { .. }),
            "nothing is refused in this case: {ack:?}"
        );
        acks.push(ack);
    }
    acks
}

/// Distinct two-byte counters, so that an omission, a repeat or a reorder shows.
fn counters(n: usize) -> Vec<Vec<u8>> {
    (0..n)
        .map(|index| {
            u16::try_from(index)
                .expect("a counter")
                .to_be_bytes()
                .to_vec()
        })
        .collect()
}

/// C1: a burst of typing reaches the worker whole while the control handler is held with a request
/// in service, and the control stream answers once the handler is let go.
async fn a_burst_with_the_handler_held(n: usize) {
    let rig = Rig::start().await;
    let (answered, release) = rig.adopted.host.pause_after_a_frame_is_answered();
    rig.device
        .read(Method::HostInfo, &NoParams {})
        .await
        .expect("the read is answered");
    tokio::time::timeout(WAIT, answered)
        .await
        .expect("the handler reached its pause")
        .expect("the pause is armed");

    let mut stream = rig.open().await;
    let frames = counters(n);
    let acks = send_all(&rig, &mut stream, &frames).await;

    let Some(InputAck::Accepted { through, .. }) = acks
        .iter()
        .rev()
        .find(|ack| matches!(ack, InputAck::Accepted { .. }))
    else {
        panic!("nothing was accepted: {acks:?}");
    };
    assert_eq!(through.get(), n as u64 - 1, "the last frame is accepted");
    let written = rig.lane.frames();
    assert_eq!(written.len(), n, "every frame reached the lane once");
    for (index, frame) in written.iter().enumerate() {
        assert_eq!(frame.sequence, index as u64, "the sequences are contiguous");
        assert_eq!(frame.epoch, rig.epoch.get());
    }
    assert_eq!(
        rig.lane.bytes(),
        frames.concat(),
        "the lane has every byte, in order, with none changed or repeated"
    );

    release.send(()).expect("the handler is let go");
    rig.device
        .read(Method::HostInfo, &NoParams {})
        .await
        .expect("control is answered after the burst");
    rig.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_of_82_frames_reaches_the_worker_whole_while_the_handler_is_held() {
    a_burst_with_the_handler_held(82).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_of_1024_frames_reaches_the_worker_whole_while_the_handler_is_held() {
    a_burst_with_the_handler_held(1024).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_of_4096_frames_reaches_the_worker_whole_while_the_handler_is_held() {
    a_burst_with_the_handler_held(4096).await;
}

/// C2: typing goes on while a second attach that claims no input waits at the worker, and the
/// attach is answered once afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn typing_continues_while_an_attach_that_claims_no_input_is_held_at_the_worker() {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;

    let held = rig.adopted.workers[0].hold_the_dispatch_boundary().await;
    let attach = tokio::spawn({
        let device = Arc::clone(&rig.device);
        let target = rig.adopted.workers[0].target(rig.adopted.host.environment_id);
        let params = attach_params(rig.session, &[AttachmentCapability::ObserveTerminal]);
        async move {
            device
                .mutate(
                    Method::SessionAttach,
                    ActionId::new(kr_ipc::new_uuid()),
                    target,
                    &params,
                )
                .await
        }
    });

    let frames = counters(30);
    send_all(&rig, &mut stream, &frames).await;
    assert_eq!(
        rig.lane.bytes(),
        frames.concat(),
        "every byte is at the lane before the held attach is let go"
    );
    assert!(!attach.is_finished(), "the attach is still held");

    held.release();
    let answered = tokio::time::timeout(WAIT, attach)
        .await
        .expect("the attach is answered once it is let go")
        .expect("the attach task ends");
    assert!(answered.is_ok(), "the attach is answered: {answered:?}");
    rig.stop().await;
}

/// Waits until `condition` holds, looking again at each change of the host's stages.
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

/// The detach of the rig's attachment, sent on the device's control stream.
async fn detach(rig: &Rig) {
    let target = rig.adopted.workers[0].target(rig.adopted.host.environment_id);
    rig.device
        .mutate(
            Method::SessionDetach,
            ActionId::new(kr_ipc::new_uuid()),
            target,
            &SessionDetachParams {
                attachment_id: Nullable::some(rig.attachment),
                line_token: Nullable::null(),
                after_input: None,
                fenced_report: false,
            },
        )
        .await
        .expect("the device detaches");
}

/// What the worker writes on the lane when the attachment's lease ended.
fn lease_ended(rig: &Rig) -> LaneWindow {
    LaneWindow {
        epoch: rig.epoch,
        holder: false,
        frames: 0,
        bytes: U64::new(0),
        ended: Nullable::some(LaneEnded {
            epoch: rig.epoch,
            fenced_bytes: U64::new(0),
        }),
    }
}

/// The authority feed withdraws what a frame stands on between the host's decision for it and the
/// write to the worker: the worker is never given the frame. The withdrawal also takes the
/// connection away, which may stop the writer before it asks the feed again, so this shows that the
/// frame does not go, not which of the two stopped it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withdrawal_between_the_decision_and_the_write_stops_the_frame() {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    let stages = rig.adopted.host.network().input_stages();

    stream
        .write_message(&rig.frame(0, b"a"))
        .await
        .expect("the frame is written");
    assert_eq!(
        next(&mut stream).await,
        Some(InputAck::Accepted {
            epoch: rig.epoch,
            through: InputSequence::new(0),
        }),
        "the control: before the withdrawal the typing is accepted"
    );

    let (at_write, go_write) = stages.hold_before_a_lane_write();
    stream
        .write_message(&rig.frame(1, b"b"))
        .await
        .expect("the frame is written");
    arrived(at_write).await;
    assert_eq!(stages.counts().unanswered, 1, "the frame is decided");
    rig.adopted
        .host
        .controller()
        .raise_the_unverified_withdrawal_refusal()
        .await;
    // The connection's end may have taken the writer already.
    let _ = go_write.send(());
    until("the writer has done with the frame", || {
        stages.counts().unanswered == 0
    })
    .await;
    assert_eq!(
        rig.lane.frames().len(),
        1,
        "the worker never had the withdrawn frame"
    );
    rig.stop().await;
}

/// The host ends a stream by its own decision, and what the device is owed is written whole first.
/// A detach ends the stream once the worker's notice that the lease ended is written. The
/// acknowledgement writer is held at the notice until the stream's task has stopped reading, so a
/// read let go before the notice is written would reset the stream under it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_detach_ends_the_stream_after_the_notice_of_the_lease_is_written_whole() {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    let stages = rig.adopted.host.network().input_stages();
    let mut ends = stages.reads_ended();
    let (at_ack, go_ack) = stages.hold_before_an_ack_write();

    detach(&rig).await;
    rig.lane.send_window(lease_ended(&rig));
    arrived(at_ack).await;
    tokio::time::timeout(WAIT, ends.wait_for(|ended| *ended >= 1))
        .await
        .expect("the stream task stopped reading in time")
        .expect("the count stands");
    go_ack.send(()).expect("the acknowledgement is written");

    assert_eq!(
        next_or_reset(&mut stream).await.expect("not reset"),
        Some(InputAck::EpochEnded {
            epoch: rig.epoch,
            fenced_bytes: U64::new(0),
        }),
        "the device is told its lease ended"
    );
    assert!(
        matches!(next_or_reset(&mut stream).await, Ok(None)),
        "the stream then ends cleanly, and is not reset"
    );
    rig.stop().await;
}

/// A detach whose worker sends no notice ends the stream when the wait for it is over, and the
/// device is told nothing it was not told.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_detach_with_no_notice_ends_the_stream_when_the_wait_is_over() {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    detach(&rig).await;
    assert!(
        matches!(next_or_reset(&mut stream).await, Ok(None)),
        "the stream ends cleanly, with no notice"
    );
    rig.lane.until_ended().await;
    rig.stop().await;
}
