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
use kr_protocol::ids::{
    ActionId, AttachmentId, InputLeaseEpoch, InputSequence, RequestId, SessionId,
};
use kr_protocol::input::{
    InputAck, InputAcquireParams, InputAcquireResult, InputFrame, input_claim,
};
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
    /// A rig whose lane gives the credit that the worker's own lane gives an attachment that holds
    /// the lease: 32 frames of the smallest claim.
    async fn start() -> Self {
        Self::start_with_credit(64, 512 * 1024).await
    }

    /// A rig whose lane begins with `frames` queue entries and `bytes` of credit.
    async fn start_with_credit(frames: u32, bytes: u64) -> Self {
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
            frames,
            bytes: U64::new(bytes),
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

    fn header_for(&self, attachment: AttachmentId) -> StreamHeader {
        StreamHeader {
            kind: StreamKind::TerminalInput,
            connection_id: self.device.connection_id(),
            stream_id: Nullable::null(),
            resource: StreamResource {
                environment_id: self.adopted.host.environment_id,
                session_id: Nullable::some(self.session),
                attachment_id: Nullable::some(attachment),
                transfer_id: Nullable::null(),
            },
        }
    }

    /// Opens the attachment's input stream and reads the host's `Ready`.
    async fn open(&self) -> DataStream {
        self.open_for(self.attachment).await
    }

    /// Opens the input stream that names `attachment` and reads the host's `Ready`.
    async fn open_for(&self, attachment: AttachmentId) -> DataStream {
        let mut stream = self.device.open_stream(self.header_for(attachment)).await;
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

/// Reads the stream to its end. A frame written after a restriction may be answered before the
/// stream ends, and no answer may accept it: `first_unaccepted` is the sequence of the first frame
/// written after the restriction. Returns what ended the stream.
async fn reads_to_the_end(
    stream: &mut DataStream,
    first_unaccepted: u64,
) -> kr_transport::Result<Option<InputAck>> {
    loop {
        match next_or_reset(stream).await {
            Ok(Some(InputAck::Accepted { through, .. })) => assert!(
                through.get() < first_unaccepted,
                "a frame written after the restriction was accepted"
            ),
            Ok(Some(_)) => {}
            ended => return ended,
        }
    }
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

/// The refusal of the lane's current epoch stands when a late answer of an older epoch comes: the
/// device is told once that the current epoch's typing is refused, and is not told again by the
/// older epoch's answer, nor for each later frame of the current epoch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_refusal_of_the_current_epoch_stands_against_a_late_answer_of_an_older_epoch() {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    let stages = rig.adopted.host.network().input_stages();
    rig.lane.hold_answers();
    stream
        .write_message(&rig.frame(0, b"a"))
        .await
        .expect("the frame is written");
    rig.lane
        .until("the older epoch's frame is at the lane", |frames| {
            frames.len() == 1
        })
        .await;

    let newer = InputLeaseEpoch::new(rig.epoch.get() + 1);
    rig.lane.send_window(LaneWindow {
        epoch: newer,
        holder: false,
        frames: 0,
        bytes: U64::new(0),
        ended: Nullable::some(LaneEnded {
            epoch: rig.epoch,
            fenced_bytes: U64::new(0),
        }),
    });
    let newer_frame = |sequence: u64| InputFrame {
        epoch: newer,
        sequence: InputSequence::new(sequence),
        bytes: Bytes::new(b"n".to_vec()),
    };
    stream
        .write_message(&newer_frame(0))
        .await
        .expect("the frame is written");
    let mut refused_newer = 0;
    loop {
        match next(&mut stream).await {
            Some(InputAck::Refused { epoch, .. }) if epoch == newer => {
                refused_newer += 1;
                break;
            }
            Some(InputAck::EpochEnded { .. }) => {}
            other => panic!("the host was to refuse the newer epoch's frame: {other:?}"),
        }
    }

    // The worker now answers the older epoch's frame with the refusal that the window's move
    // gives it, and the device then types once more in the current epoch.
    rig.lane.refuse_from(0);
    rig.lane.release_answers();
    until("the late answer is read", || {
        stages.counts().unanswered == 0
    })
    .await;
    let (mut reader, mut writer) = stream.split();
    writer
        .write_message(&newer_frame(1))
        .await
        .expect("the frame is written");
    drop(writer);
    let mut refused_older = 0;
    while let Some(ack) = tokio::time::timeout(WAIT, reader.read_message::<InputAck>())
        .await
        .expect("the host answers in time")
        .expect("the stream is not reset")
    {
        if let InputAck::Refused { epoch, .. } = ack {
            if epoch == newer {
                refused_newer += 1;
            } else {
                refused_older += 1;
            }
        }
    }
    assert_eq!(refused_newer, 1, "the current epoch is refused once");
    assert_eq!(
        refused_older, 0,
        "the older epoch's late answer says nothing"
    );
    rig.stop().await;
}

/// How many acknowledgements the host keeps for a device that does not read them, as the door
/// names it.
const MAX_UNREAD_ACKS: usize = 64;

/// A device that does not read what it is told holds the host to a bounded number of
/// acknowledgements: the worker's events would make the host hold more, so the stream is cut, and
/// the device's connection stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_acknowledgements_owed_to_a_device_that_does_not_read_are_bounded() {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    let stages = rig.adopted.host.network().input_stages();
    let (at_ack, go_ack) = stages.hold_before_an_ack_write();

    // The first notice parks the acknowledgement writer; the rest wait behind it.
    rig.lane.send_window(lease_ended(&rig));
    arrived(at_ack).await;
    for _ in 0..MAX_UNREAD_ACKS + 8 {
        rig.lane.send_window(lease_ended(&rig));
    }
    assert!(
        reads_to_the_end(&mut stream, 0).await.is_err(),
        "the stream is cut when more is owed than the host keeps"
    );
    rig.device
        .read(Method::HostInfo, &NoParams {})
        .await
        .expect("the connection stands and answers");
    drop(go_ack);
    rig.stop().await;
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

/// Frames the host passes on within the lane's credit at most, when each claims the least: the lane
/// begins an epoch with 64 queue entries and a frame claims two.
const LANE_FRAMES: u64 = 32;

/// How many frames the host keeps read and not yet routed, as the door names it.
const READ_AHEAD: u64 = 2;

/// A new attachment identifier, for a stream that names an attachment the device has not made.
fn another_attachment() -> AttachmentId {
    AttachmentId::new(kr_ipc::new_uuid())
}

/// The most input streams one connection holds, as the listener allows.
const MAX_STREAMS: usize = kr_transport::listener::DEFAULT_MAX_INPUT_STREAMS;

/// A stream that is refused is reset and given no place: the connection holds as many as it may,
/// and the streams it holds go on typing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_fifth_input_stream_of_a_connection_is_refused() {
    let rig = Rig::start().await;
    let mut streams = vec![rig.open().await];
    for _ in 1..MAX_STREAMS {
        streams.push(rig.open_for(another_attachment()).await);
    }
    let mut fifth = rig
        .device
        .open_stream(rig.header_for(another_attachment()))
        .await;
    assert!(
        next_or_reset(&mut fifth).await.is_err(),
        "the stream above the bound is reset"
    );
    assert_eq!(rig.lane.binds().len(), MAX_STREAMS, "it was given no lane");

    streams[0]
        .write_message(&rig.frame(0, b"a"))
        .await
        .expect("the frame is written");
    assert_eq!(
        next(&mut streams[0]).await,
        Some(InputAck::Accepted {
            epoch: rig.epoch,
            through: InputSequence::new(0),
        }),
        "the control: a stream within the bound types"
    );
    rig.stop().await;
}

/// A newer stream for an attachment replaces the older, which is reset, and the newer carries the
/// typing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_newer_stream_for_an_attachment_replaces_the_older() {
    let rig = Rig::start().await;
    let mut older = rig.open().await;
    let mut newer = rig.open().await;
    assert!(
        next_or_reset(&mut older).await.is_err(),
        "the older stream is reset"
    );
    newer
        .write_message(&rig.frame(0, b"a"))
        .await
        .expect("the frame is written");
    assert_eq!(
        next(&mut newer).await,
        Some(InputAck::Accepted {
            epoch: rig.epoch,
            through: InputSequence::new(0),
        }),
        "the newer stream types"
    );
    rig.stop().await;
}

/// Credit comes for one epoch: a credit that names another epoch is ignored, so only the credit of
/// the lane's own epoch lets a held frame go.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_credit_of_another_epoch_is_ignored() {
    let claim = input_claim(2);
    let rig = Rig::start_with_credit(claim.frames as u32, claim.bytes as u64).await;
    let mut stream = rig.open().await;
    let stages = rig.adopted.host.network().input_stages();
    let mut full = stages.reads_full();
    rig.lane.withhold_credit();
    let frames = counters(5);
    for (sequence, bytes) in frames.iter().enumerate() {
        stream
            .write_message(&rig.frame(sequence as u64, bytes))
            .await
            .expect("the frame is written");
    }
    tokio::time::timeout(WAIT, full.wait_for(|turns| *turns >= 1))
        .await
        .expect("the host stopped reading in time")
        .expect("the count stands");
    rig.lane
        .until("the one frame that fits the credit", |read| read.len() == 1)
        .await;

    rig.lane.send_credit(rig.epoch.get() + 1, 200, 1 << 20);
    rig.lane
        .send_credit(rig.epoch.get(), claim.frames as u32, claim.bytes as u64);
    until("what the host has read is on the lane or waiting", || {
        let counts = stages.counts();
        counts.read >= 4 && rig.lane.frames().len() as u64 + counts.held == counts.read
    })
    .await;
    assert_eq!(
        rig.lane.bytes(),
        frames[..2].concat(),
        "the credit of the other epoch let nothing go: one frame more went, for the credit of the epoch"
    );
    rig.stop().await;
}

/// A frame of an epoch older than the lane's is refused by the host, and never forwarded; the
/// frame behind it, of the same epoch, is passed over and the refusal is not given twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_of_an_older_epoch_is_refused_by_the_host_and_never_forwarded() {
    let rig = Rig::start().await;
    let stream = rig.open().await;
    let newer = InputLeaseEpoch::new(rig.epoch.get() + 1);
    rig.lane.send_window(LaneWindow {
        epoch: newer,
        holder: false,
        frames: 0,
        bytes: U64::new(0),
        ended: Nullable::some(LaneEnded {
            epoch: rig.epoch,
            fenced_bytes: U64::new(0),
        }),
    });
    let (mut reader, mut writer) = stream.split();
    let ended = tokio::time::timeout(WAIT, reader.read_message::<InputAck>())
        .await
        .expect("the host tells the device in time")
        .expect("not reset");
    assert_eq!(
        ended,
        Some(InputAck::EpochEnded {
            epoch: rig.epoch,
            fenced_bytes: U64::new(0),
        }),
        "the device is told the epoch ended"
    );
    writer
        .write_message(&rig.frame(0, b"a"))
        .await
        .expect("the frame is written");
    writer
        .write_message(&rig.frame(1, b"b"))
        .await
        .expect("the frame is written");
    drop(writer);
    let Some(InputAck::Refused {
        epoch,
        sequence,
        accepted_through,
        error,
    }) = reader.read_message::<InputAck>().await.expect("not reset")
    else {
        panic!("the older epoch's frame was to be refused");
    };
    assert_eq!(epoch, rig.epoch);
    assert_eq!(sequence.get(), 0);
    assert_eq!(accepted_through.0, None);
    assert_eq!(error.code, ErrorCode::LeaseLost);
    assert!(
        matches!(reader.read_message::<InputAck>().await, Ok(None)),
        "the stream ends with no second refusal"
    );
    assert!(rig.lane.frames().is_empty(), "nothing was forwarded");
    rig.stop().await;
}

/// 32 frames are in flight on the lane at once, and reach it in the order they were read, each once,
/// before the worker answers any.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn frames_in_flight_on_the_lane_keep_their_order() {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    rig.lane.hold_answers();
    let frames = counters(LANE_FRAMES as usize);
    for (sequence, bytes) in frames.iter().enumerate() {
        stream
            .write_message(&rig.frame(sequence as u64, bytes))
            .await
            .expect("the frame is written");
    }
    rig.lane
        .until("all 32 frames, none answered", |read| {
            read.len() == LANE_FRAMES as usize
        })
        .await;
    let written = rig.lane.frames();
    for (index, frame) in written.iter().enumerate() {
        assert_eq!(frame.sequence, index as u64, "in the order they were read");
    }
    assert_eq!(rig.lane.bytes(), frames.concat());
    assert_eq!(
        rig.adopted
            .host
            .network()
            .input_stages()
            .counts()
            .unanswered_peak,
        LANE_FRAMES,
        "they were in flight together"
    );
    rig.lane.release_answers();
    loop {
        let ack = next(&mut stream).await.expect("the stream stays open");
        if matches!(
            ack,
            InputAck::Accepted { through, .. } if through.get() == LANE_FRAMES - 1
        ) {
            break;
        }
    }
    rig.stop().await;
}

/// The host reads at most [`READ_AHEAD`] frames that wait for credit, and no third: with the credit
/// spent it has the one it forwarded and the two it holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_third_frame_is_read_while_the_credit_is_spent() {
    let claim = input_claim(2);
    let rig = Rig::start_with_credit(claim.frames as u32, claim.bytes as u64).await;
    let mut stream = rig.open().await;
    let stages = rig.adopted.host.network().input_stages();
    let mut full = stages.reads_full();
    rig.lane.withhold_credit();
    for (sequence, bytes) in counters(6).iter().enumerate() {
        stream
            .write_message(&rig.frame(sequence as u64, bytes))
            .await
            .expect("the frame is written");
    }
    tokio::time::timeout(WAIT, full.wait_for(|turns| *turns >= 1))
        .await
        .expect("the host stopped reading in time")
        .expect("the count stands");
    let counts = stages.counts();
    assert_eq!(
        counts.read,
        1 + READ_AHEAD,
        "one forwarded, two held, no third"
    );
    assert_eq!(counts.held, READ_AHEAD);
    assert_eq!(counts.held_peak, READ_AHEAD);
    rig.stop().await;
}

/// A device that resets its stream while the credit is spent is heard: the host has one frame
/// waiting and reads on, so it learns of the reset, and the stream and its lane end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reset_is_learned_while_the_credit_is_spent() {
    let claim = input_claim(2);
    let rig = Rig::start_with_credit(claim.frames as u32, claim.bytes as u64).await;
    let mut stream = rig.open().await;
    let stages = rig.adopted.host.network().input_stages();
    rig.lane.withhold_credit();
    for (sequence, bytes) in counters(2).iter().enumerate() {
        stream
            .write_message(&rig.frame(sequence as u64, bytes))
            .await
            .expect("the frame is written");
    }
    until("one frame is forwarded and one waits", || {
        let counts = stages.counts();
        counts.read == 2 && counts.held == 1
    })
    .await;
    read_until_accepted(&mut stream, 0).await;
    stream.reset();
    rig.lane.until_ended().await;
    until("the stages are empty", || {
        let counts = stages.counts();
        counts.held == 0 && counts.unanswered == 0
    })
    .await;
    rig.stop().await;
}

/// A device that resets its stream while the host holds as many frames as it reads ahead and the
/// credit is spent is heard all the same, though the host reads no third frame: the stream and its
/// lane end, and the frames it held are dropped with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reset_is_learned_while_the_read_ahead_is_full() {
    let claim = input_claim(2);
    let rig = Rig::start_with_credit(claim.frames as u32, claim.bytes as u64).await;
    let mut stream = rig.open().await;
    let stages = rig.adopted.host.network().input_stages();
    let mut full = stages.reads_full();
    rig.lane.withhold_credit();
    for (sequence, bytes) in counters(3).iter().enumerate() {
        stream
            .write_message(&rig.frame(sequence as u64, bytes))
            .await
            .expect("the frame is written");
    }
    tokio::time::timeout(WAIT, full.wait_for(|turns| *turns >= 1))
        .await
        .expect("the host stopped reading in time")
        .expect("the count stands");
    assert_eq!(stages.counts().held, READ_AHEAD, "the read-ahead is full");
    // The one forwarded frame is acknowledged first, so that the host has nothing to write to the
    // device and only its read can learn of the reset.
    read_until_accepted(&mut stream, 0).await;
    stream.reset();
    rig.lane.until_ended().await;
    until("the stages are empty", || {
        let counts = stages.counts();
        counts.held == 0 && counts.unanswered == 0
    })
    .await;
    rig.stop().await;
}

/// A device that finishes its stream is answered for everything it wrote, and the stream then ends
/// cleanly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_finishes_its_stream_is_answered_for_all_it_wrote() {
    let rig = Rig::start().await;
    let stream = rig.open().await;
    let (mut reader, mut writer) = stream.split();
    for (sequence, bytes) in counters(3).iter().enumerate() {
        writer
            .write_message(&rig.frame(sequence as u64, bytes))
            .await
            .expect("the frame is written");
    }
    drop(writer);
    let mut through = None;
    while let Some(ack) = tokio::time::timeout(WAIT, reader.read_message::<InputAck>())
        .await
        .expect("the host answers in time")
        .expect("the stream is not reset")
    {
        if let InputAck::Accepted { through: seen, .. } = ack {
            through = Some(seen.get());
        }
    }
    assert_eq!(
        through,
        Some(2),
        "the last frame was answered before the end"
    );
    rig.stop().await;
}

/// What ends a stream whose stages are full.
#[derive(Clone, Copy, Debug)]
enum Ending {
    /// The device's connection, and with it its control stream, ends.
    ConnectionClosed,
    /// The device is revoked: its grant ends.
    DeviceRevoked,
    /// A newer stream for the same attachment is opened.
    NewerStream,
    /// The worker's lane ends, as when its session closes.
    LaneClosed,
}

/// A rig whose stages are full: 32 frames are on the lane and unanswered, with the credit spent; two
/// more are read and held, and the rest of what the device wrote is unread. Returns the rig, the
/// device's stream and what it wrote.
async fn full_stages() -> (Rig, DataStream, Vec<Vec<u8>>) {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    let stages = rig.adopted.host.network().input_stages();
    let mut full = stages.reads_full();
    rig.lane.hold_answers();
    rig.lane.withhold_credit();
    let frames = counters(usize::try_from(LANE_FRAMES + READ_AHEAD + 2).expect("a count"));
    for (sequence, bytes) in frames.iter().enumerate() {
        stream
            .write_message(&rig.frame(sequence as u64, bytes))
            .await
            .expect("the frame is written");
    }
    tokio::time::timeout(WAIT, full.wait_for(|turns| *turns >= 1))
        .await
        .expect("the host stopped reading in time")
        .expect("the count stands");
    rig.lane
        .until("the 32 frames the credit allows", |read| {
            read.len() as u64 == LANE_FRAMES
        })
        .await;
    let counts = stages.counts();
    assert_eq!(
        counts.read,
        LANE_FRAMES + READ_AHEAD,
        "no frame beyond the bound is read"
    );
    assert_eq!(counts.held, READ_AHEAD);
    assert_eq!(counts.unanswered, LANE_FRAMES);
    (rig, stream, frames)
}

/// C6: with every stage at its bound, an end of the stream resets it at once, nothing is accepted or
/// passed on afterwards, every count falls to zero, and none was ever above its bound.
async fn full_stages_then(ending: Ending) {
    let (rig, mut stream, _frames) = full_stages().await;
    let stages = rig.adopted.host.network().input_stages();
    let mut ended = rig.adopted.host.network().input_tasks_ended();
    let before = *ended.borrow();
    match ending {
        Ending::ConnectionClosed => rig.device.close(),
        Ending::DeviceRevoked => {
            rig.adopted
                .host
                .network()
                .revoke_device(rig._paired.1.device_id)
                .await
                .expect("the device is revoked");
        }
        Ending::NewerStream => {
            let _newer = rig.open().await;
            tokio::time::timeout(WAIT, ended.wait_for(|ends| *ends > before))
                .await
                .expect("the older stream's task ended in time")
                .expect("the count stands");
            assert!(next_or_reset(&mut stream).await.is_err(), "reset at once");
        }
        Ending::LaneClosed => rig.lane.close(),
    }
    tokio::time::timeout(WAIT, ended.wait_for(|ends| *ends > before))
        .await
        .expect("the stream's task ended in time")
        .expect("the count stands");
    until("every stage is empty", || {
        let counts = stages.counts();
        counts.held == 0 && counts.unanswered == 0
    })
    .await;
    // Whatever the device is still told is no acceptance: the lane answered nothing.
    rig.lane.release_answers();
    while let Ok(Some(ack)) = next_or_reset(&mut stream).await {
        assert!(
            !matches!(ack, InputAck::Accepted { .. }),
            "nothing is accepted after the end: {ack:?}"
        );
    }
    assert_eq!(
        rig.lane.frames().len() as u64,
        LANE_FRAMES,
        "nothing was passed on after the end"
    );
    let counts = stages.counts();
    assert!(counts.held_peak <= READ_AHEAD, "{counts:?}");
    assert!(counts.unanswered_peak <= LANE_FRAMES, "{counts:?}");
    rig.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_stages_are_emptied_when_the_connection_closes() {
    full_stages_then(Ending::ConnectionClosed).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_stages_are_emptied_when_the_device_is_revoked() {
    full_stages_then(Ending::DeviceRevoked).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_stages_are_emptied_when_a_newer_stream_replaces_the_stream() {
    full_stages_then(Ending::NewerStream).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_stages_are_emptied_when_the_workers_lane_ends() {
    full_stages_then(Ending::LaneClosed).await;
}

/// C7, the host's half: a worker that does not answer or give credit stops the host reading, control
/// is answered throughout, and when the worker goes on every byte arrives once and in order.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_that_does_not_answer_stops_the_reading_and_control_goes_on() {
    let (rig, mut stream, frames) = full_stages().await;
    for _ in 0..3 {
        rig.device
            .read(Method::HostInfo, &NoParams {})
            .await
            .expect("control is answered while the stages are full");
    }
    let claim = input_claim(2);
    rig.lane.release_answers();
    rig.lane.send_credit(
        rig.epoch.get(),
        u32::try_from(claim.frames as u64 * LANE_FRAMES).expect("a count"),
        claim.bytes as u64 * LANE_FRAMES,
    );
    let last = frames.len() as u64 - 1;
    loop {
        let ack = next(&mut stream).await.expect("the stream stays open");
        assert!(
            !matches!(ack, InputAck::Refused { .. }),
            "nothing is refused: {ack:?}"
        );
        if matches!(ack, InputAck::Accepted { through, .. } if through.get() == last) {
            break;
        }
    }
    let written = rig.lane.frames();
    for (index, frame) in written.iter().enumerate() {
        assert_eq!(frame.sequence, index as u64, "contiguous, once each");
    }
    assert_eq!(rig.lane.bytes(), frames.concat(), "every byte, in order");
    rig.stop().await;
}

/// C9: a flood of control requests behind a held handler still ends the connection, and typing
/// accepted before the flood was delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_control_flood_ends_the_connection_and_the_typing_before_it_was_delivered() {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    let frames = counters(4);
    send_all(&rig, &mut stream, &frames).await;

    let (answered, release) = rig.adopted.host.pause_after_a_frame_is_answered();
    rig.device
        .read(Method::HostInfo, &NoParams {})
        .await
        .expect("the read is answered");
    tokio::time::timeout(WAIT, answered)
        .await
        .expect("the handler reached its pause")
        .expect("the pause is armed");
    let device = Arc::clone(&rig.device);
    let flood = tokio::spawn(async move {
        for _ in 0..80 {
            device.submit_read(Method::HostInfo, &NoParams {}).await;
        }
    });
    assert_eq!(
        rig.device
            .answered_before_closing(RequestId::new(u64::MAX), WAIT)
            .await,
        Some(false),
        "the host ends the control stream, answering nothing more"
    );
    let reason = next_or_reset(&mut stream)
        .await
        .expect_err("the input stream goes with the connection");
    println!("the input stream's end: {reason:?}");
    assert_eq!(
        rig.lane.bytes(),
        frames.concat(),
        "the typing was delivered"
    );
    let _ = flood.await;
    drop(release);
    rig.stop().await;
}

/// A second paired device, attached to the same session, and its input stream.
struct Second {
    device: Arc<RawDevice>,
    _paired: (Device, DeviceRecord),
    attachment: AttachmentId,
}

impl Rig {
    /// Pairs a second device, attaches it to the rig's session and returns it.
    async fn second_typist(&self) -> Second {
        let host = &self.adopted.host;
        let device = Device::create().await;
        let record = pair_with(
            host,
            &device,
            &self.adopted.owner,
            proposal(&[ActionRight::SessionView, ActionRight::TerminalInput]),
        )
        .await;
        let connection = RawDevice::connect(host, &device, &record).await;
        self.attach_second(connection, device, record).await
    }

    /// Attaches a second device's connection to the rig's session, asking for input.
    async fn attach_second(
        &self,
        connection: RawDevice,
        device: Device,
        record: DeviceRecord,
    ) -> Second {
        let host = &self.adopted.host;
        let worker: &Worker = &self.adopted.workers[0];
        connection.claim();
        let attached: SessionAttachResult = connection
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                worker.target(host.environment_id),
                &attach_params(
                    worker.session_id,
                    &[
                        AttachmentCapability::ObserveTerminal,
                        AttachmentCapability::Input,
                    ],
                ),
            )
            .await
            .expect("the second device attaches")
            .to_typed()
            .expect("an attachment");
        Second {
            device: Arc::new(connection),
            _paired: (device, record),
            attachment: attached.attachment.attachment_id,
        }
    }

    /// Opens the second device's input stream and reads the host's `Ready`.
    async fn open_second(&self, second: &Second) -> DataStream {
        let mut header = self.header_for(second.attachment);
        header.connection_id = second.device.connection_id();
        let mut stream = second.device.open_stream(header).await;
        let first = next_or_reset(&mut stream).await;
        assert!(
            matches!(first, Ok(Some(InputAck::Ready { .. }))),
            "the host was to say Ready to the second device, and it said {first:?}"
        );
        stream
    }
}

/// Writes `bytes` as the frame at `sequence` and waits for it to be accepted.
async fn type_and_wait(rig: &Rig, stream: &mut DataStream, sequence: u64, bytes: &[u8]) {
    stream
        .write_message(&rig.frame(sequence, bytes))
        .await
        .expect("the frame is written");
    loop {
        match next(stream).await {
            Some(InputAck::Accepted { through, .. }) if through.get() >= sequence => return,
            Some(InputAck::Accepted { .. }) => {}
            other => panic!("the typing was to be accepted, and the host said {other:?}"),
        }
    }
}

/// Reads acknowledgements until the host has accepted the frame at `sequence`, so that nothing is
/// left for the host to write to the device afterwards.
async fn read_until_accepted(stream: &mut DataStream, sequence: u64) {
    loop {
        match next(stream).await {
            Some(InputAck::Accepted { through, .. }) if through.get() >= sequence => return,
            Some(InputAck::Ready { .. } | InputAck::Accepted { .. }) => {}
            other => panic!("the typing was to be accepted, and the host said {other:?}"),
        }
    }
}

/// The authority revision the lane saw on the frame that carried `bytes`.
fn revision_of(rig: &Rig, bytes: &[u8]) -> u64 {
    rig.lane
        .frames()
        .iter()
        .find(|frame| frame.bytes == bytes)
        .and_then(|frame| frame.revision)
        .expect("the frame reached the lane with a validated revision")
}

/// The rig's own device types beside `named`, which is the one a restriction is made on; both have
/// typed one frame before it. Returns what the case needs after the restriction, and the second
/// device itself: a device that is dropped can no longer learn that its stream ended, so the case
/// holds it until it has read the stream.
async fn two_typists_then(
    named: Second,
    rig: Rig,
    restrict: impl AsyncFnOnce(&Rig, &Second),
) -> (Rig, Second, DataStream, DataStream) {
    let mut unaffected = rig.open().await;
    let mut named_stream = rig.open_second(&named).await;
    type_and_wait(&rig, &mut unaffected, 0, b"1a").await;
    type_and_wait(&rig, &mut named_stream, 0, b"2a").await;
    restrict(&rig, &named).await;
    (rig, named, named_stream, unaffected)
}

/// What a restriction that names one device leaves, whichever way it names it: the device the restriction names loses its stream and nothing more of
/// its typing reaches the lane; the other device, which it does not reach, keeps typing, and the
/// host decides each of its frames afresh at the revision the restriction raised.
async fn the_other_device_keeps_typing(
    rig: Rig,
    named: Second,
    mut named_stream: DataStream,
    mut unaffected: DataStream,
) {
    // The named device types once more after the restriction. Whether the write is refused or the
    // stream is already reset, the frame is never given to the worker.
    let _ = named_stream.write_message(&rig.frame(1, b"2b")).await;
    assert!(
        reads_to_the_end(&mut named_stream, 1).await.is_err(),
        "the device the restriction names is reset"
    );
    type_and_wait(&rig, &mut unaffected, 1, b"1b").await;
    assert!(
        revision_of(&rig, b"1b") > revision_of(&rig, b"1a"),
        "the frame after the restriction is decided at the newer revision"
    );
    assert!(
        rig.lane.frames().iter().all(|frame| frame.bytes != b"2b"),
        "nothing of the named device's typing was passed on"
    );
    drop(named);
    rig.stop().await;
}

/// C16a, the host's half: a restriction that names a holder by its device only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restriction_that_names_a_device_ends_its_stream_and_leaves_the_other_typing() {
    let rig = Rig::start().await;
    let named = rig.second_typist().await;
    let (rig, named, named_stream, unaffected) =
        two_typists_then(named, rig, async |rig, named| {
            rig.adopted
                .host
                .network()
                .revoke_device(named._paired.1.device_id)
                .await
                .expect("the device is revoked");
        })
        .await;
    the_other_device_keeps_typing(rig, named, named_stream, unaffected).await;
}

/// C16c, the host's half: a restriction that reaches the whole host takes every remote stream, and
/// nothing more of any remote typing reaches the lane.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restriction_that_reaches_the_whole_host_ends_every_remote_stream() {
    let rig = Rig::start().await;
    let named = rig.second_typist().await;
    let (rig, named, mut named_stream, mut unaffected) =
        two_typists_then(named, rig, async |rig, _named| {
            rig.adopted
                .host
                .controller()
                .raise_the_unverified_withdrawal_refusal()
                .await;
        })
        .await;
    // Both devices type once more after the restriction; neither frame is given to the worker.
    let _ = named_stream.write_message(&rig.frame(1, b"2b")).await;
    let _ = unaffected.write_message(&rig.frame(1, b"1b")).await;
    assert!(
        reads_to_the_end(&mut named_stream, 1).await.is_err(),
        "the second device's stream is reset"
    );
    assert!(
        reads_to_the_end(&mut unaffected, 1).await.is_err(),
        "the first device's stream is reset"
    );
    assert_eq!(rig.lane.frames().len(), 2, "nothing was passed on after it");
    drop(named);
    rig.stop().await;
}

/// A feed refusal releases each refused connection's link to its worker and leaves the
/// connection standing, so the connection's own task never learns of it. The connection's input
/// streams end with the link all the same. The handler is held, so that the connection stands
/// through the refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_ends_when_a_feed_refusal_releases_its_connections_link() {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    type_and_wait(&rig, &mut stream, 0, b"a").await;
    let (answered, release) = rig.adopted.host.pause_after_a_frame_is_answered();
    rig.device
        .read(Method::HostInfo, &NoParams {})
        .await
        .expect("the read is answered");
    arrived(answered).await;

    rig.adopted
        .host
        .controller()
        .raise_the_unverified_withdrawal_refusal()
        .await;
    let _ = stream.write_message(&rig.frame(1, b"b")).await;
    assert!(
        reads_to_the_end(&mut stream, 1).await.is_err(),
        "the stream is reset with the link"
    );
    assert_eq!(
        rig.lane.frames().len(),
        1,
        "the frame written after the refusal was not forwarded"
    );
    drop(release);
    rig.stop().await;
}

/// C6, the end the plan is for: the device's control stream ends while its connection stands. The
/// input stream goes with it and the lane ends. Two streams have no order between them, so a frame
/// written at the same moment as the control stream's end may reach the host first and is decided
/// as any frame is; the case writes its next frame once the device has been told that the stream
/// ended, and that frame is never forwarded.
async fn the_control_stream_ends_while_the_connection_stands(reset: bool) {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    type_and_wait(&rig, &mut stream, 0, b"a").await;

    if reset {
        rig.device.reset_control().await;
    } else {
        rig.device.finish_control().await;
    }
    let ended = reads_to_the_end(&mut stream, 1).await;
    assert!(
        !matches!(ended, Ok(Some(_))),
        "the input stream ends with the control stream: {ended:?}"
    );
    let _ = stream.write_message(&rig.frame(1, b"b")).await;
    rig.lane.until_ended().await;
    assert_eq!(
        rig.lane.frames().len(),
        1,
        "the frame written after the stream ended was not forwarded"
    );
    rig.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_input_stream_ends_when_the_control_stream_is_finished_and_the_connection_stands() {
    the_control_stream_ends_while_the_connection_stands(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_input_stream_ends_when_the_control_stream_is_reset_and_the_connection_stands() {
    the_control_stream_ends_while_the_connection_stands(true).await;
}
