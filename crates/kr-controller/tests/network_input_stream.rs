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
use kr_protocol::envelope::{ControlFrame, Outcome, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::{StreamHeader, StreamKind, StreamResource};
use kr_protocol::ids::{
    ActionId, AttachmentId, InputLeaseEpoch, InputSequence, RequestId, SessionId,
};
use kr_protocol::input::{
    InputAck, InputAcquireParams, InputAcquireResult, InputFrame, input_claim,
};
use kr_protocol::local::{InputLaneReady, LaneEnded, LaneLaunch, LaneWindow};
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
        let device = Device::create().await;
        let record = pair_with(
            &adopted.host,
            &device,
            &adopted.owner,
            proposal(&[ActionRight::SessionView, ActionRight::TerminalInput]),
        )
        .await;
        Self::attached(adopted, device, record, frames, bytes).await
    }

    /// Connects the paired device to the daemon, attaches it to the worker's session, gives it the
    /// input lease and starts a lane that begins with `frames` queue entries and `bytes` of credit.
    async fn attached(
        adopted: Adopted,
        device: Device,
        record: DeviceRecord,
        frames: u32,
        bytes: u64,
    ) -> Self {
        let host = &adopted.host;
        let worker: &Worker = &adopted.workers[0];
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

    /// The rig after the daemon restarts: the device, paired as it was, connects again, attaches
    /// again and takes the lease, and a lane stands for the new daemon's door.
    async fn restarted(self) -> Self {
        let Self {
            adopted,
            device,
            _paired: (paired, record),
            lane,
            ..
        } = self;
        device.close();
        drop(device);
        drop(lane);
        let adopted = adopted.restart().await;
        Self::attached(adopted, paired, record, 64, 512 * 1024).await
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

/// The next acknowledgement from the read half of a split stream, as [`next_or_reset`] gives it.
async fn next_on(
    reader: &mut kr_transport::streams::DataReader,
) -> kr_transport::Result<Option<InputAck>> {
    tokio::time::timeout(WAIT, reader.read_message::<InputAck>())
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
        refused_older, 1,
        "the older epoch's first refusal is told, though the newer epoch was refused before it"
    );
    rig.stop().await;
}

/// The epochs of the frames on one stream never go back: a frame of an epoch lower than the newest
/// one the host has read breaks the stream's order, and the stream is cut, as for a malformed frame.
/// The device is told that the newer epoch is refused first, and then the stream is reset.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_of_an_older_epoch_after_a_newer_one_cuts_the_stream() {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    let newer = InputLeaseEpoch::new(rig.epoch.get() + 1);
    rig.lane.send_window(LaneWindow {
        epoch: newer,
        holder: false,
        frames: 0,
        bytes: U64::new(0),
        ended: Nullable::null(),
    });
    stream
        .write_message(&frame_of(newer.get(), 0, b"n"))
        .await
        .expect("the frame is written");
    assert!(
        matches!(
            next(&mut stream).await,
            Some(InputAck::Refused { epoch, .. }) if epoch == newer
        ),
        "the newer epoch is refused first"
    );

    let _ = stream.write_message(&rig.frame(0, b"o")).await;
    let ended = loop {
        match next_or_reset(&mut stream).await {
            Ok(Some(_)) => {}
            other => break other,
        }
    };
    assert!(ended.is_err(), "the stream is cut, and reset: {ended:?}");
    assert!(
        rig.lane.frames().is_empty(),
        "no frame of either epoch was passed on"
    );
    rig.stop().await;
}

/// One stream serves an attachment across the lease's changes of hands, so a long session crosses
/// far more epochs than the host holds frames for. Seventy epochs run on one stream, each in four
/// steps: the view holds the lease and one frame is accepted; the lease moves on and the device is
/// told so; one more frame of the epoch is refused. The device reads what it is told between the
/// steps. The stream stays open, every epoch is told ended and refused once, and the host's record
/// of what it has told never holds more epochs than the frames it holds plus one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seventy_changes_of_the_lease_on_one_stream_leave_it_open_and_the_record_small() {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    let stages = rig.adopted.host.network().input_stages();
    let first = rig.epoch.get() + 10;
    let mut last = first;
    for cycle in 0..70 {
        let epoch = first + 2 * cycle;
        last = epoch;
        rig.lane.send_window(holding(epoch));
        stream
            .write_message(&frame_of(epoch, 0, b"a"))
            .await
            .expect("the frame is written");
        assert!(
            matches!(
                next(&mut stream).await,
                Some(InputAck::Accepted { epoch: told, through })
                    if told.get() == epoch && through.get() == 0
            ),
            "the first frame of epoch {epoch} is accepted"
        );
        rig.lane.send_window(moved_on(epoch));
        assert!(
            matches!(
                next(&mut stream).await,
                Some(InputAck::EpochEnded { epoch: told, .. }) if told.get() == epoch
            ),
            "the end of epoch {epoch} is told"
        );
        stream
            .write_message(&frame_of(epoch, 1, b"b"))
            .await
            .expect("the frame is written");
        assert!(
            matches!(
                next(&mut stream).await,
                Some(InputAck::Refused { epoch: told, sequence, accepted_through, .. })
                    if told.get() == epoch
                        && sequence.get() == 1
                        && accepted_through.0.is_some_and(|through| through.get() == 0)
            ),
            "the second frame of epoch {epoch} is refused once, and the first stands accepted"
        );
    }
    let counts = stages.counts();
    assert!(
        counts.records_peak <= counts.host_holds_peak + 1,
        "the record held {} epochs when the host held at most {} frames",
        counts.records_peak,
        counts.host_holds_peak
    );
    assert_eq!(counts.host_holds, 0, "every frame was answered or refused");
    assert_eq!(counts.records, 1, "only the newest epoch's record is kept");

    let epoch = last + 2;
    rig.lane.send_window(holding(epoch));
    stream
        .write_message(&frame_of(epoch, 0, b"z"))
        .await
        .expect("the frame is written");
    assert!(
        matches!(
            next(&mut stream).await,
            Some(InputAck::Accepted { epoch: told, .. }) if told.get() == epoch
        ),
        "the stream is open and takes typing after seventy changes"
    );
    rig.stop().await;
}

/// An older epoch with two frames at the lane when a newer epoch is read has its first refusal told
/// once: the record of the older epoch is kept for as long as a frame of it is at the host, so the
/// worker's second answer for it tells the device nothing again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_older_epoch_with_two_frames_at_the_lane_is_told_refused_once() {
    let rig = Rig::start().await;
    let stream = rig.open().await;
    rig.lane.hold_answers();
    let (mut reader, mut writer) = stream.split();
    for sequence in 0..2 {
        writer
            .write_message(&rig.frame(sequence, b"o"))
            .await
            .expect("the frame is written");
    }
    rig.lane
        .until("both frames of the older epoch are at the lane", |frames| {
            frames.len() == 2
        })
        .await;
    let newer = InputLeaseEpoch::new(rig.epoch.get() + 1);
    writer
        .write_message(&frame_of(newer.get(), 0, b"n"))
        .await
        .expect("the newer epoch's frame is written");
    rig.lane.send_window(LaneWindow {
        epoch: newer,
        holder: false,
        frames: 0,
        bytes: U64::new(0),
        ended: Nullable::null(),
    });
    loop {
        let ack = tokio::time::timeout(WAIT, reader.read_message::<InputAck>())
            .await
            .expect("the host answers in time")
            .expect("the stream is not reset")
            .expect("the stream stays open");
        if matches!(ack, InputAck::Refused { epoch, .. } if epoch == newer) {
            break;
        }
    }
    rig.lane.refuse_from(0);
    rig.lane.release_answers();
    drop(writer);
    let mut refused_older = 0;
    while let Some(ack) = tokio::time::timeout(WAIT, reader.read_message::<InputAck>())
        .await
        .expect("the host answers in time")
        .expect("the stream is not reset")
    {
        if matches!(ack, InputAck::Refused { epoch, .. } if epoch == rig.epoch) {
            refused_older += 1;
        }
    }
    assert_eq!(
        refused_older, 1,
        "the older epoch is told refused once for its two answers"
    );
    rig.stop().await;
}

/// A worker that does not answer a frame is cut at the frame's deadline: the device's stream is
/// reset, and the connection stands. The deadline is shortened for the case.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_that_does_not_answer_is_cut_at_the_frames_deadline() {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    rig.adopted
        .host
        .network()
        .input_stages()
        .set_frame_deadline(Duration::from_millis(500));
    rig.lane.hold_answers();
    stream
        .write_message(&rig.frame(0, b"a"))
        .await
        .expect("the frame is written");
    let ended = loop {
        match next_or_reset(&mut stream).await {
            Ok(Some(_)) => {}
            other => break other,
        }
    };
    assert!(ended.is_err(), "the stream is reset: {ended:?}");
    rig.stop().await;
}

/// A frame keeps the deadline it was given when it was passed on: waiting for the lane's writer does
/// not renew it. A frame that the writer is held at past its deadline is cut and never reaches the
/// worker. Each end of the lane cuts at that deadline on its own, and this case holds what they
/// share, not the reader's half: with the reader's timer removed it still passes, because the
/// writer asks again before it writes and cuts the stream when it is let go. The reader's half, a
/// worker that does not answer, is held by the case of that name. The deadline is shortened for
/// the case, and the hold lasts longer than it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_that_waits_for_the_writer_past_its_deadline_is_cut_and_not_written() {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    let stages = rig.adopted.host.network().input_stages();
    stages.set_frame_deadline(Duration::from_millis(300));
    let (at_write, go) = stages.hold_before_a_lane_write();
    stream
        .write_message(&rig.frame(0, b"a"))
        .await
        .expect("the frame is written");
    arrived(at_write).await;
    tokio::time::sleep(Duration::from_millis(900)).await;
    let _ = go.send(());
    let ended = loop {
        match next_or_reset(&mut stream).await {
            Ok(Some(InputAck::Accepted { .. })) => panic!("a frame past its deadline was accepted"),
            Ok(Some(InputAck::Refused { .. })) => {
                panic!("a frame past its deadline was refused, and its end is a cut")
            }
            Ok(Some(_)) => {}
            other => break other,
        }
    };
    assert!(ended.is_err(), "the stream is reset: {ended:?}");
    assert!(
        rig.lane.frames().is_empty(),
        "the worker was never given the frame"
    );
    rig.stop().await;
}

/// The lane's writer does not give the worker a frame whose own deadline has passed, whatever it
/// waited for: the check is made at the write, so it holds with the lane's reader, whose timer is
/// the other cut, held where it cannot run. The reader is held at an event while no frame is
/// outstanding, so it has no deadline to cut at; the frame passes its deadline while the writer is
/// held after the host's decision; the stream is cut, the device reads a reset and no accepted
/// acknowledgement, and the lane holds no frame. The sleep only lets time pass: the frame's
/// deadline, 20 ms after it was passed on, is behind the moment the writer is let go.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_past_its_deadline_when_the_writer_goes_on_is_cut_and_never_written() {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    let stages = rig.adopted.host.network().input_stages();
    let (at_answer, go_answer) = stages.hold_before_a_lane_answer();
    rig.lane.send_credit(rig.epoch.get(), 1, 1);
    arrived(at_answer).await;

    stages.set_frame_deadline(Duration::from_millis(20));
    let (at_write, go_write) = stages.hold_before_a_lane_write();
    stream
        .write_message(&rig.frame(0, b"a"))
        .await
        .expect("the frame is written");
    arrived(at_write).await;
    tokio::time::sleep(Duration::from_millis(40)).await;
    let _ = go_write.send(());

    until("the stream was cut or the lane was given the frame", || {
        stages.counts().cuts == 1 || !rig.lane.frames().is_empty()
    })
    .await;
    assert!(
        rig.lane.frames().is_empty(),
        "the worker was given a frame past its deadline"
    );
    let ended = loop {
        match next_or_reset(&mut stream).await {
            Ok(Some(InputAck::Accepted { .. })) => panic!("a frame past its deadline was accepted"),
            Ok(Some(InputAck::Refused { .. })) => {
                panic!("a frame past its deadline was refused, and its end is a cut")
            }
            Ok(Some(_)) => {}
            other => break other,
        }
    };
    assert!(ended.is_err(), "the stream is reset: {ended:?}");
    drop(go_answer);
    rig.stop().await;
}

/// The writer's two checks before a write are made in an order: the frame's deadline, then the
/// authority feed. A frame that is past its deadline and whose authority is withdrawn, with nothing
/// sent, ends as a cut with no refusal: the deadline check cuts first, so the device reads a reset
/// and is told nothing of the frame, where the feed check would refuse it and finish the stream
/// cleanly. The reader is held where it cannot cut, the release that a withdrawal starts is held so
/// that it does not revoke the stream, and the sleep only lets the frame's deadline pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_past_its_deadline_and_withdrawn_is_cut_and_not_refused() {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    let stages = rig.adopted.host.network().input_stages();
    let (at_answer, go_answer) = stages.hold_before_a_lane_answer();
    rig.lane.send_credit(rig.epoch.get(), 1, 1);
    arrived(at_answer).await;

    stages.set_frame_deadline(Duration::from_millis(20));
    let (at_release, go_release) = stages.hold_before_a_release();
    let (at_write, go_write) = stages.hold_before_a_lane_write();
    stream
        .write_message(&rig.frame(0, b"a"))
        .await
        .expect("the frame is written");
    arrived(at_write).await;
    rig.adopted
        .host
        .controller()
        .raise_the_unverified_withdrawal_refusal()
        .await;
    arrived(at_release).await;
    tokio::time::sleep(Duration::from_millis(40)).await;
    let _ = go_write.send(());

    let ended = loop {
        match next_or_reset(&mut stream).await {
            Ok(Some(InputAck::Refused { .. })) => {
                panic!("a frame past its deadline and withdrawn was refused, and its end is a cut")
            }
            Ok(Some(InputAck::Accepted { .. })) => panic!("a frame past its deadline was accepted"),
            Ok(Some(_)) => {}
            other => break other,
        }
    };
    assert!(
        ended.is_err(),
        "the stream is reset, not finished: {ended:?}"
    );
    assert!(
        rig.lane.frames().is_empty(),
        "the worker was never given the frame"
    );
    drop(go_release);
    drop(go_answer);
    rig.stop().await;
}

/// A window of an older epoch that reaches the host after a newer one does not replace it: the
/// stream goes on in the newer epoch. The device reads the older epoch's end first, so the window
/// has been applied when the frame is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_window_of_an_older_epoch_does_not_replace_a_newer_one() {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    let newer = rig.epoch.get() + 1;
    rig.lane.send_window(holding(newer));
    rig.lane.send_window(LaneWindow {
        epoch: rig.epoch,
        holder: false,
        frames: 0,
        bytes: U64::new(0),
        ended: Nullable::some(LaneEnded {
            epoch: rig.epoch,
            fenced_bytes: U64::new(0),
        }),
    });
    assert!(
        matches!(
            next(&mut stream).await,
            Some(InputAck::EpochEnded { epoch, .. }) if epoch == rig.epoch
        ),
        "the older window is applied"
    );
    stream
        .write_message(&frame_of(newer, 0, b"n"))
        .await
        .expect("the frame is written");
    assert!(
        matches!(
            next(&mut stream).await,
            Some(InputAck::Accepted { epoch, .. }) if epoch.get() == newer
        ),
        "the newer epoch's window stands"
    );
    rig.stop().await;
}

/// A frame of an epoch newer than the lane's window waits for the window of its epoch: it is not
/// refused when it is read, and it is accepted when the window comes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_of_a_newer_epoch_waits_for_its_window_and_is_not_refused() {
    let rig = Rig::start().await;
    let stages = rig.adopted.host.network().input_stages();
    let newer = rig.epoch.get() + 1;
    // The stream task is held at its first turn that may read, and then let go with the frame
    // written. Its next turn that may read comes after it has routed the frame, so the frame has
    // met the lane's old window, and been told to wait, before the new window is given: a host
    // that refused it would have refused it by then.
    let (at_first, go_first) = stages.hold_before_a_read();
    let mut stream = rig.open().await;
    arrived(at_first).await;
    let (at_read, go) = stages.hold_before_a_read();
    stream
        .write_message(&frame_of(newer, 0, b"n"))
        .await
        .expect("the frame is written");
    let _ = go_first.send(());
    arrived(at_read).await;
    assert_eq!(
        stages.counts().host_holds,
        1,
        "the host holds the frame and has told it nothing"
    );
    rig.lane.send_window(holding(newer));
    let _ = go.send(());
    assert!(
        matches!(
            next(&mut stream).await,
            Some(InputAck::Accepted { epoch, .. }) if epoch.get() == newer
        ),
        "the frame waited for its window and was accepted"
    );
    rig.stop().await;
}

/// An answer of the worker for a frame of an epoch whose refusal the device was already told is not
/// told as an acceptance: the epoch stands refused. The frame goes to the lane, the lease moves on,
/// a later frame of the epoch is refused by the host, and only then does the worker answer the first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_after_the_epochs_refusal_is_not_told_as_an_acceptance() {
    let rig = Rig::start().await;
    let stream = rig.open().await;
    rig.lane.hold_answers();
    let (mut reader, mut writer) = stream.split();
    writer
        .write_message(&rig.frame(0, b"a"))
        .await
        .expect("the frame is written");
    rig.lane
        .until("the first frame is at the lane", |frames| frames.len() == 1)
        .await;
    rig.lane.send_window(moved_on(rig.epoch.get()));
    loop {
        let ack = tokio::time::timeout(WAIT, reader.read_message::<InputAck>())
            .await
            .expect("the host answers in time")
            .expect("the stream is not reset")
            .expect("the stream stays open");
        if matches!(ack, InputAck::EpochEnded { .. }) {
            break;
        }
    }
    writer
        .write_message(&rig.frame(1, b"b"))
        .await
        .expect("the frame is written");
    loop {
        let ack = tokio::time::timeout(WAIT, reader.read_message::<InputAck>())
            .await
            .expect("the host answers in time")
            .expect("the stream is not reset")
            .expect("the stream stays open");
        if matches!(ack, InputAck::Refused { epoch, .. } if epoch == rig.epoch) {
            break;
        }
    }
    rig.lane.release_answers();
    drop(writer);
    while let Some(ack) = tokio::time::timeout(WAIT, reader.read_message::<InputAck>())
        .await
        .expect("the stream ends in time")
        .expect("the stream is not reset")
    {
        assert!(
            !matches!(ack, InputAck::Accepted { .. }),
            "the answer after the refusal was told as an acceptance: {ack:?}"
        );
    }
    rig.stop().await;
}

/// A refusal names what was accepted in its own epoch and nothing from another: a frame of a newer
/// epoch that is refused after the older epoch accepted one carries no accepted count.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_of_a_newer_epoch_names_no_count_of_an_older_one() {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    type_and_wait(&rig, &mut stream, 0, b"a").await;
    let newer = rig.epoch.get() + 1;
    rig.lane.send_window(moved_on(rig.epoch.get()));
    assert!(
        matches!(
            next(&mut stream).await,
            Some(InputAck::EpochEnded { epoch, .. }) if epoch == rig.epoch
        ),
        "the older epoch's end is told"
    );
    stream
        .write_message(&frame_of(newer, 0, b"n"))
        .await
        .expect("the frame is written");
    match next(&mut stream).await {
        Some(InputAck::Refused {
            epoch,
            accepted_through,
            ..
        }) => {
            assert_eq!(epoch.get(), newer);
            assert!(
                accepted_through.0.is_none(),
                "no count of the older epoch is named: {accepted_through:?}"
            );
        }
        other => panic!("the newer epoch's frame was to be refused: {other:?}"),
    }
    rig.stop().await;
}

/// The cutoff stands at the newest epoch whose refusal was told, so a refusal of an older epoch does
/// not hold it back: a frame of the newest epoch that waits at the lane's writer when its epoch is
/// refused is discarded and never reaches the worker. The first epoch is refused, the lease moves
/// to the next, the worker refuses that epoch's first frame while the second waits at the writer,
/// and the second is let go unwritten.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_queued_frame_of_the_newest_refused_epoch_is_not_passed_on_after_an_older_refusal() {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    let stages = rig.adopted.host.network().input_stages();
    let newer = rig.epoch.get() + 1;
    rig.lane.refuse_from(0);
    stream
        .write_message(&rig.frame(0, b"o"))
        .await
        .expect("the frame is written");
    assert!(
        matches!(
            next(&mut stream).await,
            Some(InputAck::Refused { epoch, .. }) if epoch == rig.epoch
        ),
        "the first epoch is refused"
    );

    rig.lane.send_window(holding(newer));
    rig.lane.hold_answers();
    stream
        .write_message(&frame_of(newer, 0, b"a"))
        .await
        .expect("the first frame of the newer epoch is written");
    rig.lane
        .until("the newer epoch's first frame is at the lane", |frames| {
            frames.len() == 2
        })
        .await;
    let (at_judge, go) = stages.hold_before_a_frame_is_judged();
    stream
        .write_message(&frame_of(newer, 1, b"b"))
        .await
        .expect("the second frame of the newer epoch is written");
    arrived(at_judge).await;
    rig.lane.release_answers();
    assert!(
        matches!(
            next(&mut stream).await,
            Some(InputAck::Refused { epoch, .. }) if epoch.get() == newer
        ),
        "the newer epoch is refused"
    );

    let _ = go.send(());
    until("the host let go of every frame", || {
        stages.counts().host_holds == 0
    })
    .await;
    assert_eq!(
        rig.lane.frames().len(),
        2,
        "the second frame of the refused epoch never reached the worker"
    );
    rig.stop().await;
}

/// An answer that says the outcome is unknown is not a refusal: the worker may have taken the frame,
/// so the stream is cut and the device is never told that the frame was refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unknown_outcome_on_the_lane_cuts_the_stream_and_is_never_told_as_a_refusal() {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    rig.lane.hold_answers();
    stream
        .write_message(&rig.frame(0, b"a"))
        .await
        .expect("the frame is written");
    rig.lane
        .until("the frame is at the lane", |frames| frames.len() == 1)
        .await;
    rig.lane.send(ControlFrame::Response(Response {
        request_id: RequestId::new(1),
        outcome: Outcome::Error(ProtocolError::new(
            ErrorCode::OutcomeUnknown,
            "the worker cannot say whether it took the frame",
        )),
    }));
    let ended = loop {
        match next_or_reset(&mut stream).await {
            Ok(Some(InputAck::Refused { .. })) => {
                panic!("an unknown outcome was told as a refusal")
            }
            Ok(Some(_)) => {}
            other => break other,
        }
    };
    assert!(
        ended.is_err(),
        "the stream is cut and the device read {ended:?}"
    );
    rig.stop().await;
}

/// Opens a stream with `header` and says the host ended it without serving it: the device is not
/// told `Ready`, and no lane was bound for it at the worker.
async fn is_not_served(rig: &Rig, header: StreamHeader) {
    let mut stream = rig.device.open_stream(header).await;
    let read = tokio::time::timeout(WAIT, stream.read_message::<InputAck>())
        .await
        .expect("the host ends the stream in time");
    assert!(
        !matches!(read, Ok(Some(InputAck::Ready { .. }))),
        "the host served a stream it was to refuse: {read:?}"
    );
    assert!(rig.lane.binds().is_empty(), "no lane was bound for it");
}

/// A stream whose header names another environment than the host's is not served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_for_another_environment_is_not_served() {
    let rig = Rig::start().await;
    let mut header = rig.header_for(rig.attachment);
    header.resource.environment_id = kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid());
    is_not_served(&rig, header).await;
    rig.stop().await;
}

/// A stream whose header names a session other than the one this connection is attached to is not
/// served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_for_another_session_is_not_served() {
    let rig = Rig::start().await;
    let mut header = rig.header_for(rig.attachment);
    header.resource.session_id =
        Nullable::some(kr_protocol::ids::SessionId::new(kr_ipc::new_uuid()));
    is_not_served(&rig, header).await;
    rig.stop().await;
}

/// A device whose grant has no typing right attaches to observe and opens a stream for that
/// attachment, as a view without the lease does: the host does not serve it. The device is not told
/// `Ready`, and no lane is bound for it at the worker, which stands ready to be bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_of_a_device_whose_grant_has_no_typing_right_is_not_served() {
    let adopted = Adopted::start(1).await;
    let device = Device::create().await;
    let record = pair_with(
        &adopted.host,
        &device,
        &adopted.owner,
        proposal(&[ActionRight::SessionView]),
    )
    .await;
    let host = &adopted.host;
    let worker: &Worker = &adopted.workers[0];
    let connection = RawDevice::connect(host, &device, &record).await;
    connection.claim();
    let attached: SessionAttachResult = connection
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            worker.target(host.environment_id),
            &attach_params(worker.session_id, &[AttachmentCapability::ObserveTerminal]),
        )
        .await
        .expect("the device attaches to observe")
        .to_typed()
        .expect("an attachment");
    let lane = ScriptedLane::start(InputLaneReady {
        epoch: InputLeaseEpoch::new(1),
        holder: false,
        frames: 0,
        bytes: U64::new(0),
    });
    host.network().use_input_lane_at(lane.endpoint());
    let header = StreamHeader {
        kind: StreamKind::TerminalInput,
        connection_id: connection.connection_id(),
        stream_id: Nullable::null(),
        resource: StreamResource {
            environment_id: host.environment_id,
            session_id: Nullable::some(worker.session_id),
            attachment_id: Nullable::some(attached.attachment.attachment_id),
            transfer_id: Nullable::null(),
        },
    };
    let mut stream = connection.open_stream(header).await;
    let read = tokio::time::timeout(WAIT, stream.read_message::<InputAck>())
        .await
        .expect("the host ends the stream in time");
    assert!(
        !matches!(read, Ok(Some(InputAck::Ready { .. }))),
        "the host served a stream for a device that may not type: {read:?}"
    );
    assert!(lane.binds().is_empty(), "no lane was bound for it");
    connection.close();
    adopted.host.stop().await;
}

/// The window of the lane's epoch: the view holds the lease, with credit for what the cases write.
fn holding(epoch: u64) -> LaneWindow {
    LaneWindow {
        epoch: InputLeaseEpoch::new(epoch),
        holder: true,
        frames: 32,
        bytes: U64::new(64 * 1024),
        ended: Nullable::null(),
    }
}

/// The window after the lease of `epoch` moved to another view: the view holds nothing, and the
/// end of its lease is told with no bytes fenced.
fn moved_on(epoch: u64) -> LaneWindow {
    LaneWindow {
        epoch: InputLeaseEpoch::new(epoch + 1),
        holder: false,
        frames: 0,
        bytes: U64::new(0),
        ended: Nullable::some(LaneEnded {
            epoch: InputLeaseEpoch::new(epoch),
            fenced_bytes: U64::new(0),
        }),
    }
}

/// A frame of `epoch`, as a device writes it.
fn frame_of(epoch: u64, sequence: u64, bytes: &[u8]) -> InputFrame {
    InputFrame {
        epoch: InputLeaseEpoch::new(epoch),
        sequence: InputSequence::new(sequence),
        bytes: Bytes::new(bytes.to_vec()),
    }
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
/// write to the worker, and the release of the connection's link, which a withdrawal starts and
/// which revokes the connection's streams, is held until the writer has been let go. The writer
/// asks the feed immediately before the write, so the worker is never given the frame, the device
/// is told that the authority was withdrawn, and the stream ends cleanly: the check decides alone,
/// with no teardown to stop the writer first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withdrawal_after_the_decision_is_caught_by_the_feed_check_before_the_write() {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    let stages = rig.adopted.host.network().input_stages();
    type_and_wait(&rig, &mut stream, 0, b"a").await;

    let (at_release, go_release) = stages.hold_before_a_release();
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
    // The release has begun and stands before it ends anything.
    arrived(at_release).await;
    let _ = go_write.send(());

    match next_or_reset(&mut stream).await {
        Ok(Some(InputAck::Refused {
            epoch,
            sequence,
            error,
            ..
        })) => {
            assert_eq!(epoch, rig.epoch);
            assert_eq!(sequence.get(), 1);
            assert_eq!(error.code, ErrorCode::PermissionDenied);
        }
        other => panic!("the host was to refuse the frame, and the stream gave {other:?}"),
    }
    assert!(
        matches!(next_or_reset(&mut stream).await, Ok(None)),
        "the stream ends cleanly, by the check and not by the release"
    );
    assert_eq!(
        rig.lane.frames().len(),
        1,
        "the worker never had the withdrawn frame"
    );
    drop(go_release);
    rig.stop().await;
}

/// A frame that the host's own decision refuses while the connection stands is refused: the device
/// is told once, in the decision's words, the worker is never given the frame, and the host lets go
/// of it. The authority behind the typing is withdrawn and the release of the connection's link,
/// which would end the stream, is held, so the decision is the only thing that stops the frame. A
/// later frame of the epoch is not told refused again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_the_decision_refuses_while_the_connection_stands_is_refused_once_and_not_forwarded()
 {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    let stages = rig.adopted.host.network().input_stages();
    type_and_wait(&rig, &mut stream, 0, b"a").await;

    let (at_release, go_release) = stages.hold_before_a_release();
    rig.adopted
        .host
        .controller()
        .raise_the_unverified_withdrawal_refusal()
        .await;
    arrived(at_release).await;

    stream
        .write_message(&rig.frame(1, b"b"))
        .await
        .expect("the frame is written");
    match next_or_reset(&mut stream).await {
        Ok(Some(InputAck::Refused {
            epoch,
            sequence,
            error,
            ..
        })) => {
            assert_eq!(epoch, rig.epoch);
            assert_eq!(sequence.get(), 1);
            assert_eq!(error.code, ErrorCode::PermissionDenied);
        }
        other => panic!("the host was to refuse the frame, and the stream gave {other:?}"),
    }
    assert_eq!(
        stages.counts().host_holds,
        0,
        "the host let go of the refused frame"
    );

    let (mut reader, mut writer) = stream.split();
    writer
        .write_message(&rig.frame(2, b"c"))
        .await
        .expect("the next frame is written");
    drop(writer);
    let ended = loop {
        match tokio::time::timeout(WAIT, reader.read_message::<InputAck>())
            .await
            .expect("the host ends the stream in time")
        {
            Ok(Some(InputAck::Refused { .. })) => panic!("the epoch was told refused twice"),
            Ok(Some(_)) => {}
            other => break other,
        }
    };
    assert!(
        matches!(ended, Ok(None)),
        "the stream ends cleanly: {ended:?}"
    );
    assert_eq!(
        rig.lane.frames().len(),
        1,
        "the worker was given the first frame and no other"
    );
    drop(go_release);
    rig.stop().await;
}

/// The stream task marks the state's version before it looks at whether the stream has ended, so an
/// end that comes between the mark and the look is seen at the look, and one that comes after the
/// look is seen as a change. The task is woken by a credit from the worker, so that no frame is
/// ready for it to turn on, and held between the mark and the look while a detach ends the stream:
/// a task that missed the end would wait for a frame that never comes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_end_that_comes_between_the_mark_and_the_look_is_not_missed() {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    let stages = rig.adopted.host.network().input_stages();
    let mut ended = rig.adopted.host.network().input_tasks_ended();
    let (at_mark, go) = stages.hold_after_the_version_mark();
    rig.lane.send_credit(rig.epoch.get(), 1, 1);
    arrived(at_mark).await;

    rig.lane.send_window(lease_ended(&rig));
    detach(&rig).await;
    assert_eq!(
        next_or_reset(&mut stream).await.expect("not reset"),
        Some(InputAck::EpochEnded {
            epoch: rig.epoch,
            fenced_bytes: U64::new(0),
        }),
        "the device is told while the stream task is held"
    );
    assert!(
        matches!(next_or_reset(&mut stream).await, Ok(None)),
        "the end is written by the acknowledgement writer, which is another task"
    );

    let _ = go.send(());
    tokio::time::timeout(WAIT, ended.changed())
        .await
        .expect("the stream task ended in time once it was let go")
        .expect("the count stands");
    rig.stop().await;
}

/// A stream is finished only if its end is graceful when the acknowledgement writer lets it go. A
/// cut that comes after the writer found the end graceful, and before it let go, is a reset: the
/// device must not read a clean end for a stream that was cut. The writer is held after it has
/// looked at a graceful end with nothing left to write, while the worker's lane ends; the stream
/// task, which waits for the writer, has not revoked the stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cut_that_follows_the_writers_look_at_a_graceful_end_is_a_reset_not_a_finish() {
    let rig = Rig::start().await;
    let stream = rig.open().await;
    let stages = rig.adopted.host.network().input_stages();
    let (at_look, go) = stages.hold_after_a_graceful_look();
    let (mut reader, writer) = stream.split();
    drop(writer);
    arrived(at_look).await;

    rig.lane.close();
    until("the lane's end cut the stream", || {
        stages.counts().cuts == 1
    })
    .await;
    let _ = go.send(());
    let ended = loop {
        match tokio::time::timeout(WAIT, reader.read_message::<InputAck>())
            .await
            .expect("the host ends the stream in time")
        {
            Ok(Some(_)) => {}
            other => break other,
        }
    };
    assert!(
        ended.is_err(),
        "a cut stream is reset, and the device read {ended:?}"
    );
    rig.stop().await;
}

/// A stream that is cut is reset by the acknowledgement writer itself, whatever the stream task is
/// doing: the device must not read a clean end for it. The stream task is woken by a credit and held
/// between the mark and the look, where it cannot reset the stream, while the worker's lane ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cut_while_the_stream_task_is_held_is_a_reset_that_the_writer_gives() {
    let rig = Rig::start().await;
    let stream = rig.open().await;
    let stages = rig.adopted.host.network().input_stages();
    let (at_mark, go) = stages.hold_after_the_version_mark();
    rig.lane.send_credit(rig.epoch.get(), 1, 1);
    arrived(at_mark).await;

    rig.lane.close();
    until("the lane's end cut the stream", || {
        stages.counts().cuts == 1
    })
    .await;
    let (mut reader, _writer) = stream.split();
    let ended = loop {
        match tokio::time::timeout(WAIT, reader.read_message::<InputAck>())
            .await
            .expect("the host ends the stream in time")
        {
            Ok(Some(_)) => {}
            other => break other,
        }
    };
    assert!(
        ended.is_err(),
        "a cut stream is reset, and the device read {ended:?}"
    );
    let _ = go.send(());
    rig.stop().await;
}

/// A detach that waits for the worker's notice and finds the stream already cut does not make the
/// end graceful: the device reads a reset. The stream task is held at the version mark, where it
/// cannot reset the stream, and the acknowledgement writer is held with a launch marker in hand,
/// taken before the cut. The detach begins its wait, the worker's lane ends, the detach's wait is
/// over because the stream ended, and it asks for its graceful end; the case waits for that ask
/// and only then lets the writer go.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_detach_that_finds_the_stream_cut_leaves_it_a_reset() {
    let rig = Rig::start().await;
    let stream = rig.open().await;
    let stages = rig.adopted.host.network().input_stages();
    let (at_mark, go_mark) = stages.hold_after_the_version_mark();
    rig.lane.send_credit(rig.epoch.get(), 1, 1);
    arrived(at_mark).await;
    let (at_ack, go_ack) = stages.hold_before_an_ack_write();
    rig.lane.send_launch(LaneLaunch {
        attachment_id: rig.attachment,
        launch: 1,
    });
    arrived(at_ack).await;

    detach(&rig).await;
    until("the detach was told to the stream", || {
        stages.counts().detaches == 1
    })
    .await;
    rig.lane.close();
    until("the detach asked for its graceful end", || {
        stages.counts().detach_ends == 1
    })
    .await;
    assert_eq!(stages.counts().cuts, 1, "the lane's end cut the stream");
    let _ = go_ack.send(());

    let (mut reader, _writer) = stream.split();
    let ended = loop {
        match tokio::time::timeout(WAIT, reader.read_message::<InputAck>())
            .await
            .expect("the host ends the stream in time")
        {
            Ok(Some(_)) => {}
            other => break other,
        }
    };
    assert!(
        ended.is_err(),
        "a cut stream is reset, and the device read {ended:?}"
    );
    let _ = go_mark.send(());
    rig.stop().await;
}

/// A frame that waits in the lane writer's queue behind a frame that the worker then refuses is
/// discarded by the writer, which leaves nothing in flight. The stream task, which waits for the
/// stream to drain because the device has finished, is woken to see it. The writer is held at the
/// queued frame until the stream task is waiting. What the host holds is read at the stream's
/// graceful end, with the acknowledgement writer held there, before the device reads the end: the
/// teardown of the stream's state gives held frames back too, so a read after it would not show
/// that the discard let its frame go.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_the_writer_discards_wakes_the_wait_for_the_stream_to_drain() {
    let rig = Rig::start().await;
    let stream = rig.open().await;
    let stages = rig.adopted.host.network().input_stages();
    rig.lane.refuse_from(0);
    let (at_first, go_first) = stages.hold_before_a_frame_is_judged();
    let (mut reader, mut writer) = stream.split();
    writer
        .write_message(&rig.frame(0, b"a"))
        .await
        .expect("the frame is written");
    arrived(at_first).await;
    let (at_second, go_second) = stages.hold_before_a_frame_is_judged();
    writer
        .write_message(&rig.frame(1, b"b"))
        .await
        .expect("the frame is written");
    until("both frames are passed on", || {
        stages.counts().unanswered == 2
    })
    .await;
    let _ = go_first.send(());
    arrived(at_second).await;

    // The worker's refusal of the first frame is recorded and told before the second is judged.
    let told = tokio::time::timeout(WAIT, reader.read_message::<InputAck>())
        .await
        .expect("the host answers in time")
        .expect("not reset");
    assert!(
        matches!(told, Some(InputAck::Refused { sequence, .. }) if sequence.get() == 0),
        "the first frame is refused: {told:?}"
    );
    let mut waits = stages.drain_waits();
    drop(writer);
    tokio::time::timeout(WAIT, waits.changed())
        .await
        .expect("the stream task waits for the frame in flight")
        .expect("the count stands");
    let (at_look, go_look) = stages.hold_after_a_graceful_look();
    let _ = go_second.send(());
    arrived(at_look).await;
    assert_eq!(
        stages.counts().host_holds,
        0,
        "the discarded frame is let go with the others"
    );
    let _ = go_look.send(());

    while let Some(ack) = tokio::time::timeout(WAIT, reader.read_message::<InputAck>())
        .await
        .expect("the stream ends in time once the frame is discarded")
        .expect("the stream is not reset")
    {
        assert!(
            !matches!(ack, InputAck::Accepted { .. }),
            "nothing was accepted: {ack:?}"
        );
    }
    assert_eq!(
        rig.lane.frames().len(),
        1,
        "the discarded frame never reached the lane"
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

/// The notice of an earlier epoch does not stand for the notice of the epoch the view holds when
/// it is detached: the view lost the lease, took it again in a newer epoch, and is detached before
/// that epoch's notice comes. The stream waits for that notice and tells the device, as a detach
/// that follows no earlier notice does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_detach_waits_for_the_notice_of_the_epoch_the_view_holds() {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    rig.lane.send_window(lease_ended(&rig));
    assert_eq!(
        next_or_reset(&mut stream).await.expect("not reset"),
        Some(InputAck::EpochEnded {
            epoch: rig.epoch,
            fenced_bytes: U64::new(0),
        }),
        "the device is told its first epoch ended"
    );
    let held = InputLeaseEpoch::new(rig.epoch.get() + 2);
    rig.lane.send_window(LaneWindow {
        epoch: held,
        holder: true,
        frames: 64,
        bytes: U64::new(512 * 1024),
        ended: Nullable::null(),
    });
    // The host has applied the window the view holds once a frame of that epoch is accepted.
    stream
        .write_message(&InputFrame {
            epoch: held,
            sequence: InputSequence::new(0),
            bytes: Bytes::new(b"h".to_vec()),
        })
        .await
        .expect("the frame is written");
    assert_eq!(
        next(&mut stream).await,
        Some(InputAck::Accepted {
            epoch: held,
            through: InputSequence::new(0),
        }),
        "the host applied the window of the epoch the view holds"
    );

    detach(&rig).await;
    // One read is kept pending across the wait: a read that is dropped part way resets the stream.
    let told = {
        let mut read = std::pin::pin!(stream.read_message::<InputAck>());
        assert!(
            tokio::time::timeout(Duration::from_millis(500), &mut read)
                .await
                .is_err(),
            "the stream waits for the notice of the epoch the view holds"
        );
        rig.lane.send_window(LaneWindow {
            epoch: InputLeaseEpoch::new(held.get() + 1),
            holder: false,
            frames: 0,
            bytes: U64::new(0),
            ended: Nullable::some(LaneEnded {
                epoch: held,
                fenced_bytes: U64::new(3),
            }),
        });
        tokio::time::timeout(WAIT, &mut read)
            .await
            .expect("the host answers in time")
            .expect("not reset")
    };
    assert_eq!(
        told,
        Some(InputAck::EpochEnded {
            epoch: held,
            fenced_bytes: U64::new(3),
        }),
        "the device is told its newer epoch ended"
    );
    assert!(
        matches!(next_or_reset(&mut stream).await, Ok(None)),
        "the stream then ends cleanly"
    );
    rig.stop().await;
}

/// A detach that the worker refuses before it acts, because the subject facts it expects have
/// moved, took no attachment away: the attachment's stream is not told of a detach and goes on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_detach_the_worker_refuses_before_it_acts_leaves_the_stream_standing() {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    let stages = rig.adopted.host.network().input_stages();
    type_and_wait(&rig, &mut stream, 0, b"a").await;

    let target = rig.adopted.workers[0].target(rig.adopted.host.environment_id);
    let refused = rig
        .device
        .mutate_expecting(
            Method::SessionDetach,
            ActionId::new(kr_ipc::new_uuid()),
            target,
            &std::collections::BTreeMap::from([("input_lease_epoch", rig.epoch.get() + 5)]),
            &SessionDetachParams {
                attachment_id: Nullable::some(rig.attachment),
                line_token: Nullable::null(),
                after_input: None,
                fenced_report: false,
            },
        )
        .await
        .expect_err("the worker refuses the detach");
    assert_eq!(refused.code, ErrorCode::DraftConflict, "{refused:?}");
    assert_eq!(
        stages.counts().detaches,
        0,
        "the stream was not told of a detach"
    );
    type_and_wait(&rig, &mut stream, 1, b"b").await;
    rig.stop().await;
}

/// A detach that names an attachment which the asking connection does not hold is refused by the
/// worker before it acts. The attachment belongs to another device, and its stream is untouched: it
/// goes on, and its next frame is accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_detach_that_names_another_devices_attachment_leaves_its_stream_standing() {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    let stages = rig.adopted.host.network().input_stages();
    type_and_wait(&rig, &mut stream, 0, b"a").await;

    let second = rig.second_typist().await;
    let target = rig.adopted.workers[0].target(rig.adopted.host.environment_id);
    let refused = second
        .device
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
        .expect_err("the worker refuses a detach of another device's attachment");
    assert_eq!(
        refused.code,
        ErrorCode::AmbiguousAttachment,
        "the worker refuses it as an attachment its link does not hold: {refused:?}"
    );
    assert_eq!(
        stages.counts().detaches,
        0,
        "no stream was told of a detach"
    );
    type_and_wait(&rig, &mut stream, 1, b"b").await;
    drop(second);
    rig.stop().await;
}

/// A detach that another device sends for this device's attachment, and that the worker refuses as
/// `INVALID_ARGUMENT` before it checks whose attachment it is (an unknown key among the facts it
/// expects), counts as one that may have acted, and the hook is told of it. The hook reaches the
/// asking connection's stream alone, so this device's stream stands and takes its next frame after
/// the wait that a detach's notice gets. The wait is not a delay the case relies on to pass: a
/// stream that the hook ended would end within it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_detach_another_device_sends_and_the_worker_refuses_as_invalid_leaves_this_stream_standing()
 {
    let rig = Rig::start().await;
    let mut stream = rig.open().await;
    let stages = rig.adopted.host.network().input_stages();
    type_and_wait(&rig, &mut stream, 0, b"a").await;

    let second = rig.second_typist().await;
    let target = rig.adopted.workers[0].target(rig.adopted.host.environment_id);
    let refused = second
        .device
        .mutate_expecting(
            Method::SessionDetach,
            ActionId::new(kr_ipc::new_uuid()),
            target,
            &serde_json::json!({ "no_such_fact": 1 }),
            &SessionDetachParams {
                attachment_id: Nullable::some(rig.attachment),
                line_token: Nullable::null(),
                after_input: None,
                fenced_report: false,
            },
        )
        .await
        .expect_err("the worker refuses a detach that expects a fact it does not know");
    assert_eq!(
        refused.code,
        ErrorCode::InvalidArgument,
        "the worker refuses it before it checks whose attachment it is: {refused:?}"
    );
    assert_eq!(
        stages.counts().detaches,
        1,
        "the hook was told of a detach that may have acted"
    );
    tokio::time::sleep(DETACH_NOTICE_WAIT + Duration::from_secs(1)).await;
    type_and_wait(&rig, &mut stream, 1, b"b").await;
    drop(second);
    rig.stop().await;
}

/// How long the host waits for the notice of a detach, as the door names it.
const DETACH_NOTICE_WAIT: Duration = Duration::from_secs(2);

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

/// What the host holds for a stream is let go with the stream's state: a stream that is replaced
/// while frames of it are at the host gives them back, and a stream that ends with the record of
/// its newest refusal gives the record back. The counts are read after the replacement and after
/// the close, and they are of the streams that stand.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_frames_and_the_record_a_stream_held_are_let_go_when_it_is_replaced_and_when_it_ends() {
    let rig = Rig::start().await;
    let stages = rig.adopted.host.network().input_stages();
    let mut older = rig.open().await;
    rig.lane.hold_answers();
    for sequence in 0..2 {
        older
            .write_message(&rig.frame(sequence, b"a"))
            .await
            .expect("the frame is written");
    }
    rig.lane
        .until("both frames are at the lane", |frames| frames.len() == 2)
        .await;
    assert_eq!(
        stages.counts().host_holds,
        2,
        "the host holds both frames, with no answer"
    );
    let newer = rig.open().await;
    assert!(
        next_or_reset(&mut older).await.is_err(),
        "the older stream is reset"
    );
    until("the replaced stream's frames are let go", || {
        stages.counts().host_holds == 0
    })
    .await;

    rig.lane.refuse_from(0);
    rig.lane.release_answers();
    let (mut reader, mut writer) = newer.split();
    writer
        .write_message(&rig.frame(0, b"b"))
        .await
        .expect("the frame is written");
    assert!(
        matches!(
            next_on(&mut reader).await,
            Ok(Some(InputAck::Refused { .. }))
        ),
        "the frame is refused"
    );
    assert_eq!(
        stages.counts().records,
        1,
        "the host keeps the record of the newest epoch's refusal while the stream stands"
    );
    drop(writer);
    assert!(
        matches!(next_on(&mut reader).await, Ok(None)),
        "the stream ends cleanly"
    );
    until("the ended stream's record is let go", || {
        let counts = stages.counts();
        counts.records == 0 && counts.host_holds == 0
    })
    .await;
    rig.stop().await;
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
    next_or_reset(&mut stream)
        .await
        .expect_err("the input stream goes with the connection");
    until("the device has been told why the connection closed", || {
        rig.device.close_reason().is_some()
    })
    .await;
    assert!(
        matches!(
            rig.device.close_reason(),
            Some(iroh::endpoint::ConnectionError::ApplicationClosed(ref close))
                if close.error_code == kr_transport::listener::CONTROL_LOST.into()
                    && close.reason.as_ref() == b"the control queue overflowed"
        ),
        "the connection closed as a lost control stream, with the queue's words: {:?}",
        rig.device.close_reason()
    );
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

/// C16d, the host's half: a daemon that has restarted serves the device that comes back, and a
/// restriction that reaches the whole host takes the new stream as it takes any remote stream. The
/// stream the old daemon served ended with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restriction_that_reaches_the_whole_host_ends_a_stream_opened_after_a_restart() {
    let rig = Rig::start().await;
    let mut before = rig.open().await;
    type_and_wait(&rig, &mut before, 0, b"a").await;
    let rig = rig.restarted().await;
    assert!(
        !matches!(next_or_reset(&mut before).await, Ok(Some(_))),
        "the old daemon's stream ended with it"
    );

    let mut stream = rig.open().await;
    type_and_wait(&rig, &mut stream, 0, b"b").await;
    rig.adopted
        .host
        .controller()
        .raise_the_unverified_withdrawal_refusal()
        .await;
    let _ = stream.write_message(&rig.frame(1, b"c")).await;
    assert!(
        reads_to_the_end(&mut stream, 1).await.is_err(),
        "the stream is reset by the restriction"
    );
    assert_eq!(
        rig.lane.frames().len(),
        1,
        "nothing was passed on after it, and the first daemon's frame is not in this lane"
    );
    rig.stop().await;
}

/// A feed refusal releases each refused connection's link to its worker, and the connection's end
/// follows from the loss of that link. The connection's input streams end with the release and do
/// not wait for that end. The handler is held, so the connection's end waits behind it and the
/// stream's end is the release's alone.
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

/// A grant that ends at its deadline ends the streams of the connection that stands on it, while a
/// stream is open and the device says nothing: the connection's grant watch ends the connection,
/// and releasing its link ends its input streams.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_that_ends_at_its_deadline_ends_the_open_stream() {
    let rig = Rig::start().await;
    let host = &rig.adopted.host;
    let mut short = proposal(&[ActionRight::SessionView, ActionRight::TerminalInput]);
    short.expiry = kr_protocol::grant::GrantExpiry::At {
        expires_at_ms: kr_protocol::scalars::TimestampMs::new(kr_ipc::now_ms().get() + 15_000),
    };
    let device = Device::create().await;
    let record = pair_with(host, &device, &rig.adopted.owner, short).await;
    let connection = RawDevice::connect(host, &device, &record).await;
    let second = rig.attach_second(connection, device, record).await;
    let mut stream = rig.open_second(&second).await;
    type_and_wait(&rig, &mut stream, 0, b"a").await;

    let ended = reads_to_the_end(&mut stream, 1).await;
    assert!(
        ended.is_err(),
        "the stream is reset when the grant ends: {ended:?}"
    );
    drop(second);
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
