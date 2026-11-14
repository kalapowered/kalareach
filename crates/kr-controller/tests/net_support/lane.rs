//! A worker's input lane, scripted.
//!
//! A local endpoint that answers the host's input lane as the worker's lane does: it reads
//! `InputLane` and answers `InputLaneReady`, then reads each forwarded `input.write`, records it
//! and answers it in the order it came, and writes the lane's own frames (the window, the credit
//! and the launch marker) when a suite asks it to. A suite decides when it answers and what it
//! answers, so every stage of the host's lane is held where the suite wants it. The product's own
//! worker lane is exercised by the worker's suites and by the cases that run the two together.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kr_ipc::client::{LinkReader, LinkWriter};
use kr_ipc::endpoint::{Connection, Listener};
use kr_ipc::framed::split;
use kr_ipc::paths::Endpoint;
use kr_ipc::testing::PrivateTempDir;
use kr_protocol::envelope::{ControlEvent, ControlFrame, Outcome, ParamsValue, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::StreamKind;
use kr_protocol::ids::InputLeaseEpoch;
use kr_protocol::input::{InputContent, InputWriteParams, InputWriteResult, input_claim};
use kr_protocol::local::{InputLane, InputLaneReady, LaneCredit, LaneLaunch, LaneWindow};
use kr_protocol::retained::Level;
use kr_protocol::scalars::U64;
use tokio::sync::{Notify, mpsc, watch};

/// What a case waits at most for the lane: a host that does what the case says gets there at once,
/// and the bound ends a case that would hang.
const WAIT: Duration = Duration::from_secs(60);

/// One frame the lane read from the host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Written {
    pub epoch: u64,
    pub sequence: u64,
    pub bytes: Vec<u8>,
}

/// What the lane did, in the order it happened.
#[derive(Debug, Default)]
struct Log {
    binds: Vec<InputLane>,
    frames: Vec<Written>,
    answered: usize,
    ended: bool,
}

/// What a lane does with the frames it reads.
#[derive(Clone, Copy, Debug)]
struct Behaviour {
    /// Give each answered frame's claim back as credit for its epoch, as the worker does once its
    /// writer has finished the frame.
    credit_on_answer: bool,
    /// Refuse every frame whose sequence is at least this, with `LEASE_LOST`.
    refuse_from: Option<u64>,
}

#[derive(Debug)]
struct Shared {
    log: Mutex<Log>,
    changed: Notify,
    /// Answers wait while this is true; frames are still read and recorded.
    held: watch::Sender<bool>,
    behaviour: Mutex<Behaviour>,
}

/// A command to the lane's writer, so its own frames and its answers stay in one order.
enum Command {
    Frame(ControlFrame),
    /// End the lane's connection.
    Close,
}

/// A scripted lane and the endpoint it listens at.
pub struct ScriptedLane {
    endpoint: Endpoint,
    _dir: PrivateTempDir,
    shared: Arc<Shared>,
    commands: mpsc::UnboundedSender<Command>,
    task: tokio::task::JoinHandle<()>,
}

impl ScriptedLane {
    /// Starts a lane that answers a bind with `ready`.
    pub fn start(ready: InputLaneReady) -> Self {
        let dir = PrivateTempDir::create();
        let endpoint = Endpoint::from_path(dir.path().join("lane")).expect("an endpoint");
        let listener = Listener::bind(&endpoint).expect("binds the lane's endpoint");
        let (held, _) = watch::channel(false);
        let shared = Arc::new(Shared {
            log: Mutex::new(Log::default()),
            changed: Notify::new(),
            held,
            behaviour: Mutex::new(Behaviour {
                credit_on_answer: true,
                refuse_from: None,
            }),
        });
        let (commands, received) = mpsc::unbounded_channel();
        let task = tokio::spawn(serve(listener, Arc::clone(&shared), ready, received));
        Self {
            endpoint,
            _dir: dir,
            shared,
            commands,
            task,
        }
    }

    /// Where the host is to connect its lane.
    pub fn endpoint(&self) -> Endpoint {
        self.endpoint.clone()
    }

    /// Stops answering frames until [`Self::release_answers`]. Frames are still read and recorded.
    pub fn hold_answers(&self) {
        self.shared.held.send_replace(true);
    }

    /// Answers every frame that waited, in order, and the ones after.
    pub fn release_answers(&self) {
        self.shared.held.send_replace(false);
    }

    /// Stops giving each answered frame's claim back as credit.
    pub fn withhold_credit(&self) {
        self.behaviour(|behaviour| behaviour.credit_on_answer = false);
    }

    /// Refuses every frame from `sequence` on, with `LEASE_LOST`.
    pub fn refuse_from(&self, sequence: u64) {
        self.behaviour(|behaviour| behaviour.refuse_from = Some(sequence));
    }

    fn behaviour(&self, change: impl FnOnce(&mut Behaviour)) {
        change(
            &mut self
                .shared
                .behaviour
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
    }

    /// Writes `frame` on the lane, in order with its answers.
    pub fn send(&self, frame: ControlFrame) {
        let _ = self.commands.send(Command::Frame(frame));
    }

    /// Writes the window of a lease epoch on the lane.
    pub fn send_window(&self, window: LaneWindow) {
        self.send(ControlFrame::Event(ControlEvent::InputWindow(window)));
    }

    /// Writes credit for an epoch on the lane.
    pub fn send_credit(&self, epoch: u64, frames: u32, bytes: u64) {
        self.send(ControlFrame::Event(ControlEvent::InputCredit(LaneCredit {
            epoch: InputLeaseEpoch::new(epoch),
            frames,
            bytes: U64::new(bytes),
        })));
    }

    /// Writes the launch marker of `attachment` on the lane.
    pub fn send_launch(&self, launch: LaneLaunch) {
        self.send(ControlFrame::Event(ControlEvent::InputLaunchReserved(
            launch,
        )));
    }

    /// Ends the lane's connection, as a worker that has gone does.
    pub fn close(&self) {
        let _ = self.commands.send(Command::Close);
    }

    /// The binds the lane has read.
    pub fn binds(&self) -> Vec<InputLane> {
        self.log(|log| log.binds.clone())
    }

    /// Every frame the lane has read, in the order it read them.
    pub fn frames(&self) -> Vec<Written> {
        self.log(|log| log.frames.clone())
    }

    /// The bytes of every frame, joined in order.
    pub fn bytes(&self) -> Vec<u8> {
        self.log(|log| {
            log.frames
                .iter()
                .flat_map(|frame| frame.bytes.iter().copied())
                .collect()
        })
    }

    /// Whether the host ended the lane's connection.
    pub fn ended(&self) -> bool {
        self.log(|log| log.ended)
    }

    fn log<T>(&self, read: impl FnOnce(&Log) -> T) -> T {
        read(
            &self
                .shared
                .log
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }

    /// Waits until `condition` holds of the frames the lane has read.
    ///
    /// # Panics
    ///
    /// Panics when it does not hold in time.
    pub async fn until(&self, what: &str, condition: impl Fn(&[Written]) -> bool) {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            let changed = self.shared.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.log(|log| condition(&log.frames)) {
                return;
            }
            assert!(
                tokio::time::timeout_at(deadline, changed).await.is_ok(),
                "the lane never saw {what}: it has read {} frames",
                self.log(|log| log.frames.len())
            );
        }
    }

    /// Waits until the host has ended the lane's connection.
    ///
    /// # Panics
    ///
    /// Panics when it does not in time.
    pub async fn until_ended(&self) {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            let changed = self.shared.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.ended() {
                return;
            }
            assert!(
                tokio::time::timeout_at(deadline, changed).await.is_ok(),
                "the host never ended the lane"
            );
        }
    }
}

impl Drop for ScriptedLane {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn note(shared: &Shared, change: impl FnOnce(&mut Log)) {
    change(&mut shared.log.lock().unwrap_or_else(PoisonError::into_inner));
    shared.changed.notify_waiters();
}

/// Accepts the host's lane and plays it until it ends.
async fn serve(
    listener: Listener,
    shared: Arc<Shared>,
    ready: InputLaneReady,
    mut commands: mpsc::UnboundedReceiver<Command>,
) {
    let Ok((connection, _peer)) = listener.accept().await else {
        return;
    };
    play(connection, &shared, ready, &mut commands).await;
    note(&shared, |log| log.ended = true);
}

async fn play(
    connection: Connection,
    shared: &Arc<Shared>,
    ready: InputLaneReady,
    commands: &mut mpsc::UnboundedReceiver<Command>,
) {
    let (reader, writer) = split(connection, StreamKind::Control);
    let mut reader = LinkReader::over(Level::this(), reader);
    let mut writer = LinkWriter::over(Level::this(), writer);
    let Ok(ControlFrame::InputLane(bind)) = reader.read().await else {
        return;
    };
    note(shared, |log| log.binds.push(bind));
    if writer
        .write(&ControlFrame::InputLaneReady(ready))
        .await
        .is_err()
    {
        return;
    }
    // Frames read and not yet answered, in the order they came.
    let mut waiting: VecDeque<(kr_protocol::ids::RequestId, Written)> = VecDeque::new();
    let mut held = shared.held.subscribe();
    loop {
        let answerable = !waiting.is_empty() && !*held.borrow();
        tokio::select! {
            command = commands.recv() => match command {
                Some(Command::Frame(frame)) => {
                    if writer.write(&frame).await.is_err() {
                        return;
                    }
                }
                Some(Command::Close) | None => return,
            },
            frame = reader.read() => {
                let Ok(ControlFrame::ForwardedRead(forwarded)) = frame else {
                    return;
                };
                let Ok(params) = forwarded.request.params.to_typed::<InputWriteParams>() else {
                    return;
                };
                let InputContent::Bytes { bytes } = params.input else {
                    return;
                };
                let written = Written {
                    epoch: params.epoch.get(),
                    sequence: params.sequence.get(),
                    bytes: bytes.as_slice().to_vec(),
                };
                note(shared, |log| log.frames.push(written.clone()));
                waiting.push_back((forwarded.request.request_id, written));
            },
            changed = held.changed(), if !answerable => {
                if changed.is_err() {
                    return;
                }
            },
            () = std::future::ready(()), if answerable => {
                let Some((request_id, written)) = waiting.pop_front() else {
                    continue;
                };
                let behaviour = *shared
                    .behaviour
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let refused = behaviour
                    .refuse_from
                    .is_some_and(|from| written.sequence >= from);
                let outcome = if refused {
                    Outcome::Error(ProtocolError::new(
                        ErrorCode::LeaseLost,
                        "the lease of this epoch has ended",
                    ))
                } else {
                    Outcome::Ok(
                        ParamsValue::from_typed(&InputWriteResult {
                            sequence: kr_protocol::ids::InputSequence::new(written.sequence + 1),
                            forwarded_bytes: U64::new(written.bytes.len() as u64),
                            held_prefix_bytes: U64::new(0),
                        })
                        .expect("a result encodes"),
                    )
                };
                if writer
                    .write(&ControlFrame::Response(Response { request_id, outcome }))
                    .await
                    .is_err()
                {
                    return;
                }
                note(shared, |log| log.answered += 1);
                if behaviour.credit_on_answer && !refused {
                    let claim = input_claim(written.bytes.len());
                    let credit = ControlFrame::Event(ControlEvent::InputCredit(LaneCredit {
                        epoch: InputLeaseEpoch::new(written.epoch),
                        frames: claim.frames as u32,
                        bytes: U64::new(claim.bytes as u64),
                    }));
                    if writer.write(&credit).await.is_err() {
                        return;
                    }
                }
            },
        }
    }
}
