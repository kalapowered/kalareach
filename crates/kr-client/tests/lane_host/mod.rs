//! The host's side of the terminal-input stream, over a real loopback connection between two endpoints.
//!
//! The client library's lane cases and the companion's terminal cases both play a host that takes
//! `terminal_input` streams, records every frame it reads and the stream's end, and writes exactly the
//! words a case tells it to: the window, an acceptance, a refusal, the launch marker, the notice that an
//! epoch ended, a reset. What a case does with the control stream is its own: it gives [`spawn_host`] the
//! function that serves it.

#![allow(dead_code, reason = "each suite uses the part of the host it needs")]

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::{Endpoint, EndpointAddr};
use kr_crypto::connect::{ChallengeLedger, PairedPeer};
use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::{StreamHeader, StreamKind};
use kr_protocol::ids::{
    BootEpoch, BuildId, ClockEpoch, DeviceId, DeviceKeyRevision, InputLeaseEpoch, InputSequence,
};
use kr_protocol::input::{InputAck, InputFrame, InputWindow};
use kr_protocol::scalars::{EndpointKey, Nullable, U64, Uuid};
use kr_transport::clock::{ContinuousClock, ManualClock};
use kr_transport::codec::{FrameReader, FrameWriter};
use kr_transport::config::EndpointConfig;
use kr_transport::handshake::{self, Admitted, HostEpochs, LocalIdentity, PairedDirectory};
use kr_transport::scheduler::SendLimits;
use kr_transport::streams::{PendingStream, StreamRegistry};
use kr_transport::window::{ActionWindowIssuer, MAX_WINDOW_VALIDITY};

/// How long a case waits for the host to see something that must happen: it fails a wait that never
/// ends, and is not a measurement.
pub const LIVENESS: Duration = Duration::from_secs(60);

/* ---------------------------------------------------------------------------------------- */
/* Two endpoints                                                                          */
/* ---------------------------------------------------------------------------------------- */

pub struct Side {
    pub identity: Arc<LocalIdentity>,
    pub endpoint: Endpoint,
    pub record: PairedPeer,
}

#[derive(Debug)]
pub struct OneDevice {
    pub endpoint_id: EndpointKey,
    pub record: PairedPeer,
}

impl PairedDirectory for OneDevice {
    fn paired_peer(&self, endpoint_id: &EndpointKey) -> Option<PairedPeer> {
        (endpoint_id == &self.endpoint_id).then_some(self.record)
    }
}

pub async fn side(device_byte: u8, listening: bool) -> Side {
    let config = EndpointConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("a loopback address")),
        ..EndpointConfig::default()
    };
    let keys = DeviceKeys::generate().expect("device keys");
    let endpoint = if listening {
        kr_transport::endpoint::bind_listener(&config, &keys.transport)
            .await
            .expect("a listening endpoint")
    } else {
        kr_transport::endpoint::bind_dialer(&config, &keys.transport)
            .await
            .expect("a dialling endpoint")
    };
    let device_id = DeviceId::new(Uuid::from_bytes([device_byte; 16]));
    let record = PairedPeer {
        device_id,
        device_key_revision: DeviceKeyRevision::new(1),
        authorisation: *keys.authorisation.public(),
        endpoint_id: *keys.transport.public(),
    };
    let identity = Arc::new(LocalIdentity::new(
        device_id,
        DeviceKeyRevision::new(1),
        *keys.transport.public(),
        keys.authorisation.clone(),
        BuildId::new("kr/0.1.0+test").expect("a build identity"),
    ));
    Side {
        identity,
        endpoint,
        record,
    }
}

pub fn direct_addr(side: &Side) -> EndpointAddr {
    let mut addr = EndpointAddr::new(side.endpoint.id());
    for socket in side.endpoint.bound_sockets() {
        addr = addr.with_ip_addr(socket);
    }
    addr
}

/* ---------------------------------------------------------------------------------------- */
/* The scripted host                                                                          */
/* ---------------------------------------------------------------------------------------- */

/// A frame the host read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeenFrame {
    pub epoch: u64,
    pub sequence: u64,
    pub bytes: Vec<u8>,
}

#[derive(Default)]
pub struct Seen {
    pub headers: Vec<StreamHeader>,
    pub frames: Vec<SeenFrame>,
    pub ended_streams: u64,
    /// Streams whose end the host read as a clean finish, not a reset.
    pub finished_streams: u64,
    /// Streams whose end the host read as a reset or a failure.
    pub reset_streams: u64,
    pub methods: Vec<String>,
}

/// What the host writes next on the stream.
pub enum Out {
    Ack(InputAck),
    /// Resets the stream, as a host does that ends it.
    Reset,
    /// Finishes the host's side of the stream, as a host does that has nothing more to say.
    Finish,
}

pub struct Script {
    pub streams: Mutex<Vec<StreamKind>>,
    pub window: Mutex<InputWindow>,
    pub seen: Mutex<Seen>,
    pub changed: tokio::sync::Notify,
    pub out: Mutex<Option<tokio::sync::mpsc::UnboundedSender<Out>>>,
    /// Frames the host writes on the control stream, as the host's own words to the connection.
    pub control_out: tokio::sync::mpsc::UnboundedSender<ControlFrame>,
    pub pending_control: Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<ControlFrame>>>,
}

impl Script {
    pub fn new(window: InputWindow, streams: Vec<StreamKind>) -> Arc<Self> {
        let (control_out, pending) = tokio::sync::mpsc::unbounded_channel();
        Arc::new(Self {
            streams: Mutex::new(streams),
            window: Mutex::new(window),
            seen: Mutex::new(Seen::default()),
            changed: tokio::sync::Notify::new(),
            out: Mutex::new(None),
            control_out,
            pending_control: Mutex::new(Some(pending)),
        })
    }

    pub fn seen<T>(&self, read: impl FnOnce(&Seen) -> T) -> T {
        read(&self.seen.lock().expect("what the host saw"))
    }

    pub fn record(&self, write: impl FnOnce(&mut Seen)) {
        write(&mut self.seen.lock().expect("what the host saw"));
        self.changed.notify_waiters();
    }

    /// Waits until what the host saw satisfies `condition`: a condition of the host's state, never
    /// of a time.
    pub async fn until(&self, what: &str, condition: impl Fn(&Seen) -> bool) {
        tokio::time::timeout(LIVENESS, self.reached(&condition))
            .await
            .unwrap_or_else(|_| panic!("the host never saw {what}"));
    }

    /// As [`Script::until`], for what the case needs within a few seconds of the step that makes it
    /// happen: a lane that does not do it fails the case here, by this assertion, and not by the
    /// liveness limit.
    pub async fn until_soon(&self, what: &str, condition: impl Fn(&Seen) -> bool) {
        let reached = tokio::time::timeout(Duration::from_secs(5), self.reached(&condition)).await;
        assert!(
            reached.is_ok(),
            "five seconds after the step, the host had still not seen {what}"
        );
    }

    pub async fn reached(&self, condition: &impl Fn(&Seen) -> bool) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.seen(condition) {
                return;
            }
            changed.await;
        }
    }

    pub fn frames(&self) -> Vec<SeenFrame> {
        self.seen(|seen| seen.frames.clone())
    }

    pub fn say(&self, out: Out) {
        self.out
            .lock()
            .expect("the stream's writer")
            .as_ref()
            .expect("a stream is open")
            .send(out)
            .expect("the stream's writer is alive");
    }

    pub fn accept(&self, epoch_number: u64, through: u64) {
        self.say(Out::Ack(InputAck::Accepted {
            epoch: epoch(epoch_number),
            through: sequence(through),
        }));
    }

    pub fn refuse(
        &self,
        epoch_number: u64,
        first: u64,
        accepted_through: Option<u64>,
        code: ErrorCode,
    ) {
        self.say(Out::Ack(InputAck::Refused {
            epoch: epoch(epoch_number),
            sequence: sequence(first),
            accepted_through: Nullable::from(accepted_through.map(sequence)),
            error: ProtocolError::new(code, "refused"),
        }));
    }

    pub fn marker(&self, launch: u32) {
        self.say(Out::Ack(InputAck::LaunchReserved { launch }));
    }

    pub fn epoch_ended(&self, epoch_number: u64, fenced_bytes: u64) {
        self.say(Out::Ack(InputAck::EpochEnded {
            epoch: epoch(epoch_number),
            fenced_bytes: U64::new(fenced_bytes),
        }));
    }
}

/// Records that the host's side of a stream has ended.
pub struct Ends(Arc<Script>);

impl Drop for Ends {
    fn drop(&mut self) {
        self.0.record(|seen| seen.ended_streams += 1);
    }
}

/// Takes one input stream: its header, the window it says, every frame read, and the words the
/// case writes.
pub async fn serve_stream(script: Arc<Script>, pending: PendingStream) {
    let Ok(stream) = pending.open(&[StreamKind::TerminalInput]).await else {
        return;
    };
    script.record(|seen| seen.headers.push(stream.header().clone()));
    let ends = Arc::new(Ends(Arc::clone(&script)));
    let (mut reader, mut writer) = stream.split();
    let handle = reader.handle();
    let (words, mut queued) = tokio::sync::mpsc::unbounded_channel();
    *script.out.lock().expect("the stream's writer") = Some(words);
    let ready = *script.window.lock().expect("the window");
    if writer
        .write_message(&InputAck::Ready { window: ready })
        .await
        .is_err()
    {
        return;
    }
    let reading = Arc::clone(&script);
    let reading_ends = Arc::clone(&ends);
    tokio::spawn(async move {
        let _ends = reading_ends;
        loop {
            match reader.read_message::<InputFrame>().await {
                Ok(Some(frame)) => reading.record(|seen| {
                    seen.frames.push(SeenFrame {
                        epoch: frame.epoch.get(),
                        sequence: frame.sequence.get(),
                        bytes: frame.bytes.into_vec(),
                    });
                }),
                Ok(None) => {
                    reading.record(|seen| seen.finished_streams += 1);
                    break;
                }
                Err(_) => {
                    reading.record(|seen| seen.reset_streams += 1);
                    break;
                }
            }
        }
    });
    while let Some(out) = queued.recv().await {
        match out {
            Out::Ack(ack) => {
                if writer.write_message(&ack).await.is_err() {
                    return;
                }
            }
            Out::Reset => {
                handle.revoke();
                return;
            }
            Out::Finish => {
                drop(writer);
                return;
            }
        }
    }
}

/// Serves connections: for each, the handshake, the input streams (until the connection ends) and, on the
/// control stream, whatever `control` does with its reader and writer.
pub fn spawn_host<F, Fut>(
    host: &Side,
    client_record: PairedPeer,
    script: Arc<Script>,
    control: F,
) -> tokio::task::JoinHandle<()>
where
    F: Fn(Arc<Script>, FrameReader, FrameWriter) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let endpoint = host.endpoint.clone();
    let identity = Arc::clone(&host.identity);
    let directory: Arc<dyn PairedDirectory> = Arc::new(OneDevice {
        endpoint_id: client_record.endpoint_id,
        record: client_record,
    });
    let control = Arc::new(control);
    tokio::spawn(async move {
        loop {
            let Some(incoming) = endpoint.accept().await else {
                return;
            };
            let Ok(connection) = incoming.await else {
                continue;
            };
            let identity = Arc::clone(&identity);
            let directory = Arc::clone(&directory);
            let script = Arc::clone(&script);
            let control = Arc::clone(&control);
            tokio::spawn(async move {
                let clock: Arc<dyn ContinuousClock> = Arc::new(ManualClock::new());
                let issuer = Arc::new(ActionWindowIssuer::new(clock, MAX_WINDOW_VALIDITY));
                let challenges = Arc::new(std::sync::Mutex::new(ChallengeLedger::with_limit(16)));
                let Ok(Admitted::Authorised(authorised)) = handshake::accept(
                    &connection,
                    &identity,
                    HostEpochs {
                        boot_epoch: BootEpoch::new(1),
                        clock_epoch: ClockEpoch::new(1),
                    },
                    directory.as_ref(),
                    &challenges,
                    &issuer,
                )
                .await
                else {
                    return;
                };
                connection.set_max_concurrent_bi_streams(iroh::endpoint::VarInt::from_u32(16));
                let streams = StreamRegistry::new(
                    authorised.connection_id,
                    Arc::new(kr_transport::scheduler::StreamBudget::new(
                        SendLimits::default(),
                    )),
                    None,
                );
                let accepting = Arc::clone(&script);
                let taken = connection.clone();
                tokio::spawn(async move {
                    while let Ok(pending) = streams.accept_pending(&taken).await {
                        tokio::spawn(serve_stream(Arc::clone(&accepting), pending));
                    }
                });
                control(script, authorised.control_reader, authorised.control_writer).await;
            });
        }
    })
}

/// The lease epoch `number`.
pub fn epoch(number: u64) -> InputLeaseEpoch {
    InputLeaseEpoch::new(number)
}

/// The input sequence `number`.
pub fn sequence(number: u64) -> InputSequence {
    InputSequence::new(number)
}
