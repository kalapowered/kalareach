//! The Channels consumer: one admitted native bridge channel, served for as long as it is open.
//!
//! Claude Code starts `kr-hook claude-code channel` as an MCP server. The forwarder terminates MCP
//! and relays only the Channels frames, one JSON line each, and the command backend admits its
//! connection like any other bridge. This serves what follows:
//!
//! 1. **Open.** The broker opens a gateway connection of the channel kind, only for the launched
//!    application's own channel: its starter is the process the launch registered, an instance has
//!    one channel open at a time, and the connector's table is qualified for the version the
//!    executable's digest selects. Anything else is closed unread, and the application's own
//!    dialog answers.
//! 2. **Read.** Every frame goes through the broker's own receipt: the table routes it, reads its
//!    identifier and records a relayed approval as a pending resource with its source frame. A
//!    frame the table does not route towards this host ends the channel: the forwarder relays only
//!    approvals it has checked, so anything else is a defect.
//! 3. **Evidence and meaning.** A relayed approval is evidence that the channel is registered with
//!    the application, which is what makes the instance's approval capability available. Where the
//!    instance holds a binding of the connector's package trusted to decode the request, the broker
//!    interprets it from the table's own decision destination; without one it stays recorded,
//!    visible and unanswerable here.
//! 4. **Answer and message.** An admitted answer is written on the channel by the channel's own
//!    writer, in the order admitted, and recorded as the response of an installed bridge: the
//!    verdict goes to the bridge's forwarder, and nothing in the application acknowledges it. A
//!    queued message into the session goes the same way, through the same writer and in the same
//!    order, in the shape the package declares for one and naming the sender the host verified;
//!    it ends as an outcome nobody can establish, because the application acknowledges no message
//!    either. A submit, a steer, a cancellation and a package's action are refused: the table
//!    names no method for them.
//! 5. **Close.** However it ends (the channel closing, a frame it should not have sent, the backend
//!    retiring), it is closed through [`Broker::close_bridge_channel`], which settles what it
//!    relayed and discharges what a recovery owes for it.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use kr_protocol::broker::{
    ActionProvenance, DecodedProjection, InstanceCapabilityIdentity, InstanceCapabilityRecord,
    InstanceCapabilityState, InstanceEvidenceSource, InstanceInvalidation, MethodTableVersionText,
};
use kr_protocol::gateway::{GatewayMode, PendingResource, RichOperation};
use kr_protocol::ids::{
    ApplicationInstanceId, CapabilityId, CapabilityRevision, EnvironmentId, GatewayConnectionId,
    PendingResourceId, PublisherId, SessionId,
};
use kr_protocol::scalars::{Nullable, TimestampMs};

use crate::broker::bridge::{
    AdmittedBridge, BRIDGE_FRAME_DEADLINE, BridgeProcess, BridgeReader, BridgeSurface, BridgeWriter,
};
use crate::broker::channel_prompt::{ChannelEventShape, NO_SENDER, PromptSender};
use crate::broker::connectors::{DECISION_SCHEMA, InstalledConnector};
use crate::broker::duplex::{Counted, detached};
use crate::broker::error::{BrokerError, Result};
use crate::broker::gateway::ChannelConnection;
use crate::broker::methods::{
    PendingTransmission, SubmitGate, UpstreamBody, UpstreamDispatch, UpstreamRequest,
};
use crate::broker::{Broker, BrokerState, UpstreamArrival};

/// What the receipt of an answer a channel took says, and so what an inspection of it reads.
///
/// It claims no write, because a failed write ends the same way: what the host can say is that
/// the channel confirms nothing.
pub const ANSWER_NOT_CONFIRMED: &str = "The host cannot tell whether Claude Code took this \
     answer. Claude Code does not confirm answers. If the request still waits in its terminal, \
     answer it there.";

/// What the receipt of a message a channel took says, and so what an inspection of it reads.
///
/// It claims no write either, for the same reason as [`ANSWER_NOT_CONFIRMED`].
pub const MESSAGE_NOT_CONFIRMED: &str = "The host cannot tell whether Claude Code took this \
     message. Claude Code does not confirm messages on this channel.";

/// How many admitted answers and messages one channel holds before its writer takes them.
///
/// The application holds one approval dialog open at a time, so the bound is generous for
/// answers; messages are held below it by [`MAX_QUEUED_PROMPTS`], so they never take the room an
/// answer needs. One past either bound is refused before its marker rather than queued without
/// end.
pub const MAX_QUEUED_ANSWERS: usize = 64;

/// How many messages one channel holds, from the queue taking one until its write is over.
pub const MAX_QUEUED_PROMPTS: usize = 8;

/// What a person is told when a message is refused for the queue's bound: nothing was sent.
const QUEUE_FULL: &str = "The message queue is full. Nothing was sent. Try again later.";

/// What a person is told when a message meets a channel that has closed: nothing was sent.
const CHANNEL_CLOSED: &str = "The channel is closed. Nothing was sent.";

/// What a person is told when a message is not the queued kind.
const QUEUE_ONLY: &str = "Use Queue to send a message through this channel.";

/// What a person is told when a message names a draft.
const TEXT_ONLY: &str = "This channel accepts text only. It cannot send a draft or attachments.";

/// Why the queue capability is unavailable once the channel has closed.
const QUEUE_CLOSED: &str = "The application's channel closed.";

/// The capability a channel's relayed approval is evidence of.
const APPROVAL_CAPABILITY: &str = "agent.approval";

/// The capability the same evidence gives a channel that carries messages.
const QUEUE_CAPABILITY: &str = "agent.prompt.queue";

/// What one channel is served with: the launch it belongs to and where its transitions go.
#[derive(Clone)]
pub struct ChannelLaunch {
    /// The broker the launched instance is registered on.
    pub broker: Arc<Broker>,
    /// The instance the channel speaks for.
    pub application_instance_id: ApplicationInstanceId,
    /// The connector the launch was established from.
    pub connector: Arc<InstalledConnector>,
    /// The version the connector's signed qualification records name for the executable's
    /// digest, where one does.
    pub version: Option<String>,
    /// The environment the session runs in.
    pub site: EnvironmentId,
    /// The operating-system user the session runs as.
    pub os_user: String,
    /// The session whose attached views the channel's transitions are delivered to, where one
    /// is watching.
    pub views: Option<(SessionId, Weak<crate::runtime::SessionRuntime>)>,
}

impl std::fmt::Debug for ChannelLaunch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ChannelLaunch")
            .field("application_instance_id", &self.application_instance_id)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// How one channel's service ended.
#[derive(Debug)]
pub enum ChannelEnd {
    /// The channel was not served, and its connection was closed unread.
    Refused(BrokerError),
    /// The channel was served on this connection until it ended.
    Ended {
        /// The connection it was served on.
        connection: GatewayConnectionId,
        /// Why it ended.
        why: String,
        /// How many of the resources it relayed were still unresolved and were settled.
        settled: usize,
    },
}

/// Serves one admitted channel until it closes, sends what it must not, or `until` completes, and
/// then closes it through the broker.
///
/// The close is this function's own last step on every path, so a channel is never left open in
/// the gateway, bound as a transport or holding resources nobody will answer. `until` is how the
/// caller ends it: the backend's retirement, which comes with the end of the instance and with
/// the session closing.
pub async fn serve(
    launch: ChannelLaunch,
    admitted: AdmittedBridge,
    until: impl std::future::Future<Output = ()> + Send,
) -> ChannelEnd {
    let AdmittedBridge {
        surface,
        process,
        mut stream,
        // A channel reports no observation, so privacy mode at its admission is not asked.
        privacy: _,
    } = admitted;
    if surface != BridgeSurface::Channel {
        stream.close().await;
        return ChannelEnd::Refused(BrokerError::invalid(
            "only a channel is served here; a hook is observed",
        ));
    }
    let broker = Arc::clone(&launch.broker);
    // Derived once, before the channel opens: a package whose declaration is not a whole shape
    // carries no message, and nothing is recorded that says it does.
    let shape = ChannelEventShape::of(&launch.connector);
    let connection = match broker.open_bridge_channel(
        launch.application_instance_id,
        &process,
        &launch.connector,
        launch.version.as_deref(),
        shape.as_ref(),
    ) {
        Ok(connection) => connection,
        Err(refusal) => {
            stream.close().await;
            return ChannelEnd::Refused(refusal);
        }
    };
    let (mut reader, writer) = stream.into_halves();
    let (queue, outgoing) = tokio::sync::mpsc::channel(MAX_QUEUED_ANSWERS);
    let channel = Arc::new(ChannelDispatch {
        connection,
        queue: Mutex::new(Some(queue)),
        counted: Counted::of_package(&broker, launch.connector.plugin_id().as_str()),
        shape: shape.map(Arc::new),
        prompts: Arc::new(AtomicUsize::new(0)),
    });
    let carrying: Arc<dyn UpstreamDispatch> = channel.clone();
    // The channel's own transport, for the answers to what it relayed, and the instance's, so a
    // message or a steer reaches the channel's refusal rather than finding no transport at all.
    broker.bind_connection_dispatch(connection, Arc::clone(&carrying));
    let _ = broker.bind_dispatch(launch.application_instance_id, carrying);
    let observatory = broker.observatory();
    let delivering = launch.views.as_ref().and_then(|(session_id, runtime)| {
        let runtime = runtime.upgrade()?;
        Some(tokio::spawn(crate::broker::attach::deliver_to_views(
            observatory.subscribe(connection),
            Arc::clone(&broker),
            *session_id,
            runtime,
        )))
    });
    let mut writing = tokio::spawn(write_answers(Arc::clone(&broker), writer, outgoing));
    // The channel ends with whichever of its three ends comes first. A writer that could not write
    // leaves a connection nothing can answer on, however long the reader stays open.
    let mut writer_ended = false;
    let why = tokio::select! {
        biased;
        () = until => "the launch it belongs to ended".to_owned(),
        stopped = &mut writing => {
            writer_ended = true;
            stopped.unwrap_or_else(|error| format!("the channel's writer stopped: {error}"))
        }
        why = read_until_ended(&launch, connection, &mut reader) => why,
    };
    let settled = broker
        .close_bridge_channel(connection, kr_ipc::now_ms())
        .unwrap_or(0);
    channel.shut();
    if delivering.is_some() {
        observatory.withdraw(connection);
    }
    // What was already queued may still go out, for as long as a connection's writes are given at
    // teardown; the resources they answer were settled as what may have happened.
    if !writer_ended
        && tokio::time::timeout(crate::broker::attach::TEARDOWN_DEADLINE, &mut writing)
            .await
            .is_err()
    {
        writing.abort();
        let _ = (&mut writing).await;
    }
    if let Some(delivering) = delivering {
        let _ = tokio::time::timeout(crate::broker::attach::TEARDOWN_DEADLINE, delivering).await;
    }
    ChannelEnd::Ended {
        connection,
        why,
        settled,
    }
}

/// Reads the channel's frames into the broker until the channel ends, and says why it did.
async fn read_until_ended(
    launch: &ChannelLaunch,
    connection: GatewayConnectionId,
    reader: &mut BridgeReader,
) -> String {
    loop {
        let frame = match reader.read_frame().await {
            Ok(Some(frame)) => frame,
            Ok(None) => return "the channel closed its connection".to_owned(),
            Err(error) => return error.to_string(),
        };
        let now = kr_ipc::now_ms();
        match launch
            .broker
            .receive_upstream(connection, &frame, launch.site, &launch.os_user, now)
        {
            Ok(UpstreamArrival::Forward {
                resource: Some(resource),
                ..
            }) => {
                launch.broker.note_relayed_approval(connection, now);
                // A request no binding may decode stays recorded and unanswerable here.
                let _ = launch.broker.interpret_request(resource.resource_id, now);
            }
            Ok(UpstreamArrival::Forward { resource: None, .. }) => {}
            Ok(UpstreamArrival::Reverse(_)) => {
                return "the channel asked this host to perform an operation, which no channel \
                        may"
                .to_owned();
            }
            Err(error) => return error.to_string(),
        }
    }
}

/// What one queued frame is, which the words of its failures say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Carried {
    /// The verdict on a request the channel relayed.
    Answer,
    /// A message into the session.
    Message,
}

impl Carried {
    /// What it is called after an article.
    const fn a_noun(self) -> &'static str {
        match self {
            Self::Answer => "an answer",
            Self::Message => "a message",
        }
    }

    /// What it is called after "the".
    const fn noun(self) -> &'static str {
        match self {
            Self::Answer => "answer",
            Self::Message => "message",
        }
    }

    /// What the receipt of one the channel took says.
    const fn not_confirmed(self) -> &'static str {
        match self {
            Self::Answer => ANSWER_NOT_CONFIRMED,
            Self::Message => MESSAGE_NOT_CONFIRMED,
        }
    }
}

/// One of the places a channel keeps for messages. It is held from the moment the queue takes a
/// message until the writer has done with it, and released when it drops.
#[derive(Debug)]
struct PromptSlot(Arc<AtomicUsize>);

impl Drop for PromptSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// One frame the channel's writer takes, and where it says what became of it.
struct Outgoing {
    frame: Vec<u8>,
    written: tokio::sync::oneshot::Sender<Result<()>>,
    carried: Carried,
    /// The message's place, kept until the write is over.
    slot: Option<PromptSlot>,
}

/// Writes admitted answers and messages on the channel, one at a time, until the channel is shut
/// or a write fails, and says which.
async fn write_answers(
    broker: Arc<Broker>,
    mut writer: BridgeWriter,
    mut outgoing: tokio::sync::mpsc::Receiver<Outgoing>,
) -> String {
    let mut why = "the channel was shut".to_owned();
    while let Some(Outgoing {
        frame,
        written,
        carried,
        slot,
    }) = outgoing.recv().await
    {
        broker.at_channel_write_pause().await;
        let result = tokio::time::timeout(BRIDGE_FRAME_DEADLINE, writer.write_frame(&frame))
            .await
            .unwrap_or_else(|_| {
                Err(BrokerError::UpstreamUnavailable {
                    detail: format!(
                        "the channel did not take {} within {} seconds",
                        carried.a_noun(),
                        BRIDGE_FRAME_DEADLINE.as_secs()
                    ),
                })
            });
        let failed = result.as_ref().err().map(|error| {
            format!(
                "the channel's writer could not write {}: {error}",
                carried.a_noun()
            )
        });
        let _ = written.send(result);
        // The message's place is kept until its write is over and its end has been said.
        drop(slot);
        // A write that failed leaves the connection unusable, and the answers behind it are told.
        if let Some(failed) = failed {
            why = failed;
            break;
        }
    }
    writer.close().await;
    why
}

/// What carries answers and messages out on one channel.
///
/// Only an answer to a request this channel relayed goes, and a queued message that the package's
/// declared shape can carry from a sender the host can name: the table names no way to carry
/// anything else that this host can stand behind.
#[derive(Debug)]
pub struct ChannelDispatch {
    connection: GatewayConnectionId,
    /// The writer's queue, until the channel is shut.
    queue: Mutex<Option<tokio::sync::mpsc::Sender<Outgoing>>>,
    /// Where the failures of the channel's adapter are counted, when its package is a bundled one.
    counted: Option<Counted>,
    /// How a message is written, where the package declares a whole shape for one.
    shape: Option<Arc<ChannelEventShape>>,
    /// How many messages the queue has taken whose writes are not over.
    prompts: Arc<AtomicUsize>,
}

impl ChannelDispatch {
    /// Takes the writer's queue away: nothing more is queued, and the writer ends once it has
    /// taken what was.
    fn shut(&self) {
        self.queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }
}

impl std::fmt::Debug for Outgoing {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Outgoing")
            .field("bytes", &self.frame.len())
            .finish_non_exhaustive()
    }
}

impl ChannelDispatch {
    /// Takes one of the places for messages, or says none is free.
    fn take_prompt_slot(&self) -> Option<PromptSlot> {
        self.prompts
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                (held < MAX_QUEUED_PROMPTS).then_some(held + 1)
            })
            .ok()
            .map(|_| PromptSlot(Arc::clone(&self.prompts)))
    }

    /// Whether this channel can carry this message at all, before anything is marked: queued, text
    /// only, from a sender the host can name, and text within the package's declared length that
    /// is neither shaped like an answer to an approval nor like the channel's own tag.
    fn admit_message(
        &self,
        operation: RichOperation,
        draft: bool,
        text: Option<&str>,
        sender: &PromptSender,
    ) -> Result<()> {
        if !matches!(operation, RichOperation::PromptQueue) {
            return Err(BrokerError::UnsupportedCapability {
                detail: QUEUE_ONLY.to_owned(),
            });
        }
        let Some(shape) = &self.shape else {
            return Err(BrokerError::UnsupportedCapability {
                detail: "the connector's table names no method on this channel that carries a \
                         message"
                    .to_owned(),
            });
        };
        if draft {
            return Err(BrokerError::UnsupportedCapability {
                detail: TEXT_ONLY.to_owned(),
            });
        }
        if sender.kind().is_none() {
            return Err(BrokerError::denied(NO_SENDER));
        }
        let text = text.ok_or_else(|| BrokerError::invalid("a message carries text"))?;
        shape.check_text(text)
    }
}

impl UpstreamDispatch for ChannelDispatch {
    fn admit(&self, request: &UpstreamRequest) -> Result<()> {
        match &request.body {
            UpstreamBody::Approval { response, .. } => {
                if response.request().connection == self.connection {
                    Ok(())
                } else {
                    Err(BrokerError::denied(format!(
                        "this answer resolves a request of {}, and this channel is {}",
                        response.request().connection,
                        self.connection
                    )))
                }
            }
            UpstreamBody::Prompt {
                draft_id,
                text,
                sender,
            } => self.admit_message(
                request.operation,
                draft_id.is_some(),
                text.as_deref(),
                sender,
            ),
            UpstreamBody::Steer { .. } => Err(BrokerError::UnsupportedCapability {
                detail: "the connector's table names no method on this channel that steers a turn"
                    .to_owned(),
            }),
            UpstreamBody::Cancel => Err(BrokerError::UnsupportedCapability {
                detail: "the connector's table names no method on this channel that cancels a \
                         turn"
                    .to_owned(),
            }),
            UpstreamBody::PluginAction { .. } => Err(BrokerError::UnsupportedCapability {
                detail: "a package's action is not carried on this channel; an answer to a \
                         relayed approval goes as an answer"
                    .to_owned(),
            }),
        }
    }

    fn submit(&self, request: &UpstreamRequest) -> Result<PendingTransmission> {
        self.submit_gated(request, &SubmitGate::default())
    }

    fn provenance(&self) -> ActionProvenance {
        // What a channel carries is written on the application's own channel, and recorded as a
        // bridge's response, whatever the application does with it.
        ActionProvenance::AuthenticatedHookResponse
    }

    fn submit_gated(
        &self,
        request: &UpstreamRequest,
        gate: &SubmitGate,
    ) -> Result<PendingTransmission> {
        self.admit(request)?;
        let count = |refusal: BrokerError| {
            if let Some(counted) = &self.counted {
                counted.refused(&refusal);
            }
            refusal
        };
        let (frame, carried) = match &request.body {
            UpstreamBody::Approval { response, .. } => (response.frame().to_vec(), Carried::Answer),
            UpstreamBody::Prompt { text, sender, .. } => {
                let (Some(shape), Some(text)) = (&self.shape, text) else {
                    return Err(BrokerError::invalid(
                        "only an answer or a message is carried on a channel",
                    ));
                };
                (shape.frame(text, sender)?, Carried::Message)
            }
            _ => {
                return Err(BrokerError::invalid(
                    "only an answer or a message is carried on a channel",
                ));
            }
        };
        // Every refusal below comes before a byte enters the queue: nothing was sent, which is
        // established and not uncertain.
        let queue = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or_else(|| {
                BrokerError::NotTransmitted(Box::new(count(BrokerError::UpstreamUnavailable {
                    detail: match carried {
                        Carried::Answer => "the channel has closed".to_owned(),
                        Carried::Message => CHANNEL_CLOSED.to_owned(),
                    },
                })))
            })?;
        // The bound on messages is this channel's own and not a failure of the application's
        // adapter, so its refusal is not counted.
        let slot = match carried {
            Carried::Answer => None,
            Carried::Message => Some(self.take_prompt_slot().ok_or_else(|| {
                BrokerError::NotTransmitted(Box::new(BrokerError::UpstreamUnavailable {
                    detail: QUEUE_FULL.to_owned(),
                }))
            })?),
        };
        let (written, outcome) = tokio::sync::oneshot::channel();
        // Through the gate: the caller that stops waiting for this call decides under the same
        // lock, so a queue that took the frame is a fact it reads, and one that has not taken it
        // by then never does.
        gate.queue(carried.not_confirmed(), carried.noun(), || {
            queue
                .try_send(Outgoing {
                    frame,
                    written,
                    carried,
                    slot,
                })
                .map_err(|error| {
                    let detail = match (carried, &error) {
                        (Carried::Answer, _) => "the channel's writer has closed or holds as many \
                                                 answers as it takes"
                            .to_owned(),
                        (Carried::Message, tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            QUEUE_FULL.to_owned()
                        }
                        (Carried::Message, tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            CHANNEL_CLOSED.to_owned()
                        }
                    };
                    BrokerError::NotTransmitted(Box::new(count(BrokerError::UpstreamUnavailable {
                        detail,
                    })))
                })
        })?;
        let counted = self.counted.clone();
        // On a task of its own: the writer's verdict on the answer is counted whether or not the
        // caller is still waiting for it.
        //
        // Every end past the queue is a channel end. A completed write is the host's own fact and
        // not the application's acknowledgement, which a channel never gives, so it ends unknown;
        // a failed write, or a channel that closed first, ends the same way, because the frame may
        // have gone in part. The worker's own bound on the wait ends the same way: a frame the
        // queue took, whether or not this call has returned and whether or not the writer has
        // reached it, is still a channel's, and the caller is not told it was a typed upstream
        // that never answered. The gate holds that fact.
        Ok(detached(async move {
            let refusal = match outcome.await {
                Ok(Ok(())) => {
                    return Err(BrokerError::ChannelEnd {
                        detail: carried.not_confirmed().to_owned(),
                    });
                }
                Ok(Err(error)) => error,
                Err(_) => BrokerError::UpstreamUnavailable {
                    detail: format!(
                        "the channel closed before the {} was written",
                        carried.noun()
                    ),
                },
            };
            if let Some(counted) = &counted {
                counted.refused(&refusal);
            }
            Err(BrokerError::ChannelEnd {
                detail: refusal.to_string(),
            })
        }))
    }
}

/// The two ends of one armed pause before a channel's write: what says the writer arrived there,
/// and what lets it go on.
#[cfg(feature = "testing")]
pub(crate) type WritePause = (
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::oneshot::Receiver<()>,
);

impl Broker {
    /// Opens the gateway connection one admitted channel is served on.
    ///
    /// Only the launched application's own channel is served: the kernel's parent of the channel,
    /// start-checked, is the process the launch registered, so a program the application runs,
    /// which inherits its variables and starts a channel of its own, is not taken for it. An
    /// instance has one channel open at a time. The connector's table is served only for a version
    /// it is qualified for, and the version is the one a signed record names for the executable's
    /// digest; an executable no record names has no version, and its channel is not served.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] for an instance this broker does not hold,
    /// [`BrokerError::PermissionDenied`] for an instance this host did not launch, a channel
    /// another process started, or a second channel; and
    /// [`BrokerError::UnsupportedCapability`] for a version the table is not qualified for.
    ///
    /// `shape` is the shape of a message the connector's package declares, when it declares a
    /// whole one: the channel carries messages only then.
    pub fn open_bridge_channel(
        &self,
        application_instance_id: ApplicationInstanceId,
        bridge: &BridgeProcess,
        connector: &InstalledConnector,
        version: Option<&str>,
        shape: Option<&ChannelEventShape>,
    ) -> Result<GatewayConnectionId> {
        let mut state = self.state();
        let instance = state
            .instances
            .get(&application_instance_id)
            .ok_or_else(|| crate::broker::unknown_instance(application_instance_id))?;
        let launched = instance
            .process
            .as_ref()
            .map(|launched| &launched.process)
            .ok_or_else(|| {
                BrokerError::denied(
                    "this host launched nothing for this instance, so no channel speaks for it",
                )
            })?;
        if bridge.starter.as_ref() != Some(launched) {
            return Err(BrokerError::denied(format!(
                "this channel was started by another process than the application this host \
                 launched as process {}; a program the application runs starts a channel of its \
                 own, which does not speak for this instance",
                launched.pid
            )));
        }
        if let Some(open) = state.gateway.channel_of(application_instance_id) {
            return Err(BrokerError::denied(format!(
                "{application_instance_id} already has its channel open on {open}, and an \
                 instance has one"
            )));
        }
        let table = connector.table();
        let version = version.ok_or_else(|| BrokerError::UnsupportedCapability {
            detail: "no signed qualification record names the executable running, so its \
                     version is unknown and the connector's table is not qualified against it"
                .to_owned(),
        })?;
        let qualified = kr_plugin_sdk::version::PackageVersion::parse(version)
            .is_ok_and(|version| table.protocol.qualified_range.admits(&version));
        if !qualified {
            return Err(BrokerError::UnsupportedCapability {
                detail: format!(
                    "the connector's table is not qualified for version {version} of {}",
                    table.protocol.name
                ),
            });
        }
        let publisher_id = PublisherId::new(connector.manifest().publisher_id.as_str())
            .map_err(|error| BrokerError::invalid(format!("the package's publisher: {error}")))?;
        let connection = state.mint_connection();
        state.gateway.open_channel(ChannelConnection {
            connection,
            application_instance_id,
            process: bridge.identity.clone(),
            plugin_id: connector.plugin_id(),
            publisher_id,
            package_digest: connector.package_digest(),
            version: version.to_owned(),
            table: Arc::new(table.clone()),
            offered: connector.offered_decisions(),
            carries_messages: shape.is_some(),
        });
        Ok(connection)
    }

    /// Closes one channel, the one way a channel ends, whatever mode the broker is in.
    ///
    /// Under one lock: the channel stops carrying answers (as its connection's transport and as
    /// its instance's); every resource it relayed that is still unresolved is settled as what has
    /// already happened, which is cancelled for one no answer went for, because a closed channel
    /// can answer nothing, and uncertain for one an answer went for; the connection is closed;
    /// and a recovery that owed this channel a reconciliation is told it has none to wait for.
    /// A settlement the store cannot record is kept as a transition of the gap, as native
    /// traffic's is, so a fenced broker closes a channel too. The instance's approval capability
    /// stops being available, because nothing relays an answer to it now.
    ///
    /// Returns how many resources were settled, or `None` when no such channel was open.
    pub fn close_bridge_channel(
        &self,
        connection: GatewayConnectionId,
        now: TimestampMs,
    ) -> Option<usize> {
        let mut state = self.state();
        let application_instance_id = state.gateway.channel(connection)?.application_instance_id;
        if let Some(dispatch) = state.connection_dispatch.remove(&connection)
            && let Some(instance) = state.instances.get_mut(&application_instance_id)
            && instance
                .dispatch
                .as_ref()
                .is_some_and(|held| Arc::ptr_eq(held, &dispatch))
        {
            instance.dispatch = None;
        }
        // Settled while the channel is still an observer of its instance, so its own subscription
        // is told, before the connection goes.
        let scope = crate::broker::arbitration::ReconcileScope {
            application_instance_id,
            connection,
        };
        let (settled, complete) = state.settle_ended(scope, now);
        state.gateway.close_channel(connection);
        // What it settled, here or before, is final now that nothing can name it on the channel.
        state.forget_resolved();
        if complete.is_ok() && state.volatile.mode() == GatewayMode::Recovering {
            state
                .volatile
                .reconciled(application_instance_id, connection);
        }
        for (capability, reason) in [
            (
                APPROVAL_CAPABILITY,
                "the application's channel closed, so nothing relays an answer to it",
            ),
            (QUEUE_CAPABILITY, QUEUE_CLOSED),
        ] {
            state.channel_evidence(
                application_instance_id,
                capability,
                Evidence::Withdrawn(reason),
                now,
            );
        }
        Some(settled)
    }

    /// Records that a channel relayed an approval: the application relays only to a channel it
    /// registered, so the instance's approval capability is available from a live binding, and so
    /// is its queue capability when the channel's package declares a shape for a message.
    ///
    /// The record names what established it: the executable the launch hashed, the version a
    /// signed record names for it, the connector package by its identifier, hash and publisher,
    /// and the launch profile.
    pub fn note_relayed_approval(&self, connection: GatewayConnectionId, now: TimestampMs) {
        let mut state = self.state();
        let Some(channel) = state.gateway.channel(connection) else {
            return;
        };
        let application_instance_id = channel.application_instance_id;
        let carries_messages = channel.carries_messages;
        let mut identity = InstanceCapabilityIdentity {
            schema_version: Nullable::some(MethodTableVersionText(channel.version.clone())),
            plugin_id: Nullable::some(channel.plugin_id.clone()),
            package_digest: Nullable::some(channel.package_digest),
            publisher_id: Nullable::some(channel.publisher_id.clone()),
            ..InstanceCapabilityIdentity::default()
        };
        if let Some(instance) = state.instances.get(&application_instance_id) {
            identity.binary_digest = Nullable::from(
                instance
                    .process
                    .as_ref()
                    .map(|launched| launched.handle.executable_digest),
            );
            identity.profile_id = Nullable::from(instance.profile_id.clone());
        }
        if carries_messages {
            state.channel_evidence(
                application_instance_id,
                QUEUE_CAPABILITY,
                Evidence::Available(Box::new(identity.clone())),
                now,
            );
        }
        state.channel_evidence(
            application_instance_id,
            APPROVAL_CAPABILITY,
            Evidence::Available(Box::new(identity)),
            now,
        );
    }

    /// Interprets one resource a channel relayed, from the connector table's own decision
    /// destination, where the instance holds a binding of that package trusted to decode it.
    ///
    /// The projection is the table's: schema [`DECISION_SCHEMA`], the decisions the destination
    /// maps in the table's order, labelled as the package's answer action labels them, and no
    /// summary (the table declares none; a view shows the source frame). It goes through
    /// [`Broker::interpret`]'s own checks. Returns `None` where no binding may decode it: the
    /// resource then stays recorded, visible and unanswerable here, and the application's own
    /// dialog answers.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UnknownSubject`] for a resource this broker does not hold,
    /// [`BrokerError::InvalidArgument`] for one no channel relayed, and whatever
    /// [`Broker::interpret`] refuses.
    pub fn interpret_declared(
        &self,
        resource_id: PendingResourceId,
        now: TimestampMs,
    ) -> Result<Option<PendingResource>> {
        // One lock for the choice of decoder and the interpretation it commits, so the binding
        // chosen for this channel's package is the one whose trust the interpretation records.
        let mut state = self.state();
        let (binding_id, projection) = {
            let pending = state
                .arbitration
                .get(resource_id)
                .ok_or_else(|| BrokerError::unknown(format!("no pending resource {resource_id}")))?
                .resource
                .clone();
            let channel = state
                .gateway
                .channel(pending.request.connection)
                .ok_or_else(|| {
                    BrokerError::invalid(format!(
                        "{resource_id} was not relayed by a channel, so no table of a channel \
                         gives it a meaning"
                    ))
                })?;
            // A binding of exactly the package whose table the channel reads: the same identifier
            // at other bytes or from another publisher is another decoder, whose meaning this
            // table's answer would not carry.
            let Some(binding) = state.bindings.values().find(|binding| {
                binding.application_instance_id == pending.application_instance_id
                    && binding.plugin_id == channel.plugin_id
                    && binding.publisher_id == channel.publisher_id
                    && binding.package_digest == channel.package_digest
                    && binding.may_decode(&pending.method)
            }) else {
                return Ok(None);
            };
            (
                binding.binding_id,
                DecodedProjection {
                    schema_version: DECISION_SCHEMA.to_owned(),
                    summary: String::new(),
                    decisions: channel.offered.clone(),
                },
            )
        };
        state
            .interpret_in(binding_id, resource_id, projection, None, now)
            .map(Some)
    }

    /// Stops the next answer a channel writes before it is written, for this host's own tests.
    ///
    /// Returns the end that says the writer has arrived there and the end that lets it go on;
    /// dropping that end lets it go on too. It is compiled away in every shipped build.
    #[cfg(feature = "testing")]
    pub fn pause_before_channel_write(
        &self,
    ) -> (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (arrived, watch) = tokio::sync::oneshot::channel();
        let (release, go) = tokio::sync::oneshot::channel();
        *self
            .channel_write_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((arrived, go));
        (watch, release)
    }

    /// Waits at an armed pause before a channel's write, for this host's own tests.
    #[cfg(feature = "testing")]
    async fn at_channel_write_pause(&self) {
        let armed = self
            .channel_write_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some((arrived, go)) = armed {
            let _ = arrived.send(());
            let _ = go.await;
        }
    }

    /// No pause is ever armed in a shipped build.
    #[cfg(not(feature = "testing"))]
    #[allow(clippy::unused_async)]
    async fn at_channel_write_pause(&self) {}
}

/// What a channel says about one of its instance's capabilities.
enum Evidence<'a> {
    /// Available from the live channel, established by this identity.
    Available(Box<InstanceCapabilityIdentity>),
    /// Unavailable, for this reason, since the channel closed.
    Withdrawn(&'a str),
}

impl BrokerState {
    /// Records what a channel says about one capability of the instance.
    ///
    /// Only a change is recorded, as the next revision of the capability's record, so a stream of
    /// relayed approvals does not move the revision a client read. A withdrawal keeps the identity
    /// the evidence was established by.
    fn channel_evidence(
        &mut self,
        application_instance_id: ApplicationInstanceId,
        capability: &str,
        evidence: Evidence<'_>,
        now: TimestampMs,
    ) {
        let Ok(capability_id) = CapabilityId::new(capability) else {
            return;
        };
        let held = self
            .capabilities
            .map(application_instance_id)
            .record(&capability_id)
            .cloned();
        let (state, identity, reason) = match evidence {
            Evidence::Available(identity) => {
                if held.as_ref().is_some_and(|record| record.state.is_usable()) {
                    return;
                }
                (InstanceCapabilityState::QualifiedAvailable, *identity, None)
            }
            Evidence::Withdrawn(reason) => {
                // Only the channel's own evidence is withdrawn by the channel, and there is nothing
                // to withdraw where nothing said the capability was available.
                let Some(record) = held.as_ref().filter(|record| {
                    record.state.is_usable() && record.source == InstanceEvidenceSource::LiveBinding
                }) else {
                    return;
                };
                (
                    InstanceCapabilityState::TemporarilyUnavailable,
                    record.identity.clone(),
                    Some(reason.to_owned()),
                )
            }
        };
        if !self.instances.contains_key(&application_instance_id) {
            return;
        }
        let revision = held.map_or(0, |record| record.revision.get());
        let _ = self.capabilities.record(InstanceCapabilityRecord {
            capability_id,
            capability_version: "1".to_owned(),
            application_instance_id,
            identity,
            revision: CapabilityRevision::new(revision.saturating_add(1)),
            state,
            source: InstanceEvidenceSource::LiveBinding,
            invalidated_by: [
                InstanceInvalidation::BinaryChanged,
                InstanceInvalidation::BindingChanged,
            ]
            .into_iter()
            .collect(),
            disabled_reason: Nullable::from(reason),
            observed_at: now,
        });
    }
}

#[cfg(test)]
mod tests {
    use kr_protocol::broker::ActionName;
    use kr_protocol::error::ErrorCode;
    use kr_protocol::gateway::RichOperation;
    use kr_protocol::ids::{AgentBindingRevision, PluginId};
    use kr_protocol::scalars::Uuid;

    use super::*;
    use crate::broker::methods::Admitted;

    fn request(operation: RichOperation, body: UpstreamBody) -> UpstreamRequest {
        UpstreamRequest {
            admitted: Admitted::new(),
            application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([2; 16])),
            binding_revision: AgentBindingRevision::new(1),
            operation,
            thread_id: None,
            turn_id: None,
            body,
        }
    }

    /// A submit into the session, a steer, a cancellation and a package's action are refused on
    /// a channel, each with its own reason, and nothing is queued for any of them.
    #[test]
    fn a_submit_a_steer_a_cancellation_and_an_action_are_refused_with_their_reasons() {
        let (queue, mut outgoing) = tokio::sync::mpsc::channel(MAX_QUEUED_ANSWERS);
        let channel = ChannelDispatch {
            connection: GatewayConnectionId::new(7),
            queue: Mutex::new(Some(queue)),
            counted: None,
            shape: None,
            prompts: Arc::new(AtomicUsize::new(0)),
        };
        let refused = [
            (
                RichOperation::PromptSubmit,
                UpstreamBody::Prompt {
                    draft_id: None,
                    text: Some("hello".to_owned()),
                    sender: crate::broker::channel_prompt::PromptSender {
                        actor_id: kr_protocol::ids::ActorId::new("local:the-owner")
                            .expect("an actor"),
                        ingress: kr_protocol::actor::ActorIngress::LocalIpc,
                        device_id: None,
                        grant_id: None,
                    },
                },
                "Use Queue to send a message through this channel.",
            ),
            (
                RichOperation::TurnSteer,
                UpstreamBody::Steer {
                    text: "shorter".to_owned(),
                },
                "steers a turn",
            ),
            (
                RichOperation::TurnCancel,
                UpstreamBody::Cancel,
                "cancels a turn",
            ),
            (
                RichOperation::PluginAction,
                UpstreamBody::PluginAction {
                    plugin_id: PluginId::new("kalareach/claude-code").expect("valid"),
                    action: ActionName::new("prompt.send").expect("valid"),
                    draft_id: None,
                    draft_revision: None,
                    attachment: None,
                    parameters: Vec::new(),
                    operation: None,
                    token: None,
                },
                "a package's action",
            ),
        ];
        for (operation, body, reason) in refused {
            let admitted = channel.admit(&request(operation, body.clone()));
            let refusal = admitted.expect_err("refused");
            assert_eq!(refusal.code(), ErrorCode::UnsupportedCapability);
            assert!(refusal.to_string().contains(reason), "{refusal}");
            assert!(
                channel.submit(&request(operation, body)).is_err(),
                "and not submitted either"
            );
        }
        assert!(outgoing.try_recv().is_err(), "nothing was queued");
    }
}
