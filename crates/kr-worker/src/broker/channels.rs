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
//! 4. **Answer.** An admitted answer is written on the channel by the channel's own writer, in the
//!    order admitted. A message into the session, a steer, a cancellation and a package's action
//!    are refused: nothing establishes that the application received a message and no sender
//!    stands behind one, and the table names no method for the others.
//! 5. **Close.** However it ends (the channel closing, a frame it should not have sent, the backend
//!    retiring), it is closed through [`Broker::close_bridge_channel`], which settles what it
//!    relayed and discharges what a recovery owes for it.

use std::sync::{Arc, Mutex, Weak};

use kr_protocol::broker::{
    ActionProvenance, DecodedProjection, InstanceCapabilityIdentity, InstanceCapabilityRecord,
    InstanceCapabilityState, InstanceEvidenceSource, InstanceInvalidation,
};
use kr_protocol::gateway::{GatewayMode, PendingResource};
use kr_protocol::ids::{
    ApplicationInstanceId, CapabilityId, CapabilityRevision, EnvironmentId, GatewayConnectionId,
    PendingResourceId, SessionId,
};
use kr_protocol::scalars::{Nullable, TimestampMs};

use crate::broker::bridge::{
    AdmittedBridge, BRIDGE_FRAME_DEADLINE, BridgeProcess, BridgeReader, BridgeSurface, BridgeWriter,
};
use crate::broker::connectors::{DECISION_SCHEMA, InstalledConnector};
use crate::broker::error::{BrokerError, Result};
use crate::broker::gateway::ChannelConnection;
use crate::broker::methods::{
    PendingTransmission, UpstreamBody, UpstreamDispatch, UpstreamOutcome, UpstreamRequest,
};
use crate::broker::{Broker, BrokerState, OnStoreFault, UpstreamArrival};

/// How many admitted answers one channel holds before its writer takes them.
///
/// The application holds one approval dialog open at a time, so the bound is generous; an answer
/// past it is refused before its marker rather than queued without end.
pub const MAX_QUEUED_ANSWERS: usize = 64;

/// The capability a channel's relayed approval is evidence of.
const APPROVAL_CAPABILITY: &str = "agent.approval";

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
    } = admitted;
    if surface != BridgeSurface::Channel {
        stream.close().await;
        return ChannelEnd::Refused(BrokerError::invalid(
            "only a channel is served here; a hook is observed",
        ));
    }
    let broker = Arc::clone(&launch.broker);
    let connection = match broker.open_bridge_channel(
        launch.application_instance_id,
        &process,
        &launch.connector,
        launch.version.as_deref(),
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
    let why = tokio::select! {
        biased;
        () = until => "the launch it belongs to ended".to_owned(),
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
    if tokio::time::timeout(crate::broker::attach::TEARDOWN_DEADLINE, &mut writing)
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
                launch
                    .broker
                    .note_relayed_approval(launch.application_instance_id, now);
                // A request no binding may decode stays recorded and unanswerable here.
                let _ = launch.broker.interpret_declared(resource.resource_id, now);
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

/// One answer the channel's writer takes, and where it says what became of it.
struct Outgoing {
    frame: Vec<u8>,
    written: tokio::sync::oneshot::Sender<Result<()>>,
}

/// Writes admitted answers on the channel, one at a time, until the channel is shut.
async fn write_answers(
    broker: Arc<Broker>,
    mut writer: BridgeWriter,
    mut outgoing: tokio::sync::mpsc::Receiver<Outgoing>,
) {
    while let Some(Outgoing { frame, written }) = outgoing.recv().await {
        broker.at_channel_write_pause().await;
        let result = tokio::time::timeout(BRIDGE_FRAME_DEADLINE, writer.write_frame(&frame))
            .await
            .unwrap_or_else(|_| {
                Err(BrokerError::UpstreamUnavailable {
                    detail: format!(
                        "the channel did not take an answer within {} seconds",
                        BRIDGE_FRAME_DEADLINE.as_secs()
                    ),
                })
            });
        let failed = result.is_err();
        let _ = written.send(result);
        // A write that failed leaves the connection unusable, and the answers behind it are told.
        if failed {
            break;
        }
    }
    writer.close().await;
}

/// What carries answers out on one channel.
///
/// Only an answer to a request this channel relayed goes: the table names no way to carry
/// anything else that this host can stand behind.
#[derive(Debug)]
pub struct ChannelDispatch {
    connection: GatewayConnectionId,
    /// The writer's queue, until the channel is shut.
    queue: Mutex<Option<tokio::sync::mpsc::Sender<Outgoing>>>,
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
            UpstreamBody::Prompt { .. } => Err(BrokerError::UnsupportedCapability {
                detail: "a message into the session is not delivered on this channel: the \
                         application acknowledges nothing, so nothing establishes that it \
                         received one, and the package names no sender to stand behind it"
                    .to_owned(),
            }),
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
        self.admit(request)?;
        let UpstreamBody::Approval {
            response,
            upstream_request_id,
            ..
        } = &request.body
        else {
            return Err(BrokerError::invalid(
                "only an answer is carried on a channel",
            ));
        };
        let queue = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or_else(|| BrokerError::UpstreamUnavailable {
                detail: "the channel has closed".to_owned(),
            })?;
        let (written, outcome) = tokio::sync::oneshot::channel();
        queue
            .try_send(Outgoing {
                frame: response.frame().to_vec(),
                written,
            })
            .map_err(|_| BrokerError::UpstreamUnavailable {
                detail: "the channel's writer has closed or holds as many answers as it takes"
                    .to_owned(),
            })?;
        let upstream_request_id = upstream_request_id.clone();
        Ok(PendingTransmission::carried(async move {
            match outcome.await {
                Ok(Ok(())) => Ok(UpstreamOutcome {
                    upstream_request_id: Some(upstream_request_id),
                    turn_id: None,
                    provenance: ActionProvenance::UpstreamTypedRpc,
                }),
                Ok(Err(error)) => Err(error),
                Err(_) => Err(BrokerError::UpstreamUnavailable {
                    detail: "the channel closed before the answer was written".to_owned(),
                }),
            }
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
    pub fn open_bridge_channel(
        &self,
        application_instance_id: ApplicationInstanceId,
        bridge: &BridgeProcess,
        connector: &InstalledConnector,
        version: Option<&str>,
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
        let connection = state.mint_connection();
        state.gateway.open_channel(ChannelConnection {
            connection,
            application_instance_id,
            process: bridge.identity.clone(),
            plugin_id: connector.plugin_id(),
            table: Arc::new(table.clone()),
            offered: connector.offered_decisions(),
        });
        // A channel that begins inside a gap is carried by its own reader and writer for the
        // whole of its life, as a native connection is.
        if state.volatile.mode() != GatewayMode::Normal {
            state.continuous.insert(connection);
        }
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
        let (_, transitions) = state.arbitration.plan_reconcile(scope, &[]);
        let mut settled = 0;
        for transition in transitions {
            if state
                .commit_transition(
                    transition,
                    now,
                    crate::broker::ledger::TransitionCause::Reconciliation,
                    None,
                    OnStoreFault::CarryOn,
                )
                .is_ok()
            {
                settled += 1;
            }
        }
        state.gateway.close_channel(connection);
        state.continuous.remove(&connection);
        if state.volatile.mode() == GatewayMode::Recovering {
            let generation = state.volatile.generation();
            let _ = state
                .volatile
                .reconciled(generation, application_instance_id, connection);
        }
        state.channel_evidence(
            application_instance_id,
            Some("the application's channel closed, so nothing relays an answer to it"),
            now,
        );
        Some(settled)
    }

    /// Records that a channel relayed an approval: the application relays only to a channel it
    /// registered, so the instance's approval capability is available from a live binding.
    pub fn note_relayed_approval(
        &self,
        application_instance_id: ApplicationInstanceId,
        now: TimestampMs,
    ) {
        self.state()
            .channel_evidence(application_instance_id, None, now);
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
        let (binding_id, projection) = {
            let state = self.state();
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
            let Some(binding) = state.bindings.values().find(|binding| {
                binding.application_instance_id == pending.application_instance_id
                    && binding.plugin_id == channel.plugin_id
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
        self.interpret(binding_id, resource_id, projection, None, now)
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

impl BrokerState {
    /// Records what a channel says about the instance's approval capability: available from a
    /// live binding, or unavailable for `unavailable`'s reason once it has closed.
    ///
    /// Only a change is recorded, as the next revision of the capability's record, so a stream of
    /// relayed approvals does not move the revision a client read.
    fn channel_evidence(
        &mut self,
        application_instance_id: ApplicationInstanceId,
        unavailable: Option<&str>,
        now: TimestampMs,
    ) {
        let Ok(capability_id) = CapabilityId::new(APPROVAL_CAPABILITY) else {
            return;
        };
        let held = self
            .capabilities
            .map(application_instance_id)
            .record(&capability_id)
            .cloned();
        let usable = unavailable.is_none();
        match held.as_ref() {
            // Nothing to say an approval is unavailable about when nothing said it was available.
            None if !usable => return,
            Some(record) if record.state.is_usable() == usable => return,
            // Only the channel's own evidence is withdrawn by the channel.
            Some(record) if !usable && record.source != InstanceEvidenceSource::LiveBinding => {
                return;
            }
            _ => {}
        }
        if !self.instances.contains_key(&application_instance_id) {
            return;
        }
        let revision = held.map_or(0, |record| record.revision.get());
        let _ = self.capabilities.record(InstanceCapabilityRecord {
            capability_id,
            capability_version: "1".to_owned(),
            application_instance_id,
            identity: InstanceCapabilityIdentity::default(),
            revision: CapabilityRevision::new(revision.saturating_add(1)),
            state: if usable {
                InstanceCapabilityState::QualifiedAvailable
            } else {
                InstanceCapabilityState::TemporarilyUnavailable
            },
            source: InstanceEvidenceSource::LiveBinding,
            invalidated_by: [
                InstanceInvalidation::BinaryChanged,
                InstanceInvalidation::BindingChanged,
            ]
            .into_iter()
            .collect(),
            disabled_reason: Nullable::from(unavailable.map(str::to_owned)),
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
            turn_id: None,
            body,
        }
    }

    /// A message into the session, a steer, a cancellation and a package's action are refused on
    /// a channel, each with its own reason, and nothing is queued for any of them.
    #[test]
    fn a_message_a_steer_a_cancellation_and_an_action_are_refused_with_their_reasons() {
        let (queue, mut outgoing) = tokio::sync::mpsc::channel(MAX_QUEUED_ANSWERS);
        let channel = ChannelDispatch {
            connection: GatewayConnectionId::new(7),
            queue: Mutex::new(Some(queue)),
        };
        let refused = [
            (
                RichOperation::PromptSubmit,
                UpstreamBody::Prompt {
                    draft_id: None,
                    text: Some("hello".to_owned()),
                },
                "acknowledges nothing",
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
