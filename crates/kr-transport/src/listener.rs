//! One call that puts a host on the network.
//!
//! The controller's integration with this crate is [`register`] and nothing else. It hands over a
//! configuration, its transport identity and one implementation of [`HostHandler`], and gets back
//! a [`NetworkListener`] it can shut down. Everything between an incoming QUIC connection and an
//! authorised control stream happens here: the handshake, the pre-authorisation surface, the
//! keepalive, the action-window renewal, and the revocation that follows a lost control stream.
//!
//! Keeping that in one call is deliberate. The rules a connection has to obey are not the kind of
//! thing a host should be able to get subtly wrong by wiring the pieces itself.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use iroh::Endpoint;
use iroh::endpoint::Connection;
use kr_crypto::connect::ChallengeLedger;
use kr_crypto::keys::TransportIdentityKeyPair;
use kr_protocol::envelope::{ControlEvent, ControlFrame};
use kr_protocol::hello::{ActionWindow, ClientOffer, HostSelection};
use kr_protocol::ids::{ActorId, ConnectionId, ControllerGeneration, DeviceId};
use kr_protocol::scalars::{Digest256, EndpointKey, to_base64url};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::actor::ConnectionActor;
use crate::clock::{ContinuousClock, SystemContinuousClock};
use crate::codec::{FrameReader, FrameWriter};
use crate::config::EndpointConfig;
use crate::endpoint::{KEEPALIVE, bind_listener};
use crate::error::{Result, TransportError};
use crate::handshake::{Admitted, HostEpochs, LocalIdentity, PairedDirectory};
use crate::preauth::{PairingSurface, PreAuthLimits};
use crate::scheduler::{BulkLimits, StreamBudget};
use crate::streams::{RevocationHook, StreamRegistry};
use crate::window::{ActionWindowIssuer, MAX_WINDOW_VALIDITY};

/// A boxed future, so [`HostHandler`] stays usable behind a trait object.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// How many connection challenges a host will hold at once.
///
/// A challenge is outstanding only between `hello` and the proof, so this bounds concurrent
/// half-finished handshakes rather than connections. A full ledger is answered by ending idle
/// connections, not by forgetting a challenge.
pub const DEFAULT_MAX_OUTSTANDING_CHALLENGES: usize = 1024;

/// Everything the listener needs beyond the host's own implementation.
#[derive(Debug)]
pub struct ListenerConfig {
    /// The endpoint's selected network services.
    pub endpoint: EndpointConfig,
    /// The host's boot and clock epochs.
    pub epochs: HostEpochs,
    /// The controller generation admitting connections. A replacement generation rebinds every
    /// connection, because an envelope records the generation that admitted it.
    pub controller_generation: ControllerGeneration,
    /// The bulk-stream limits each connection is held to.
    pub bulk_limits: BulkLimits,
    /// What an unpaired connection may do.
    pub preauth_limits: PreAuthLimits,
    /// How long an action window lasts, capped at five minutes.
    pub action_window_validity: Duration,
    /// How many half-finished handshakes may be outstanding.
    pub max_outstanding_challenges: usize,
    /// How often the host sends a control-stream keepalive.
    pub keepalive: Duration,
    /// How long a connection has to finish its handshake and its pairing exchange.
    pub handshake_deadline: Duration,
    /// How many connections may be mid-handshake or unpaired at once, across the whole host.
    pub max_unauthorised_connections: usize,
}

impl ListenerConfig {
    /// Builds a configuration with the specified defaults.
    #[must_use]
    pub fn new(
        endpoint: EndpointConfig,
        epochs: HostEpochs,
        controller_generation: ControllerGeneration,
    ) -> Self {
        Self {
            endpoint,
            epochs,
            controller_generation,
            bulk_limits: BulkLimits::default(),
            preauth_limits: PreAuthLimits::default(),
            action_window_validity: MAX_WINDOW_VALIDITY,
            max_outstanding_challenges: DEFAULT_MAX_OUTSTANDING_CHALLENGES,
            keepalive: KEEPALIVE,
            handshake_deadline: DEFAULT_HANDSHAKE_DEADLINE,
            max_unauthorised_connections: DEFAULT_MAX_UNAUTHORISED_CONNECTIONS,
        }
    }
}

/// How long an unauthorised connection may stay open.
///
/// A handshake is four frames and a pairing exchange is a handful more, so a minute is generous.
/// The deadline exists because QUIC keepalives would otherwise hold an incomplete handshake open
/// indefinitely, and an incomplete handshake costs the host a task and an admission slot.
pub const DEFAULT_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(60);

/// How many connections may be mid-handshake or unpaired at once.
///
/// A configurable resource limit. It bounds what an endpoint can cost the host before it has proved
/// anything, which is what a per-connection budget alone cannot do: reconnecting resets a
/// per-connection budget, and this does not.
pub const DEFAULT_MAX_UNAUTHORISED_CONNECTIONS: usize = 64;

/// What the host supplies.
///
/// One trait rather than several, because a host that can answer one of these questions can answer
/// all of them, and a listener that took four separate objects would let a caller pair them wrongly.
pub trait HostHandler: PairedDirectory + Send + Sync + 'static {
    /// Returns the principal this device acts under on this host.
    ///
    /// The host assigns it; nothing on the connection can claim one. A device principal is stable
    /// for the device, which is what makes `(actor_id, action_id)` a de-duplication key.
    fn principal_for(&self, device_id: &DeviceId) -> ActorId;

    /// Returns the pairing implementation, when the host is accepting pairing.
    ///
    /// A host that returns `None` refuses unpaired connections outright, which is what a host with
    /// no outstanding invitation does.
    fn pairing_surface(&self) -> Option<Arc<dyn PairingSurface>>;

    /// Serves one authorised connection until it ends.
    ///
    /// The listener has already proved both authorisation keys, allocated the connection identity,
    /// issued the first action window and started the keepalive. What is left is the host's own:
    /// reading requests, checking authority and answering.
    fn serve(self: Arc<Self>, session: AuthorisedSession) -> BoxFuture<'static, ()>;

    /// Called when a connection's control stream ends.
    ///
    /// Section 23: closing or failing the control stream revokes every associated data stream and
    /// stops remote lease renewal. The data streams are revoked by the listener before this runs;
    /// stopping renewal is the host's half, because the host owns the leases.
    fn control_stream_lost(&self, _connection_id: ConnectionId) {}
}

/// The control stream of an authorised connection.
///
/// The writer is shared, because the keepalive and the window renewal send on the same stream the
/// host answers requests on. The reader is not: exactly one task reads a stream.
#[derive(Debug)]
pub struct ControlChannel {
    writer: Arc<Mutex<FrameWriter>>,
    reader: FrameReader,
}

impl ControlChannel {
    /// Sends one control frame.
    ///
    /// # Errors
    ///
    /// Returns a framing error when the frame exceeds the control bound, and a stream error when
    /// the stream has ended.
    pub async fn send(&self, frame: &ControlFrame) -> Result<()> {
        self.writer.lock().await.write_message(frame).await
    }

    /// Reads the next control frame, or `None` when the peer ended the stream.
    ///
    /// # Errors
    ///
    /// Returns a framing error when the frame is refused.
    pub async fn recv(&mut self) -> Result<Option<ControlFrame>> {
        self.reader.read_message().await
    }

    /// Returns a handle that can send without holding the channel.
    #[must_use]
    pub fn sender(&self) -> ControlSender {
        ControlSender {
            writer: Arc::clone(&self.writer),
        }
    }
}

/// A send-only handle on a control stream.
#[derive(Clone, Debug)]
pub struct ControlSender {
    writer: Arc<Mutex<FrameWriter>>,
}

impl ControlSender {
    /// Sends one control frame.
    ///
    /// # Errors
    ///
    /// As [`ControlChannel::send`].
    pub async fn send(&self, frame: &ControlFrame) -> Result<()> {
        self.writer.lock().await.write_message(frame).await
    }
}

/// One authorised connection, handed to the host.
#[derive(Debug)]
pub struct AuthorisedSession {
    /// The underlying iroh connection, for opening and accepting data streams.
    pub connection: Connection,
    /// The connection identity the host allocated.
    pub connection_id: ConnectionId,
    /// The peer's device identity.
    pub peer_device_id: DeviceId,
    /// The peer's endpoint identity, as authenticated by iroh.
    pub peer_endpoint_id: EndpointKey,
    /// The digest of the transcript both sides signed.
    pub transcript_digest: Digest256,
    /// The offer, as signed.
    pub offer: ClientOffer,
    /// The selection, as signed.
    pub selection: HostSelection,
    /// The actor every request on this connection is attributed to.
    pub actor: ConnectionActor,
    /// The control stream.
    pub control: ControlChannel,
    /// Every data stream of this connection.
    pub streams: Arc<StreamRegistry>,
    /// The host's action windows.
    pub windows: Arc<ActionWindowIssuer>,
    /// The window this connection started with.
    pub action_window: ActionWindow,
    /// The host's continuous clock.
    pub clock: Arc<dyn ContinuousClock>,
}

/// A running listener.
#[derive(Debug)]
pub struct NetworkListener {
    endpoint: Endpoint,
    accept_loop: JoinHandle<()>,
    windows: Arc<ActionWindowIssuer>,
}

impl NetworkListener {
    /// Returns the endpoint, for its identity and its addresses.
    #[must_use]
    pub const fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Returns this host's endpoint identity.
    #[must_use]
    pub fn endpoint_id(&self) -> EndpointKey {
        EndpointKey::from_bytes(*self.endpoint.id().as_bytes())
    }

    /// Returns the action-window issuer, so the host can validate a window a request names.
    #[must_use]
    pub fn windows(&self) -> &Arc<ActionWindowIssuer> {
        &self.windows
    }

    /// Stops accepting and closes the endpoint.
    pub async fn shutdown(self) {
        self.accept_loop.abort();
        self.endpoint.close().await;
    }
}

/// Puts a host on the network.
///
/// # Errors
///
/// Returns a configuration or bind failure. Once it returns, the listener is accepting.
pub async fn register<H: HostHandler>(
    config: ListenerConfig,
    identity: Arc<LocalIdentity>,
    transport_key: &TransportIdentityKeyPair,
    handler: Arc<H>,
) -> Result<NetworkListener> {
    let clock: Arc<dyn ContinuousClock> = Arc::new(SystemContinuousClock::new());
    register_with_clock(config, identity, transport_key, handler, clock).await
}

/// Puts a host on the network against a caller-supplied clock.
///
/// A host that owns a qualified platform time adapter passes it here rather than accepting the
/// default clock.
///
/// # Errors
///
/// As [`register`].
pub async fn register_with_clock<H: HostHandler>(
    config: ListenerConfig,
    identity: Arc<LocalIdentity>,
    transport_key: &TransportIdentityKeyPair,
    handler: Arc<H>,
    clock: Arc<dyn ContinuousClock>,
) -> Result<NetworkListener> {
    let endpoint = bind_listener(&config.endpoint, transport_key).await?;
    let windows = Arc::new(ActionWindowIssuer::new(
        Arc::clone(&clock),
        config.action_window_validity,
    ));
    let challenges = Arc::new(std::sync::Mutex::new(ChallengeLedger::with_limit(
        config.max_outstanding_challenges,
    )));

    let admission = Arc::new(tokio::sync::Semaphore::new(
        config.max_unauthorised_connections.max(1),
    ));
    let accept_loop = tokio::spawn(accept_loop(AcceptLoop {
        endpoint: endpoint.clone(),
        config: Arc::new(config),
        identity,
        handler,
        clock,
        windows: Arc::clone(&windows),
        challenges,
        admission,
    }));

    Ok(NetworkListener {
        endpoint,
        accept_loop,
        windows,
    })
}

struct AcceptLoop<H: HostHandler> {
    endpoint: Endpoint,
    config: Arc<ListenerConfig>,
    identity: Arc<LocalIdentity>,
    handler: Arc<H>,
    clock: Arc<dyn ContinuousClock>,
    windows: Arc<ActionWindowIssuer>,
    challenges: Arc<std::sync::Mutex<ChallengeLedger>>,
    /// How many connections may be mid-handshake or unpaired at once, across the whole host.
    admission: Arc<tokio::sync::Semaphore>,
}

impl<H: HostHandler> AcceptLoop<H> {
    fn clone_state(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            config: Arc::clone(&self.config),
            identity: Arc::clone(&self.identity),
            handler: Arc::clone(&self.handler),
            clock: Arc::clone(&self.clock),
            windows: Arc::clone(&self.windows),
            challenges: Arc::clone(&self.challenges),
            admission: Arc::clone(&self.admission),
        }
    }
}

async fn accept_loop<H: HostHandler>(loop_state: AcceptLoop<H>) {
    while let Some(incoming) = loop_state.endpoint.accept().await {
        // An unauthorised connection holds one admission slot from the moment it is accepted until
        // it is either authorised or gone. Without that ceiling a peer could open connections until
        // the host ran out of tasks, and reconnecting would reset every per-connection budget.
        let Ok(slot) = Arc::clone(&loop_state.admission).try_acquire_owned() else {
            tracing::debug!(
                "an incoming connection was refused: the host is at its admission bound"
            );
            incoming.refuse();
            continue;
        };
        let connecting = match incoming.accept() {
            Ok(connecting) => connecting,
            Err(error) => {
                tracing::debug!(%error, "an incoming connection was refused");
                continue;
            }
        };
        let state = loop_state.clone_state();
        tokio::spawn(async move {
            if let Err(error) = serve_connection(state, connecting, slot).await {
                tracing::debug!(%error, "a connection ended");
            }
        });
    }
}

async fn serve_connection<H: HostHandler>(
    state: AcceptLoop<H>,
    connecting: iroh::endpoint::Accepting,
    slot: tokio::sync::OwnedSemaphorePermit,
) -> Result<()> {
    // The deadline covers the unauthorised phase and nothing else. An authorised session lasts as
    // long as its peer keeps it, and cancelling one after a minute would be a far worse failure
    // than the one this bound exists to prevent.
    let deadline = state.config.handshake_deadline;
    let admitted = match tokio::time::timeout(deadline, admit(&state, connecting)).await {
        Ok(admitted) => admitted?,
        Err(_) => {
            return Err(TransportError::handshake(
                kr_protocol::error::ErrorCode::ResourceUnavailable,
                "the connection exceeded its handshake deadline",
            ));
        }
    };
    let (connection, admitted) = admitted;

    match admitted {
        Admitted::Unpaired(mut unpaired) => {
            let Some(surface) = state.handler.pairing_surface() else {
                connection.close(REFUSED_UNPAIRED.into(), b"pairing is not open");
                return Ok(());
            };
            let outcome = tokio::time::timeout(
                deadline,
                crate::preauth::serve(
                    &mut unpaired,
                    surface.as_ref(),
                    state.config.preauth_limits,
                    state.clock.as_ref(),
                    state.config.controller_generation,
                ),
            )
            .await;
            connection.close(REFUSED_UNPAIRED.into(), b"the pairing exchange ended");
            match outcome {
                Ok(outcome) => outcome,
                Err(_) => Err(TransportError::handshake(
                    kr_protocol::error::ErrorCode::ResourceUnavailable,
                    "the pairing exchange exceeded its deadline",
                )),
            }
        }
        Admitted::Authorised(authorised) => {
            // An authorised connection is no longer unauthorised traffic, so it releases the
            // admission slot it held; its own limits govern it from here.
            drop(slot);
            serve_authorised(state, connection, authorised).await
        }
    }
}

/// Completes the QUIC handshake and the KalaReach one, under the caller's deadline.
async fn admit<H: HostHandler>(
    state: &AcceptLoop<H>,
    connecting: iroh::endpoint::Accepting,
) -> Result<(Connection, Admitted)> {
    // The first bidirectional stream is accepted from the 0-RTT connection, because QUIC marks a
    // stream as early data only when it is accepted while the handshake is still running. Nothing
    // is *read* from it here: the read happens after `handshake_completed`, so no frame is ever
    // acted on before the peer's endpoint identity is authenticated. What this buys is an honest
    // answer to "did this arrive as early data", which the 0-RTT rules below depend on.
    let zero_rtt = connecting.into_0rtt();
    let (send, recv) = zero_rtt
        .accept_bi()
        .await
        .map_err(|error| TransportError::Stream(error.to_string()))?;
    let early_data = recv.is_0rtt();
    let connection = zero_rtt
        .handshake_completed()
        .await
        .map_err(|error| TransportError::Connect(error.to_string()))?;

    let admitted = crate::handshake::accept_on(
        &connection,
        send,
        recv,
        early_data,
        &state.identity,
        state.config.epochs,
        state.handler.as_ref(),
        &state.challenges,
        &state.windows,
    )
    .await?;
    Ok((connection, admitted))
}

async fn serve_authorised<H: HostHandler>(
    state: AcceptLoop<H>,
    connection: Connection,
    authorised: Box<crate::handshake::AuthorisedConnection>,
) -> Result<()> {
    let connection_id = authorised.connection_id;
    let hook: Arc<dyn RevocationHook> = Arc::new(HandlerHook {
        handler: Arc::clone(&state.handler) as Arc<dyn ControlLossListener>,
    });
    let streams = Arc::new(StreamRegistry::new(
        connection_id,
        Arc::new(StreamBudget::new(state.config.bulk_limits)),
        Some(hook),
    ));
    let actor = ConnectionActor::network_device(
        state.handler.principal_for(&authorised.peer_device_id),
        authorised.peer_device_id,
        state.config.controller_generation,
        connection_id,
    );
    let control = ControlChannel {
        writer: Arc::new(Mutex::new(authorised.control_writer)),
        reader: authorised.control_reader,
    };
    // While this flag is set the keepalive may issue a window. The guard clears it before it
    // retires the connection, and the keepalive retires any window it issued after the flag was
    // cleared, so no window can outlive the connection whichever order the two run in.
    let issuing = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let keepalive = tokio::spawn(keepalive_loop(Keepalive {
        sender: control.sender(),
        connection: connection.clone(),
        windows: Arc::clone(&state.windows),
        connection_id,
        epochs: state.config.epochs,
        keepalive: state.config.keepalive,
        window_validity: state.config.action_window_validity,
        issuing: Arc::clone(&issuing),
    }));

    // The guard runs on every way out of this function, including a panic in the host's handler and
    // a cancellation of the task: the control stream is gone either way, and everything it
    // authorised goes with it, the keepalive included.
    let cleanup = ConnectionCleanup {
        streams: Arc::clone(&streams),
        windows: Arc::clone(&state.windows),
        connection_id,
        keepalive: Some(keepalive),
        issuing,
        connection: connection.clone(),
    };

    let session = AuthorisedSession {
        connection: connection.clone(),
        connection_id,
        peer_device_id: authorised.peer_device_id,
        peer_endpoint_id: authorised.peer_endpoint_id,
        transcript_digest: authorised.transcript_digest,
        offer: authorised.offer,
        selection: authorised.selection,
        actor,
        control,
        streams: Arc::clone(&streams),
        windows: Arc::clone(&state.windows),
        action_window: authorised.action_window,
        clock: Arc::clone(&state.clock),
    };
    Arc::clone(&state.handler).serve(session).await;
    drop(cleanup);
    Ok(())
}

/// Ends a connection's authority whatever way the connection ended.
#[derive(Debug)]
struct ConnectionCleanup {
    streams: Arc<StreamRegistry>,
    windows: Arc<ActionWindowIssuer>,
    connection_id: ConnectionId,
    keepalive: Option<tokio::task::JoinHandle<()>>,
    issuing: Arc<std::sync::atomic::AtomicBool>,
    connection: Connection,
}

impl Drop for ConnectionCleanup {
    fn drop(&mut self) {
        // The order matters. Issuance is fenced first, so a keepalive that is between its check and
        // its write cannot leave a window behind; then the task is stopped, the connection closed,
        // the streams revoked and the windows retired.
        self.issuing
            .store(false, std::sync::atomic::Ordering::Release);
        if let Some(keepalive) = self.keepalive.take() {
            keepalive.abort();
        }
        self.connection
            .close(CONTROL_LOST.into(), b"the connection ended");
        self.streams.revoke_all();
        self.windows.retire_connection(self.connection_id);
    }
}

/// The QUIC application error code an unpaired connection is closed with when pairing is not open.
pub const REFUSED_UNPAIRED: u32 = 2;

/// The half of [`HostHandler`] the stream registry needs.
trait ControlLossListener: Send + Sync + std::fmt::Debug {
    fn control_stream_lost(&self, connection_id: ConnectionId);
}

impl<H: HostHandler> ControlLossListener for H {
    fn control_stream_lost(&self, connection_id: ConnectionId) {
        HostHandler::control_stream_lost(self, connection_id);
    }
}

#[derive(Debug)]
struct HandlerHook {
    handler: Arc<dyn ControlLossListener>,
}

impl RevocationHook for HandlerHook {
    fn control_stream_lost(&self, connection_id: ConnectionId) {
        self.handler.control_stream_lost(connection_id);
    }
}

/// What the keepalive task works from.
#[derive(Debug)]
struct Keepalive {
    sender: ControlSender,
    connection: Connection,
    windows: Arc<ActionWindowIssuer>,
    connection_id: ConnectionId,
    epochs: HostEpochs,
    keepalive: Duration,
    window_validity: Duration,
    issuing: Arc<std::sync::atomic::AtomicBool>,
}

/// Sends a keepalive while the connection is idle and renews the action window before it expires.
///
/// The window is renewed at half its validity, which leaves a full half-window of margin for a
/// slow link. Section 9 calls the renewal explicit, and this is where the host is explicit about
/// it: the client never asks.
async fn keepalive_loop(state: Keepalive) {
    let Keepalive {
        sender,
        connection,
        windows,
        connection_id,
        epochs,
        keepalive,
        window_validity,
        issuing,
    } = state;
    let mut keepalive_timer = tokio::time::interval(keepalive);
    keepalive_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut renewal_timer = tokio::time::interval(window_validity / 2);
    renewal_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick of a tokio interval fires immediately; neither message is wanted at once.
    keepalive_timer.tick().await;
    renewal_timer.tick().await;

    loop {
        let frame = tokio::select! {
            _ = keepalive_timer.tick() => ControlFrame::Event(ControlEvent::Keepalive),
            _ = renewal_timer.tick() => {
                if !issuing.load(std::sync::atomic::Ordering::Acquire) {
                    return;
                }
                match windows.issue(connection_id, epochs.boot_epoch) {
                    Ok(window) => {
                        if !issuing.load(std::sync::atomic::Ordering::Acquire) {
                            // The connection ended while this window was being issued, so it is
                            // retired here rather than left for a retirement that already ran.
                            windows.retire(&window.action_window_id);
                            return;
                        }
                        ControlFrame::Event(ControlEvent::ActionWindowRenewed(window))
                    }
                    Err(error) => {
                        tracing::warn!(%error, "an action window could not be renewed");
                        continue;
                    }
                }
            }
        };
        if sender.send(&frame).await.is_err() {
            // The host can no longer write to this connection, so its control stream has failed
            // whatever the read side is doing. Closing the connection is what makes the handler
            // notice, which is what runs the cleanup.
            connection.close(CONTROL_LOST.into(), b"the control stream failed");
            return;
        }
    }
}

/// The QUIC application error code a connection is closed with when its control stream fails.
pub const CONTROL_LOST: u32 = 3;

/// Returns the principal a paired device acts under, derived from its device identity.
///
/// A host with its own principal scheme uses that instead; this exists so a host that has no
/// reason to invent one does not have to.
#[must_use]
pub fn device_principal(device_id: &DeviceId) -> ActorId {
    ActorId::new(format!(
        "device:{}",
        to_base64url(device_id.get().as_bytes())
    ))
    .expect("a base64url device identity is a valid opaque identifier")
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::Uuid;

    #[test]
    fn a_device_principal_names_one_device() {
        let first = device_principal(&DeviceId::new(Uuid::from_bytes([1; 16])));
        let second = device_principal(&DeviceId::new(Uuid::from_bytes([2; 16])));
        assert_ne!(first, second);
        assert!(first.as_str().starts_with("device:"));
    }

    #[test]
    fn the_default_configuration_uses_the_specified_intervals() {
        let config = ListenerConfig::new(
            EndpointConfig::default(),
            HostEpochs {
                boot_epoch: kr_protocol::ids::BootEpoch::new(1),
                clock_epoch: kr_protocol::ids::ClockEpoch::new(1),
            },
            ControllerGeneration::new(1),
        );
        assert_eq!(config.keepalive, Duration::from_secs(10));
        assert_eq!(config.action_window_validity, Duration::from_secs(300));
    }
}
