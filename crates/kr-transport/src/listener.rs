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
use crate::error::Result;
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
        }
    }
}

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
    let challenges = Arc::new(Mutex::new(ChallengeLedger::with_limit(
        config.max_outstanding_challenges,
    )));

    let accept_loop = tokio::spawn(accept_loop(AcceptLoop {
        endpoint: endpoint.clone(),
        config: Arc::new(config),
        identity,
        handler,
        clock,
        windows: Arc::clone(&windows),
        challenges,
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
    challenges: Arc<Mutex<ChallengeLedger>>,
}

async fn accept_loop<H: HostHandler>(loop_state: AcceptLoop<H>) {
    while let Some(incoming) = loop_state.endpoint.accept().await {
        let connecting = match incoming.accept() {
            Ok(connecting) => connecting,
            Err(error) => {
                tracing::debug!(%error, "an incoming connection was refused");
                continue;
            }
        };
        let state = AcceptLoop {
            endpoint: loop_state.endpoint.clone(),
            config: Arc::clone(&loop_state.config),
            identity: Arc::clone(&loop_state.identity),
            handler: Arc::clone(&loop_state.handler),
            clock: Arc::clone(&loop_state.clock),
            windows: Arc::clone(&loop_state.windows),
            challenges: Arc::clone(&loop_state.challenges),
        };
        tokio::spawn(async move {
            // The connection is never turned into a 0-RTT connection here, so the authorised path
            // accepts no early data at all. The pre-authorisation surface is the only place where
            // early data could arrive, and it refuses every mutation in it.
            let connection = match connecting.await {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::debug!(%error, "a connection failed before the handshake");
                    return;
                }
            };
            if let Err(error) = serve_connection(state, connection).await {
                tracing::debug!(%error, "a connection ended");
            }
        });
    }
}

async fn serve_connection<H: HostHandler>(
    state: AcceptLoop<H>,
    connection: Connection,
) -> Result<()> {
    let admitted = crate::handshake::accept(
        &connection,
        &state.identity,
        state.config.epochs,
        state.handler.as_ref(),
        &state.challenges,
        &state.windows,
    )
    .await?;

    match admitted {
        Admitted::Unpaired(mut unpaired) => {
            let Some(surface) = state.handler.pairing_surface() else {
                connection.close(REFUSED_UNPAIRED.into(), b"pairing is not open");
                return Ok(());
            };
            crate::preauth::serve(
                &mut unpaired,
                surface.as_ref(),
                state.config.preauth_limits,
                state.clock.as_ref(),
                state.config.controller_generation,
            )
            .await
        }
        Admitted::Authorised(authorised) => {
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
            let keepalive = tokio::spawn(keepalive_loop(
                control.sender(),
                Arc::clone(&state.windows),
                connection_id,
                state.config.epochs,
                state.config.keepalive,
                state.config.action_window_validity,
            ));

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

            // The control stream has ended, whatever the reason. Everything it authorised goes
            // with it, and the windows it could first-admit through are retired.
            keepalive.abort();
            streams.revoke_all();
            state.windows.retire_connection(connection_id);
            Ok(())
        }
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

/// Sends a keepalive while the connection is idle and renews the action window before it expires.
///
/// The window is renewed at half its validity, which leaves a full half-window of margin for a
/// slow link. Section 9 calls the renewal explicit, and this is where the host is explicit about
/// it: the client never asks.
async fn keepalive_loop(
    sender: ControlSender,
    windows: Arc<ActionWindowIssuer>,
    connection_id: ConnectionId,
    epochs: HostEpochs,
    keepalive: Duration,
    window_validity: Duration,
) {
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
                match windows.issue(connection_id, epochs.boot_epoch) {
                    Ok(window) => ControlFrame::Event(ControlEvent::ActionWindowRenewed(window)),
                    Err(error) => {
                        tracing::warn!(%error, "an action window could not be renewed");
                        continue;
                    }
                }
            }
        };
        if sender.send(&frame).await.is_err() {
            return;
        }
    }
}

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
