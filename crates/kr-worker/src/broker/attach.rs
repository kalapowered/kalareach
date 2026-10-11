//! The production path from a bound endpoint to a served connection.
//!
//! [`endpoint`](crate::broker::endpoint) binds a socket, [`listener`](crate::broker::listener)
//! says what authenticates on it, [`Broker::open_native_connection`] admits a connection and
//! [`duplex`](crate::broker::duplex) drives one. This is the one place where those four are joined
//! in the order section 11 and section 12 require, so that a launched agent's bridge reaching the
//! socket becomes a connection this host serves and nothing in between is left to a caller.
//!
//! The order is the contract.
//!
//! 1. **Accept.** The kernel names the peer, or the platform has no private socket and says so.
//! 2. **Hello.** One frame, in the connection's own framing, and nothing else is read until the
//!    connection is authenticated. It is read under a deadline, so a process that connects and
//!    says nothing holds the endpoint for a bounded time rather than for ever.
//! 3. **Authenticate.** The owner, the process and the private exchange of the launch this host
//!    made, plus the refusal of anything a browser would have added.
//! 4. **Admit.** The broker opens the gateway connection, against the tables this host pinned for
//!    the connector package, and mints the identifier that namespaces everything the connection
//!    produces.
//! 5. **Register.** The connection's own dispatch becomes the one the broker hands admissions to,
//!    and the connection is subscribed to the resolutions of the instance it speaks for.
//! 6. **Serve and tear down.** The owner reads both ends until one closes; then the connection is
//!    closed and its subscription withdrawn.
//!
//! A failure at any step leaves nothing behind: an admitted connection whose owner could not start
//! is closed again, so a refused bridge does not leave a gateway connection nobody drives.

use std::collections::BTreeMap;
use std::sync::Arc;

use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{ApplicationInstanceId, GatewayConnectionId, PluginId};

use crate::broker::duplex::{Closure, Duplex, Observations, Observatory};
use crate::broker::endpoint::{Accepted, BoundEndpoint, PeerIdentity, Stream};
use crate::broker::error::{BrokerError, Result};
use crate::broker::framing::Framing;
use crate::broker::listener::{BridgeHello, ListenerAddress, Registration, reject_browser_origin};
use crate::broker::{Broker, ResourceTransition};

/// How long a connecting bridge has to say who it is.
///
/// A process that connects and then says nothing is not a bridge this host is waiting for, and an
/// endpoint that waits for it indefinitely is an endpoint one stalled process closes.
pub const HELLO_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// The file a launch's registration is published as, inside its owner-only directory.
pub const REGISTRATION_FILE: &str = "registration";

/// The owner-only file beside the registration that holds a launch's private exchange.
pub const CREDENTIAL_FILE: &str = "credential";

/// How long a connection's own writes are given to finish once both ends have stopped reading.
pub const TEARDOWN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// What one launched agent's bridge must satisfy, and what its connection is read with.
#[derive(Clone, Debug)]
pub struct NativeLaunch {
    /// The launch profile this registration belongs to.
    pub profile_id: kr_protocol::ids::LaunchProfileId,
    /// The bridge process this host expects on the connection.
    ///
    /// It is absent until the gateway is bound for a process the invocation presented: the
    /// registration names the process, so the process has to exist before the registration does.
    pub expected_process: Option<ProcessStartIdentity>,
    /// The instance the connection speaks for.
    pub application_instance_id: ApplicationInstanceId,
    /// The connector package whose pinned tables read this connection's frames.
    pub plugin_id: PluginId,
    /// The installed upstream protocol version those tables are qualified against.
    pub installed_protocol_version: String,
    /// How this connector frames.
    pub framing: Framing,
    /// Where reverse work would run, derived from the connection rather than from a request.
    pub site: kr_protocol::ids::EnvironmentId,
    /// The operating-system user the agent runs as.
    pub os_user: String,
}

/// What a connecting bridge writes before anything else.
///
/// Nothing in it is authority on its own. The credential is compared with the one this host
/// generated for the launch; on a private socket the process it names is compared with the one the
/// kernel named, and the kernel wins. The session identifier is carried for diagnostics and
/// section 11 is explicit that it authenticates nothing.
#[derive(serde::Deserialize)]
struct Hello {
    /// The credential the bridge read from its own owner-only file, as hexadecimal.
    credential: String,
    /// The process the bridge is.
    pid: u64,
    /// That process's start value.
    start: u64,
    /// Whatever the application thought its session was.
    #[serde(default)]
    session: Option<String>,
    /// Anything the connecting side attached to the connection.
    #[serde(default)]
    headers: BTreeMap<String, String>,
    /// Which native bridge the connecting side says it is, when it is one.
    ///
    /// A claim like everything else here: [`NativeGateway::accept_bridge`] validates it against
    /// the installation this host recorded for the launch.
    #[serde(default)]
    bridge: Option<crate::broker::bridge::BridgeDeclaration>,
}

/// What one connection's ending meant, as the closure itself established it.
///
/// It says what the socket closing was, and nothing about what the terminal does afterwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ended {
    /// Why the connection ended.
    pub closure: Closure,
}

fn map_content_class(
    class: crate::persistence::stores::ContentClass,
) -> kr_protocol::projection::AgentResourceContentClass {
    match class {
        crate::persistence::stores::ContentClass::Metadata => {
            kr_protocol::projection::AgentResourceContentClass::Metadata
        }
        crate::persistence::stores::ContentClass::TerminalContent => {
            kr_protocol::projection::AgentResourceContentClass::TerminalContent
        }
        crate::persistence::stores::ContentClass::AuthoredContent => {
            kr_protocol::projection::AgentResourceContentClass::AuthoredContent
        }
        crate::persistence::stores::ContentClass::ApplicationNotice => {
            kr_protocol::projection::AgentResourceContentClass::ApplicationNotice
        }
        crate::persistence::stores::ContentClass::Secret => {
            kr_protocol::projection::AgentResourceContentClass::Secret
        }
    }
}

fn map_cause(
    cause: crate::broker::ledger::TransitionCause,
) -> kr_protocol::projection::AgentResourceCause {
    match cause {
        crate::broker::ledger::TransitionCause::Recorded => {
            kr_protocol::projection::AgentResourceCause::Recorded
        }
        crate::broker::ledger::TransitionCause::Interpreted => {
            kr_protocol::projection::AgentResourceCause::Interpreted
        }
        crate::broker::ledger::TransitionCause::RichClaim => {
            kr_protocol::projection::AgentResourceCause::RichClaim
        }
        crate::broker::ledger::TransitionCause::Dispatched => {
            kr_protocol::projection::AgentResourceCause::Dispatched
        }
        crate::broker::ledger::TransitionCause::RichAnswer => {
            kr_protocol::projection::AgentResourceCause::RichAnswer
        }
        crate::broker::ledger::TransitionCause::NativeAnswer => {
            kr_protocol::projection::AgentResourceCause::NativeAnswer
        }
        crate::broker::ledger::TransitionCause::HostAnswer => {
            kr_protocol::projection::AgentResourceCause::HostAnswer
        }
        crate::broker::ledger::TransitionCause::Upstream => {
            kr_protocol::projection::AgentResourceCause::Upstream
        }
        crate::broker::ledger::TransitionCause::Reconciliation => {
            kr_protocol::projection::AgentResourceCause::Reconciliation
        }
    }
}

fn to_agent_resource_event(
    session_id: kr_protocol::ids::SessionId,
    stream_generation: u64,
    transition: ResourceTransition,
) -> kr_protocol::projection::AgentResourceEvent {
    kr_protocol::projection::AgentResourceEvent {
        session_id,
        application_instance_id: transition.application_instance_id,
        resource_id: transition.resource_id,
        state: transition.state,
        content: map_content_class(transition.content),
        durability: transition.durability,
        cause: map_cause(transition.cause),
        actor_id: kr_protocol::scalars::Nullable(transition.actor_id),
        causal_root: transition.causal_root,
        binding_revision: transition.binding_revision,
        stream_generation: kr_protocol::scalars::U64::new(stream_generation),
        sequence: kr_protocol::scalars::U64::new(transition.sequence),
        event_id: transition.event_id,
        parent_sequence: kr_protocol::scalars::Nullable(
            transition
                .parent_sequence
                .map(kr_protocol::scalars::U64::new),
        ),
    }
}

fn from_transition_event(
    session_id: kr_protocol::ids::SessionId,
    stream_generation: u64,
    transition: crate::broker::ledger::TransitionEvent,
) -> kr_protocol::projection::AgentResourceEvent {
    kr_protocol::projection::AgentResourceEvent {
        session_id,
        application_instance_id: transition.application_instance_id,
        resource_id: transition.resource_id,
        state: transition.state,
        content: map_content_class(transition.content),
        durability: transition.durability,
        cause: map_cause(transition.cause),
        actor_id: kr_protocol::scalars::Nullable(transition.actor_id),
        causal_root: transition.causal_root,
        binding_revision: transition.binding_revision,
        stream_generation: kr_protocol::scalars::U64::new(stream_generation),
        sequence: kr_protocol::scalars::U64::new(transition.sequence),
        event_id: transition.event_id,
        parent_sequence: kr_protocol::scalars::Nullable(
            transition
                .parent_sequence
                .map(kr_protocol::scalars::U64::new),
        ),
    }
}

/// Reads what the broker holds about the resource one transition is about.
///
/// The live arbitration first, then the ledger's record of it. A session's views are shown a
/// transition by what the resource is now and when it was recorded: a request becomes an approval
/// when a decoder interprets it, and the moment it was recorded never changes. It is read once for
/// each transition, before the session is locked, and no lock of the broker's is held once it
/// returns, since the subscription path holds the session's lock while it reads the broker.
fn resource_of(
    broker: &Broker,
    resource_id: kr_protocol::ids::PendingResourceId,
) -> Option<kr_protocol::gateway::PendingResource> {
    broker
        .pending(resource_id)
        .or_else(|| broker.recorded(resource_id).ok().flatten())
}

/// Carries every transition this connection observes to the views attached to a session.
///
/// It is the production consumer of the broker's own published transitions: the broker commits
/// them in order and publishes them in that order, and this reads that one stream and hands each
/// one to the session pipeline, which delivers it to every attached view.
///
/// The interesting half is what happens when the queue ends, because it ends for two reasons and
/// this must not confuse them. An observer that fell behind lost its queue and the resolutions in
/// it; a connection that was torn down has no further resolutions to lose. Either way what this
/// has not delivered is recovered before delivery stops: a fresh queue is taken first, so nothing
/// committed during the recovery is missed, and the outbox is then replayed from the last position
/// the views were told about. What the outbox cannot return — a transition announced while the
/// journal was faulted — is reported to the views as a gap, so a view is never left believing a
/// history with a hole in it is complete.
pub async fn deliver_to_views(
    mut observations: Observations,
    broker: Arc<Broker>,
    session_id: kr_protocol::ids::SessionId,
    runtime: Arc<crate::runtime::SessionRuntime>,
) {
    let mut cursor = broker.stream_start();
    // The highest lost position the views have been told about. A loss is news once: a view that
    // has started again since installed a state that already accounts for it.
    let mut reported = 0_u64;
    loop {
        match observations.next().await {
            Some(transition) => {
                if transition.sequence <= cursor.sequence {
                    continue;
                }
                cursor.sequence = transition.sequence;
                let event = to_agent_resource_event(session_id, cursor.generation, transition);
                let resource = resource_of(&broker, event.resource_id);
                runtime
                    .session()
                    .publish_agent_resource(&event, resource.as_ref());
            }
            None => {
                // The fresh queue is taken before the outbox is read, so a transition committed
                // during the recovery is queued rather than falling between the two. Taking it is
                // also what says whether this connection goes on: the registry decides that with
                // the withdrawal, under one lock.
                let continuing = observations.resubscribe();
                recover_views(&broker, &runtime, session_id, &mut cursor, &mut reported).await;
                if !continuing {
                    break;
                }
            }
        }
    }
}

/// Says whether one page of a replay is news the views have not been told, and remembers it.
///
/// A reset is news: it starts the stream again, and positions from another generation mean
/// nothing here, so what was reported is forgotten. A loss is news when it reaches past the
/// highest loss already told, whichever page or recovery told it: the same loss found again is
/// not, and a later one is, because a view that started again after the first has not been told
/// about the second.
fn news_in(replay: &crate::broker::TransitionReplay, reported: &mut u64) -> bool {
    if replay.reset {
        *reported = 0;
    }
    let lost = replay.lost_through.is_some_and(|lost| lost > *reported);
    if let Some(lost) = replay.lost_through {
        *reported = (*reported).max(lost);
    }
    replay.reset || lost
}

/// Replays what the views have not been told about, in bounded pages.
///
/// The broker's lock is taken for one page at a time, so a connection that is far behind recovers
/// without holding every other caller behind its read. Each page is checked for news: a loss the
/// views were already told about, by an earlier page or an earlier recovery, is not told again,
/// and one that grew since, while the lock was given back between pages, is.
async fn recover_views(
    broker: &Arc<Broker>,
    runtime: &Arc<crate::runtime::SessionRuntime>,
    session_id: kr_protocol::ids::SessionId,
    cursor: &mut crate::broker::ReplayCursor,
    reported: &mut u64,
) {
    // Whether this recovery has told the views anything, for a read that fails part way.
    let mut told = false;
    loop {
        let replay = match broker.replay_after(*cursor) {
            Ok(replay) => replay,
            Err(_) => {
                // The outbox cannot be read at all, so nothing here can establish what the views
                // missed. They are told to install a fresh state rather than left with a partial
                // one that looks whole.
                if !told {
                    runtime
                        .session()
                        .resync_all_views(kr_protocol::recovery::ResyncReason::AgentStreamGap);
                }
                return;
            }
        };
        if news_in(&replay, reported) {
            told = true;
            runtime
                .session()
                .resync_all_views(kr_protocol::recovery::ResyncReason::AgentStreamGap);
        }
        for transition in replay.events {
            if transition.sequence <= cursor.sequence && !replay.reset {
                continue;
            }
            let event = from_transition_event(session_id, replay.cursor.generation, transition);
            let resource = resource_of(broker, event.resource_id);
            runtime
                .session()
                .publish_agent_resource(&event, resource.as_ref());
        }
        *cursor = replay.cursor;
        if !replay.more {
            return;
        }
        // The lock has been given back between pages; yielding lets whatever was waiting for it
        // run before the next one is read.
        tokio::task::yield_now().await;
    }
}

/// One connection this host admitted, served by its own supervised owner.
#[derive(Debug)]
pub struct Attached {
    /// The connection the broker minted for it.
    pub connection: GatewayConnectionId,
    /// The owner that reads both ends.
    pub owner: Arc<Duplex>,
    /// Where this connection's authorised observer reads resolutions.
    pub observations: Option<Observations>,
    /// The task driving the owner's own writes and reads.
    served: tokio::task::JoinHandle<Ended>,
    /// The broker that minted this attachment and holds its state.
    pub broker: Arc<Broker>,
}

impl Attached {
    /// Starts the delivery of this connection's observed transitions to a session's attached views.
    ///
    /// The subscription is taken out of the attachment, so it is consumed once: either a caller
    /// delivers it to views or it reads it itself, never both.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PreconditionFailed`] when this attachment's subscription has already
    /// been taken.
    pub fn deliver_to_views(
        &mut self,
        session_id: kr_protocol::ids::SessionId,
        runtime: Arc<crate::runtime::SessionRuntime>,
    ) -> Result<tokio::task::JoinHandle<()>> {
        let observations =
            self.observations
                .take()
                .ok_or_else(|| BrokerError::PreconditionFailed {
                    detail: "this attachment's transitions are already being read".to_owned(),
                })?;
        let broker = Arc::clone(&self.broker);
        Ok(tokio::spawn(deliver_to_views(
            observations,
            broker,
            session_id,
            runtime,
        )))
    }

    /// Waits for the connection to end and says why it did.
    ///
    /// What it says is about the socket. The terminal is watched separately and goes on being
    /// watched after this returns, so a terminal that exits later still stops its backend.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UpstreamUnavailable`] when the task that served the connection could
    /// not be joined, which leaves why it ended unestablished.
    pub async fn served(&mut self) -> Result<Ended> {
        (&mut self.served)
            .await
            .map_err(|error| BrokerError::UpstreamUnavailable {
                detail: format!("the connection's own task could not be joined: {error}"),
            })
    }

    /// Asks the owner to stop and waits for it.
    ///
    /// # Errors
    ///
    /// Returns what [`Attached::served`] does.
    pub async fn shutdown(&mut self) -> Result<Ended> {
        self.owner.shutdown();
        self.served().await
    }
}

/// The endpoint one launch's bridge connects to.
#[derive(Debug)]
pub struct NativeGateway {
    broker: Arc<Broker>,
    endpoint: BoundEndpoint,
    observatory: Observatory,
    launch: NativeLaunch,
    /// The registration this endpoint admits against.
    ///
    /// Set once, when the gateway is bound for the process the invocation presented. Admissions
    /// read it concurrently, so it is never replaced.
    registration: std::sync::OnceLock<Registration>,
    /// The native bridge the launched application was installed with, where it has one.
    bridge: Option<crate::broker::bridge::InstalledBridge>,
    /// How long this gateway gives a connection's writers once its reading has ended.
    ///
    /// It is [`TEARDOWN_DEADLINE`] for every gateway this product binds. It is a field rather than
    /// the constant at the one place that waits on it so that a test can set it far below the
    /// deadline a single write gets, and so tell a writer this supervision ended from a writer
    /// that ran out of its own time: with both at one value, either could be what happened.
    teardown: std::time::Duration,
}

impl NativeGateway {
    /// Sets how long this gateway gives a connection's writers once its reading has ended.
    ///
    /// It exists so that this host's own tests can put that bound far below the deadline one write
    /// gets, and prove that what ended a stuck connection was this supervision rather than the
    /// write giving up on its own. It is compiled away in every shipped build.
    #[cfg(feature = "testing")]
    #[must_use]
    pub const fn with_teardown_deadline(mut self, teardown: std::time::Duration) -> Self {
        self.teardown = teardown;
        self
    }

    /// Binds the endpoint this launch publishes.
    ///
    /// # Errors
    ///
    /// Returns whatever [`BoundEndpoint::bind`] refuses.
    pub fn bind(
        broker: Arc<Broker>,
        runtime_directory: &std::path::Path,
        launch: NativeLaunch,
    ) -> Result<Self> {
        let endpoint = BoundEndpoint::bind(runtime_directory)?;
        // The broker's own registry, not one of this gateway's. Every settled resource of this
        // broker reaches the observers watching its instance, and a second gateway's connections
        // join them rather than replacing them.
        let observatory = broker.observatory();
        // The registration is built from the address this host bound, never from one a caller
        // supplied. A launched process is told where to connect, and telling it anywhere but the
        // socket that exists is telling it nothing. Which process it will be is not known yet.
        let registration = std::sync::OnceLock::new();
        if let Some(expected) = launch.expected_process.clone() {
            let _ = registration.set(Registration::new(
                endpoint.address().clone(),
                launch.profile_id.clone(),
                launch.application_instance_id,
                expected,
                runtime_directory.join(CREDENTIAL_FILE),
            ));
        }
        Ok(Self {
            teardown: TEARDOWN_DEADLINE,
            broker,
            endpoint,
            observatory,
            launch,
            registration,
            bridge: None,
        })
    }

    /// Declares the native bridge the launched application was installed with.
    ///
    /// Section 11's bridges are installed per application, and a bridge that connects is validated
    /// against this record: the application its registration invokes the forwarder for, the
    /// surfaces the recipe registered, and the forwarder executable it points the application at.
    /// A launch with no installed bridge admits none.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the bridge was installed from a package other
    /// than the connector this launch was made for.
    pub fn with_bridge(
        mut self,
        installed: crate::broker::bridge::InstalledBridge,
    ) -> Result<Self> {
        if installed.plugin_id != self.launch.plugin_id {
            return Err(BrokerError::invalid(format!(
                "the bridge installed from {} is not the connector {} this launch was made for",
                installed.plugin_id, self.launch.plugin_id
            )));
        }
        self.bridge = Some(installed);
        Ok(self)
    }

    /// Returns the address a launched process is told to connect to.
    #[must_use]
    pub const fn address(&self) -> &ListenerAddress {
        self.endpoint.address()
    }

    /// Returns the registration file a launched process reads.
    #[must_use]
    pub fn registration(&self) -> Option<String> {
        self.registration.get().map(|registration| {
            format!(
                "{}framing={}\n",
                registration.to_file(),
                self.launch.framing.name()
            )
        })
    }

    /// Accepts one bridge, authenticates it, admits it and starts its owner.
    ///
    /// The `client` end is the native terminal the person is looking at. Frames the upstream sends
    /// go to it, and its own answers come back through the same owner.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PermissionDenied`] when the connection is not the launch this host
    /// made, or carries anything a browser would have added; and whatever the broker refuses when
    /// it admits the connection.
    pub async fn accept<CR, CW>(&self, client_reader: CR, client_writer: CW) -> Result<Attached>
    where
        CR: tokio::io::AsyncRead + Unpin + Send + 'static,
        CW: tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let accepted = self.endpoint.accept().await?;
        self.admit(accepted, client_reader, client_writer).await
    }

    /// Accepts one connection from a native bridge the launched application started, and admits it.
    ///
    /// The order is the one [`NativeGateway::accept`] keeps, with the bridge's own launch binding in
    /// place of the launched process's:
    ///
    /// 1. **Accept.** The kernel names the peer, or the platform has no private socket and says so.
    /// 2. **Hello.** One frame under [`HELLO_DEADLINE`], and nothing past it is read until the
    ///    connection is admitted. It must declare which bridge it is.
    /// 3. **Refuse a browser.** Anything a browser would have added disqualifies the connection.
    /// 4. **Authenticate and validate.** The owner, the process the hello presents against the one
    ///    the kernel named, the parent chain to the process this host launched, the installation
    ///    this host recorded, and then the launch's private exchange. The process that started the
    ///    bridge and the kernel's forward-only record of its start are kept with it, to place what
    ///    it reports.
    /// 5. **Admit.** One admission frame, so the bridge knows it may speak.
    ///
    /// What the admitted bridge then says is its surface's business; see
    /// [`crate::broker::bridge`].
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PermissionDenied`] when any check fails, which closes the connection
    /// without a word, and [`BrokerError::UpstreamUnavailable`] when the admission cannot be
    /// written.
    pub async fn accept_bridge(&self) -> Result<crate::broker::bridge::AdmittedBridge> {
        match self.open(self.accept_next().await?).await? {
            Opening::Bridge(pending) => {
                let registration = self.registration.get().ok_or_else(|| {
                    BrokerError::denied(
                        "this endpoint has not launched anything to authenticate against",
                    )
                })?;
                self.authenticate_bridge(pending, registration)?
                    .admit()
                    .await
            }
            Opening::Launch(_) => Err(BrokerError::denied(
                "this connection presents a launch, and this endpoint admits bridges here",
            )),
        }
    }

    /// Accepts the next connection, naming its peer as the kernel does, and reads nothing yet.
    ///
    /// An accept loop takes each connection here and reads its first frame in a task of the
    /// connection's own, so one that connects and says nothing holds only its own task.
    ///
    /// # Errors
    ///
    /// Returns whatever [`BoundEndpoint`]'s accept refuses.
    pub async fn accept_next(&self) -> Result<Accepted> {
        self.endpoint.accept().await
    }

    /// Reads one accepted connection's first frame, under [`HELLO_DEADLINE`], and says what it is.
    ///
    /// Nothing past that frame is read. A bridge's hello goes on to
    /// [`NativeGateway::authenticate_bridge`];
    /// an invocation presenting itself goes to the command backend that owns this endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PermissionDenied`] for a connection that says nothing in time, closes
    /// first, or opens with anything else.
    pub async fn open(&self, accepted: Accepted) -> Result<Opening> {
        let Accepted { peer, stream } = accepted;
        let (mut reader, writer) = split_stream(stream);
        let (frame, held) = self.first_frame(&mut reader).await?;
        match frame {
            FirstFrame::Hello(hello, credential) => Ok(Opening::Bridge(PendingBridge {
                peer,
                reader,
                writer,
                hello,
                credential,
                held,
            })),
            FirstFrame::Launch(launch, credential) => Ok(Opening::Launch(PresentedLaunch {
                peer,
                credential,
                launch,
                stream: crate::broker::bridge::BridgeStream::new(
                    reader,
                    writer,
                    held,
                    self.launch.framing,
                ),
            })),
        }
    }

    /// Authenticates one bridge whose hello [`NativeGateway::open`] has read, against the
    /// registration of the launch it claims to belong to, and writes nothing yet.
    ///
    /// The bridge is the session owner's, the process the kernel names, started by the registered
    /// process, the installed forwarder, and it presents the launch's private exchange. What the
    /// caller checks next it checks for the program's own bridge; [`AuthenticatedBridge::admit`]
    /// then answers it.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::PermissionDenied`] when any check fails, which closes the connection
    /// without a word.
    pub fn authenticate_bridge(
        &self,
        pending: PendingBridge,
        registration: &Registration,
    ) -> Result<AuthenticatedBridge> {
        let PendingBridge {
            peer,
            reader,
            writer,
            hello,
            credential,
            held,
        } = pending;
        let credential = kr_crypto::secret::SecretVec::new(credential);
        reject_browser_origin(
            hello
                .headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        )?;
        let declared = hello.bridge.clone().ok_or_else(|| {
            BrokerError::denied("this connection does not say which native bridge it is")
        })?;
        let installed = self.bridge.as_ref().ok_or_else(|| {
            BrokerError::denied("no native bridge is installed for the application this launch is")
        })?;
        let presented = BridgeHello {
            credential,
            process: presented_process(&hello)?,
            environment_session_id: hello.session.clone(),
        };
        let starter = registration.authenticate_bridge(&presented, &peer, installed, &declared)?;
        self.broker.admit_bridge_exchange(
            self.launch.application_instance_id,
            presented.credential.expose(),
        )?;
        let identity = peer.process().clone();
        // Read while the bridge is known to be running, so the record is its own. Where the
        // platform keeps the record and it cannot be read, the bridge is not admitted: what it
        // reports could not be placed.
        #[cfg(windows)]
        let started = crate::windows::lineage::monotonic_start(&identity).map(Some);
        #[cfg(not(windows))]
        let started = crate::questions::binding::monotonic_start(&identity);
        let started = started.map_err(|why| {
            BrokerError::denied(format!(
                "the kernel's record of when this bridge started cannot be read: {why}"
            ))
        })?;
        Ok(AuthenticatedBridge {
            surface: declared.surface,
            process: crate::broker::bridge::BridgeProcess {
                identity,
                starter,
                started,
            },
            stream: crate::broker::bridge::BridgeStream::new(
                reader,
                writer,
                held,
                self.launch.framing,
            ),
        })
    }

    /// Reads the one observation an admitted hook sends, applies it, and closes the connection.
    ///
    /// The hook sends its observation straight behind its hello, and it waits for this host to
    /// close the connection before it answers its application, so an observation that selects a
    /// thread is applied before the application goes on: Claude Code holds a session's first
    /// response until its `SessionStart` hooks have finished.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the bridge is not a hook, sends nothing in
    /// time, or sends something that is not an observation, and whatever the broker refuses when it
    /// applies one.
    pub async fn observe_hook(
        &self,
        mut admitted: crate::broker::bridge::AdmittedBridge,
    ) -> Result<crate::broker::bridge::HookReport> {
        if admitted.surface != crate::broker::bridge::BridgeSurface::Hook {
            return Err(BrokerError::invalid(
                "only a hook reports an observation; a channel is served, not observed",
            ));
        }
        let body = tokio::time::timeout(
            crate::broker::bridge::BRIDGE_FRAME_DEADLINE,
            admitted.stream.read_frame(),
        )
        .await
        .map_err(|_| {
            BrokerError::invalid(format!(
                "the hook sent no observation within {} seconds",
                crate::broker::bridge::BRIDGE_FRAME_DEADLINE.as_secs()
            ))
        })??
        .ok_or_else(|| {
            BrokerError::invalid("the hook closed its connection without an observation")
        })?;
        let observation = crate::broker::bridge::Observation::from_frame(&body)?;
        let (thread, cursor) = self.broker.observe_bridge(
            self.launch.application_instance_id,
            &admitted.process,
            &observation,
            kr_ipc::now_ms(),
        )?;
        admitted.stream.close().await;
        Ok(crate::broker::bridge::HookReport {
            observation,
            thread,
            cursor,
        })
    }

    /// Everything after the accept, for one connection.
    async fn admit<CR, CW>(
        &self,
        accepted: Accepted,
        client_reader: CR,
        client_writer: CW,
    ) -> Result<Attached>
    where
        CR: tokio::io::AsyncRead + Unpin + Send + 'static,
        CW: tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let Accepted { peer, stream } = accepted;
        let (mut upstream_reader, upstream_writer) = split_stream(stream);
        let (frame, held) = self.first_frame(&mut upstream_reader).await?;
        let FirstFrame::Hello(hello, credential) = frame else {
            return Err(BrokerError::denied(
                "this connection presents a launch, and this endpoint serves a launched backend",
            ));
        };
        // Anything a browser would have added disqualifies the connection before its credential is
        // even compared: section 12 serves no browser on this listener.
        reject_browser_origin(
            hello
                .headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        )?;
        // The identity a bridge presents is read back from the operating system rather than
        // believed. A bridge that named a process it is not is then refused by the comparison
        // below instead of having its own account of itself compared with the launch.
        let read = presented_process(&hello)?;
        let presented = BridgeHello {
            credential: kr_crypto::secret::SecretVec::new(credential.clone()),
            process: read,
            environment_session_id: hello.session.clone(),
        };
        let registration = self.registration.get().ok_or_else(|| {
            BrokerError::denied("this endpoint has not launched anything to authenticate against")
        })?;
        // The owner, the kernel's naming of the process and the process the launch started. The
        // private exchange is the broker's own record and is checked where that record lives, in
        // the admission immediately below, so the credential never leaves it.
        registration.authenticate_peer(&presented, &peer)?;
        // The identity the connection is admitted under is the kernel's.
        let identity = peer.process().clone();
        let connection = self.broker.open_native_connection(
            self.launch.application_instance_id,
            &credential,
            &identity,
            &self.launch.plugin_id,
            &self.launch.installed_protocol_version,
        )?;
        let _ = identity;
        self.serve(
            connection,
            self.launch.framing,
            upstream_reader,
            upstream_writer,
            client_reader,
            client_writer,
            held,
        )
    }

    /// Starts one admitted connection's owner and the task that supervises it, framing the
    /// upstream's and the client's messages as `framing` says.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn serve<UR, UW, CR, CW>(
        &self,
        connection: GatewayConnectionId,
        framing: Framing,
        upstream_reader: UR,
        upstream_writer: UW,
        client_reader: CR,
        client_writer: CW,
        held: Vec<u8>,
    ) -> Result<Attached>
    where
        UR: tokio::io::AsyncRead + Unpin + Send + 'static,
        UW: tokio::io::AsyncWrite + Unpin + Send + 'static,
        CR: tokio::io::AsyncRead + Unpin + Send + 'static,
        CW: tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (owner, writes) = Duplex::new(
            Arc::clone(&self.broker),
            connection,
            framing,
            upstream_writer,
            client_writer,
            self.launch.site,
            self.launch.os_user.clone(),
        );
        // The dispatch is registered before either end is read. A frame that arrived first and
        // produced an admission would otherwise find no transport for the connection it came in
        // on.
        let dispatch = match owner.dispatch() {
            Ok(dispatch) => dispatch,
            Err(error) => {
                self.broker.close_connection(connection);
                return Err(error);
            }
        };
        let carrying: Arc<dyn crate::broker::methods::UpstreamDispatch> = dispatch;
        self.broker
            .bind_connection_dispatch(connection, Arc::clone(&carrying));
        // And the instance's own transport, which is what an ordinary rich mutation goes out
        // over. A connection admitted without it would take prompts, steers and cancellations and
        // have nowhere to carry them.
        if let Err(error) = self
            .broker
            .bind_dispatch(self.launch.application_instance_id, Arc::clone(&carrying))
        {
            self.broker.close_connection(connection);
            return Err(error);
        }
        let observations = self.observatory.subscribe(connection);
        let served = {
            let owner = Arc::clone(&owner);
            let broker = Arc::clone(&self.broker);
            let observatory = self.observatory.clone();
            let application_instance_id = self.launch.application_instance_id;
            let teardown = self.teardown;
            tokio::spawn(async move {
                let reading = {
                    let upstream = Arc::clone(&owner);
                    let client = Arc::clone(&owner);
                    async move {
                        tokio::select! {
                            () = upstream.serve_after(upstream_reader, true, held) => (),
                            () = client.serve(client_reader, false) => (),
                        }
                    }
                };
                // The writes run beside the reads and outlive them by exactly as long as it
                // takes to finish what was already queued: an answer this host admitted must
                // reach the socket even though the end that would have sent the next frame has
                // closed. The writer is then joined rather than abandoned, so teardown does not
                // race a frame that is still going out.
                let mut writing = tokio::spawn(writes);
                reading.await;
                let asked_to_stop = owner.stopping();
                owner.shutdown();
                if tokio::time::timeout(teardown, &mut writing).await.is_err() {
                    // A writer that has not finished by now is writing to an end that has stopped
                    // reading. It is ended rather than left detached, because a task nobody holds
                    // is a task nothing can stop.
                    writing.abort();
                    let _ = (&mut writing).await;
                }
                broker.unbind_dispatch(application_instance_id, &carrying);
                broker.close_connection(connection);
                observatory.withdraw(connection);
                let closure = if asked_to_stop {
                    Closure::Shutdown
                } else {
                    Closure::Detached
                };
                Ended { closure }
            })
        };
        Ok(Attached {
            connection,
            owner,
            observations: Some(observations),
            served,
            broker: Arc::clone(&self.broker),
        })
    }

    /// Reads the one frame a connection writes before it is authenticated.
    async fn first_frame<R>(&self, reader: &mut R) -> Result<(FirstFrame, Vec<u8>)>
    where
        R: tokio::io::AsyncRead + Unpin + Send,
    {
        use tokio::io::AsyncReadExt as _;

        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        // One deadline for the whole frame. A deadline per read would let a peer that dribbles a
        // byte at a time hold the endpoint for as long as it liked.
        let deadline = tokio::time::Instant::now() + HELLO_DEADLINE;
        let body = loop {
            if let Some(body) = self.launch.framing.decode(&mut buffer)? {
                break body;
            }
            let read = tokio::time::timeout_at(deadline, reader.read(&mut chunk))
                .await
                .map_err(|_| {
                    BrokerError::denied(format!(
                        "this connection did not say who it is within {} seconds, so there is \
                         nothing to authenticate it by",
                        HELLO_DEADLINE.as_secs()
                    ))
                })?
                .map_err(|error| {
                    BrokerError::denied(format!("this connection could not be read: {error}"))
                })?;
            if read == 0 {
                return Err(BrokerError::denied(
                    "this connection closed before it said who it was",
                ));
            }
            buffer.extend_from_slice(&chunk[..read]);
        };
        let frame: FirstFrameWire = serde_json::from_slice(&body).map_err(|error| {
            BrokerError::denied(format!(
                "this connection's first frame is neither a bridge nor a launch saying who it is: \
                 {error}"
            ))
        })?;
        let frame = match frame {
            FirstFrameWire::Hello { kr_hello } => {
                let credential = decode_credential(&kr_hello.credential)?;
                FirstFrame::Hello(kr_hello, credential)
            }
            FirstFrameWire::Launch { kr_launch } => {
                let credential = decode_credential(&kr_launch.credential)?;
                FirstFrame::Launch(kr_launch, credential)
            }
        };
        Ok((frame, buffer))
    }
}

/// One connection's first frame on the wire: a bridge's hello or a launch presenting itself.
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum FirstFrameWire {
    Hello { kr_hello: Hello },
    Launch { kr_launch: LaunchHello },
}

/// One connection's first frame, read, with its credential decoded.
enum FirstFrame {
    Hello(Hello, Vec<u8>),
    Launch(LaunchHello, Vec<u8>),
}

/// What an invocation presents to the backend before it becomes the program it runs.
///
/// Nothing in it is authority. The command backend compares the process with what the kernel
/// names, the credential with the one it generated, and the executable and arguments with the
/// invocation it was established for.
#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchHello {
    /// The credential the launcher read from the backend's owner-only file, as hexadecimal.
    credential: String,
    /// The process the launcher is, which the program it runs will be.
    pub pid: u64,
    /// That process's start value.
    pub start: u64,
    /// The executable the launcher will run.
    pub executable: String,
    /// The argument vector it will run it with, command name first.
    pub arguments: Vec<String>,
    /// The environment the launcher runs in, which a backend that starts an application server
    /// for the program starts it with. Presented only to a backend whose launch record names a
    /// gateway.
    #[serde(default)]
    pub environment: Option<PresentedEnvironment>,
}

impl std::fmt::Debug for LaunchHello {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The credential is the launch's secret and is never shown.
        formatter
            .debug_struct("LaunchHello")
            .field("pid", &self.pid)
            .field("start", &self.start)
            .field("executable", &self.executable)
            .field("arguments", &self.arguments)
            .field("environment", &self.environment)
            .finish_non_exhaustive()
    }
}

/// The environment a launcher presented.
///
/// It can hold what the person keeps in their environment, so it is shown to nothing: its debug
/// form says how many variables it has and no more.
#[derive(Clone, Default, serde::Deserialize)]
#[serde(transparent)]
pub struct PresentedEnvironment(BTreeMap<String, String>);

impl PresentedEnvironment {
    /// The bytes of its names and values together.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.0
            .iter()
            .map(|(name, value)| name.len() + value.len())
            .sum()
    }

    /// The variables, as a process is started with them.
    #[must_use]
    pub fn pairs(&self) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
        self.0
            .iter()
            .map(|(name, value)| (name.into(), value.into()))
            .collect()
    }
}

impl std::fmt::Debug for PresentedEnvironment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "PresentedEnvironment({} variables)",
            self.0.len()
        )
    }
}

/// One connection whose first frame said it is what it opened as.
pub enum Opening {
    /// A native bridge's hello, not yet authenticated.
    Bridge(PendingBridge),
    /// An invocation presenting itself to the backend, not yet authenticated.
    Launch(PresentedLaunch),
}

/// A bridge that has said who it is and is waiting to be admitted.
pub struct PendingBridge {
    peer: PeerIdentity,
    reader: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    writer: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    hello: Hello,
    credential: Vec<u8>,
    held: Vec<u8>,
}

/// A bridge that passed every check against the launch it belongs to and has not been answered.
pub struct AuthenticatedBridge {
    surface: crate::broker::bridge::BridgeSurface,
    process: crate::broker::bridge::BridgeProcess,
    stream: crate::broker::bridge::BridgeStream,
}

impl std::fmt::Debug for AuthenticatedBridge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedBridge")
            .field("surface", &self.surface)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedBridge {
    /// Answers the bridge that it is admitted, and hands it over.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UpstreamUnavailable`] when the admission cannot be written.
    pub async fn admit(mut self) -> Result<crate::broker::bridge::AdmittedBridge> {
        self.stream
            .write_frame(&crate::broker::bridge::admission_frame(self.surface))
            .await?;
        Ok(crate::broker::bridge::AdmittedBridge {
            surface: self.surface,
            process: self.process,
            stream: self.stream,
        })
    }
}

impl std::fmt::Debug for PendingBridge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingBridge")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

/// An invocation that has presented itself and is waiting for the backend's answer.
pub struct PresentedLaunch {
    /// Who the kernel says is on the other end.
    pub peer: PeerIdentity,
    /// The credential it presented, decoded.
    pub credential: Vec<u8>,
    /// What it presented.
    pub launch: LaunchHello,
    /// The connection, for the answer and what follows it.
    pub stream: crate::broker::bridge::BridgeStream,
}

impl std::fmt::Debug for PresentedLaunch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PresentedLaunch")
            .field("peer", &self.peer)
            .field("pid", &self.launch.pid)
            .field("executable", &self.launch.executable)
            .finish_non_exhaustive()
    }
}

/// The two halves of an accepted connection, whichever kind this platform bound.
type Halves = (
    Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
);

/// Separates an accepted connection into the halves its owner reads and writes.
fn split_stream(stream: Stream) -> Halves {
    match stream {
        #[cfg(unix)]
        Stream::Socket(socket) => {
            let (reader, writer) = tokio::io::split(socket);
            (Box::new(reader), Box::new(writer))
        }
        #[cfg(windows)]
        Stream::Pipe(pipe) => {
            let (reader, writer) = tokio::io::split(pipe);
            (Box::new(reader), Box::new(writer))
        }
    }
}

/// Reads back from the operating system the process a hello presents.
///
/// The identity a bridge presents is read back rather than believed: a start value the operating
/// system does not report for that identifier is a process the bridge is not.
fn presented_process(hello: &Hello) -> Result<ProcessStartIdentity> {
    let presented_pid = u32::try_from(hello.pid).map_err(|_| {
        BrokerError::denied("this connection named no process this host could read")
    })?;
    let read = kr_ipc::identity::process_start_identity(presented_pid).map_err(|error| {
        BrokerError::denied(format!(
            "this connection named process {presented_pid}, which this host cannot read: {error}"
        ))
    })?;
    if read.start_value.get() != hello.start {
        return Err(BrokerError::denied(format!(
            "this connection says process {presented_pid} started at {} and the operating system \
             says {}",
            hello.start,
            read.start_value.get()
        )));
    }
    Ok(read)
}

/// Reads the hexadecimal credential a bridge presents.
fn decode_credential(text: &str) -> Result<Vec<u8>> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) {
        return Err(BrokerError::denied("a launch credential is hexadecimal"));
    }
    let mut bytes = Vec::with_capacity(text.len() / 2);
    for index in (0..text.len()).step_by(2) {
        let pair = text
            .get(index..index + 2)
            .ok_or_else(|| BrokerError::denied("a launch credential is hexadecimal"))?;
        bytes.push(
            u8::from_str_radix(pair, 16)
                .map_err(|_| BrokerError::denied("a launch credential is hexadecimal"))?,
        );
    }
    Ok(bytes)
}

/// Builds the hello frame a bridge writes, for the forwarder and for tests that stand in for one.
///
/// It is here rather than in the forwarder because the shape belongs to the host that reads it:
/// one definition, so a bridge and this listener cannot drift apart.
#[must_use]
pub fn hello_frame(
    credential: &str,
    process: &ProcessStartIdentity,
    session: Option<&str>,
    headers: &BTreeMap<String, String>,
) -> Vec<u8> {
    serde_json::json!({
        "kr_hello": {
            "credential": credential,
            "pid": process.pid.get(),
            "start": process.start_value.get(),
            "session": session,
            "headers": headers,
        }
    })
    .to_string()
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(reset: bool, lost_through: Option<u64>) -> crate::broker::TransitionReplay {
        crate::broker::TransitionReplay {
            events: Vec::new(),
            cursor: crate::broker::ReplayCursor {
                generation: 1,
                sequence: 0,
            },
            reset,
            lost_through,
            more: false,
        }
    }

    #[test]
    fn a_loss_is_news_once_and_a_later_loss_is_news_again() {
        let mut reported = 0;
        assert!(!news_in(&page(false, None), &mut reported), "nothing lost");
        assert!(
            news_in(&page(false, Some(5)), &mut reported),
            "a first loss"
        );
        assert!(
            !news_in(&page(false, Some(5)), &mut reported),
            "the same loss on a later page or in a later recovery"
        );
        assert!(
            news_in(&page(false, Some(9)), &mut reported),
            "a loss that grew while the lock was given back, even inside one recovery"
        );
        assert!(!news_in(&page(false, Some(9)), &mut reported));
        assert!(
            news_in(&page(true, None), &mut reported),
            "a reset starts the stream again"
        );
        assert!(
            news_in(&page(false, Some(3)), &mut reported),
            "and a loss after it is measured in the new generation's positions"
        );
    }
}
