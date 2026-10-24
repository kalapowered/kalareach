//! Reaching the host on this machine, and publishing what it says.
//!
//! The desktop application connects to the controller on its own machine over local IPC. That is
//! the only connection it makes on its own: pairing another host is an explicit act with its own
//! screen, and a client that dialled out at startup would be making a decision the person has not
//! made.
//!
//! When the connection cannot be made the application is unconnected and says so, and it tries
//! again, after a pause that grows while the host does not answer. That is a state the interface
//! has to have anyway, because a host that stops answering produces it, and it is the state
//! section 13 is most specific about: a host that cannot be contacted is disconnected, and nothing
//! about elapsed time makes its processes failed.

use std::sync::Arc;

use kr_client::organisation::LeaseStop;
use kr_client::pairing::link::LinkError;
use kr_client::pairing::paired::PairedHost;
use kr_client::{Said as _, Session};
use kr_protocol::ids::{BuildId, DeviceId, EnvironmentId};
use kr_protocol::rights::ActionRight;
use serde::Serialize;
use tauri::{AppHandle, Emitter as _, Manager as _, Runtime};

use crate::device::Device;
use crate::error::{CommandError, Result};
use crate::state::AppState;

/// How long a connection to a paired host, and the question that follows it, may take.
pub(crate) const CONNECT_WITHIN: std::time::Duration = std::time::Duration::from_secs(20);

/// The event the backend publishes each host notification on.
pub const HOST_EVENT: &str = "kr://event";

/// The event the backend publishes a change of connection state on.
pub const CONNECTION_EVENT: &str = "kr://connection";

/// The build this client declares in its handshake.
///
/// The host records it, and refuses a connection whose protocol major it does not share.
///
/// # Errors
///
/// Returns the failure when the compiled version is not a valid build identity, which is a
/// packaging mistake rather than a runtime condition.
pub fn build_id() -> Result<BuildId> {
    BuildId::new(concat!("kalareach-companion/", env!("CARGO_PKG_VERSION")))
        .map_err(|error| CommandError::local_failure(error.to_string()))
}

/// Who this application is on the host it reached, and what the host lets it do there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Standing {
    /// The owner at this machine, over its own socket: every right.
    Owner,
    /// A device the host paired with: the rights its grant carries, as this device recorded them
    /// when it paired, under the identity the host gave it.
    Paired {
        /// The device identity the host gave this application.
        device_id: DeviceId,
        /// What the host decided this connection may do, when it opened it for the host. The host
        /// checks each action against its own record again.
        rights: Vec<ActionRight>,
        /// The host, which the connections opened for one session are made to.
        host: Box<PairedHost>,
    },
}

/// How another connection to the same host is opened: for a client that asks the host again with
/// a request it sent on this one, or reads its state, and must not do either on the connection
/// that may still carry the original.
pub type Reopen = Arc<
    dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Connection>> + Send>>
        + Send
        + Sync,
>;

/// What puts a connection in the place of the withdrawn connection `session` was, when that is
/// still the connection held to the host on this machine.
pub type Replacer = Arc<dyn Fn(&Arc<Session>, Connection) + Send + Sync>;

/// A live connection to a host: the one on this machine, or one this device is paired with.
///
/// Cloning it shares the session; it does not open another connection.
#[derive(Clone)]
pub struct Connection {
    session: Arc<Session>,
    environment_id: EnvironmentId,
    standing: Standing,
    /// The operating-system user the host authenticated on a local connection: the host makes the
    /// actor its actions are claimed under from it.
    local_user: Option<u64>,
    reopen: Option<Reopen>,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Connection")
            .field("environment_id", &self.environment_id)
            .field("standing", &self.standing)
            .finish_non_exhaustive()
    }
}

impl Connection {
    /// A connection over a local transport, belonging to the environment the host stamped on the
    /// handshake.
    ///
    /// # Errors
    ///
    /// Returns the client library's refusal to start a session on the transport.
    pub fn over(transport: kr_client::ipc::IpcTransport) -> Result<Self> {
        let environment_id = transport.context().environment_id;
        let local_user = transport.context().peer.uid.get();
        let session = Session::start(transport.shared())?;
        Ok(Self {
            session: Arc::new(session),
            environment_id,
            standing: Standing::Owner,
            local_user: Some(local_user),
            reopen: None,
        })
    }

    /// A connection assembled from a session the caller started on a transport of its own, and
    /// what is true of it. The application builds its connections with [`Self::over`],
    /// [`Self::paired`] and [`connect_local`]; a suite that puts something between a session and
    /// the host, to lose an answer, builds this.
    #[must_use]
    pub fn assembled(
        session: Session,
        environment_id: EnvironmentId,
        standing: Standing,
        local_user: Option<u64>,
        reopen: Option<Reopen>,
    ) -> Self {
        Self {
            session: Arc::new(session),
            environment_id,
            standing,
            local_user,
            reopen,
        }
    }

    /// This connection, with the way another to the same host is opened.
    #[must_use]
    pub fn reopening(mut self, reopen: Reopen) -> Self {
        self.reopen = Some(reopen);
        self
    }

    /// Opens another connection to the same host, as the same device or user.
    ///
    /// # Errors
    ///
    /// Returns why the host could not be reached, or that this connection cannot be opened again.
    pub async fn another(&self) -> Result<Self> {
        match &self.reopen {
            // The one opened can be opened from again: it may take the place of this one.
            Some(reopen) => Ok(reopen().await?.reopening(Arc::clone(reopen))),
            None => Err(CommandError::unavailable(
                "this application cannot open a second connection to this host",
            )),
        }
    }

    /// The actor the host claims this connection's actions under, when this build can say: a local
    /// caller's, which the host makes from the user it authenticated.
    #[must_use]
    pub fn actor(&self) -> Option<kr_protocol::ids::ActorId> {
        self.local_user.map(kr_protocol::sharing::local_actor)
    }

    /// A connection to a host this device is paired with, as the device the host made it, opened
    /// for the host.
    ///
    /// The environment is the one the host says it is, read over the connection: a paired
    /// connection carries no environment on its handshake. The connection is opened for the host
    /// alone: it serves the host's own reads under the pairing, and the host refuses it every
    /// decision under a share and every route to a session's worker, so no share's end reaches it.
    /// A session is opened on a connection of its own ([`crate::standing`]). The rights it reports
    /// are the ones the host decided the open with, not the ones the pairing proposed.
    ///
    /// # Errors
    ///
    /// Returns the failure when the host cannot be reached, cannot say which environment it is, or
    /// refuses to open the connection.
    pub async fn paired(device: &Arc<Device>, host: &PairedHost) -> Result<Self> {
        let connection = Self::paired_once(device, host).await?;
        let (device, host) = (Arc::clone(device), host.clone());
        Ok(connection.reopening(Arc::new(move || {
            let (device, host) = (Arc::clone(&device), host.clone());
            Box::pin(async move { Self::paired_once(&device, &host).await })
        })))
    }

    /// A connection to a paired host for a visit: a look at a host that is not the one this device
    /// is using, as [`Self::paired`] opens one, except that it never cuts off the connection to the
    /// host in use (see [`kr_client::pairing::link::HostLink::visit_paired`]) and says whether the
    /// host refused it. It is not opened again when it ends: whoever visits opens another.
    ///
    /// # Errors
    ///
    /// Returns [`Unopened::Refused`] with the host's refusal when the host answered and refused at
    /// any step, and [`Unopened::Unreached`] with why when it could not be reached or did not
    /// answer.
    pub async fn visited(
        device: &Arc<Device>,
        host: &PairedHost,
    ) -> std::result::Result<Self, Unopened> {
        Self::open(device, host, true).await
    }

    async fn paired_once(device: &Arc<Device>, host: &PairedHost) -> Result<Self> {
        Self::open(device, host, false)
            .await
            .map_err(Unopened::into_error)
    }

    /// Opens the connection, as a visit when `visiting`.
    async fn open(
        device: &Arc<Device>,
        host: &PairedHost,
        visiting: bool,
    ) -> std::result::Result<Self, Unopened> {
        let pairing = device.pairing();
        let identity = pairing.candidate.paired_identity(host.device_id);
        let connecting = async {
            if visiting {
                let in_use = || device.host_in_use().map(|using| using.network_config);
                pairing.link.visit_paired(host, &identity, &in_use).await
            } else {
                pairing.link.connect_paired(host, &identity).await
            }
        };
        let session = tokio::time::timeout(CONNECT_WITHIN, connecting)
            .await
            .map_err(|_| Unopened::unreached("the host did not answer in time"))?
            .map_err(|error| match error {
                LinkError::Refused(refusal) => Unopened::Refused(CommandError::from(refusal)),
                other => Unopened::unreached(other.said().into_string()),
            })?;
        let info: kr_protocol::hostinfo::HostInfoResult = tokio::time::timeout(
            CONNECT_WITHIN,
            session.read(
                kr_protocol::method::Method::HostInfo,
                &crate::commands::NoParams {},
            ),
        )
        .await
        .map_err(|_| Unopened::unreached("the host did not say which environment it is"))?
        .map_err(Unopened::of_read)?;
        let rights = open_for_the_host(&session).await?;
        Ok(Self {
            session: Arc::new(session),
            environment_id: info.environment_id,
            standing: Standing::Paired {
                device_id: host.device_id,
                rights,
                host: Box::new(host.clone()),
            },
            local_user: None,
            reopen: None,
        })
    }

    /// Who this application is on the host, and what that lets it do.
    #[must_use]
    pub const fn standing(&self) -> &Standing {
        &self.standing
    }

    /// The session every command goes through.
    #[must_use]
    pub fn session(&self) -> Arc<Session> {
        Arc::clone(&self.session)
    }

    /// The environment this connection belongs to, as the host stamped it.
    ///
    /// It comes from the handshake rather than from the page: an environment the WebView named
    /// would be a value the WebView chose.
    #[must_use]
    pub const fn environment_id(&self) -> EnvironmentId {
        self.environment_id
    }
}

/// Opens a paired connection for the host alone, and returns the rights the host decided the open
/// with.
///
/// A host of an earlier build does not list the method and refuses it as any unlisted method is
/// refused, so a refusal that is not a transient one says that.
async fn open_for_the_host(session: &Session) -> std::result::Result<Vec<ActionRight>, Unopened> {
    use kr_protocol::scalars::Nullable;
    use kr_protocol::session::{SessionOpenParams, SessionOpenResult};

    let opened = tokio::time::timeout(
        CONNECT_WITHIN,
        session.read::<_, SessionOpenResult>(
            kr_protocol::method::Method::SessionOpen,
            &SessionOpenParams {
                session_id: Nullable::null(),
                grant_id: Nullable::null(),
            },
        ),
    )
    .await
    .map_err(|_| Unopened::unreached("the host did not open the connection in time"))?
    .map_err(|error| match error {
        kr_client::ClientError::Host(refusal)
            if matches!(
                refusal.code,
                kr_protocol::error::ErrorCode::PermissionDenied
                    | kr_protocol::error::ErrorCode::InvalidArgument
            ) =>
        {
            Unopened::Refused(CommandError::stated(
                refusal.code,
                format!(
                    "{} If the host is of an earlier build than this application, update it.",
                    refusal.message
                ),
            ))
        }
        other => Unopened::of_read(other),
    })?;
    match opened {
        SessionOpenResult::InForce { actions, .. } => Ok(actions.iter().copied().collect()),
        SessionOpenResult::Ended { .. } => Err(Unopened::Refused(CommandError::stated(
            kr_protocol::error::ErrorCode::PermissionDenied,
            "the host answered that this connection has ended",
        ))),
    }
}

/// Why a connection to a paired host was not opened.
#[derive(Debug)]
pub enum Unopened {
    /// The host answered, and refused: it is in contact, and the refusal is its own.
    Refused(CommandError),
    /// The host could not be reached, did not answer in time, or failed in a way that is no
    /// refusal of the host's.
    Unreached(CommandError),
}

impl Unopened {
    fn unreached(reason: impl Into<String>) -> Self {
        Self::Unreached(CommandError::unavailable(reason))
    }

    /// What a failed read says: a refusal when the host sent an error, and otherwise that the host
    /// was not reached.
    #[must_use]
    pub fn of_read(error: kr_client::ClientError) -> Self {
        match error {
            kr_client::ClientError::Host(_) => Self::Refused(CommandError::from(error)),
            _ => Self::Unreached(CommandError::from(error)),
        }
    }

    /// The failure, as a command that needed the connection answers with it.
    #[must_use]
    pub fn into_error(self) -> CommandError {
        match self {
            Self::Refused(error) | Self::Unreached(error) => error,
        }
    }
}

/// What the interface is told about the connection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConnectionState {
    /// True while a session is live.
    pub connected: bool,
    /// The environment the connection belongs to, when there is one.
    pub environment_id: Option<String>,
    /// Why there is no connection, in plain words, when there is none.
    pub reason: Option<String>,
    /// What this connection may do, when it is live.
    ///
    /// The connection is to the host on this machine, over its own socket, which authenticated the
    /// operating-system user this application runs as: the host's owner, whose authority is every
    /// action. A control whose visibility turns on a right is shown from this, and the host checks
    /// the right again when the action arrives.
    pub rights: Option<Vec<kr_protocol::rights::ActionRight>>,
    /// True while the live connection is to a host this device is paired with, and false for the
    /// host on this machine and when there is no connection.
    ///
    /// A file this application uploads goes to the host on this machine. A host this device is
    /// paired with takes no file from it, so the page offers no attachment over one.
    pub paired: bool,
    /// How many times, since this application started, a connection the host withdrew has been
    /// replaced by one it admits. A request refused on the withdrawn connection was answered with a
    /// failure just before the replacement, so the page says so whenever this grows.
    pub replaced: u64,
}

impl ConnectionState {
    /// The state of an application that has not reached a host.
    #[must_use]
    pub fn unreachable(reason: impl Into<String>) -> Self {
        Self {
            connected: false,
            environment_id: None,
            reason: Some(reason.into()),
            rights: None,
            paired: false,
            replaced: 0,
        }
    }

    /// The state of a live connection to the host on this machine, in `environment_id`.
    #[must_use]
    pub fn owner(environment_id: EnvironmentId) -> Self {
        Self {
            connected: true,
            environment_id: Some(environment_id.to_string()),
            reason: None,
            rights: Some(kr_protocol::rights::ActionRight::ALL.to_vec()),
            paired: false,
            replaced: 0,
        }
    }

    /// The state of a live connection to a host this device is paired with, in `environment_id`,
    /// with the rights its grant carries.
    #[must_use]
    pub fn paired(
        environment_id: EnvironmentId,
        rights: Vec<kr_protocol::rights::ActionRight>,
    ) -> Self {
        Self {
            connected: true,
            environment_id: Some(environment_id.to_string()),
            reason: None,
            rights: Some(rights),
            paired: true,
            replaced: 0,
        }
    }

    /// The state of a live connection, with the rights its standing gives.
    #[must_use]
    pub fn of(connection: &Connection) -> Self {
        match &connection.standing {
            Standing::Owner => Self::owner(connection.environment_id),
            Standing::Paired { rights, .. } => {
                Self::paired(connection.environment_id, rights.clone())
            }
        }
    }
}

/// Connects to the controller on this machine.
///
/// # Errors
///
/// Returns the failure when there is no controller to reach, when its endpoint belongs to another
/// user, or when the two builds share no protocol major.
pub async fn connect_local() -> Result<Connection> {
    Ok(connect_local_once()
        .await?
        .reopening(Arc::new(|| Box::pin(connect_local_once()))))
}

/// One connection to the controller on this machine, that cannot be opened again from.
async fn connect_local_once() -> Result<Connection> {
    let paths = kr_ipc::paths::HostPaths::discover()
        .map_err(|error| CommandError::unavailable(format!("no host on this machine: {error}")))?;
    let environment_id = paths
        .open_environment_id()
        .map_err(|error| CommandError::unavailable(format!("no host on this machine: {error}")))?;
    let endpoint = paths
        .environment(environment_id)
        .controller_endpoint()
        .map_err(|error| CommandError::unavailable(format!("no host on this machine: {error}")))?;
    let transport = kr_client::ipc::IpcTransport::connect_app(&endpoint, build_id()?)
        .await
        .map_err(absent_host)?;
    Connection::over(transport)
}

/// Names the ordinary case of no host running before it reaches the window.
///
/// A socket that is not there, or that nothing is listening on, is not a fault in either build: it
/// is what this machine looks like before the host is started. The window has to say something,
/// and "no such file or directory" is the operating system talking about a path the person never
/// chose. Every other failure keeps its own words, because they describe something that did go
/// wrong.
fn absent_host(error: kr_client::error::ClientError) -> CommandError {
    if let kr_client::error::ClientError::Ipc(kr_ipc::IpcError::Socket { source, .. }) = &error
        && matches!(
            source.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
        )
    {
        return CommandError::unavailable("no host on this machine");
    }
    CommandError::from(error)
}

/// What one attempt to reach a host came to.
#[derive(Debug)]
pub enum Attempt {
    /// The host answered, and this is the connection to it.
    Reached(Connection),
    /// The host did not answer, and why.
    Failed(CommandError),
    /// There is nothing to keep a connection to, so the task that keeps it ends.
    Nothing,
}

/// Keeps a connection to a host for `choice`: reaches it with `attempt`, forwards what it
/// publishes, and when it ends, or the host does not answer, reaches it again.
///
/// The pause between attempts is the client library's reconnect backoff (section 23): jittered
/// exponential from 250 ms to 30 seconds, starting over once a connection has been stable. `first`
/// is told once the first attempt has ended either way. The task ends as soon as another host is
/// chosen: it installs a connection, or records that it has none, only while its own choice is the
/// one in force.
pub async fn keep<R, A, F>(
    app: AppHandle<R>,
    choice: u64,
    mut first: Option<tokio::sync::oneshot::Sender<()>>,
    mut attempt: A,
) where
    R: Runtime,
    A: FnMut() -> F + Send,
    F: std::future::Future<Output = Attempt> + Send,
{
    let mut backoff = kr_client::reconnect::ReconnectLoop::new();
    loop {
        let state = app.state::<AppState>();
        match attempt().await {
            Attempt::Nothing => return,
            Attempt::Reached(connection) => {
                let session = connection.session();
                // Before the connection is announced to anything, so that nothing the host sends
                // on it can come before the subscription: an event sent to a connection nobody
                // listens on yet is lost to the page.
                let events = session.events();
                let environment_id = connection.environment_id();
                let paired_host = match connection.standing() {
                    Standing::Paired { host, .. } => Some(host.host_device_id),
                    Standing::Owner => None,
                };
                // A host whose grant answers to an organisation holds this device's lease only while
                // the device keeps it fresh.
                let leased = match connection.standing() {
                    Standing::Paired { host, .. }
                        if host.proposed_grant.organisation.as_ref().is_some() =>
                    {
                        Some((**host).clone())
                    }
                    _ => None,
                };
                if !state.connected_for(choice, connection) {
                    return;
                }
                let _ = app.emit(CONNECTION_EVENT, state.connection_state());
                // A host that is reached again is asked once more for what a call left owed it.
                if let (Some(host), Some(calls)) =
                    (paired_host, app.try_state::<crate::voice::Calls>())
                {
                    calls.host_reached(host, environment_id, Arc::clone(&session));
                }
                if let Some(first) = first.take() {
                    let _ = first.send(());
                }
                // The lease is kept for as long as the connection lasts, in this task: when the
                // person chooses another host or forgets this one, the task ends and the lease is
                // no longer kept. When something only a person can mend stops it, the connection
                // says so and ends, and the next attempt presents the lease first and says the
                // same until it is mended.
                let leased = leased.and_then(|host| {
                    let device = state.device().ok()?;
                    let desk = device.leases()?.clone();
                    let key = *device
                        .pairing()
                        .candidate
                        .paired_identity(host.device_id)
                        .authorisation
                        .public();
                    Some((desk, host, key))
                });
                // A connection that did not last is not a recovery: a host that accepts and then
                // closes is waited for as one that does not answer.
                backoff.connected();
                let ended =
                    forward_events(app.clone(), Arc::clone(&session), environment_id, events);
                tokio::pin!(ended);
                if let Some((desk, host, key)) = leased {
                    let kept = desk.keep(&session, &host, key);
                    tokio::select! {
                        () = &mut ended => {}
                        stopped = kept => {
                            if let Some(stopped) = stopped {
                                // A connection whose lease is not kept is let go, so the next one
                                // presents it first. One the host ended needs no word to the person.
                                if stopped != LeaseStop::ConnectionEnded
                                    && state.disconnected_for(choice, stopped.to_string())
                                {
                                    let _ = app.emit(CONNECTION_EVENT, state.connection_state());
                                }
                                session.close();
                            }
                            // The connection is closed or closing, and ends the way any does.
                            ended.await;
                        }
                    }
                } else {
                    ended.await;
                }
            }
            Attempt::Failed(error) => {
                if !state.disconnected_for(choice, error.message) {
                    return;
                }
                let _ = app.emit(CONNECTION_EVENT, state.connection_state());
                if let Some(first) = first.take() {
                    let _ = first.send(());
                }
            }
        }
        tokio::time::sleep(backoff.disconnected()).await;
    }
}

/// Keeps the connection to the host on this machine, as the application's host: it is reached, and
/// reached again when it ends, until another host is chosen.
///
/// # Errors
///
/// Returns why the choice could not be made.
pub fn reach_host_on_this_machine<R, A, F>(app: &AppHandle<R>, attempt: A) -> Result<()>
where
    R: Runtime,
    A: FnMut() -> F + Send + 'static,
    F: std::future::Future<Output = Attempt> + Send + 'static,
{
    let handle = app.clone();
    app.state::<AppState>().choose_host(
        "this application is reaching the host on this machine",
        |choice| {
            Ok(tauri::async_runtime::spawn(keep(
                handle, choice, None, attempt,
            )))
        },
    )
}

/// One attempt to reach the controller on this machine.
pub async fn this_machines_host() -> Attempt {
    match connect_local().await {
        Ok(connection) => Attempt::Reached(connection),
        Err(error) => Attempt::Failed(error),
    }
}

/// One host notification, in the shape the interface reads.
#[derive(Clone, Debug, Serialize)]
pub struct PublishedEvent {
    /// The environment of the host it came from. The page drops an event of a host it no longer
    /// uses, so one still on its way when the host changed is not taken for the new host's.
    pub host: String,
    /// The stream it belongs to.
    pub stream_id: String,
    /// Its position in that stream.
    pub sequence: String,
    /// What happened.
    pub event_type: String,
    /// The payload, as JSON.
    pub payload: serde_json::Value,
}

/// Reads an event payload into the shape the page reads.
///
/// The payload of an event is the canonical value the host sent, and its shape depends on the
/// event type. What crosses to the page is its JSON representation, which is the same form every
/// other answer arrives in. A payload that has no JSON representation is published as null beside
/// its event type, so the view still learns that the event happened and asks for a snapshot rather
/// than being handed something it cannot read.
fn read_payload(payload: &kr_protocol::envelope::ParamsValue) -> serde_json::Value {
    payload
        .to_typed::<serde_json::Value>()
        .unwrap_or(serde_json::Value::Null)
}

/// Waits for the question of whether the host withdrew a connection to end, if one is out.
async fn question_ended(asking: &mut Option<tauri::async_runtime::JoinHandle<()>>) {
    if let Some(asking) = asking.as_mut() {
        let _ = asking.await;
    }
}

/// Publishes the session's events to the window until the connection ends, and then says so.
///
/// `events` is the session's subscription, taken by the caller before anything could be sent on the
/// connection: a subscription made here, when this task first runs, would miss whatever the host
/// sent in between.
///
/// Every event carries the stream it came from, so a view that is showing one session can ignore
/// another's. A client that published events without their stream would leave each view guessing
/// whether an event was its own. When the connection ends the application is told it is not
/// connected, and its state says so, so a command made afterwards is refused as unconnected rather
/// than sent down a connection that is gone.
pub async fn forward_events<R: Runtime>(
    app: AppHandle<R>,
    session: Arc<Session>,
    host: EnvironmentId,
    mut events: tokio::sync::broadcast::Receiver<kr_protocol::envelope::Notification>,
) {
    let host = host.to_string();
    // The question of whether the host withdrew this connection, while one is out: one at a time.
    let mut asking: Option<tauri::async_runtime::JoinHandle<()>> = None;
    loop {
        let heard = tokio::select! {
            heard = events.recv() => heard,
            // The host refused a request on this connection as not permitted. A host that
            // withdrew what the connection was admitted under refuses everything on it and does
            // not close it, so whether this is that is asked of the host, over another connection,
            // and nothing waits on the answer: events go on being forwarded meanwhile. The
            // question is asked one at a time. Its own refusal raises no signal, and what other
            // requests are refused while it is out is the same answer to it, not a new question.
            () = session.denied(), if asking.is_none() => {
                let app = app.clone();
                let session = Arc::clone(&session);
                asking = Some(tauri::async_runtime::spawn(async move {
                    app.state::<AppState>().replace_if_withdrawn(&session).await;
                }));
                continue;
            }
            () = question_ended(&mut asking), if asking.is_some() => {
                asking = None;
                let _ = tokio::time::timeout(std::time::Duration::ZERO, session.denied()).await;
                continue;
            }
            () = session.closed() => {
                let state = app.state::<AppState>();
                state.disconnected_from(&session, "the connection to this host ended");
                let _ = app.emit(CONNECTION_EVENT, state.connection_state());
                return;
            }
        };
        match heard {
            Ok(notification) => {
                let published = PublishedEvent {
                    host: host.clone(),
                    payload: read_payload(&notification.payload),
                    stream_id: notification.stream_id.to_string(),
                    sequence: notification.sequence.to_string(),
                    event_type: notification.event_type.to_string(),
                };
                if app.emit(HOST_EVENT, published).is_err() {
                    return;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                // The interface fell behind the host. Section 8 makes that a resynchronisation
                // rather than a gap to paper over, so the view is told to take a snapshot again
                // instead of receiving a stream with a hole in it.
                if app
                    .emit(
                        HOST_EVENT,
                        PublishedEvent {
                            host: host.clone(),
                            stream_id: String::new(),
                            sequence: String::new(),
                            event_type: "resync_required".to_owned(),
                            payload: serde_json::Value::Null,
                        },
                    )
                    .is_err()
                {
                    return;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_declared_build_identity_is_valid() {
        let build = build_id().expect("a valid build identity");
        assert!(build.as_str().starts_with("kalareach-companion/"));
    }

    /// KR-REQ-11.48: a live connection to the host on this machine says what it may do, in the
    /// protocol's own names, so a control whose visibility turns on a right is decided from a fact
    /// rather than a guess; a lost connection says nothing about rights at all.
    #[test]
    fn a_live_local_connection_carries_every_right_and_a_lost_one_none() {
        let environment: EnvironmentId = "3f1a2c40-11aa-4b2c-9d3e-000000000001"
            .parse()
            .expect("an environment identity");
        let live = serde_json::to_value(ConnectionState::owner(environment)).expect("encodes");
        let rights: Vec<String> = serde_json::from_value(live["rights"].clone()).expect("a list");
        let every: Vec<String> = kr_protocol::rights::ActionRight::ALL
            .iter()
            .map(|right| {
                serde_json::to_value(right)
                    .expect("encodes")
                    .as_str()
                    .expect("a name")
                    .to_owned()
            })
            .collect();
        assert_eq!(rights, every);
        assert!(rights.contains(&"agent.prompt".to_owned()));
        assert_eq!(live["connected"], serde_json::Value::Bool(true));
        assert_eq!(
            live["environment_id"],
            serde_json::json!(environment.to_string())
        );

        let lost = serde_json::to_value(ConnectionState::unreachable("no host")).expect("encodes");
        assert_eq!(lost["rights"], serde_json::Value::Null);
    }

    /// A read that failed is the host's refusal when the host sent an error, and the host not
    /// reached otherwise: a visit draws the first as an answer and the second as lost contact.
    #[test]
    fn a_failed_read_is_a_refusal_only_when_the_host_sent_the_error() {
        use kr_protocol::error::{ErrorCode, ProtocolError};

        let sent = kr_client::ClientError::Host(ProtocolError::new(
            ErrorCode::StorageUnavailable,
            "the host cannot read its store",
        ));
        let Unopened::Refused(refusal) = Unopened::of_read(sent) else {
            panic!("an error the host sent is its refusal");
        };
        assert_eq!(refusal.code, ErrorCode::StorageUnavailable);
        assert!(matches!(
            Unopened::of_read(kr_client::ClientError::ConnectionEnded),
            Unopened::Unreached(_)
        ));
    }

    /// A connection says whether its host is one this device is paired with, because an
    /// attachment is offered only for the host on this machine: the path it is given is a path
    /// there.
    #[test]
    fn a_connection_says_whether_its_host_is_one_this_device_is_paired_with() {
        let environment: EnvironmentId = "3f1a2c40-11aa-4b2c-9d3e-000000000001"
            .parse()
            .expect("an environment identity");
        let here = serde_json::to_value(ConnectionState::owner(environment)).expect("encodes");
        assert_eq!(here["paired"], serde_json::Value::Bool(false));

        let there = serde_json::to_value(ConnectionState::paired(
            environment,
            vec![kr_protocol::rights::ActionRight::AgentPrompt],
        ))
        .expect("encodes");
        assert_eq!(there["paired"], serde_json::Value::Bool(true));
        assert_eq!(there["rights"], serde_json::json!(["agent.prompt"]));

        let lost = serde_json::to_value(ConnectionState::unreachable("no host")).expect("encodes");
        assert_eq!(lost["paired"], serde_json::Value::Bool(false));
    }

    /// KR-REQ-10.01: what crosses to the WebView is a host event's payload as the native client
    /// validated and decoded it: a payload with a JSON form arrives as that JSON, and one without
    /// arrives as null beside its event type rather than as something the page cannot read.
    #[test]
    fn an_event_payload_reaches_the_page_as_json_or_as_null() {
        let published = serde_json::json!({
            "session_id": "0f1e2d3c",
            "state": "live",
            "cursor": 42,
            "changed": [true, null],
        });
        let payload = kr_protocol::envelope::ParamsValue::from_typed(&published)
            .expect("a canonical payload");
        assert_eq!(read_payload(&payload), published);

        let opaque =
            kr_protocol::envelope::ParamsValue::new(kr_cbor::CanonicalValue::Bytes(vec![1, 2, 3]));
        assert_eq!(read_payload(&opaque), serde_json::Value::Null);
    }

    #[test]
    fn an_unreachable_host_carries_a_reason_and_no_environment() {
        let state = ConnectionState::unreachable("no host on this machine");
        assert!(!state.connected);
        assert_eq!(state.environment_id, None);
        assert_eq!(state.reason.as_deref(), Some("no host on this machine"));
    }
}
