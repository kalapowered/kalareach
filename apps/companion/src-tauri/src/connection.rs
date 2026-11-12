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
    dyn Fn() -> std::pin::Pin<
            Box<dyn std::future::Future<Output = std::result::Result<Connection, Unopened>> + Send>,
        > + Send
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

    /// Why this device ended the connection, when it did: the account it was opened under signed
    /// out or was replaced (see [`crate::bound`]), in the words of why. Asking also finds out
    /// whether it should have ended already, so a caller that publishes what it read over the
    /// connection asks last, and publishes nothing of an account that has left.
    #[must_use]
    pub fn ended_by_this_device(&self) -> Option<CommandError> {
        self.session
            .transport()
            .ended_by_this_device()
            .map(CommandError::from)
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
    /// Returns why no other connection was opened: what the first one's dial says, or that this
    /// connection cannot be opened again.
    pub async fn another(&self) -> std::result::Result<Self, Unopened> {
        match &self.reopen {
            // The one opened can be opened from again: it may take the place of this one.
            Some(reopen) => Ok(reopen().await?.reopening(Arc::clone(reopen))),
            None => Err(Unopened::unreached(
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
    /// Returns why the connection was not opened ([`Unopened`]): the host cannot be reached, cannot
    /// say which environment it is, or refuses to open the connection, or this application holds
    /// as many connections to the host as it keeps.
    pub async fn paired(
        device: &Arc<Device>,
        host: &PairedHost,
    ) -> std::result::Result<Self, Unopened> {
        let connection = Self::open(device, host, false).await?;
        let (device, host) = (Arc::clone(device), host.clone());
        Ok(connection.reopening(Arc::new(move || {
            let (device, host) = (Arc::clone(&device), host.clone());
            Box::pin(async move { Self::open(&device, &host, false).await })
        })))
    }

    /// A connection to a paired host for a visit: a look at a host that is not the one this device
    /// is using, as [`Self::paired`] opens one, except that it never cuts off the connection to the
    /// host in use (see [`kr_client::pairing::link::HostLink::visit_paired`]) and says whether the
    /// host refused it. It is not opened again when it ends: whoever visits opens another.
    ///
    /// # Errors
    ///
    /// Returns [`Unopened::Refused`] with the request the host refused and its refusal when the
    /// host answered and refused at any step, and [`Unopened::Unreached`] with why when it could
    /// not be reached or did not answer.
    pub async fn visited(
        device: &Arc<Device>,
        host: &PairedHost,
    ) -> std::result::Result<Self, Unopened> {
        Self::open(device, host, true).await
    }

    /// Opens the connection, as a visit when `visiting`.
    async fn open(
        device: &Arc<Device>,
        host: &PairedHost,
        visiting: bool,
    ) -> std::result::Result<Self, Unopened> {
        let pairing = device.pairing();
        let identity = pairing.paired_identity_for(host);
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
            .map_err(Unopened::of_link)?;
        // The connection is bound to the account signed in when it was dialled (`crate::bound`): if
        // that account left while the host was asked who it is, or at any time before this
        // returns, nothing is opened, and the words say why.
        let asked = async {
            let info: kr_protocol::hostinfo::HostInfoResult = tokio::time::timeout(
                CONNECT_WITHIN,
                session.read(
                    kr_protocol::method::Method::HostInfo,
                    &crate::commands::NoParams {},
                ),
            )
            .await
            .map_err(|_| Unopened::unreached("the host did not say which environment it is"))?
            .map_err(|error| Unopened::of_call(&session, Asked::HostInfo, error))?;
            let rights = open_for_the_host(&session).await?;
            Ok::<_, Unopened>((info, rights))
        }
        .await;
        let left = session.transport().ended_by_this_device();
        let (info, rights) = match (asked, left) {
            (Ok(asked), None) => asked,
            (_, Some(refusal)) => {
                session.close();
                return Err(Unopened::Refused(
                    Asked::Connection,
                    CommandError::from(refusal),
                ));
            }
            (Err(failed), None) => {
                session.close();
                return Err(failed);
            }
        };
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

/// What a host's refusal to open a paired connection becomes. A host of an earlier build does not
/// list the method and refuses it as any unlisted method is refused (`PERMISSION_DENIED` with
/// [`kr_transport::actor::METHOD_NOT_AVAILABLE`]), and only that refusal is told to be updated: a
/// host that refuses for a reason of its own, such as a feed it has not caught up with, says that
/// reason alone.
fn opening_refused(refusal: kr_protocol::error::ProtocolError) -> Unopened {
    use kr_protocol::error::ErrorCode;

    if refusal.code == ErrorCode::PermissionDenied
        && refusal.message == kr_transport::actor::METHOD_NOT_AVAILABLE
    {
        return Unopened::Refused(
            Asked::SessionOpen,
            CommandError::stated(
                refusal.code,
                format!(
                    "{} If the host is of an earlier build than this application, update it.",
                    refusal.message
                ),
            ),
        );
    }
    Unopened::of_read(Asked::SessionOpen, kr_client::ClientError::Host(refusal))
}

/// Opens a paired connection for the host alone, and returns the rights the host decided the open
/// with.
///
/// A host of an earlier build does not list the method and refuses it as any unlisted method is
/// refused, so that refusal says to update the host.
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
    .map_err(|error| {
        Unopened::of_connection(session, &error).unwrap_or_else(|| match error {
            kr_client::ClientError::Host(refusal) => opening_refused(refusal),
            other => Unopened::of_read(Asked::SessionOpen, other),
        })
    })?;
    match opened {
        SessionOpenResult::InForce { actions, .. } => Ok(actions.iter().copied().collect()),
        SessionOpenResult::Ended { .. } => Err(Unopened::Refused(
            Asked::SessionOpen,
            CommandError::stated(
                kr_protocol::error::ErrorCode::PermissionDenied,
                "the host answered that this connection has ended",
            ),
        )),
    }
}

/// What a visit asked of a host when the host refused it, which is what the page says it refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Asked {
    /// Nothing yet: the host refused the connection itself, or this device could not give the host
    /// the lease its organisation signs for it, or the account the connection was opened under left.
    Connection,
    /// `host.info`: who the host is.
    HostInfo,
    /// `session.open`: the opening of the connection for the host alone.
    SessionOpen,
    /// `attention.read`: the host's inbox.
    AttentionRead,
}

impl Asked {
    /// What the host was asked to do, as the words that follow "the host refused to", for a
    /// refusal of a request; none for a refusal of the connection itself, which asked the host
    /// nothing yet.
    #[must_use]
    pub const fn request(self) -> Option<&'static str> {
        match self {
            Self::Connection => None,
            Self::HostInfo => Some("say who it is"),
            Self::SessionOpen => Some("open the session"),
            Self::AttentionRead => Some("read its inbox"),
        }
    }
}

/// Why a dial or a call did not get its connection to a paired host.
///
/// The cause is made where it is known and carried on unchanged: no text for a person is chosen
/// from an error's code or words after that place, because one code stands for several causes.
/// The host refuses a connection it cannot take with the code it also uses for a supervision, work
/// in another session and a resource that is short, and a host that did not answer is told with it
/// too.
#[derive(Debug)]
pub enum Unopened {
    /// The host answered, and refused the request named: it is in contact, and the refusal is its
    /// own. Or the host refused the connection itself at the handshake (named
    /// [`Asked::Connection`]), a version or a pairing, which is its decision about this device. Or
    /// this device could not give the host the lease its organisation signs for it, which a host
    /// that holds none refuses everything for, and the words are the reason.
    Refused(Asked, CommandError),
    /// The host refused the connection itself because this computer holds as many connections to
    /// it as it allows and the host has heard from every one of them lately: the host cannot take
    /// another for now. It is in contact. The refusal comes from the host's id-0 error that the
    /// session kept ([`Self::of_connection`]), and no other refusal is this one.
    HostFull,
    /// This application's own budget of connections to the host is used ([`crate::places`]): no
    /// connection was made and the host was asked nothing.
    BudgetFull,
    /// The host refused the connection itself at its admission, for a reason that is not its
    /// bound: an authority that was withdrawn since the handshake, or a daemon that has stopped
    /// while its listener still accepts. The connection is as good as lost, so every dialer does
    /// what it does when a connection is lost, and the host's words are the reason that a person
    /// reads while that stays so. It is made in [`Self::of_refused_connection`] and nowhere else.
    NotAdmitted(CommandError),
    /// The host could not be reached, did not answer in time, or failed in a way that is no
    /// refusal of the host's.
    Unreached(CommandError),
}

impl Unopened {
    pub(crate) fn unreached(reason: impl Into<String>) -> Self {
        Self::Unreached(CommandError::unavailable(reason))
    }

    /// What a failed dial of the link says.
    #[must_use]
    pub fn of_link(error: LinkError) -> Self {
        match error {
            LinkError::Refused(refusal) => {
                Self::Refused(Asked::Connection, CommandError::from(refusal))
            }
            // The host was reachable and was not asked for anything: the device could not give it
            // the lease it needs, or the account it was to be opened under left, and the words say
            // why.
            LinkError::Membership(refusal) => {
                Self::Refused(Asked::Connection, CommandError::from(refusal))
            }
            // The host refused the connection itself while the lease it needs was being
            // presented, and its refusal is what the session kept: the same cause as one that
            // the first call on the connection reads.
            LinkError::ConnectionRefused(refusal) => Self::of_refused_connection(refusal),
            // This application's own budget refused the dial, so no host was asked.
            LinkError::Declined(_) => Self::BudgetFull,
            other => Self::unreached(other.said().into_string()),
        }
    }

    /// What a failed read of `asked` says: a refusal of that request when the host sent an error,
    /// and otherwise that the host was not reached.
    #[must_use]
    pub fn of_read(asked: Asked, error: kr_client::ClientError) -> Self {
        match error {
            kr_client::ClientError::Host(_) => Self::Refused(asked, CommandError::from(error)),
            other => Self::lost(other),
        }
    }

    /// What a failed read of `asked` over `session` says: the host's refusal of the connection
    /// when `error` is it ([`Self::of_connection`]), and otherwise what [`Self::of_read`] says.
    #[must_use]
    pub fn of_call(session: &Session, asked: Asked, error: kr_client::ClientError) -> Self {
        Self::of_connection(session, &error).unwrap_or_else(|| Self::of_read(asked, error))
    }

    /// The host's refusal of the connection `session` runs on, when `error` is it. The session
    /// keeps the first error the host answered with request identifier zero, which no request of
    /// this application carries, and answers every call with it, so only the session can tell that
    /// refusal from a refusal of a request.
    #[must_use]
    pub fn of_connection(session: &Session, error: &kr_client::ClientError) -> Option<Self> {
        let kr_client::ClientError::Host(refusal) = error else {
            return None;
        };
        Self::of_kept_refusal(session.connection_refusal(), refusal)
    }

    /// The host's refusal of a connection, when `refusal` is the one that the connection's owner
    /// kept as the host's answer to the connection itself (`kept`, as a session or a wire keeps
    /// it), and not a refusal of a request.
    #[must_use]
    pub fn of_kept_refusal(
        kept: Option<kr_protocol::error::ProtocolError>,
        refusal: &kr_protocol::error::ProtocolError,
    ) -> Option<Self> {
        (kept.as_ref() == Some(refusal)).then(|| Self::of_refused_connection(refusal.clone()))
    }

    /// What the host's refusal of a connection at its admission means, for every dialer: the one
    /// function that reads such a refusal, as a session or a wire kept it
    /// ([`Self::of_kept_refusal`]).
    ///
    /// - The host's bound is [`Self::HostFull`]: the host cannot take another connection for now,
    ///   and the dialer asks again as it does for any cause that time may mend.
    /// - Any other refusal is [`Self::NotAdmitted`]: the connection is lost, as it was when the
    ///   host's refusal was not read, and the host's words are why.
    ///
    /// A refusal at the handshake (a version, a pairing) is no refusal at admission: it is the
    /// host's decision about this device, and [`Self::of_link`] gives it as such. A refusal of a
    /// request on an open connection stays that request's own refusal.
    ///
    /// The code of the refusal is read here and nowhere else.
    #[must_use]
    pub fn of_refused_connection(refusal: kr_protocol::error::ProtocolError) -> Self {
        if refusal.code == kr_protocol::error::ErrorCode::ResourceUnavailable {
            Self::HostFull
        } else {
            Self::NotAdmitted(CommandError::from(refusal))
        }
    }

    /// Whether the cause is one that time or another connection may mend, so that a caller that
    /// waits asks again: a host that was not reached, that has no room for this computer's
    /// connection or that refused the connection at its admission, this computer's own budget used,
    /// or a refusal of a request whose code is for now. Any other refusal is the host's decision.
    #[must_use]
    pub fn for_now(&self) -> bool {
        match self {
            Self::Unreached(_) | Self::NotAdmitted(_) | Self::HostFull | Self::BudgetFull => true,
            Self::Refused(_, refusal) => crate::standing::transient(refusal.code),
        }
    }

    /// A read that failed for a reason that is no answer of the host's: the host was not reached.
    #[must_use]
    pub fn lost(error: kr_client::ClientError) -> Self {
        Self::Unreached(CommandError::from(error))
    }

    /// The failure, as a command that needed the connection answers with it.
    #[must_use]
    pub fn into_error(self) -> CommandError {
        match self {
            Self::Refused(_, error) | Self::NotAdmitted(error) | Self::Unreached(error) => error,
            Self::HostFull => crate::places::host_full_error(),
            Self::BudgetFull => crate::places::full_error(),
        }
    }
}

impl From<Unopened> for CommandError {
    fn from(unopened: Unopened) -> Self {
        unopened.into_error()
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
    Ok(connect_local_once().await?.reopening(Arc::new(|| {
        Box::pin(async { connect_local_once().await.map_err(Unopened::Unreached) })
    })))
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
                        .paired_identity_for(&host)
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
                // An account that left ended it, and says so: not that the connection was lost.
                let why = session
                    .transport()
                    .ended_by_this_device()
                    .map_or_else(
                        || "the connection to this host ended".to_owned(),
                        |refusal| refusal.message,
                    );
                state.disconnected_from(&session, why);
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
        let Unopened::Refused(asked, refusal) = Unopened::of_read(Asked::AttentionRead, sent)
        else {
            panic!("an error the host sent is its refusal");
        };
        assert_eq!(asked, Asked::AttentionRead);
        assert_eq!(refusal.code, ErrorCode::StorageUnavailable);
        assert!(matches!(
            Unopened::of_read(
                Asked::AttentionRead,
                kr_client::ClientError::ConnectionEnded
            ),
            Unopened::Unreached(_)
        ));
    }

    /// A host that opens a paired connection with a refusal of its own says that reason alone. Only
    /// the refusal a host of an earlier build gives (it does not list the method, and refuses it as
    /// it refuses any unlisted method) is told to be updated; the refusals the host's authority feed
    /// produces, which are `PERMISSION_DENIED` too, are not.
    #[test]
    fn only_the_refusal_of_an_unlisted_method_tells_the_person_to_update_the_host() {
        use kr_controller::grants::Refusal;
        use kr_protocol::error::{ErrorCode, ProtocolError};

        let hint = "If the host is of an earlier build than this application, update it.";
        let said = |refusal: ProtocolError| match opening_refused(refusal) {
            Unopened::Refused(Asked::SessionOpen, error) => error.message,
            Unopened::Refused(asked, _) => panic!("the opening was refused, not {asked:?}"),
            Unopened::Unreached(_)
            | Unopened::NotAdmitted(_)
            | Unopened::HostFull
            | Unopened::BudgetFull => {
                panic!("a refusal the host sent")
            }
        };

        let earlier_host = ProtocolError::new(
            ErrorCode::PermissionDenied,
            kr_transport::actor::METHOD_NOT_AVAILABLE,
        );
        let told = said(earlier_host);
        assert!(told.contains(hint), "{told}");
        assert!(told.starts_with(kr_transport::actor::METHOD_NOT_AVAILABLE));

        for refusal in [Refusal::BehindItsFeed, Refusal::WithdrawalUnverified] {
            let error = refusal.to_protocol_error();
            assert_eq!(error.code, ErrorCode::PermissionDenied);
            let words = error.message.clone();
            let told = said(error);
            assert!(told.ends_with(&words), "the host's own words: {told}");
            assert!(!told.contains(hint));
        }
        let other = ProtocolError::new(ErrorCode::InvalidArgument, "the grant is malformed");
        assert!(said(other).ends_with("the grant is malformed"));
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
