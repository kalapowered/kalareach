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
//!    closed, its subscription withdrawn, and — only for the native exit section 7 names — the
//!    dedicated backend is stopped through the normal grace period.
//!
//! A failure at any step leaves nothing behind: an admitted connection whose owner could not start
//! is closed again, so a refused bridge does not leave a gateway connection nobody drives.

use std::collections::BTreeMap;
use std::sync::Arc;

use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{ApplicationInstanceId, GatewayConnectionId, PluginId};

use crate::broker::Broker;
use crate::broker::duplex::{Closure, Duplex, Observations, Observatory};
use crate::broker::endpoint::{Accepted, BoundEndpoint, Stream};
use crate::broker::error::{BrokerError, Result};
use crate::broker::framing::Framing;
use crate::broker::listener::{BridgeHello, ListenerAddress, Registration, reject_browser_origin};
use crate::broker::process::ManagedProcess;

/// How long a connecting bridge has to say who it is.
///
/// A process that connects and then says nothing is not a bridge this host is waiting for, and an
/// endpoint that waits for it indefinitely is an endpoint one stalled process closes.
pub const HELLO_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// What one launched agent's bridge must satisfy, and what its connection is read with.
#[derive(Clone, Debug)]
pub struct NativeLaunch {
    /// The registration this launch published, which names the process this host expects.
    pub registration: Registration,
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
struct HelloFrame {
    kr_hello: Hello,
}

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
}

/// One connection this host admitted, served by its own supervised owner.
#[derive(Debug)]
pub struct Attached {
    /// The connection the broker minted for it.
    pub connection: GatewayConnectionId,
    /// The owner that reads both ends.
    pub owner: Arc<Duplex>,
    /// Where this connection's authorised observer reads resolutions.
    pub observations: Observations,
    /// The task driving the owner's own writes and reads.
    served: tokio::task::JoinHandle<Closure>,
}

impl Attached {
    /// Waits for the connection to end and says why it did.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UpstreamUnavailable`] when the task that served the connection could
    /// not be joined, which leaves why it ended unestablished.
    pub async fn served(self) -> Result<Closure> {
        self.served
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
    pub async fn shutdown(self) -> Result<Closure> {
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
}

impl NativeGateway {
    /// Binds the endpoint this launch publishes.
    ///
    /// # Errors
    ///
    /// Returns whatever [`BoundEndpoint::bind`] refuses.
    pub fn bind(
        broker: Arc<Broker>,
        runtime_directory: &std::path::Path,
        observatory: Observatory,
        launch: NativeLaunch,
    ) -> Result<Self> {
        let endpoint = BoundEndpoint::bind(runtime_directory)?;
        Ok(Self {
            broker,
            endpoint,
            observatory,
            launch,
        })
    }

    /// Returns the address a launched process is told to connect to.
    #[must_use]
    pub const fn address(&self) -> &ListenerAddress {
        self.endpoint.address()
    }

    /// Returns the registration file a launched process reads.
    #[must_use]
    pub fn registration(&self) -> String {
        self.launch.registration.to_file()
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
    pub async fn accept<CR, CW>(
        &self,
        process: &ManagedProcess,
        client_reader: CR,
        client_writer: CW,
    ) -> Result<Attached>
    where
        CR: tokio::io::AsyncRead + Unpin + Send + 'static,
        CW: tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let accepted = self.endpoint.accept().await?;
        self.admit(accepted, process, client_reader, client_writer)
            .await
    }

    /// Everything after the accept, for one connection.
    async fn admit<CR, CW>(
        &self,
        accepted: Accepted,
        process: &ManagedProcess,
        client_reader: CR,
        client_writer: CW,
    ) -> Result<Attached>
    where
        CR: tokio::io::AsyncRead + Unpin + Send + 'static,
        CW: tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let Accepted { peer, stream } = accepted;
        let (upstream_reader, upstream_writer) = match stream {
            #[cfg(unix)]
            Stream::Socket(socket) => {
                let (reader, writer) = tokio::io::split(socket);
                (
                    Box::new(reader) as Box<dyn tokio::io::AsyncRead + Unpin + Send>,
                    Box::new(writer) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
                )
            }
            Stream::Loopback(socket) => {
                let (reader, writer) = tokio::io::split(socket);
                (
                    Box::new(reader) as Box<dyn tokio::io::AsyncRead + Unpin + Send>,
                    Box::new(writer) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
                )
            }
        };
        let mut upstream_reader = upstream_reader;
        let (hello, credential) = self.hello(&mut upstream_reader).await?;
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
        let presented_pid = u32::try_from(hello.pid).map_err(|_| {
            BrokerError::denied("this connection named no process this host could read")
        })?;
        let read = kr_ipc::identity::process_start_identity(presented_pid).map_err(|error| {
            BrokerError::denied(format!(
                "this connection named process {presented_pid}, which this host cannot read: \
                 {error}"
            ))
        })?;
        if read.start_value.get() != hello.start {
            return Err(BrokerError::denied(format!(
                "this connection says process {presented_pid} started at {} and the operating \
                 system says {}",
                hello.start,
                read.start_value.get()
            )));
        }
        let presented = BridgeHello {
            credential: kr_crypto::secret::SecretVec::new(credential.clone()),
            process: read,
            environment_session_id: hello.session.clone(),
        };
        self.launch
            .registration
            .authenticate(&presented, &peer, process)?;
        // The identity the connection is admitted under is the kernel's where there is one. The
        // presented one is only ever used where the platform names no peer, which is the case the
        // authentication above has already established.
        let identity = peer.process().unwrap_or(&presented.process).clone();
        let connection = self.broker.open_native_connection(
            self.launch.application_instance_id,
            &credential,
            &identity,
            &self.launch.plugin_id,
            &self.launch.installed_protocol_version,
        )?;
        self.serve(
            connection,
            identity,
            upstream_reader,
            upstream_writer,
            client_reader,
            client_writer,
        )
    }

    /// Starts one admitted connection's owner and the task that supervises it.
    fn serve<UR, UW, CR, CW>(
        &self,
        connection: GatewayConnectionId,
        identity: ProcessStartIdentity,
        upstream_reader: UR,
        upstream_writer: UW,
        client_reader: CR,
        client_writer: CW,
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
            self.launch.framing,
            upstream_writer,
            client_writer,
            self.observatory.clone(),
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
        self.broker.bind_connection_dispatch(connection, dispatch);
        let observations = self.observatory.subscribe(connection);
        let served = {
            let owner = Arc::clone(&owner);
            let broker = Arc::clone(&self.broker);
            let observatory = self.observatory.clone();
            tokio::spawn(async move {
                let reading = {
                    let upstream = Arc::clone(&owner);
                    let client = Arc::clone(&owner);
                    async move {
                        tokio::select! {
                            () = upstream.serve(upstream_reader, true) => (),
                            () = client.serve(client_reader, false) => (),
                        }
                    }
                };
                // The writes outlive the reads by exactly as long as it takes to finish what was
                // already queued: an answer this host admitted must reach the socket even though
                // the end that would have sent the next frame has closed.
                let writing = tokio::spawn(writes);
                reading.await;
                owner.shutdown();
                let closure = match kr_ipc::identity::process_state(&identity) {
                    // Section 7: the native TUI's intentional exit ends the instance. A connection
                    // that closed while the process this host launched is still running is an
                    // attachment closing, and that ends nothing.
                    kr_ipc::identity::ProcessState::Ended => Closure::NativeExit,
                    _ => Closure::Detached,
                };
                broker.close_connection(connection);
                observatory.withdraw(connection);
                drop(writing);
                closure
            })
        };
        Ok(Attached {
            connection,
            owner,
            observations,
            served,
        })
    }

    /// Ends what one connection's closure ends, and stops what it stops.
    ///
    /// Section 7 draws the line here: the native TUI's intentional exit ends the instance and
    /// stops its dedicated backend through the normal grace period, and closing a KR attachment
    /// ends nothing. A backend this host did not start, or one a bypassed launch shares, is never
    /// claimed or terminated as owned — the broker answers which of those it is, and it answers
    /// with the full process identity so that what stops is the process this host started rather
    /// than whatever holds that identifier now.
    pub async fn ended(&self, closure: Closure) -> Option<crate::broker::process::BackendStop> {
        if closure != Closure::NativeExit {
            return None;
        }
        let outcome = self.broker.end(
            self.launch.application_instance_id,
            crate::broker::InstanceEnding::NativeExit,
        );
        let backend = outcome.backend?;
        Some(
            crate::broker::process::stop_backend(&backend, crate::broker::process::BACKEND_GRACE)
                .await,
        )
    }

    /// Reads the one frame a bridge writes before it is authenticated.
    async fn hello<R>(&self, reader: &mut R) -> Result<(Hello, Vec<u8>)>
    where
        R: tokio::io::AsyncRead + Unpin + Send,
    {
        use tokio::io::AsyncReadExt as _;

        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        let body = loop {
            if let Some(body) = self.launch.framing.decode(&mut buffer)? {
                break body;
            }
            let read = tokio::time::timeout(HELLO_DEADLINE, reader.read(&mut chunk))
                .await
                .map_err(|_| {
                    BrokerError::denied(format!(
                        "this connection said nothing within {} seconds, so there is nothing to \
                         authenticate it by",
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
        let frame: HelloFrame = serde_json::from_slice(&body).map_err(|error| {
            BrokerError::denied(format!(
                "this connection's first frame is not a bridge saying who it is: {error}"
            ))
        })?;
        let credential = decode_credential(&frame.kr_hello.credential)?;
        Ok((frame.kr_hello, credential))
    }
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
