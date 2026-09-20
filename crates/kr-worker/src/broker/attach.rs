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
use crate::broker::process::{Credential, ManagedProcess};

/// How long a connecting bridge has to say who it is.
///
/// A process that connects and then says nothing is not a bridge this host is waiting for, and an
/// endpoint that waits for it indefinitely is an endpoint one stalled process closes.
pub const HELLO_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// How long a connection's own writes are given to finish once both ends have stopped reading.
pub const TEARDOWN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// How often the native terminal this host started is read while it is still running.
///
/// A socket reaching end of file and the process behind it exiting are two events in either order,
/// and neither is a bound on the other: a terminal can close its connection and go on running for
/// an hour, and a terminal whose connection stays open can exit at once. So the process is watched
/// for as long as it runs rather than for a window after something else happened.
pub const TERMINAL_POLL: std::time::Duration = std::time::Duration::from_millis(250);

/// What one launched agent's bridge must satisfy, and what its connection is read with.
#[derive(Clone, Debug)]
pub struct NativeLaunch {
    /// The launch profile this registration belongs to.
    pub profile_id: kr_protocol::ids::LaunchProfileId,
    /// The bridge process this host expects on the connection.
    ///
    /// It is absent until this host has started one. [`NativeGateway::launch`] fills it in from
    /// the process it actually spawned, which is the only thing that can: the registration names
    /// the process, so the process has to exist before the registration does.
    pub expected_process: Option<ProcessStartIdentity>,
    /// The native terminal this host started, where it started one.
    ///
    /// Section 7 draws its line between two processes: the terminal the person is typing in, and
    /// the backend that serves it. The terminal ending is the intentional native exit that ends
    /// the instance and stops that backend; the connection closing is not, and an attachment
    /// closing is not. Where this host started no terminal of its own — a bypassed or shared
    /// backend — it is absent, and no closure is read as an exit.
    pub native_terminal: Option<ProcessStartIdentity>,
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

/// What one connection's ending meant, as the closure itself established it.
///
/// It says what the socket closing was, and nothing about what the terminal does afterwards: that
/// belongs to [`TerminalWatch`], which is still running when this is returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ended {
    /// Why the connection ended.
    pub closure: Closure,
}

/// The supervision of the native terminal this host started.
///
/// Section 7 makes the terminal's own exit the intentional native exit that ends the instance and
/// stops its dedicated backend. The connection is not that event and cannot stand in for it: the
/// socket can close while the terminal runs on, and the terminal can exit long after any window a
/// teardown could reasonably wait. So this watches the process itself, from the moment the
/// connection is served until the process ends, and it is what stops the backend.
#[derive(Debug)]
pub struct TerminalWatch {
    stopping: Arc<tokio::sync::Notify>,
    stopped: Arc<std::sync::atomic::AtomicBool>,
    watching: tokio::task::JoinHandle<Option<crate::broker::process::BackendStop>>,
}

impl TerminalWatch {
    /// Waits for the terminal to exit and returns what stopping its dedicated backend did.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::UpstreamUnavailable`] when the supervising task could not be joined,
    /// which leaves what became of the terminal unestablished.
    pub async fn exited(self) -> Result<Option<crate::broker::process::BackendStop>> {
        self.watching
            .await
            .map_err(|error| BrokerError::UpstreamUnavailable {
                detail: format!("the terminal's supervision could not be joined: {error}"),
            })
    }

    /// Ends the supervision without waiting for the terminal.
    ///
    /// Nothing is stopped and nothing is ended: this is the host giving up the watch, which is
    /// what a session shutting down does. The request is recorded rather than signalled, so one
    /// made before the watch first waits, or between two of its readings, still ends it.
    pub fn stop(&self) {
        self.stopped
            .store(true, std::sync::atomic::Ordering::Release);
        self.stopping.notify_waiters();
    }
}

/// Watches one terminal for as long as it runs, and stops what its exit stops.
async fn supervise_terminal(
    broker: Arc<Broker>,
    application_instance_id: ApplicationInstanceId,
    terminal: ProcessStartIdentity,
    stopping: Arc<tokio::sync::Notify>,
    stopped: Arc<std::sync::atomic::AtomicBool>,
) -> Option<crate::broker::process::BackendStop> {
    loop {
        // The request to stop is read first and read from state, so one made while this task was
        // not waiting is not a request that disappeared.
        if stopped.load(std::sync::atomic::Ordering::Acquire) {
            return None;
        }
        if matches!(
            kr_ipc::identity::process_state(&terminal),
            kr_ipc::identity::ProcessState::Ended
        ) {
            return stop_what_ended(&broker, application_instance_id).await;
        }
        tokio::select! {
            () = tokio::time::sleep(TERMINAL_POLL) => {}
            () = stopping.notified() => return None,
        }
    }
}

/// Returns true when the terminal this host started has ended, read once.
fn terminal_has_ended(terminal: Option<&ProcessStartIdentity>) -> bool {
    terminal.is_some_and(|terminal| {
        matches!(
            kr_ipc::identity::process_state(terminal),
            kr_ipc::identity::ProcessState::Ended
        )
    })
}

/// Ends the instance an intentional native exit ends, and stops the backend it stops.
async fn stop_what_ended(
    broker: &Broker,
    application_instance_id: ApplicationInstanceId,
) -> Option<crate::broker::process::BackendStop> {
    let outcome = broker.end(
        application_instance_id,
        crate::broker::InstanceEnding::NativeExit,
    );
    let backend = outcome.backend?;
    Some(
        crate::broker::process::stop_backend(&backend, crate::broker::process::BACKEND_GRACE).await,
    )
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
    /// The supervision of the native terminal, where this host started one.
    ///
    /// It is already running and it outlives this connection. Closing the attachment does not end
    /// it, because the terminal exiting is a different event from the socket closing and section 7
    /// acts on the first.
    pub terminal: Option<TerminalWatch>,
    /// The task driving the owner's own writes and reads.
    served: tokio::task::JoinHandle<Ended>,
}

impl Attached {
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
    registration: Option<Registration>,
    runtime_directory: std::path::PathBuf,
}

/// One agent this host started, and what it started.
#[derive(Debug)]
pub struct Launched {
    /// The process itself, so its owner can wait for it or end it.
    pub child: std::process::Child,
    /// What the kernel says it is.
    pub process: ProcessStartIdentity,
    /// The profile it was started from.
    pub profile: kr_protocol::broker::LaunchProfile,
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
        let registration = launch.expected_process.clone().map(|expected| {
            Registration::new(
                endpoint.address().clone(),
                launch.profile_id.clone(),
                launch.application_instance_id,
                expected,
            )
        });
        Ok(Self {
            broker,
            endpoint,
            observatory,
            launch,
            registration,
            runtime_directory: runtime_directory.to_path_buf(),
        })
    }

    /// Starts the agent this launch names and publishes what its forwarder needs to reach here.
    ///
    /// This is the whole of the production order, and the order is the point.
    ///
    /// 1. The intent is checked against the foreground it was prepared against, because section 12
    ///    refuses a launch an application took the foreground in front of.
    /// 2. The executable is started, with the two file paths in its environment and nothing secret
    ///    in its argument vector.
    /// 3. The kernel is asked what it started, and that identity is what the registration names.
    ///    Nothing the process says about itself is used.
    /// 4. The private exchange is generated, written to an owner-only file, and handed to the
    ///    broker as the launch's own record.
    /// 5. The registration file is written last, so a forwarder that reads it reads a complete
    ///    one and the credential it names already exists.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Launch`] when the intent is stale, and
    /// [`BrokerError::LedgerUnavailable`] when the process cannot be started or its files written.
    pub fn launch(
        &mut self,
        intent: &crate::broker::profiles::LaunchIntent,
        foreground: &crate::broker::profiles::ForegroundMark,
        mode: kr_protocol::broker::IntegrationMode,
        now: kr_protocol::scalars::TimestampMs,
    ) -> Result<Launched> {
        let application_instance_id = self.launch.application_instance_id;
        let registration_path = self.runtime_directory.join("registration");
        let credential_path = self.runtime_directory.join("credential");
        // Refused before anything is started. A stale intent must cost nothing.
        let profile = self
            .broker
            .execute_launch(intent, foreground, application_instance_id)?;
        let mut command = std::process::Command::new(&profile.binary.resolved_path);
        command
            .args(&profile.arguments)
            .current_dir(&self.runtime_directory)
            .env("KR_REGISTRATION", &registration_path)
            .env("KR_CREDENTIAL", &credential_path)
            // The worker owns the standard streams of the backend it starts. The person's own
            // terminal is the session's PTY and is a different path; what this pair carries is
            // whatever the launched process says to the host that started it.
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped());
        let child = command.spawn().map_err(|error| {
            BrokerError::ledger(format!(
                "could not start {}: {error}",
                profile.binary.resolved_path
            ))
        })?;
        let started = kr_ipc::identity::started_process_identity(child.id()).map_err(|error| {
            BrokerError::ledger(format!("the started process cannot be read: {error}"))
        })?;
        let process = ManagedProcess::new(
            application_instance_id,
            started.clone(),
            crate::broker::process::TransportHandle {
                transport: crate::broker::process::BrokerTransport::PrivateSocket,
                application_instance_id,
                executable_digest: profile.binary.digest,
                process: started.clone(),
            },
            Credential::generate()?,
            // Dedicated: this host started it for this instance, so section 7 stops it when the
            // terminal intentionally exits.
            true,
            now,
        );
        process.write_registration(&credential_path)?;
        self.broker.register_instance(
            application_instance_id,
            mode,
            Some(profile.profile_id.clone()),
            Some(process),
        )?;
        let registration = Registration::new(
            self.endpoint.address().clone(),
            profile.profile_id.clone(),
            application_instance_id,
            started.clone(),
        );
        // The framing travels with it, because the forwarder writes one frame before this host
        // has told it anything else and it has to write that frame the way this connector reads.
        let published = format!(
            "{}framing={}\n",
            registration.to_file(),
            self.launch.framing.name()
        );
        std::fs::write(&registration_path, published).map_err(|error| {
            BrokerError::ledger(format!(
                "could not write the registration file {}: {error}",
                registration_path.display()
            ))
        })?;
        self.launch.expected_process = Some(started.clone());
        self.registration = Some(registration);
        Ok(Launched {
            child,
            process: started,
            profile,
        })
    }

    /// Returns the address a launched process is told to connect to.
    #[must_use]
    pub const fn address(&self) -> &ListenerAddress {
        self.endpoint.address()
    }

    /// Returns the registration file a launched process reads.
    #[must_use]
    pub fn registration(&self) -> Option<String> {
        self.registration.as_ref().map(|registration| {
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
        let (hello, credential, held) = self.hello(&mut upstream_reader).await?;
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
        let registration = self.registration.as_ref().ok_or_else(|| {
            BrokerError::denied("this endpoint has not launched anything to authenticate against")
        })?;
        // The owner, the kernel's naming of the process and the process the launch started. The
        // private exchange is the broker's own record and is checked where that record lives, in
        // the admission immediately below, so the credential never leaves it.
        registration.authenticate_peer(&presented, &peer)?;
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
        let _ = identity;
        self.serve(
            connection,
            upstream_reader,
            upstream_writer,
            client_reader,
            client_writer,
            held,
        )
    }

    /// Starts one admitted connection's owner and the task that supervises it.
    #[allow(clippy::too_many_arguments)]
    fn serve<UR, UW, CR, CW>(
        &self,
        connection: GatewayConnectionId,
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
            self.launch.framing,
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
        // The terminal is watched from here, and the watch is not this connection's to end.
        // Section 7 acts on the terminal exiting, which is neither caused by nor bounded by the
        // socket closing, so the supervision starts now and runs until the process ends.
        let terminal = self.launch.native_terminal.clone().map(|terminal| {
            let stopping = Arc::new(tokio::sync::Notify::new());
            let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
            TerminalWatch {
                stopping: Arc::clone(&stopping),
                stopped: Arc::clone(&stopped),
                watching: tokio::spawn(supervise_terminal(
                    Arc::clone(&self.broker),
                    self.launch.application_instance_id,
                    terminal,
                    stopping,
                    stopped,
                )),
            }
        });
        let served = {
            let owner = Arc::clone(&owner);
            let broker = Arc::clone(&self.broker);
            let observatory = self.observatory.clone();
            let watched = self.launch.native_terminal.clone();
            let application_instance_id = self.launch.application_instance_id;
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
                if tokio::time::timeout(TEARDOWN_DEADLINE, &mut writing)
                    .await
                    .is_err()
                {
                    // A writer that has not finished by now is writing to an end that has stopped
                    // reading. It is ended rather than left detached, because a task nobody holds
                    // is a task nothing can stop.
                    writing.abort();
                    let _ = (&mut writing).await;
                }
                broker.unbind_dispatch(application_instance_id, &carrying);
                broker.close_connection(connection);
                observatory.withdraw(connection);
                // What the closure was, read once, from the process rather than from the socket.
                // Nothing is stopped here: the terminal's own supervision owns that, and it is
                // still running whichever of these this closure turns out to be.
                let closure = if asked_to_stop {
                    Closure::Shutdown
                } else if terminal_has_ended(watched.as_ref()) {
                    Closure::NativeExit
                } else {
                    Closure::Detached
                };
                Ended { closure }
            })
        };
        Ok(Attached {
            connection,
            owner,
            observations,
            terminal,
            served,
        })
    }

    /// Reads the one frame a bridge writes before it is authenticated.
    async fn hello<R>(&self, reader: &mut R) -> Result<(Hello, Vec<u8>, Vec<u8>)>
    where
        R: tokio::io::AsyncRead + Unpin + Send,
    {
        use tokio::io::AsyncReadExt as _;

        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        // One deadline for the whole hello. A deadline per read would let a peer that dribbles a
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
        let frame: HelloFrame = serde_json::from_slice(&body).map_err(|error| {
            BrokerError::denied(format!(
                "this connection's first frame is not a bridge saying who it is: {error}"
            ))
        })?;
        let credential = decode_credential(&frame.kr_hello.credential)?;
        Ok((frame.kr_hello, credential, buffer))
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
