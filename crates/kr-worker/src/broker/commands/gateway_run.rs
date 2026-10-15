//! A backend that runs an application server for its program: starting the server, accepting the
//! program's one connection, and ending both.
//!
//! The order in a launch is the one [`super`] describes. Here are the three things the lifecycle
//! adds to it:
//!
//! * **Start.** After the launcher says it is going, the server is started in a group of its own
//!   with the environment the launcher presented, the session records it as a root of what it
//!   owns and the worker waits for that record to be on disk, and the socket is bound; all within
//!   what the launcher waits for the commitment. A server whose record is not written is one a
//!   daemon cannot stop after the worker dies, so it is not left running: the launch fails and the
//!   program runs as typed.
//! * **Accept.** Only the process the launch registered may connect, the kernel names it, it must
//!   still run the code that was hashed, and its upgrade must be a plain one. One connection is
//!   admitted; a process, an upgrade or a connection that is refused has not used the admission.
//!   The gateway then stands between the program's WebSocket and the server's standard streams.
//! * **End.** The program exiting, the connection ending, the backend being retired, or no
//!   connection within the bound ends the server through one operation (see
//!   [`crate::broker::server`]), run in a task of its own that retiring the backend does not abort.
//!   A session that is closing ends its servers after the acceptance of its close is delivered, so
//!   until then none of these ends the server: the connection ending leaves the server running
//!   with its input open and its output read and discarded. (A launch that did not commit ends
//!   the server it started at once, whatever the session is doing: no program has connected to
//!   it, so no command of the program can be asking for the close.)

use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, ReadBuf};
use tokio::process::ChildStdout;

use crate::broker::Broker;
use crate::broker::attach::PresentedEnvironment;
use crate::broker::endpoint::{Accepted, BoundEndpoint, Stream};
use crate::broker::error::{BrokerError, Result};
use crate::broker::image::ExecutableIdentity;
use crate::broker::listener::Registration;
use crate::broker::server::{Owned, Server, ServerSpec};

use super::{Backend, BackendState, GATEWAY_SOCKET, verify};

/// How long the program has to connect to its gateway once its launch is committed.
///
/// A program that fell back to running as typed never connects, and its server and instance end
/// when this is over.
pub(super) const CONNECTION_DEADLINE: Duration = Duration::from_secs(30);

/// How long starting the server, recording it and binding the socket may take together: less than
/// the two seconds the launcher waits for the commitment, so the launch is given back before the
/// launcher gives up on it.
const START_DEADLINE: Duration = Duration::from_millis(1700);

/// The server's output as the program's connection reads it.
///
/// When the connection lets go of it, it is not closed: it is read and discarded until the pipe
/// closes, which is when the server and everything that inherited it have let go. A server whose
/// output is closed fails its next write, and an application server is right to end its commands
/// then; one of them may be what asked the session to close.
struct LentOutput {
    output: Option<ChildStdout>,
}

impl AsyncRead for LentOutput {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.output.as_mut() {
            Some(output) => Pin::new(output).poll_read(cx, buffer),
            None => Poll::Ready(Ok(())),
        }
    }
}

impl Drop for LentOutput {
    fn drop(&mut self) {
        let (Some(mut output), Ok(runtime)) =
            (self.output.take(), tokio::runtime::Handle::try_current())
        else {
            return;
        };
        runtime.spawn(async move {
            let _ = tokio::io::copy(&mut output, &mut tokio::io::sink()).await;
        });
    }
}

/// What a session recorded below a server, as the ending reads and changes it.
///
/// Held weakly: the backends belong to the session, and a session that has gone has nothing
/// recorded to read.
pub(super) struct SessionOwned(Option<Weak<crate::runtime::SessionRuntime>>);

impl Owned for SessionOwned {
    fn below(
        &self,
        server: &kr_protocol::identity::ProcessStartIdentity,
    ) -> Vec<kr_protocol::identity::ProcessStartIdentity> {
        self.0
            .as_ref()
            .and_then(Weak::upgrade)
            .map(|runtime| runtime.session().read_below_server(server))
            .unwrap_or_default()
    }

    fn left(&self, process: &kr_protocol::identity::ProcessStartIdentity) -> bool {
        self.0
            .as_ref()
            .and_then(Weak::upgrade)
            .is_some_and(|runtime| runtime.session().process_has_left(process))
    }

    fn forced(&self, process: &kr_protocol::identity::ProcessStartIdentity) {
        if let Some(runtime) = self.0.as_ref().and_then(Weak::upgrade) {
            runtime.session().note_process_forced(process);
        }
    }

    fn unsignalled(&self, process: &kr_protocol::identity::ProcessStartIdentity, why: &str) {
        if let Some(runtime) = self.0.as_ref().and_then(Weak::upgrade) {
            runtime.session().note_process_unsignalled(process, why);
        }
    }
}

impl Backend {
    /// The session whose record of processes the server is a root of, where this backend has one.
    fn runtime(&self) -> Option<Arc<crate::runtime::SessionRuntime>> {
        self.views
            .as_ref()
            .and_then(|(_, runtime)| runtime.upgrade())
    }

    /// Ends the connection, the server and what the session recorded below it. It is idempotent: a
    /// second call finds nothing to end.
    ///
    /// The ending runs in a task of its own, kept in the backend's list of endings, which retiring
    /// the backend does not abort and [`Backend::endings`] waits for.
    pub(super) fn end_gateway(&self) {
        self.end_gateway_since(tokio::time::Instant::now());
    }

    /// The same, for a graceful stop that began at `begun`: a session's closure begins its own
    /// stop before it asks for the servers to end, and the two keep one clock.
    pub(super) fn end_gateway_since(&self, begun: tokio::time::Instant) {
        let Some(run) = self.gateway_run.as_ref() else {
            return;
        };
        let connection = run
            .connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(owner) = connection {
            owner.shutdown();
        }
        // The list of endings is held from the taking of the server to the keeping of its ending,
        // so that whoever waits for the endings finds this one.
        let mut ladders = run.ladders.lock().unwrap_or_else(PoisonError::into_inner);
        let server = run
            .server
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(server) = server {
            let owned = SessionOwned(self.views.as_ref().map(|(_, runtime)| Weak::clone(runtime)));
            let ending = run.handle.spawn(async move {
                let retirement = server.retire(&owned, begun).await;
                if !retirement.survivors.is_empty() {
                    eprintln!(
                        "kr-worker: {} process(es) a server the session started could not be \
                         ended: {:?}",
                        retirement.survivors.len(),
                        retirement.ended
                    );
                }
                retirement
            });
            ladders.push(ending);
        }
    }

    /// Ends the server, unless the session is closing, whose closure ends the servers after the
    /// acceptance of its close has been delivered (`CommandBackends::end_servers`), since the
    /// command that asked for the close may be one the server started. It is what the end of the
    /// program's connection, the end of the program and a retirement ask for; a launch that had
    /// not committed has no such command and ends its server outright ([`Backend::end_gateway`]).
    pub(super) fn end_unless_closing(&self) {
        if !self.closing.load(Ordering::SeqCst) {
            self.end_gateway();
        }
    }

    /// Waits for the endings in progress. What survived them is in the session's record of its
    /// processes, which the closure's receipt reads.
    pub(super) async fn endings(&self) {
        let Some(run) = self.gateway_run.as_ref() else {
            return;
        };
        let endings: Vec<_> = run
            .ladders
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain(..)
            .collect();
        for ending in endings {
            let _ = ending.await;
        }
    }
}

/// Starts the server for a launch that has said it is going, records it and binds the socket.
///
/// # Errors
///
/// Returns why the launch cannot go on: the launcher presented no environment, the server could
/// not be started or does not run the executable that was hashed, its record is not on disk in
/// time, or the socket could not be bound. The server, if it started, is ended.
pub(super) async fn start(
    backend: &Arc<Backend>,
    identity: &ExecutableIdentity,
    environment: Option<PresentedEnvironment>,
) -> Result<()> {
    let run = backend
        .gateway_run
        .as_ref()
        .ok_or_else(|| BrokerError::invalid("this backend runs no server"))?;
    let environment = environment.ok_or_else(|| {
        BrokerError::denied(
            "the launcher presented no environment, and this backend starts a server with it",
        )
    })?;
    let attempt = async {
        let presented = environment.pairs();
        drop(environment);
        let (server, unshown) = Server::spawn(
            &ServerSpec {
                executable: std::path::Path::new(&backend.invocation.executable),
                digest: &identity.hashed.digest,
                arguments: &run.server_arguments,
                directory: std::path::Path::new(&backend.invocation.cwd),
                presented: &presented,
            },
            Arc::clone(&run.hashed),
        )
        .await
        .map_err(|detail| BrokerError::UpstreamUnavailable { detail })?;
        // From here the ending finds the server, whatever stops this attempt: nothing that can be
        // cancelled sits between the process being started and its being put where it is ended
        // from, and it is recorded before it is shown to run what was hashed, which takes as long
        // as the executable is large.
        let server = Arc::new(server);
        *run.server.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&server));
        run.broker
            .set_instance_backend(backend.application_instance_id, server.identity().clone())?;
        // The record is handed over under the session's lock and waited for outside it.
        let written = {
            let runtime = backend
                .runtime()
                .ok_or_else(|| BrokerError::PreconditionFailed {
                    detail: "the session that was to own the server has gone".to_owned(),
                })?;
            let mut session = runtime.session();
            session.record_backend(server.identity().clone())
        }
        .map_err(|detail| BrokerError::PreconditionFailed { detail })?;
        server
            .show(unshown)
            .await
            .map_err(|detail| BrokerError::UpstreamUnavailable { detail })?;
        match written.await {
            Ok(true) => {}
            _ => {
                return Err(BrokerError::PreconditionFailed {
                    detail: "the record of the server could not be written, so a daemon could not \
                             stop it after this worker, and it was not left running"
                        .to_owned(),
                });
            }
        }
        let endpoint = BoundEndpoint::bind_named(&backend.directory, GATEWAY_SOCKET)?;
        *run.listener.lock().unwrap_or_else(PoisonError::into_inner) = Some(endpoint);
        Ok(())
    };
    let started = tokio::time::timeout(START_DEADLINE, attempt)
        .await
        .unwrap_or_else(|_| {
            Err(BrokerError::UpstreamUnavailable {
                detail: "the server was not started and recorded in the time a launch waits"
                    .to_owned(),
            })
        });
    if started.is_err() {
        backend.end_gateway();
    }
    started
}

/// Accepts the program's connection to the gateway and serves it, until the backend is retired.
///
/// If the program has not connected within the bound, the instance and its server end.
pub(super) async fn accept(
    backend: Arc<Backend>,
    broker: Arc<Broker>,
    registration: Arc<Registration>,
) {
    let Some(run) = backend.gateway_run.as_ref() else {
        return;
    };
    let Some(listener) = run
        .listener
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
    else {
        return;
    };
    let mut state = backend.lifecycle.state.subscribe();
    let retired = async move {
        let _ = state
            .wait_for(|state| matches!(state, BackendState::Retired))
            .await;
    };
    tokio::pin!(retired);
    let deadline = tokio::time::sleep(run.connection_deadline);
    tokio::pin!(deadline);
    loop {
        enum Event {
            Retired,
            NoConnection,
            Accepted(Result<Accepted>),
        }
        let event = tokio::select! {
            biased;
            () = &mut retired => Event::Retired,
            () = &mut deadline, if !run.claimed.load(Ordering::Acquire) => Event::NoConnection,
            accepted = listener.accept() => Event::Accepted(accepted),
        };
        match event {
            Event::Retired => return,
            Event::NoConnection => {
                end_unconnected(&backend, &broker);
                return;
            }
            Event::Accepted(Ok(accepted)) => {
                // The admission is held to the same bound: a program that is part way through
                // being admitted when the bound passes has not connected, and a check of its image
                // or its upgrade that does not finish is not a connection either.
                tokio::select! {
                    biased;
                    () = &mut retired => return,
                    () = &mut deadline, if !run.claimed.load(Ordering::Acquire) => {
                        end_unconnected(&backend, &broker);
                        return;
                    }
                    () = handle(&backend, &broker, &registration, accepted) => {}
                }
            }
            Event::Accepted(Err(_)) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
}

/// Ends what a program that never connected leaves: it ran as typed, so there is nothing for the
/// server to serve, and the instance names a program that has no gateway.
fn end_unconnected(backend: &Arc<Backend>, broker: &Arc<Broker>) {
    let _ = broker.end(
        backend.application_instance_id,
        crate::broker::InstanceEnding::NativeExit,
    );
    backend.end_unless_closing();
    backend.announce_ended();
}

/// Admits one connection if it is the program's, and serves it.
async fn handle(
    backend: &Arc<Backend>,
    broker: &Arc<Broker>,
    registration: &Arc<Registration>,
    accepted: Accepted,
) {
    let Some(run) = backend.gateway_run.as_ref() else {
        return;
    };
    let Accepted { peer, stream } = accepted;
    // The process the kernel names has to be the one the launch registered: the launcher that
    // proved itself with the private exchange and then became the program in place. Another
    // process, or another user, or a second connection, is refused before it is read.
    if run.claimed.load(Ordering::Acquire)
        || !peer.is_owner()
        || !registration.expected_process.matches(peer.process())
    {
        return;
    }
    // It must still run what was hashed; the check reads files, so not on the runtime's threads.
    let verdict = {
        let backend = Arc::clone(backend);
        let registration = Arc::clone(registration);
        tokio::task::spawn_blocking(move || verify(&backend, &registration)).await
    };
    match verdict {
        Ok(Ok(())) => {}
        Ok(Err(why)) => {
            backend.announce_refusal(&why);
            return;
        }
        Err(_) => return,
    }
    let Stream::Socket(stream) = stream;
    let Some(tables) = run
        .tables
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
    else {
        return;
    };
    // An upgrade that is not a plain one from a native terminal does not use the admission.
    let Ok(lines) = crate::broker::websocket::accept(stream, tables.framing).await else {
        return;
    };
    // From the claim to the end of this function nothing is awaited, so the deadline cannot cut an
    // admission between its being claimed and its being served.
    if run.claimed.swap(true, Ordering::AcqRel) {
        return;
    }
    let opened = broker.open_launched_connection(
        backend.application_instance_id,
        &backend.credential,
        peer.process(),
        &backend.connector.plugin_id(),
        &tables.protocol_version,
    );
    let Ok(connection) = opened else {
        run.claimed.store(false, Ordering::Release);
        return;
    };
    let server = run
        .server
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let Some((output, input)) = server.and_then(|server| server.take_pipes()) else {
        broker.close_connection(connection);
        return;
    };
    let (client_reader, client_writer) = tokio::io::split(lines);
    let output = LentOutput {
        output: Some(output),
    };
    let Ok(mut attached) = backend.gateway.serve(
        connection,
        tables.framing,
        output,
        input,
        client_reader,
        client_writer,
        Vec::new(),
    ) else {
        broker.close_connection(connection);
        return;
    };
    // What an agent starts is started in answer to a frame, so each frame has the session look at
    // the processes it owns shortly after, and the server's commands are recorded while it runs.
    if let Some(runtime) = backend.runtime() {
        let runtime = Arc::downgrade(&runtime);
        attached.owner.on_frame(move || {
            if let Some(runtime) = runtime.upgrade() {
                runtime.note_activity();
            }
        });
    }
    let delivering = backend.views.as_ref().and_then(|(session_id, runtime)| {
        let runtime = runtime.upgrade()?;
        attached.deliver_to_views(*session_id, runtime).ok()
    });
    *run.connection
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&attached.owner));
    let backend = Arc::clone(backend);
    tokio::spawn(async move {
        let _ = attached.served().await;
        if let Some(delivering) = delivering {
            delivering.abort();
        }
        // The connection is over, and nothing is left for the server to serve.
        backend.end_unless_closing();
    });
}
