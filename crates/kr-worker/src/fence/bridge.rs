//! The bridge endpoint's accept loop and the frames in both directions.
//!
//! One session, one endpoint, one registered root integration. The loop below accepts a connection,
//! decides the handshake, and then does three things at once for as long as the shell lives: it
//! reads what the reader reports, it writes what the driver has queued, and it fires the driver's
//! one timer at the deadline the machine set.
//!
//! Nothing here decides anything about the fence. Every frame that arrives becomes a stimulus, and
//! every frame that leaves is an action the machine produced.

use std::sync::Arc;

use kr_shell_integration::contract::qualification::IntegrationLoss;
use kr_shell_integration::contract::transport::{HandshakeOutcome, WorkerExpectation};
use kr_shell_integration::host::endpoint::HostEndpoint;
use kr_shell_integration::host::handshake::{Registration, admit, observe};
use kr_shell_integration::host::link::{BridgeReader, BridgeWriter, FromBridge, accept};
use kr_shell_integration::host::phase::is_root_method_name;

use crate::fence::driver::Outbound;
use crate::runtime::SessionRuntime;

/// Serves one session's root-integration endpoint.
///
/// It holds the endpoint for the session's whole life: the address the shell was told about is
/// this listener's, and nothing else ever binds it.
#[derive(Debug)]
pub struct BridgeServer {
    runtime: Arc<SessionRuntime>,
    endpoint: HostEndpoint,
    expectation: WorkerExpectation,
}

impl BridgeServer {
    /// Builds a server for one session.
    #[must_use]
    pub const fn new(
        runtime: Arc<SessionRuntime>,
        endpoint: HostEndpoint,
        expectation: WorkerExpectation,
    ) -> Self {
        Self {
            runtime,
            endpoint,
            expectation,
        }
    }

    /// Returns the methods this endpoint serves.
    ///
    /// Section 23 puts the five root methods in a group of their own, reachable from a validated
    /// root registration over private IPC and nowhere else. They travel on this endpoint as bridge
    /// events rather than as ordinary requests, which is what makes that true of the transport
    /// rather than only of an authority table: there is no frame on the worker's client endpoint
    /// that carries one, and no other process can open this one.
    #[must_use]
    pub fn serves(method: &str) -> bool {
        is_root_method_name(method)
    }

    /// Accepts and serves the root integration until the session closes.
    ///
    /// One registration at a time. A second connection is refused by the contract, because the
    /// session already has a registered root integration; a connection that ends is reported to the
    /// driver as a lost bridge and the endpoint goes on listening, so a reader that was restarted
    /// inside the same shell can register again.
    pub async fn serve(self) {
        loop {
            let Ok((connection, peer)) = self.endpoint.listener().accept().await else {
                return;
            };
            let (mut reader, mut writer) = accept(connection);
            let Ok(FromBridge::Hello(hello)) = reader.recv().await else {
                continue;
            };
            let already = {
                let session = self.runtime.session();
                session
                    .fence()
                    .is_some_and(|driver| driver.phase().shell().is_some())
            };
            let expectation = WorkerExpectation {
                already_registered: already,
                ..self.expectation.clone()
            };
            let Ok(outcome) = admit(
                self.endpoint.secret(),
                &expectation,
                self.endpoint.address(),
                &peer,
                &hello,
            ) else {
                continue;
            };
            if writer.send_handshake(&outcome).await.is_err() {
                continue;
            }
            let HandshakeOutcome::Accepted(accepted) = &outcome else {
                // A refused bridge is told why and the connection ends. It is not a loss: nothing
                // was registered, so there is nothing for the session to lose.
                continue;
            };
            let Some(observed) = observe(&peer).process else {
                continue;
            };
            // The socket's writer is a task of its own. A reader that has stopped reading its own
            // socket must not be able to stop the 250 ms timer: the hold belongs to the clock, not
            // to whether the peer is keeping up.
            let (outbound, receiving) = tokio::sync::mpsc::unbounded_channel();
            {
                let mut session = self.runtime.session();
                if let Some(driver) = session.fence_mut() {
                    let _ = driver.registered(hello.shell.kind);
                    driver.send_through(outbound);
                }
                session.record_root_integration(Registration::new(
                    accepted.clone(),
                    &hello,
                    observed,
                ));
            }
            let mut writing = tokio::spawn(write_outbound(writer, receiving));
            self.pump(&mut reader, &mut writing).await;
            // The connection has ended. The driver stops queueing for it and the session hears that
            // its integration has gone, before the writer is waited on at all: a peer that has
            // stopped reading its own socket must not be able to hold up the loss that releases
            // held input and answers the callers waiting on a launch.
            {
                let mut session = self.runtime.session();
                if let Some(driver) = session.fence_mut() {
                    driver.stop_sending();
                }
            }
            let _ = self
                .runtime
                .drive_fence(|driver| driver.integration_lost(IntegrationLoss::BridgeDisconnected));
            writing.abort();
            if self.runtime.state() == kr_protocol::session::SessionState::Closed {
                return;
            }
        }
    }

    /// Reads and times one registered connection.
    ///
    /// Three things happen here and nothing else: a frame arrives, the machine's one timer fires,
    /// or the writer's task ends. Writing is the other task's, so neither can hold the other up,
    /// but a writer that has failed is this connection over: a peer can close the side it reads
    /// from and leave the side it writes to open, and a read that waited for a frame that will
    /// never come would leave the loss unreported and every caller waiting on a launch unanswered.
    async fn pump(&self, reader: &mut BridgeReader, writing: &mut tokio::task::JoinHandle<()>) {
        loop {
            let (wake, deadline) = {
                let session = self.runtime.session();
                let Some(driver) = session.fence() else {
                    return;
                };
                (driver.waker(), driver.deadline())
            };
            // A stimulus stores a permit rather than broadcasting, so a deadline that moved
            // between the reading above and this wait is not missed: the permit is waiting here.
            let notified = wake.notified();
            let frame = match deadline {
                Some(left) => tokio::select! {
                    biased;
                    frame = reader.recv() => Some(frame),
                    _ = &mut *writing => {
                        reader.finish();
                        return;
                    }
                    () = tokio::time::sleep(left) => None,
                    () = notified => continue,
                },
                None => tokio::select! {
                    biased;
                    frame = reader.recv() => Some(frame),
                    _ = &mut *writing => {
                        reader.finish();
                        return;
                    }
                    () = notified => continue,
                },
            };
            let mut ended = false;
            let _ = self.runtime.drive_fence(|driver| match frame {
                // The timer fired. A deadline is a fact about the clock rather than about which
                // message arrives next, so the sweep happens here whether or not the reader is
                // saying anything.
                None => driver.expire(),
                Some(Ok(FromBridge::Event { id, event })) => driver.bridge_event(id, &event),
                Some(Ok(FromBridge::Answer { answer, .. })) => driver.bridge_answer(&answer),
                // A second hello on a registered connection, or a frame a bridge does not send, or
                // a connection that ended. All three end the connection.
                Some(Ok(FromBridge::Hello(_))) | Some(Err(_)) => {
                    ended = true;
                    crate::fence::Effects::default()
                }
            });
            if ended {
                reader.finish();
                return;
            }
        }
    }
}

/// Writes what the driver queues, for as long as the connection lasts.
async fn write_outbound(
    mut writer: BridgeWriter,
    mut queued: tokio::sync::mpsc::UnboundedReceiver<Outbound>,
) {
    while let Some(frame) = queued.recv().await {
        let sent = match frame {
            Outbound::Request(request) => {
                let id = writer.next_request_id();
                writer.send_request(id, *request).await
            }
            Outbound::EventResult { id, result } => writer.send_event_result(id, *result).await,
            Outbound::Publication(publication) => writer.send_publication(publication).await,
            Outbound::Revocation {
                transaction,
                reason,
            } => writer.send_revocation(transaction, reason).await,
        };
        if sent.is_err() {
            // The peer has gone or the frame was cut in half. Either way this connection is over.
            // Ending this task is what says so: the read loop is waiting on it as well as on the
            // socket, because a read already in progress hears nothing from the flag alone.
            writer.finish();
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use kr_protocol::identity::{DesktopBinding, WorkerProfile};
    use kr_protocol::ids::{SessionEpoch, SessionId};
    use kr_protocol::root::{
        CwdRevision, EditorBufferRevision, EditorKeymap, EditorState, PendingReaderInput,
        PromptGeneration, ReaderContext, ReaderRevision, RootEditorEnterParams,
    };
    use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
    use kr_shell_integration::contract::events::{BridgeEvent, EofGesture, HooksActivated};
    use kr_shell_integration::contract::fence::LeaseView;
    use kr_shell_integration::contract::qualification::ShellKind;
    use kr_transport::clock::{ContinuousClock, ManualClock, SystemContinuousClock};

    use crate::fence::FenceDriver;
    use crate::pty::ShellCommand;
    use crate::session::{Session, SessionConfig};

    use super::*;

    /// A session with a managed editor, on a shell that says nothing.
    fn session(host: &kr_ipc::testing::TempHost, clock: Arc<dyn ContinuousClock>) -> Session {
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let mut session = Session::open(SessionConfig {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id: host.environment_id(),
            display_number: DisplayNumber::new(1),
            shell: ShellCommand {
                program: "/bin/cat".to_owned(),
                arguments: Vec::new(),
                cwd: "/".to_owned(),
                environment: Vec::new(),
            },
            shell_mode: ShellMode::Managed,
            worker_profile: WorkerProfile::HeadlessUser,
            desktop: DesktopBinding::none(),
            dimensions: Dimensions::new(80, 24),
            journal_path: Some(host.environment().journal_database(session_id)),
            spool_directory: Some(host.environment().session_spool(session_id)),
            send_queue_bytes: 8 * 1024 * 1024,
            resident_bytes: 1024 * 1024,
        })
        .expect("opens the session");
        session.launch().expect("launches the shell");
        let mut driver = FenceDriver::new(
            session_id,
            LeaseView::unheld(kr_protocol::ids::InputLeaseEpoch::new(0)),
            clock,
        );
        assert!(driver.registered(ShellKind::Zsh));
        session.install_fence(driver);
        session
    }

    /// A writer that fails ends the connection, even while the read is still waiting.
    ///
    /// A peer can close the side it reads from and leave the side it writes to open. The worker's
    /// write fails; its read waits for a frame that is never coming. Nothing else would report the
    /// loss, so every caller waiting on a launch would wait with it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_read_ends_when_the_writer_it_shares_a_connection_with_does() {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let session = session(&temp, Arc::new(SystemContinuousClock::new()));
        let session_id = session.id();
        let runtime = Arc::new(
            crate::runtime::SessionRuntime::start(
                session,
                Arc::new(kr_ipc::clock::SystemSharedClock),
            )
            .expect("starts the runtime"),
        );
        let endpoint = HostEndpoint::open_for_session(
            environment.runtime_root(),
            environment.runtime_dir(),
            session_id,
        )
        .expect("binds the bridge");

        // A real connection on that endpoint, so the read below is a read of a socket rather than
        // of something this test is pretending with. Nothing is ever sent on it.
        let address =
            kr_ipc::paths::Endpoint::from_path(std::path::Path::new(&endpoint.address().path))
                .expect("an address");
        let connecting =
            tokio::spawn(async move { kr_ipc::endpoint::Connection::connect(&address).await });
        let (served, _peer) = endpoint.listener().accept().await.expect("accepts");
        let _client = connecting.await.expect("joins").expect("connects");
        let (mut reader, _writer) = accept(served);

        let server = BridgeServer::new(
            Arc::clone(&runtime),
            endpoint,
            WorkerExpectation {
                session_id,
                root_process: kr_ipc::identity::current_process_start_identity()
                    .expect("this process"),
                supported_editor_abis: vec!["zle-5.9".to_owned()],
                supported_integration_versions: vec!["1".to_owned()],
                already_registered: false,
                gesture: EofGesture::default(),
            },
        );

        // The writer's task ends the way a failed write ends it. The read has nothing to read.
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let mut writing = tokio::spawn(async move {
            let _ = stopped.await;
        });
        let pumping = tokio::spawn(async move {
            server.pump(&mut reader, &mut writing).await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!pumping.is_finished(), "the read is still waiting");
        let _ = stop.send(());
        tokio::time::timeout(Duration::from_secs(5), pumping)
            .await
            .expect("the read ends with the writer")
            .expect("the task did not panic");

        runtime
            .close(kr_protocol::session::ClosureReason::CloseRequested)
            .1
            .release();
        let _ = tokio::time::timeout(Duration::from_secs(30), runtime.wait_closed()).await;
    }

    /// The same, with the machine's own timer armed.
    ///
    /// The read waits in a different arm of the same choice when a deadline is set, and a writer
    /// that stopped has to end the connection from either one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_read_with_a_deadline_armed_ends_with_its_writer_too() {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        // A clock this test never moves, so the exchange's own deadline never arrives however long
        // the read waits: the only way out of that arm is the writer this test stops.
        let mut session = session(&temp, Arc::new(ManualClock::new()));
        let session_id = session.id();
        // Qualified, with the keys held and a reader entering, which arms the machine's timer.
        {
            let mut requested = kr_protocol::scalars::CanonicalSet::new();
            requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
            requested.insert(kr_protocol::attachment::AttachmentCapability::Input);
            let params = kr_protocol::attachment::SessionAttachParams {
                session_id,
                mode: kr_protocol::attachment::AttachMode::Terminal,
                claim_geometry: false,
                dimensions: kr_protocol::scalars::Nullable::some(Dimensions::new(80, 24)),
                terminal_profile_id: kr_protocol::scalars::Nullable::some(
                    "xterm-256color".to_owned(),
                ),
                requested,
            };
            let attachment_id = kr_protocol::ids::AttachmentId::new(kr_ipc::new_uuid());
            session
                .attach(&params, params.requested.clone(), attachment_id)
                .expect("attaches");
            session
                .acquire_input(
                    attachment_id,
                    kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid()),
                    None,
                )
                .expect("takes the keys");
            let driver = session.fence_mut().expect("a driver");
            let _ = driver.bridge_event(
                kr_protocol::ids::RequestId::new(1),
                &BridgeEvent::HooksActivated(HooksActivated {
                    session_id,
                    prompt_generation: PromptGeneration::new(1),
                }),
            );
            let _ = driver.bridge_event(
                kr_protocol::ids::RequestId::new(2),
                &BridgeEvent::EditorEnter(RootEditorEnterParams {
                    session_id,
                    root_process: kr_ipc::identity::current_process_start_identity()
                        .expect("this process"),
                    prompt_generation: PromptGeneration::new(1),
                    reader_revision: ReaderRevision::new(1),
                    reader_context: ReaderContext::Primary,
                    editor: EditorState {
                        buffer_empty: true,
                        buffer_revision: EditorBufferRevision::new(1),
                        keymap: EditorKeymap::Emacs,
                        pending: PendingReaderInput::NONE,
                    },
                    cwd_revision: CwdRevision::new(1),
                }),
            );
            assert!(driver.deadline().is_some(), "the exchange armed the timer");
        }
        let runtime = Arc::new(
            crate::runtime::SessionRuntime::start(
                session,
                Arc::new(kr_ipc::clock::SystemSharedClock),
            )
            .expect("starts the runtime"),
        );
        let endpoint = HostEndpoint::open_for_session(
            environment.runtime_root(),
            environment.runtime_dir(),
            session_id,
        )
        .expect("binds the bridge");
        let address =
            kr_ipc::paths::Endpoint::from_path(std::path::Path::new(&endpoint.address().path))
                .expect("an address");
        let connecting =
            tokio::spawn(async move { kr_ipc::endpoint::Connection::connect(&address).await });
        let (served, _peer) = endpoint.listener().accept().await.expect("accepts");
        let _client = connecting.await.expect("joins").expect("connects");
        let (mut reader, _writer) = accept(served);
        let server = BridgeServer::new(
            Arc::clone(&runtime),
            endpoint,
            WorkerExpectation {
                session_id,
                root_process: kr_ipc::identity::current_process_start_identity()
                    .expect("this process"),
                supported_editor_abis: vec!["zle-5.9".to_owned()],
                supported_integration_versions: vec!["1".to_owned()],
                already_registered: false,
                gesture: EofGesture::default(),
            },
        );

        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let mut writing = tokio::spawn(async move {
            let _ = stopped.await;
        });
        let pumping = tokio::spawn(async move {
            server.pump(&mut reader, &mut writing).await;
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!pumping.is_finished(), "the read is still waiting");
        let _ = stop.send(());
        tokio::time::timeout(Duration::from_secs(5), pumping)
            .await
            .expect("the read ends with the writer")
            .expect("the task did not panic");

        runtime
            .close(kr_protocol::session::ClosureReason::CloseRequested)
            .1
            .release();
        let _ = tokio::time::timeout(Duration::from_secs(30), runtime.wait_closed()).await;
    }
}
