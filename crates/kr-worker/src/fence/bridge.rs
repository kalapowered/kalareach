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
            let writing = tokio::spawn(write_outbound(writer, receiving));
            self.pump(&mut reader).await;
            // The connection has ended. The driver stops queueing for it, the writer task finishes
            // whatever it had, and the session hears that its integration has gone.
            {
                let mut session = self.runtime.session();
                if let Some(driver) = session.fence_mut() {
                    driver.stop_sending();
                }
            }
            let _ = writing.await;
            let _ = self
                .runtime
                .drive_fence(|driver| driver.integration_lost(IntegrationLoss::BridgeDisconnected));
            if self.runtime.state() == kr_protocol::session::SessionState::Closed {
                return;
            }
        }
    }

    /// Reads and times one registered connection.
    ///
    /// Two things happen here and nothing else: a frame arrives, or the machine's one timer fires.
    /// Writing is the other task's, so neither can hold the other up.
    async fn pump(&self, reader: &mut BridgeReader) {
        loop {
            let (wake, deadline) = {
                let session = self.runtime.session();
                let Some(driver) = session.fence() else {
                    return;
                };
                (driver.waker(), driver.deadline())
            };
            // The wait is created before the deadline is read, and a stimulus stores a permit
            // rather than broadcasting, so a deadline that moved between the two is not missed.
            let notified = wake.notified();
            let frame = match deadline {
                Some(left) => tokio::select! {
                    biased;
                    frame = reader.recv() => Some(frame),
                    () = tokio::time::sleep(left) => None,
                    () = notified => continue,
                },
                None => tokio::select! {
                    biased;
                    frame = reader.recv() => Some(frame),
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
            // The peer has gone or the frame was cut in half. Either way this connection is over,
            // and the reader's side finds out on its own next read.
            writer.finish();
            return;
        }
    }
}
