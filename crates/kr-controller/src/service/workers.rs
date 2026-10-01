//! The workers this daemon knows: the directory, the one connection to each, a read from one.

use std::sync::Arc;

use kr_ipc::client::LocalClient;
use kr_protocol::ids::SessionId;
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::session::{SessionReadParams, SessionReadResult, SessionSummary};

use crate::directory::{KnownWorker, Reconnect};
use crate::error::{ControllerError, Result};

use super::{Controller, reported_read};

/// The resource kind a closure uses to say its worker was never confirmed gone.
///
/// A closure removes the registry's worker row and retires the published descriptor, so after it
/// is written those two can no longer say whether anything is still there. This is what does: a
/// session closed on a boot record the platform would not corroborate lists its worker here
/// rather than among the processes it terminated, and every read and migration asks for it.
pub(super) const UNACCOUNTED_WORKER: &str = "unaccounted_worker";

/// How long the daemon waits for one worker to answer before it reports that worker as pending.
///
/// Section 9: waiting is not completion. A worker that will not answer is `pending`, and the only
/// way to make it complete is an acknowledgement or a confirmed ending, so the wait has a bound and
/// the report goes out without it.
pub(super) const WORKER_EXCHANGE: std::time::Duration = std::time::Duration::from_secs(5);

impl Controller {
    /// Records that a worker's control path was lost, wherever the loss was noticed.
    ///
    /// Renewal stops with the path. Section 9 ties renewal to the live binding rather than to a
    /// revision number, so every place that gives up on a worker's client says so here rather than
    /// leaving a lease renewable over a socket that has gone.
    pub(super) fn lost_control_path(&self, session_id: SessionId) {
        let binding = self.leases.binding(session_id);
        self.leases.stop_renewal(session_id, binding);
    }

    /// Returns what a worker needs to accept this daemon's authority.
    pub(super) fn reconnect(&self) -> Reconnect<'_> {
        Reconnect {
            identity: &self.identity,
            generation: self.generation,
            boot_identity: &self.boot_identity,
            build_id: &self.build_id,
        }
    }

    /// Adds a verified worker to the directory, with its own description of its session where
    /// this daemon has one (`Directory::insert`), and starts reading its attention sources.
    pub(super) async fn add_worker(&self, worker: KnownWorker, described: Option<SessionSummary>) {
        // A recorded or adopted worker answers rounds of plugin admissions on its own endpoint from
        // here on, and is sent one at once.
        self.plugin_bridge.recorded(
            worker.descriptor.session_id,
            worker.descriptor.process_start_identity.clone(),
        );
        self.directory
            .lock()
            .await
            .insert(worker.clone(), described);
        self.attention.watch(self.attention_reach(), worker.clone());
        self.describe_worker(&worker);
        self.admissions_due();
    }

    pub(super) async fn read_from_worker(&self, worker: &KnownWorker) -> Result<SessionReadResult> {
        self.read_from_worker_within(worker, None).await
    }

    /// Reads a session from its worker, optionally giving the worker a bounded moment to answer.
    ///
    /// The bound belongs here rather than around the call. A request abandoned from outside would
    /// leave this connection with an answer nobody read, and the next caller to use it would take
    /// that answer for its own; ending the connection is the only way to abandon a request on it,
    /// and that can only be done from inside, while its guard is still held.
    ///
    /// One deadline covers both halves. Waiting for the connection and waiting for the answer are
    /// two waits on one worker, and giving each the whole patience would let a worker take twice
    /// what its caller allowed, which is what a caller dividing a budget between workers is
    /// counting on it not doing.
    pub(super) async fn read_from_worker_within(
        &self,
        worker: &KnownWorker,
        patience: Option<std::time::Duration>,
    ) -> Result<SessionReadResult> {
        let deadline = patience.map(|patience| tokio::time::Instant::now() + patience);
        let mut held = match deadline {
            Some(deadline) => tokio::time::timeout_at(deadline, self.worker_client(worker))
                .await
                .map_err(|_| {
                    ControllerError::supervision("the worker's connection was busy for too long")
                })??,
            None => self.worker_client(worker).await?,
        };
        let client = held.as_mut().expect("the connection is open");
        let params = SessionReadParams {
            session_id: worker.descriptor.session_id,
        };
        let asked = client.request(Method::SessionRead, &params);
        let result = match deadline {
            Some(deadline) => match tokio::time::timeout_at(deadline, asked).await {
                Ok(result) => result,
                Err(_) => {
                    // The request was abandoned, so this connection has an answer nobody will
                    // read. It ends here; the next call opens a new one.
                    *held = None;
                    return Err(ControllerError::supervision(
                        "the worker did not answer in time",
                    ));
                }
            },
            None => asked.await,
        };
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                // A transport failure ends this connection. The next call opens a new one and
                // presents the generation again rather than writing into a socket that is gone,
                // and renewal stops with the path rather than outliving it.
                *held = None;
                self.lost_control_path(worker.descriptor.session_id);
                return Err(error.into());
            }
        };
        let read = match result {
            Ok(value) => reported_read(&value)
                .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?,
            Err(error) => return Err(ControllerError::InvalidArgument(error.to_string())),
        };
        // Kept for the moment this worker can no longer be asked (`Directory::ending`), while the
        // link is still held: every exchange with this worker runs over it in turn, so what the
        // worker said is kept in the order it said it.
        self.directory
            .lock()
            .await
            .heard(worker.descriptor.session_id, &read.session);
        drop(held);
        Ok(read)
    }

    /// Returns this daemon's one connection to a worker, opening it if there is none.
    ///
    /// The guard is held for the whole call, so two operations against one worker run in order
    /// rather than racing each other's authority.
    pub(super) async fn worker_client(
        &self,
        worker: &KnownWorker,
    ) -> Result<tokio::sync::OwnedMutexGuard<Option<LocalClient>>> {
        let link = {
            let mut connections = self.connections.lock().await;
            Arc::clone(
                connections
                    .entry(worker.descriptor.session_id)
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(None))),
            )
        };
        let mut held = link.lock_owned().await;
        if held.is_none() {
            *held = Some(self.open_worker(worker).await?);
        }
        Ok(held)
    }

    /// Returns this daemon's one connection to the worker of one session.
    ///
    /// The directory is what says where that worker is. A session the directory does not list has
    /// no connection to open, which is a worker this daemon has not reached rather than an error
    /// about the session.
    pub(super) async fn worker_client_of(
        &self,
        session_id: SessionId,
    ) -> Result<tokio::sync::OwnedMutexGuard<Option<LocalClient>>> {
        let worker = self.directory.lock().await.get(session_id).cloned();
        let worker = worker.ok_or_else(|| ControllerError::UnknownSession {
            session: session_id.to_string(),
        })?;
        self.worker_client(&worker).await
    }

    async fn open_worker(&self, worker: &KnownWorker) -> Result<LocalClient> {
        let mut client = LocalClient::connect(
            &worker.endpoint,
            LocalClientKind::Controller,
            self.build_id.clone(),
        )
        .await?;
        // Two proofs, both required: the worker proves it is the one the descriptor names, and
        // this daemon proves which generation it speaks for.
        client.verify_worker(&worker.descriptor).await?;
        let identity = &self.identity;
        let generation = self.generation;
        let boot = self.boot_identity.clone();
        client
            .present_generation(move |nonce| {
                identity
                    .generation_token(generation, &boot, nonce)
                    .map_err(kr_ipc::IpcError::from)
            })
            .await?;
        Ok(client)
    }
}
