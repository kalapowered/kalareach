//! The workers this daemon knows: the directory, the one connection to each, a read from one.

use std::sync::{Arc, Weak};

use kr_ipc::client::LocalClient;
use kr_protocol::ids::SessionId;
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::session::{SessionReadParams, SessionReadResult, SessionSummary};
use kr_transport::lease::WorkerBinding;

use crate::directory::{KnownWorker, Reconnect};
use crate::error::{ControllerError, Result};
use crate::service::net::proxy::{Purpose, WorkerProxy};

use super::recovery::ReservationHold;
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

/// This daemon's link to one worker, taken out of its slot for the work its holder does over it.
///
/// The link goes back into the slot only when that work ended whole ([`Self::give_back`]), which is
/// when no answer is still on its way over it and the worker's control path is as it was. Dropped
/// any other way, because opening it failed, an exchange over it failed or ran out of time, or the
/// future that held it was abandoned part way, it is closed instead, and the worker's lease stops
/// renewing with it: an answer may still be on its way, the next caller would read it as its own,
/// and the control path the lease rests on is not one this daemon can vouch for. That is done while
/// the slot is still held, so the next caller finds the path given up already.
///
/// It is the path in force when the link was taken that is given up. A path bound since, by an
/// announcement of an authority revision that waited for the slot, is not this link's to lose; one
/// bound before, by an announcement that queued for the slot behind this link's holder, is given up
/// with it, and that announcement's acknowledgement is then refused, so the worker stays pending
/// until the next one.
///
/// A wait for the slot that runs out holds nothing and so gives nothing up: it is not a failure of
/// the link, only of the wait. The daemon is held only weakly, so a daemon let go while a link is
/// out is not kept alive by it.
pub(crate) struct WorkerLink {
    daemon: Weak<Controller>,
    session_id: SessionId,
    /// The control path the worker was on when the slot was taken.
    binding: WorkerBinding,
    /// The link, out of the slot. It is declared before `slot`, so it is closed before the slot is
    /// released.
    client: Option<LocalClient>,
    /// Whether the link went back whole, or was never put at risk.
    returned: bool,
    /// The slot, held from taking the link until the link is dropped.
    slot: tokio::sync::OwnedMutexGuard<Option<LocalClient>>,
}

impl WorkerLink {
    /// The link, for the exchange. It was opened when the slot was empty.
    pub(crate) fn client(&mut self) -> &mut LocalClient {
        self.client.as_mut().expect("the link is out of its slot")
    }

    /// Whether this link still holds the connection it was taken with, which is so until it goes
    /// back into the slot.
    #[cfg(test)]
    pub(crate) const fn holds_the_connection(&self) -> bool {
        self.client.is_some()
    }

    /// Puts the link back into the slot, because the work it was taken for ended whole: an
    /// answer, including a refusal, that was read to its end. The slot stays held, so what the
    /// holder still has to do in order, such as recording what the worker said, is done before the
    /// next caller has the link; and the link is no longer at risk, so a holder dropped from here
    /// gives nothing up.
    pub(crate) fn give_back(&mut self) {
        *self.slot = self.client.take();
        self.returned = true;
    }
}

impl Drop for WorkerLink {
    fn drop(&mut self) {
        if self.returned {
            return;
        }
        if let Some(daemon) = self.daemon.upgrade() {
            daemon.leases.stop_renewal(self.session_id, self.binding);
        }
    }
}

impl std::fmt::Debug for WorkerLink {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkerLink")
            .field("session_id", &self.session_id)
            .field("binding", &self.binding)
            .field("returned", &self.returned)
            .finish_non_exhaustive()
    }
}

impl Controller {
    /// Returns what a worker needs to accept this daemon's authority.
    pub(super) fn reconnect(&self) -> Reconnect<'_> {
        Reconnect {
            identity: &self.identity,
            generation: self.generation,
            boot_identity: &self.boot_identity,
            build_id: &self.build_id,
        }
    }

    /// Publishes a verified worker's descriptor and makes this daemon hold the worker: it goes in
    /// the directory, with its own description of its session where this daemon has one
    /// (`Directory::insert`), in the set of workers the plugin admissions wait for, and its
    /// attention sources and its description are read. Nothing is done for a worker whose session
    /// has closed.
    ///
    /// The one place a running daemon makes a worker known (a start restores the workers it finds
    /// from the registry's rows and the descriptors on disk), and what this daemon holds of it is
    /// made in a section that holds the registry's lock and has found no closure. That is the lock
    /// a closure is recorded under, and the closure's own tidying takes the worker out of all of
    /// this after it, so a worker is either made known before its closure and removed by it, or the
    /// closure is seen here and nothing is made: a closure that lands between a worker's row being
    /// written and its publication cannot leave a closed session's worker in the directory, on the
    /// disk or in the admissions' set for as long as the daemon runs.
    ///
    /// The descriptor is written before that section, not in it. The write is a durable one that
    /// waits for the disk, and where a rename is refused for a moment it is tried again for seconds,
    /// while every request that is admitted waits for the registry's lock. A closure that lands
    /// while it is written has its own tidying remove a descriptor that may not yet be there, so the
    /// section that finds the closure removes it again. All of it runs on a task of its own that the
    /// caller awaits, as a closure's tidying does: a request that stops waiting after the descriptor
    /// is written must not leave one for a session whose closure has finished, and nothing would
    /// remove it.
    ///
    /// The reservation the worker was started for (`held`, which the caller holds) is shared with
    /// that task, and is given back when the publication ends as well as when the request does. A look at the reservation presents a
    /// generation token to the worker, and one presented while the worker is being made known
    /// fences the connections that begins to open, so a look that came after a request stopped
    /// waiting would otherwise overlap the publication that request left running.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read or the descriptor cannot be published.
    pub(super) async fn publish_worker(
        &self,
        worker: KnownWorker,
        described: Option<SessionSummary>,
        held: &ReservationHold,
    ) -> Result<()> {
        let Some(daemon) = self.me.upgrade() else {
            return self.make_worker_known(worker, described).await;
        };
        let held = held.clone();
        match tokio::spawn(async move {
            let _held = held;
            daemon.make_worker_known(worker, described).await
        })
        .await
        {
            Ok(published) => published,
            Err(ended) if ended.is_panic() => std::panic::resume_unwind(ended.into_panic()),
            Err(_) => Err(ControllerError::supervision(
                "this daemon stopped before it finished making a worker known",
            )),
        }
    }

    async fn make_worker_known(
        &self,
        worker: KnownWorker,
        described: Option<SessionSummary>,
    ) -> Result<()> {
        let session_id = worker.descriptor.session_id;
        #[cfg(test)]
        self.before_a_worker_is_made_known.wait().await;
        // Whether it was written is looked at once the closure has been: a write that fails after
        // the file has its name (the directory's flush) leaves a descriptor all the same.
        let published = kr_ipc::descriptor::publish(&self.paths, &worker.descriptor);
        let registry = self.registry.lock().await;
        if registry.closure(session_id)?.is_some() {
            drop(registry);
            kr_ipc::descriptor::retire(&self.paths, session_id)?;
            return Ok(());
        }
        published?;
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
        // Still in the section: a closure's tidying stops what these start, and it begins only once
        // the registry is let go, so none of it can be begun after it has been stopped.
        self.attention.watch(self.attention_reach(), worker.clone());
        self.describe_worker(&worker);
        self.admissions_due();
        drop(registry);
        Ok(())
    }

    /// The workers the directory holds.
    pub(super) async fn directory_workers(&self) -> Vec<KnownWorker> {
        self.directory.lock().await.iter().cloned().collect()
    }

    /// Keeps the workers whose sessions have no closure, for a caller that holds the registry's
    /// lock (`registry`) and begins on what it keeps before it lets that go.
    ///
    /// A closure is recorded under that lock, and its worker leaves the directory afterwards, on a
    /// task of its own. A caller that copies the directory and then acts without the lock can act on
    /// a worker that task has already tidied away. One that holds the lock acts on workers whose
    /// tidying is still to come, and that tidying undoes what the caller did.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read.
    pub(super) fn without_a_closure(
        registry: &crate::registry::Registry,
        workers: Vec<KnownWorker>,
    ) -> Result<Vec<KnownWorker>> {
        let mut open = Vec::with_capacity(workers.len());
        for worker in workers {
            if registry.closure(worker.descriptor.session_id)?.is_none() {
                open.push(worker);
            }
        }
        Ok(open)
    }

    /// Makes this daemon hold a link a remote connection has opened to a session's worker, unless
    /// the session has closed.
    ///
    /// The worker was read from the directory before the link was opened, and a closure can have
    /// landed since. The directory is read again, with its lock kept while the link is entered in
    /// the table the closure ends links from. A link entered before the closure takes the worker out
    /// of the directory is ended by the closure; one that comes after finds the worker gone, and is
    /// closed and refused. A link that carries a close is not entered ([`Purpose::Close`]) and is
    /// refused in the same way.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::UnknownSession`] when the directory no longer holds the worker.
    pub(super) async fn hold_proxy(
        &self,
        proxy: &Arc<WorkerProxy>,
        purpose: Purpose,
    ) -> Result<()> {
        let session_id = proxy.session_id();
        let directory = self.directory.lock().await;
        if directory.get(session_id).is_none() {
            drop(directory);
            proxy.close();
            return Err(ControllerError::UnknownSession {
                session: session_id.to_string(),
            });
        }
        if purpose == Purpose::Attachment {
            let mut proxies = self
                .proxies
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let held = proxies.entry(session_id).or_default();
            held.retain(|link| link.strong_count() > 0);
            held.push(Arc::downgrade(proxy));
        }
        drop(directory);
        Ok(())
    }

    /// Ends every link remote connections hold to a closed session's worker. Called once the
    /// closure has taken the worker out of the directory, which is what makes the links entered
    /// before it all the links there will be ([`Self::hold_proxy`]).
    pub(super) fn end_proxies_of(&self, session_id: SessionId) {
        let held = self
            .proxies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&session_id)
            .unwrap_or_default();
        for proxy in held.iter().filter_map(std::sync::Weak::upgrade) {
            proxy.close();
        }
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
        let mut link = match deadline {
            Some(deadline) => tokio::time::timeout_at(deadline, self.worker_client(worker))
                .await
                .map_err(|_| {
                    ControllerError::supervision("the worker's connection was busy for too long")
                })??,
            None => self.worker_client(worker).await?,
        };
        let params = SessionReadParams {
            session_id: worker.descriptor.session_id,
        };
        let asked = link.client().request(Method::SessionRead, &params);
        let result = match deadline {
            Some(deadline) => match tokio::time::timeout_at(deadline, asked).await {
                Ok(result) => result,
                // The request was abandoned, so this connection has an answer nobody will read.
                // The link goes with it, not back to the slot: the next call opens a new one.
                Err(_) => {
                    return Err(ControllerError::supervision(
                        "the worker did not answer in time",
                    ));
                }
            },
            None => asked.await,
        };
        // A transport failure ends this connection. The next call opens a new one and presents the
        // generation again rather than writing into a socket that is gone, and renewal stops with
        // the path rather than outliving it: the link is dropped, which does both. An answer
        // that is a refusal is a whole exchange, and the link goes back.
        let result = result?;
        link.give_back();
        let read = match result {
            Ok(value) => reported_read(&value)
                .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?,
            Err(error) => return Err(ControllerError::InvalidArgument(error.to_string())),
        };
        // Kept for the moment this worker can no longer be asked (`Directory::ending`), while the
        // slot is still held: every exchange with this worker runs over it in turn, so what the
        // worker said is kept in the order it said it.
        self.directory
            .lock()
            .await
            .heard(worker.descriptor.session_id, &read.session);
        drop(link);
        Ok(read)
    }

    /// Returns this daemon's one connection to a worker, opening it if there is none.
    ///
    /// The slot is held for as long as the link is, so two operations against one worker run in
    /// order rather than racing each other's authority. A wait for the slot is the caller's to
    /// bound, and one that runs out gives up nothing ([`WorkerLink`]); a link that cannot be opened
    /// is a failure of the path, and the worker's lease stops renewing with it.
    pub(super) async fn worker_client(&self, worker: &KnownWorker) -> Result<WorkerLink> {
        let session_id = worker.descriptor.session_id;
        let slot = {
            // A slot is made only for a worker the directory holds, with the directory's lock kept
            // while it is made. A closure takes the worker out of the directory and then out of the
            // table, so a caller that took the worker before the closure and asks for its
            // connection after it finds the directory without it and makes no slot, and one that
            // is before it has its slot taken out with the worker.
            let directory = self.directory.lock().await;
            if directory.get(session_id).is_none() {
                return Err(ControllerError::UnknownSession {
                    session: session_id.to_string(),
                });
            }
            let mut connections = self.connections.lock().await;
            Arc::clone(
                connections
                    .entry(session_id)
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(None))),
            )
        }
        .lock_owned()
        .await;
        let mut slot = slot;
        let mut link = WorkerLink {
            daemon: self.me.clone(),
            session_id,
            binding: self.leases.binding(session_id),
            client: slot.take(),
            returned: false,
            slot,
        };
        if link.client.is_none() {
            link.client = Some(self.open_worker(worker).await?);
        }
        Ok(link)
    }

    /// Returns this daemon's connection to a worker as it stands in `slot`, for a caller that
    /// writes over a link that exists and would not open one: nothing when the slot holds none.
    ///
    /// The slot is the one `slot` holds, taken by the caller, and the link carries the binding the
    /// worker's control path is on now, so what is given up with it is that path.
    pub(super) fn link_in(
        &self,
        session_id: SessionId,
        mut slot: tokio::sync::OwnedMutexGuard<Option<LocalClient>>,
    ) -> Option<WorkerLink> {
        let client = slot.take()?;
        Some(WorkerLink {
            daemon: self.me.clone(),
            session_id,
            binding: self.leases.binding(session_id),
            client: Some(client),
            returned: false,
            slot,
        })
    }

    /// Returns this daemon's one connection to the worker of one session.
    ///
    /// The directory is what says where that worker is. A session the directory does not list has
    /// no connection to open, which is a worker this daemon has not reached rather than an error
    /// about the session.
    pub(super) async fn worker_client_of(&self, session_id: SessionId) -> Result<WorkerLink> {
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
