//! Serving one authorised remote connection.
//!
//! Everything a paired device asks for passes through here, and the order is the contract:
//!
//! 1. **The registry decides.** `ConnectionActor::admit` resolves the method against the authority
//!    table at the *paired-device* ingress, so a method kept to private IPC is unreachable however
//!    broad the device's grant is, and no mutation is admitted in 0-RTT.
//! 2. **The registration decides.** The connection's registration in the daemon's authority store
//!    is checked before anything is read, before anything is dispatched, and again before the
//!    answer is written. That is the fence a revocation sets: section 9's dispatch barrier covers a
//!    worker's dispatch, and this covers a read or a subscription on a connection that was
//!    authorised a moment earlier.
//! 3. **The grant decides, through the one intersection.** The grant the device holds is intersected
//!    with this host's policy and with the rights ceiling its configuration put in force, and the
//!    method is decided against what is left: the grant's expiry, the environment and session its
//!    selectors admit, the rights the method requires, and the content its history scope reaches.
//!    A right the configuration removed is refused by its name.
//! 4. **The window decides.** A mutation's accepted deadline is the earliest of what its action
//!    window has left, receipt time plus the requested lifetime, what remains of the grant's own
//!    lifetime, and the dispatch lease's remaining time.
//! 5. **The subject acts.** The daemon performs what it owns; everything else is forwarded to the
//!    worker that owns the session, under the verified envelope and the accepted deadline, through
//!    the same serial barrier a local caller's mutation passes through.
//!
//! # The write boundary
//!
//! Every frame this connection sends — a response, a receipt, a relayed notification — is decided
//! and written behind one turn, and a withdrawal takes the same turn's latch before it closes the
//! connection. So no write can *begin* after the authority behind it was withdrawn. A write that
//! had already begun decided its bytes while the registration stood, and the closed connection is
//! what stops it reaching a peer; the withdrawal itself never waits for a peer.
//!
//! A batch a subscription carries is a read that goes on, so it is also written under the decision
//! that allowed it: the grant, this host's policy and the configured ceiling, taken for that batch.
//! The boundary holds the batch to that decision after every wait and at every attempt to hand
//! bytes over, through an epoch that any change to the policy or the ceiling moves and the moment
//! the decision's own time bound runs out; the watch takes the whole decision again while the write
//! waits. A decision that stops holding before the first byte goes has the batch decided again,
//! and one that stops holding once bytes are moving ends the connection.
//!
//! # What outlives the connection
//!
//! A mutation's effect runs on its own task, so a durable commit is never left half done because a
//! peer went away. So does the release of what the connection owned at its worker, and that runs
//! from a guard's destructor rather than from the end of the serve loop, because the transport
//! drops the handler's future the moment the control stream ends.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use kr_protocol::actor::ActorEnvelope;
use kr_protocol::envelope::{ControlFrame, Outcome, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{AuthorityRevision, ConnectionId, DeviceId, RequestId};
use kr_transport::actor::ConnectionActor;
use kr_transport::listener::AuthorisedSession;

use super::devices::DeviceRecord;
use super::proxy::{RELAY_QUEUED_BYTES, RelayBudget, Relayed, WorkerProxy};
use crate::service::Controller;

mod decision;
mod forwarding;
mod narrowing;
mod output;
mod routes;

pub use decision::Answered;
pub use output::{AUTHORITY_POLL, ExpiryObserver, RELAY_DECISIONS, RemoteOutput, WITHDRAWN};
pub use routes::EFFECT_WAIT;

use output::Authorisation;

#[cfg(test)]
use output::FrameSink;

/// What one authorised remote connection is serving.
pub struct RemoteConnection {
    controller: Arc<Controller>,
    /// This host's device directory, which also records where each action was dispatched.
    devices: Arc<super::devices::DeviceDirectory>,
    /// The device this connection belongs to, as the record stood when it was admitted.
    device: DeviceRecord,
    actor: ConnectionActor,
    connection_id: ConnectionId,
    output: Arc<RemoteOutput>,
    authority: Arc<Authorisation>,
    /// This connection's own link to the worker it has attached to, opened on first use.
    proxy: tokio::sync::Mutex<Option<Arc<WorkerProxy>>>,
    /// Where a notification the proxy read is written.
    notifications: tokio::sync::mpsc::Sender<Relayed>,
    /// What this connection has queued for the device and not yet had written.
    budget: Arc<RelayBudget>,
    /// Notified when this connection's link to its worker ends, whichever way it ends.
    lost: Arc<tokio::sync::Notify>,
    windows: Arc<kr_transport::window::ActionWindowIssuer>,
}

impl std::fmt::Debug for RemoteConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteConnection")
            .field("connection", &self.connection_id)
            .field("device", &self.device.device_id)
            .finish_non_exhaustive()
    }
}

impl RemoteConnection {
    /// Builds the server of one authorised connection.
    #[must_use]
    pub fn new(
        controller: Arc<Controller>,
        records: super::devices::HostRecords,
        device: DeviceRecord,
        session: &AuthorisedSession,
        notifications: tokio::sync::mpsc::Sender<Relayed>,
        grant_deadline: Option<kr_transport::clock::ContinuousInstant>,
    ) -> Self {
        let authority = Arc::new(Authorisation {
            grant_deadline,
            grant_expires_at_ms: match device.grant.expiry {
                kr_protocol::grant::GrantExpiry::At { expires_at_ms } => Some(expires_at_ms.get()),
                kr_protocol::grant::GrantExpiry::Never => None,
            },
            controller: Arc::clone(&controller),
            device_id: device.device_id,
            devices: Arc::clone(&records.devices),
            pending: Arc::clone(&records.pending),
            clock: Arc::clone(&records.clock),
            connection_id: session.connection_id,
            expired: AtomicBool::new(false),
            recorded: AtomicBool::new(false),
        });
        Self {
            controller,
            devices: Arc::clone(&records.devices),
            device,
            actor: session.actor.clone(),
            connection_id: session.connection_id,
            output: Arc::new(RemoteOutput::new(session, Arc::clone(&authority))),
            authority,
            proxy: tokio::sync::Mutex::new(None),
            notifications,
            // What this connection said it could receive, never more than the protocol's own
            // bound: a peer that offered a smaller send queue is held to what it offered.
            budget: Arc::new(RelayBudget::new(
                usize::try_from(session.selection.limits.max_send_queue_bytes.get())
                    .unwrap_or(RELAY_QUEUED_BYTES)
                    .min(RELAY_QUEUED_BYTES),
            )),
            lost: Arc::new(tokio::sync::Notify::new()),
            windows: Arc::clone(&session.windows),
        }
    }

    /// A connection for `device` that writes nothing anywhere, registered at the revision in
    /// force, for a test that drives this door's own methods.
    #[cfg(test)]
    pub(crate) fn for_test(controller: &Arc<Controller>, device: DeviceRecord) -> Self {
        /// A control stream that takes every frame and sends it nowhere.
        #[derive(Debug)]
        struct Nowhere;

        impl FrameSink for Nowhere {
            fn send_while<'a>(
                &'a self,
                _frame: &'a ControlFrame,
                _admits: &'a (dyn Fn() -> bool + Send + Sync),
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = kr_transport::Result<bool>> + Send + 'a>,
            > {
                Box::pin(async { Ok(true) })
            }

            fn close(&self) {}
        }

        Self::for_test_writing_to(controller, device, Box::new(Nowhere))
    }

    /// A connection for `device` that writes to `sink`, registered at the revision in force.
    #[cfg(test)]
    fn for_test_writing_to(
        controller: &Arc<Controller>,
        device: DeviceRecord,
        sink: Box<dyn FrameSink>,
    ) -> Self {
        let connection_id = ConnectionId::new(kr_ipc::new_uuid());
        controller.admitted_table().insert(
            connection_id,
            crate::service::AdmittedConnection::new(
                device.principal(),
                controller.policy().authority_revision(),
            ),
        );
        let authority = Arc::new(Authorisation {
            grant_deadline: None,
            grant_expires_at_ms: None,
            controller: Arc::clone(controller),
            device_id: device.device_id,
            devices: Arc::clone(controller.devices()),
            pending: Arc::new(super::devices::PendingExpiry::default()),
            clock: Arc::clone(controller.lifetimes().clock_trust()),
            connection_id,
            expired: AtomicBool::new(false),
            recorded: AtomicBool::new(false),
        });
        let (notifications, _) = tokio::sync::mpsc::channel(1);
        Self {
            controller: Arc::clone(controller),
            devices: Arc::clone(controller.devices()),
            actor: ConnectionActor::network_device(
                device.principal(),
                device.device_id,
                controller.generation,
                connection_id,
            ),
            device,
            connection_id,
            output: Arc::new(RemoteOutput::writing_to(sink, Arc::clone(&authority))),
            authority,
            proxy: tokio::sync::Mutex::new(None),
            notifications,
            budget: Arc::new(RelayBudget::new(RELAY_QUEUED_BYTES)),
            lost: Arc::new(tokio::sync::Notify::new()),
            windows: Arc::new(
                kr_transport::window::ActionWindowIssuer::with_default_validity(Arc::clone(
                    &controller.clock,
                )),
            ),
        }
    }

    /// Returns what records this device's grant expiry, for work that outlives this connection.
    #[must_use]
    pub fn expiry_observer(&self) -> ExpiryObserver {
        ExpiryObserver(Arc::clone(&self.authority))
    }

    /// Returns this connection's write boundary.
    #[must_use]
    pub fn output(&self) -> &Arc<RemoteOutput> {
        &self.output
    }

    /// Returns the connection this serves.
    #[must_use]
    pub const fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Returns the device this connection belongs to.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device.device_id
    }

    /// Returns true when this connection's grant still has time on it.
    ///
    /// The deadline was anchored on the continuous clock when the connection was admitted, and
    /// once it has passed it stays passed: a wall clock stepped backwards revives nothing.
    pub fn grant_is_current(&self) -> bool {
        if self.authority.has_time_left() {
            return true;
        }
        self.authority.note_expiry();
        false
    }

    /// Ends this connection's worker link and detaches whatever it owned.
    ///
    /// Closing the link is what the worker reads as the connection ending, and the worker's own
    /// deregistration then detaches the attachments and stops the delivery task. It runs on a task
    /// that outlives the connection, because dropping the handler is a cancellation.
    pub async fn release(&self) {
        if let Some(proxy) = self.proxy.lock().await.take() {
            proxy.close();
        }
    }

    /// Returns the envelope every request on this connection is attributed to.
    ///
    /// It is built from what the connection established and the record it was admitted against: a
    /// request names the grant it claims, and it cannot name its own device, its ingress or the
    /// generation that admitted it. The revision is the one this request's grant check was made
    /// at, not the one the grant was issued under: the worker compares it with the revision it
    /// holds, so it has to be the moment the host actually looked.
    fn envelope(&self, validated: AuthorityRevision) -> ActorEnvelope {
        self.actor
            .envelope(Some((self.device.grant.grant_id, validated)))
    }

    /// Resolves once this connection's link to its worker has ended.
    ///
    /// A connection with no link has no subscription and no attachment, so it is not a connection
    /// that can go on being served. It resolves immediately when there is no link to lose, so a
    /// caller selecting on it does not have to know whether one was ever opened — except that a
    /// connection which has not attached yet has nothing to lose, and waits.
    pub async fn link_lost(&self) {
        let held = self.proxy.lock().await.as_ref().map(Arc::clone);
        match held {
            Some(proxy) => proxy.lost().await,
            // Nothing to lose yet. Waiting for the notification the first link will send is what
            // keeps a connection that has not attached from ending itself.
            None => self.lost.notified().await,
        }
    }

    /// Returns whether this connection's registration still stands.
    pub async fn is_authorised(&self) -> bool {
        self.authorised().await.is_ok()
    }
}

fn outcome_unknown() -> ProtocolError {
    ProtocolError::new(
        ErrorCode::OutcomeUnknown,
        "this host could not report what happened to the action",
    )
}

fn failure(request_id: RequestId, error: ProtocolError) -> ControlFrame {
    ControlFrame::Response(Response {
        request_id,
        outcome: Outcome::Error(error),
    })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod write_boundary;

#[cfg(test)]
mod a_share_that_names_a_current_decision;
