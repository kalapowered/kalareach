//! The sessions a workflow starts, closes and reads.
//!
//! A workflow node that runs a command or creates a session is not a connection: nothing in it
//! has a door, a window or a registration. What it has is a grant, which the automation module
//! decides, and a node whose action identifier the journal recorded. This module is where that
//! asker meets the daemon's own create and close paths:
//!
//! * A **create** goes through the same code a connection's create does, with the principal the
//!   workflow's grant scopes, the node's action identifier as the create token, and an admission
//!   the caller supplies, which is asked at the launch transition under the registry guard and
//!   again at the worker's claim.
//! * A **close** is a `session.close` forwarded to the session's worker under the workflow
//!   ingress, for the run that started the session. The request is built from the node's action
//!   identifier alone, so the node's task and a later sweep send the same bytes and a second
//!   close is answered from the first one's receipt.
//! * A **closure** is read after asking whether the worker has gone: nothing records a root's exit
//!   until something looks.

use std::sync::Arc;

use kr_protocol::actor::{ActorEnvelope, ActorIngress};
use kr_protocol::envelope::{ActionTarget, MutationRequest, ParamsValue};
use kr_protocol::ids::{
    ActionId, ActionWindowId, ActorId, ConnectionId, RequestId, SessionId, WorkflowRunId,
};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::scalars::{Digest256, DurationMs, Nullable, U64, Uuid};
use kr_protocol::session::{
    ClosureRecord, SessionCloseParams, SessionCreateParams, SessionCreateResult,
};
use kr_protocol::worker::EnvironmentOrigin;

use crate::error::{ControllerError, Result};
use crate::registry::Registry;

use super::close::CLOSE_EXCHANGE;
use super::create::{CreateFor, HeldLaunch};
use super::{Controller, parse};

/// The window a workflow's close is sent under. A forwarded mutation's freshness is the deadline
/// the daemon vouches for, so the window is a fixed word and the bytes of a close do not change
/// from one send to the next.
const CLOSE_WINDOW: &str = "workflow";

/// How long a workflow's close lives, which the worker does not read for a forwarded mutation but
/// which the mutation's digest covers.
const CLOSE_TTL_MS: u64 = 30_000;

/// What keeps a workflow node's right to start its session true: asked under the registry guard at
/// the launch transition and again at the worker's claim. An admission answers the last moment, in
/// milliseconds of the machine's continuous clock since boot, at which the session's process may
/// be created, when there is one: the claim hands it to the worker.
pub(crate) type WorkflowAdmission = Arc<dyn Fn(&Registry) -> Result<Option<u64>> + Send + Sync>;

/// What a workflow node asks the daemon to create.
pub(crate) struct WorkflowCreate {
    /// The principal the create is attributed to: stable, scoped to the definition's grant.
    pub(crate) actor_id: ActorId,
    /// The node's journalled action identifier, which is the create token: one node, one session,
    /// across a restart.
    pub(crate) token: ActionId,
    /// The digest of what the token stands for, covering only what stays the same for the node.
    pub(crate) digest: Digest256,
    /// The request.
    pub(crate) create: SessionCreateParams,
    /// The command the session's root runs and the run and node it is for, when the node runs a
    /// command.
    pub(crate) command: Option<(
        kr_protocol::worker::RootCommand,
        kr_protocol::worker::WorkflowSession,
    )>,
    /// Asked at the launch transition and again at the worker's claim, both under the registry
    /// guard. A node's grant, its widened rights, its accepted deadline and whether its run was
    /// cancelled are checked here.
    pub(crate) admit: WorkflowAdmission,
}

/// A close a workflow asks of a session it started.
pub(crate) struct WorkflowClose<'a> {
    /// The principal the close is attributed to.
    pub(crate) actor_id: &'a ActorId,
    /// The run the session was started for, which the worker compares with its own provenance.
    pub(crate) run_id: WorkflowRunId,
    /// The session.
    pub(crate) session_id: SessionId,
    /// The node's action identifier, from which the close's own identity is derived.
    pub(crate) node_action: ActionId,
}

/// The identity of a node's close: distinct from the identity of its create, stable across a
/// restart, and shaped as a UUIDv4 as an action identifier is.
#[must_use]
pub(crate) fn close_action_of(node_action: ActionId) -> ActionId {
    let mut covered = b"kalareach workflow close\n".to_vec();
    covered.extend_from_slice(node_action.get().as_bytes());
    let digest = kr_cbor::sha256(&covered);
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    ActionId::new(Uuid::from_bytes(bytes))
}

impl Controller {
    /// Creates a session for a workflow node, through the same path a connection's create takes.
    ///
    /// The update handover gate is taken first and kept until the create has settled, as for any
    /// create. The document in force is never accepted from here: an unattended workflow does not
    /// put a configuration into force, and a document this host cannot use refuses the create.
    ///
    /// # Errors
    ///
    /// Returns what the create refuses or fails with. A refusal of the node's admission is
    /// [`ControllerError::PermissionDenied`] or [`ControllerError::WindowExpired`], which the
    /// caller reads as authority gone, not as a launch that failed.
    pub(crate) async fn workflow_session_create(
        self: &Arc<Self>,
        order: WorkflowCreate,
    ) -> Result<SessionCreateResult> {
        let under_way = self.handover.admit()?;
        let admit = Arc::clone(&order.admit);
        let launch = HeldLaunch {
            admit: Arc::clone(&admit),
            command: order.command,
        };
        let created = self
            .create_under(
                &under_way,
                CreateFor {
                    actor_id: &order.actor_id,
                    token: order.token.get(),
                    digest: order.digest,
                    origin: EnvironmentOrigin::HostContext,
                },
                order.create,
                Some(launch),
                &|registry| admit(registry).map(|_| ()),
            )
            .await?;
        parse(&created)
    }

    /// Asks the worker that owns a workflow's session to close it, for the run that started it.
    ///
    /// The close is the same request every time it is made for one node, so a retry, or the sweep
    /// after a restart, finds the first one's receipt. Its deadline is fresh: the node's own wait
    /// has usually ended by the time anyone closes. After the worker's acceptance the daemon
    /// confirms delivery, which is what lets the worker stop the group, and watches for the
    /// worker to end. A session with no worker in the directory is closed already, was never
    /// launched, or has a worker that has not yet reported; its record, if there is one, is what
    /// [`Self::workflow_session_closure`] reads.
    ///
    /// Answers whether a worker was asked: `false` says the directory holds no worker for the
    /// session and nothing was sent. A caller that must see a session closed asks again until it
    /// is.
    ///
    /// # Errors
    ///
    /// Returns an error when the worker could not be reached or did not answer in the time a close
    /// is given. Neither says the session is still open.
    pub(crate) async fn workflow_session_close(
        self: &Arc<Self>,
        order: WorkflowClose<'_>,
    ) -> Result<bool> {
        let worker = self.directory.lock().await.get(order.session_id).cloned();
        let Some(worker) = worker else {
            return Ok(false);
        };
        let close_action = close_action_of(order.node_action);
        let mutation = MutationRequest {
            request_id: request_id_for(close_action),
            method: Method::SessionClose.into(),
            method_version: MethodVersion::V1,
            action_id: close_action,
            grant_id: Nullable::null(),
            target: ActionTarget {
                environment_id: self.paths.environment_id(),
                session_id: Nullable::some(order.session_id),
                session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            expected: ParamsValue::empty(),
            action_window_id: ActionWindowId::new(CLOSE_WINDOW)
                .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?,
            requested_ttl_ms: DurationMs::new(CLOSE_TTL_MS),
            params: ParamsValue::from_typed(&SessionCloseParams {
                session_id: order.session_id,
            })
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?,
        };
        // The envelope names no connection of its own and no grant: the daemon decided the grant
        // before it sent this, and a worker holds none. A connection identity is still a member of
        // the envelope, and a fresh one is the honest value for a request no connection made.
        let actor = ActorEnvelope {
            actor_id: order.actor_id.clone(),
            ingress: ActorIngress::Workflow,
            device_id: Nullable::null(),
            grant_id: Nullable::null(),
            grant_revision: Nullable::null(),
            controller_generation: self.generation,
            connection_id: ConnectionId::new(kr_ipc::new_uuid()),
        };
        let budget = tokio::time::Instant::now() + CLOSE_EXCHANGE;
        let mut link = match tokio::time::timeout_at(budget, self.worker_client(&worker)).await {
            Ok(Ok(link)) => link,
            Ok(Err(ControllerError::UnknownSession { .. })) => return Ok(false),
            Ok(Err(error)) => return Err(error),
            Err(_) => {
                return Err(ControllerError::supervision(
                    "the connection to the worker that owns this session did not come free in \
                     time, so nothing was closed",
                ));
            }
        };
        // The deadline is read once the link is held, because holding it is where the wait was.
        let deadline = U64::new(
            self.shared_clock
                .boot_elapsed_ms()
                .saturating_add(u64::try_from(CLOSE_EXCHANGE.as_millis()).unwrap_or(u64::MAX)),
        );
        let answered = tokio::time::timeout_at(
            budget,
            link.client()
                .forward_for_workflow(&mutation, &actor, order.run_id, deadline),
        )
        .await;
        match answered {
            Ok(Ok(Ok(_))) => {
                // The worker holds its close on this link until the acceptance has been delivered,
                // and signals nothing before it. The link is let go of first: confirming takes
                // every worker's link in turn, this one included, and the slot is held for as long
                // as the link is. A link that fails here is given up with its lease, and the close
                // is still the worker's: the closure is read from the record.
                link.give_back();
                drop(link);
                self.confirm_delivery(close_action).await;
                tokio::spawn(Arc::clone(self).watch_closure(
                    order.session_id,
                    kr_protocol::session::ClosureReason::CloseRequested,
                ));
                Ok(true)
            }
            Ok(Ok(Err(refusal))) => {
                link.give_back();
                Err(ControllerError::refused(&refusal))
            }
            Ok(Err(error)) => Err(error.into()),
            Err(_) => Err(ControllerError::Uncertain {
                detail: "the worker did not answer this close within the time a closure is \
                         given, so whether the session is stopping is not known"
                    .to_owned(),
            }),
        }
    }

    /// The closure of a session, after asking whether its worker has gone.
    ///
    /// A command that ends takes its worker with it, and nothing records that on its own: this
    /// asks the kernel about the worker the registry holds, and only a worker the kernel says has
    /// ended is reconciled. Reconciling closes the session and fences what it owned, which is for
    /// a worker that is gone; a worker that is still running, or that the kernel will not speak
    /// for, is left alone and the session has no closure yet. A worker that handed over its own
    /// account has that account recorded as it stands.
    ///
    /// `None` says the session has not closed, not that it is open.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read.
    pub(crate) async fn workflow_session_closure(
        self: &Arc<Self>,
        session_id: SessionId,
    ) -> Result<Option<ClosureRecord>> {
        let worker = {
            let registry = self.registry.lock().await;
            if let Some(closure) = registry.closure(session_id)? {
                return Ok(Some(closure));
            }
            registry
                .workers()?
                .into_iter()
                .find(|record| record.session_id == session_id)
        };
        let Some(worker) = worker else {
            return Ok(None);
        };
        if !matches!(
            kr_ipc::identity::process_state(&worker.process_identity),
            kr_ipc::identity::ProcessState::Ended
        ) {
            return Ok(None);
        }
        self.reconcile(session_id).await
    }

    /// The admission a workflow node's create stands on, as the registry guard asks it.
    ///
    /// It first asks whether this host owes a fence it could not raise, and then `check`, which
    /// the caller supplies: the node's grant on both clocks, the moment its wait ends and whether
    /// its run was cancelled, and which answers the last moment the process may be created, if any. It is asked at the launch transition and again at the worker's
    /// claim, both under the guard, and holds the daemon weakly, so a create that outlives it
    /// asks nothing. The decision reads the grant and policy stores, so it runs where the runtime
    /// may block, and the other tasks of the thread move to its peers meanwhile; the guard is
    /// held across it, which is what keeps a revocation from completing in between.
    pub(crate) fn workflow_admission(
        self: &Arc<Self>,
        check: impl Fn() -> Result<Option<u64>> + Send + Sync + 'static,
    ) -> WorkflowAdmission {
        let daemon = Arc::downgrade(self);
        Arc::new(move |_registry: &Registry| {
            let daemon = daemon
                .upgrade()
                .ok_or_else(|| ControllerError::PermissionDenied {
                    detail: "this host's daemon is not serving".to_owned(),
                })?;
            crate::supervision::blocking_start(|| {
                daemon.check_fence()?;
                check()
            })
        })
    }

    /// The boot this daemon runs in, which a worker of an earlier boot did not survive.
    pub(crate) fn boot(&self) -> &kr_protocol::identity::BootIdentity {
        &self.boot_identity
    }

    /// Milliseconds on the machine's continuous clock since boot, which a worker also reads.
    pub(crate) fn boot_elapsed_ms(&self) -> u64 {
        self.shared_clock.boot_elapsed_ms()
    }

    /// The session a node's create token resolved to, when one was launched, with the process of
    /// its worker.
    ///
    /// A reservation that failed before its worker started holds no session to close and none to
    /// wait for: its node has nothing left to release but what the node itself owned. The process
    /// is the one the launcher reported, which the worker's claim proved to be the worker's own,
    /// and the registry keeps it after the session has closed and its worker's row is gone.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read.
    pub(crate) async fn workflow_session_of(
        self: &Arc<Self>,
        actor_id: &ActorId,
        token: ActionId,
    ) -> Result<Option<NodeSession>> {
        Ok(self
            .registry
            .lock()
            .await
            .reservation_for_token(actor_id, token.get())?
            .filter(|reservation| reservation.phase != crate::registry::LaunchPhase::Failed)
            .map(|reservation| NodeSession {
                session_id: reservation.session_id,
                worker: reservation.launcher_identity,
            }))
    }
}

/// The session a workflow node's create token resolved to.
pub(crate) struct NodeSession {
    /// The session.
    pub(crate) session_id: SessionId,
    /// The process of its worker, once the launcher has reported it.
    pub(crate) worker: Option<kr_protocol::identity::ProcessStartIdentity>,
}

/// A request identifier for a close, derived from its action so the bytes of a retry match.
fn request_id_for(action: ActionId) -> RequestId {
    let bytes = action.get();
    let mut head = [0_u8; 8];
    head.copy_from_slice(&bytes.as_bytes()[..8]);
    RequestId::new(u64::from_le_bytes(head))
}

#[cfg(test)]
mod tests {
    use kr_protocol::ids::{ActionId, ActorId, SessionId, WorkflowRunId};
    use kr_protocol::scalars::Uuid;

    use super::WorkflowClose;
    use crate::service::a_link_that_is_not_given_back::Served;

    /// A close for a session whose worker is not in the directory asks nobody and says so: the
    /// session has closed, or its worker has not reported yet, and a caller that must see it closed
    /// asks again. Answering that as a close that was made would end the asking while the worker,
    /// once it reported, ran on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_close_for_a_session_with_no_worker_in_the_directory_says_nobody_was_asked() {
        let world = Served::recorded().await;
        let stranger = SessionId::new(Uuid::from_bytes([0x5a; 16]));
        let actor_id = ActorId::new("workflow:grant").expect("a principal");
        let asked = world
            .controller
            .workflow_session_close(WorkflowClose {
                actor_id: &actor_id,
                run_id: WorkflowRunId::new(Uuid::from_bytes([0x21; 16])),
                session_id: stranger,
                node_action: ActionId::new(Uuid::from_bytes([0x33; 16])),
            })
            .await
            .expect("having nobody to ask is no failure");
        assert!(!asked, "no worker was asked to close the session");
    }
}
