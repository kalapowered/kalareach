//! The environment's automation service, hosted by the control daemon.
//!
//! The daemon owns the service's lifetime and its admission; `kr-automation` owns the definitions,
//! the runs, the node receipts and the causal budgets. What this module adds is the part that has
//! to be the daemon's.
//!
//! * Every method of the "Automation" group arrives through the daemon's ordinary path. A read is
//!   checked against current authority; a mutation carries an action window, is checked against
//!   the method registry and its rights, and runs on a task a dropped connection cannot cancel
//!   part way through.
//! * The admission the daemon accepted a mutation under is carried into the workflow journal and
//!   asked inside the transaction that performs the action, immediately before its first write.
//! * **The grant a definition names is this host's own, decided as a device's request is.** The
//!   engine never sees a grant a request carried. It asks [`HostGrants`], which reads the daemon's
//!   grant store and has the daemon decide the grant under its own model: the rights ceiling its
//!   configuration put in force, revocation and a revoked ancestor, the clock floor, expiry, the
//!   organisation leases, and the bounded offline validity on the continuous clock. It decides
//!   that again before every node a run dispatches.
//! * **An action is a real effect or it is a refusal.** [`HostActions`] carries out the change-set
//!   nodes against the environment's own change-set service, binding each result to the run that
//!   asked for it. The node's grant is held in force around every transaction that commits the
//!   effect, so a grant withdrawn while the write waits for the store stops the write. Every other
//!   action kind is refused by name. Nothing here writes a success receipt for work that was never
//!   done.
//!
//! The journal lives in the environment's state directory beside the registry, because section 24
//! requires a causal budget to survive a restart and a reboot, and a runtime directory does not
//! survive a reboot on every platform this host runs on.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use kr_automation::resources::{Owned, OwnedState, ResourceLedger, session_principal};
use kr_automation::{
    ActionKey, ActionOutcome, ActionRunner, Answer as Recorded, AuthoritySource, AutomationService,
    Dispatch, Host, Submitted, WorkflowStore,
};
use kr_changeset::ChangeSetService;
use kr_changeset::materialise;
use kr_changeset::service::CaptureOrder;
use kr_protocol::actor::ActorIngress;
use kr_protocol::automation::{
    NodeOutput, WorkflowActionKind, WorkflowDefinition, WorkflowEnableParams,
    WorkflowInstallParams, WorkflowNode, WorkflowPauseParams, WorkflowReadParams,
    WorkflowRunParams,
};
use kr_protocol::changeset::{ChangesetCaptureParams, ChangesetMaterializeParams, Provenance};
use kr_protocol::envelope::{
    ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::grant::Grant;
use kr_protocol::ids::{ActorId, EnvironmentId, GrantId, RequestId};
use kr_protocol::method::{Method, MethodGroup};
use kr_protocol::scalars::Nullable;

use crate::error::{ControllerError, Result};
use crate::service::Controller;

/// What an automation call answers with: the method's result, or the refusal the service decided.
pub type Answer<T> = std::result::Result<T, ProtocolError>;

/// The daemon this module decides and holds authority under.
///
/// The module is opened before the daemon that holds it is built, so the daemon is bound to it
/// once it exists, and from then on every grant is decided under the daemon's own model and every
/// change-set write is held under its registry. Until then, and after the daemon has gone, nothing
/// is decided: an answer about a grant needs the daemon that owns it.
#[derive(Debug, Default)]
struct Daemon {
    /// The daemon, once it is bound.
    bound: std::sync::OnceLock<Weak<Controller>>,
    /// Where automation's clock counts from, once it has taken a reading.
    anchor: std::sync::Mutex<Option<Anchor>>,
}

impl Daemon {
    /// A handle bound to `daemon` from the start.
    fn bound_to(daemon: &Arc<Controller>) -> Self {
        let handle = Self::default();
        let _ = handle.bound.set(Arc::downgrade(daemon));
        handle
    }

    /// The daemon, while it is serving.
    fn get(&self) -> kr_automation::Result<Arc<Controller>> {
        self.bound.get().and_then(Weak::upgrade).ok_or_else(|| {
            kr_automation::AutomationError::AuthorityUnavailable(
                "this host's daemon is not serving".to_owned(),
            )
        })
    }

    /// This host's reading of UTC for automation. See [`reading_at`]. It starts from the daemon's
    /// own reading, the later of the wall clock and its clock floor, and after that reads only the
    /// wall clock and the continuous clock, never the floor: a grant decided on one of its readings
    /// raises the floor to it, and a clock that read the floor back would count that reading as
    /// time passing. The wall clock alone before the daemon is bound and after it has gone.
    fn now_ms(&self) -> u64 {
        let Ok(daemon) = self.get() else {
            return kr_ipc::now_ms().get();
        };
        let mut anchor = self
            .anchor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let at = daemon.continuous_now();
        let start = *anchor.get_or_insert_with(|| {
            let settled = std::time::Duration::from_millis(daemon.settled_utc_now());
            Anchor {
                reading: settled,
                at,
                last: settled,
            }
        });
        let (now, kept) = reading_at(start, daemon.wall_now_ms(), at);
        *anchor = Some(kept);
        now
    }
}

/// The share of the continuous time that passes which a wall clock falling behind automation's
/// count may take back: one part in this many, a millisecond a second.
const SLEW_PARTS: u32 = 1_000;

/// Where automation's clock counts from, to the nanosecond.
#[derive(Clone, Copy, Debug)]
struct Anchor {
    /// The reading the count starts from, as time since the Unix epoch.
    reading: std::time::Duration,
    /// The continuous instant that reading was taken at.
    at: kr_transport::clock::ContinuousInstant,
    /// The last reading given, which no later one is below.
    last: std::time::Duration,
}

/// Automation's reading of UTC, in milliseconds, from the wall clock `wall_ms`, read at the
/// continuous instant `at`, and the anchor to keep.
///
/// The count is the suspend-aware continuous time since the anchor. The wall clock is the reading
/// whenever it is no further behind the count than a thousandth of that time: a wall clock on
/// time, set forward, or drifting as clocks do is followed, and the count starts again from it.
/// One further behind, which is a wall clock set back or stopped, is not followed down: the reading
/// goes on at the slowest rate allowed, closing on the wall clock by a millisecond a second. The
/// count is kept to the nanosecond, so no reading, however often it is taken, rounds any of the
/// time away: every stretch of continuous time moves the reading on by all but a thousandth of it,
/// whatever the wall clock does, and the reading never goes backwards.
fn reading_at(
    anchor: Anchor,
    wall_ms: u64,
    at: kr_transport::clock::ContinuousInstant,
) -> (u64, Anchor) {
    let elapsed = at.saturating_duration_since(anchor.at);
    let slowest = anchor
        .reading
        .saturating_add(elapsed)
        .saturating_sub(elapsed / SLEW_PARTS);
    let wall = std::time::Duration::from_millis(wall_ms);
    let kept = if wall >= slowest {
        let now = wall.max(anchor.last);
        Anchor {
            reading: now,
            at,
            last: now,
        }
    } else {
        Anchor {
            last: slowest.max(anchor.last),
            ..anchor
        }
    };
    (
        u64::try_from(kept.last.as_millis()).unwrap_or(u64::MAX),
        kept,
    )
}

/// The clock a workflow's deadlines, its action waits and its chain's lifetime are measured on:
/// the wall clock while it keeps pace with the continuous clock, and the continuous count, less a
/// thousandth, while a wall clock set back does not, so a deadline cannot be held back by more than
/// a thousandth of the time it runs.
#[derive(Debug)]
struct DaemonClock(Arc<Daemon>);

impl kr_automation::HostClock for DaemonClock {
    fn now_ms(&self) -> u64 {
        self.0.now_ms()
    }
}

/// What a new workflow chain inherits from this host: no more created sessions than the session
/// number admission enforces now, and no managed allowance, because this host gives a workflow
/// none. Before the daemon is bound and after it has gone, nothing.
#[derive(Debug)]
struct DaemonCeilings(Arc<Daemon>);

impl kr_automation::HostCeilings for DaemonCeilings {
    fn sessions(&self) -> u64 {
        self.0.get().map_or(0, |daemon| daemon.sessions_in_force())
    }

    fn managed_spend(&self) -> u64 {
        0
    }
}

/// This host's grants, as the automation engine reads them.
///
/// A definition names a grant identifier and nothing more. Whether that grant still authorises
/// anything is the grant store's and the daemon's to say: the store holds the expiry, the
/// revocation and the cascade a revoked ancestor causes, and the daemon decides the grant as it
/// decides a paired device's request, under the rights ceiling its configuration put in force, its
/// policy's clock floor and organisation leases, and the bounded offline validity held on the
/// continuous clock. Asking both here, rather than trusting a grant a request carried, is what
/// stops a workflow from acting under authority nobody holds.
#[derive(Debug)]
pub struct HostGrants {
    daemon: Arc<Daemon>,
}

impl HostGrants {
    /// Reads grants from `daemon`'s own stores and decides them under its own model.
    #[must_use]
    pub fn for_daemon(daemon: &Arc<Controller>) -> Self {
        Self {
            daemon: Arc::new(Daemon::bound_to(daemon)),
        }
    }

    /// Finds the record a grant stands on, in whichever of the daemon's stores holds it.
    ///
    /// A grant lives in one of two places: the grant store, for a grant the host issued or shared,
    /// and a paired device's own record, for the grant its pairing committed.
    fn record(
        daemon: &Controller,
        grant_id: GrantId,
    ) -> kr_automation::Result<crate::grants::GrantRecord> {
        let unavailable = |error: ControllerError| {
            kr_automation::AutomationError::AuthorityUnavailable(error.to_string())
        };
        if let Some(record) = daemon
            .sharing()
            .grants()
            .record(grant_id)
            .map_err(unavailable)?
        {
            return Ok(record);
        }
        // A paired device's grant is the one its pairing committed, and the device's record is
        // where its revocation and its expiry are written. A recorded expiry is a decision the host
        // already took, and it stands whatever the clock says now.
        let paired = daemon
            .devices()
            .devices()
            .map_err(unavailable)?
            .into_iter()
            .find(|device| device.grant.grant_id == grant_id)
            .ok_or_else(|| {
                kr_automation::AutomationError::PermissionDenied(format!(
                    "grant {grant_id} is not one this host issued"
                ))
            })?;
        if paired.expired_at_ms.is_some() {
            return Err(kr_automation::AutomationError::PermissionDenied(format!(
                "grant {grant_id}: this grant has expired"
            )));
        }
        Ok(crate::grants::GrantRecord {
            grant: paired.grant,
            session_id: None,
            issued_at_ms: paired.paired_at_ms.get(),
            activated_at_ms: Some(paired.paired_at_ms.get()),
            revoked_at_ms: paired.revoked_at_ms.map(|at| at.get()),
            revoked_by_parent: None,
        })
    }
}

impl AuthoritySource for HostGrants {
    fn grant(&self, grant_id: GrantId, now_ms: u64) -> kr_automation::Result<Grant> {
        let daemon = self.daemon.get()?;
        // The moment the caller's reading stands for. Everything from here on can wait, and the
        // daemon decides at the reading advanced by however long that was.
        let read_at = daemon.continuous_now();
        let record = Self::record(&daemon, grant_id)?;
        // A grant this host holds for itself is the owner's own authority at this machine; any
        // other recipient is a device that reached the host over the network, and the bounded
        // offline validity is about exactly that access.
        let ingress = if record.grant.recipient_device_id == daemon.sharing().host_device_id() {
            ActorIngress::LocalIpc
        } else {
            ActorIngress::PairedDevice
        };
        let rights = daemon.decide_for_workflow(&record, ingress, now_ms, read_at)?;
        // The grant as this host leaves it: a configured ceiling or an organisation lease that
        // narrows it narrows what the workflow may do, and the node is checked against the result.
        Ok(Grant {
            actions: rights,
            ..record.grant
        })
    }
}

/// The actions this host carries out for a workflow node.
///
/// The two change-set kinds reach the environment's change-set service, and the version each one
/// produces records the run that asked for it, so the evidence a later node reads is bound to the
/// execution that made it rather than to a claim about it. The node's grant is held in force
/// around every transaction that commits the effect (`HeldGrant`), the way a caller's admission is
/// held around a change-set method's own. A node that creates a session, or runs a command as the
/// root of one, goes through the daemon's own create path, with the same grant asked where the
/// session comes into being.
///
/// Every other registered kind is refused by name. A refusal is not an uncertain outcome: nothing
/// was dispatched, so the node failed and its dependants see a failure rather than a result
/// nobody produced.
pub struct HostActions {
    changesets: Arc<ChangeSetService>,
    authority: Arc<dyn AuthoritySource>,
    daemon: Arc<Daemon>,
    environment_id: EnvironmentId,
    /// What each dispatch that runs a command owns, written before it allocates.
    ledger: Arc<ResourceLedger>,
    /// Where a command that declared no workspace runs, one private directory per node.
    scratch_root: PathBuf,
    /// The dispatches this daemon is running now.
    live: Arc<LiveNodes>,
}

/// The node dispatches this daemon is running, each with the flag its cancellation sets.
///
/// A dispatch owns its ledger row while it is in here, and the sweep takes none of those: the
/// sweep is for what no task of this daemon owns.
#[derive(Debug, Default)]
struct LiveNodes {
    nodes: std::sync::Mutex<HashMap<kr_protocol::ids::ActionId, Arc<NodeTask>>>,
    /// Told when a dispatch ends or begins, so the sweep looks again.
    changed: tokio::sync::Notify,
}

/// One running dispatch, as the engine's cancellation sees it.
#[derive(Debug, Default)]
struct NodeTask {
    cancelled: AtomicBool,
}

impl LiveNodes {
    fn begin(&self, action_id: kr_protocol::ids::ActionId) -> Arc<NodeTask> {
        let task = Arc::new(NodeTask::default());
        self.nodes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(action_id, Arc::clone(&task));
        self.changed.notify_one();
        task
    }

    fn get(&self, action_id: kr_protocol::ids::ActionId) -> Option<Arc<NodeTask>> {
        self.nodes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&action_id)
            .cloned()
    }

    fn end(&self, action_id: kr_protocol::ids::ActionId) {
        self.nodes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&action_id);
        self.changed.notify_one();
    }
}

impl std::fmt::Debug for HostActions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostActions")
            .field("environment_id", &self.environment_id)
            .finish_non_exhaustive()
    }
}

impl ActionRunner for HostActions {
    /// A command's session is closed when its dispatch is asked to stop: the dispatch sees the
    /// flag, closes the session, and releases what it owned once the closure is recorded.
    /// Nothing is claimed about what the command did before it stopped.
    ///
    /// Neither change-set kind can be stopped once it has begun: the change-set service offers no
    /// point inside a capture or a materialisation to stop at. A session that was created for
    /// the node and is its output stays, and so is not stopped either. An action that outlives its
    /// wait and cannot be stopped is left unknown, and its dependants pause for review.
    fn cancel(&self, dispatch: &Dispatch<'_>) -> kr_automation::Cancellation {
        if kr_automation::definition::runs_a_command(dispatch.node.action_kind)
            && let Some(task) = self.live.get(dispatch.action_id)
        {
            task.cancelled.store(true, Ordering::SeqCst);
            return kr_automation::Cancellation::Requested;
        }
        kr_automation::Cancellation::Unsupported
    }

    fn execute(
        &self,
        dispatch: &Dispatch<'_>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = kr_automation::Result<ActionOutcome>> + Send>,
    > {
        let changesets = Arc::clone(&self.changesets);
        let held = HeldGrant {
            daemon: Arc::clone(&self.daemon),
            authority: Arc::clone(&self.authority),
            definition: dispatch.definition.clone(),
            node: dispatch.node.clone(),
            environment_id: self.environment_id,
            refused: std::sync::Mutex::new(None),
        };
        let run_id = dispatch.run_id;
        let node_context = NodeContext {
            daemon: Arc::clone(&self.daemon),
            changesets: Arc::clone(&self.changesets),
            ledger: Arc::clone(&self.ledger),
            scratch_root: self.scratch_root.clone(),
            live: Arc::clone(&self.live),
            run_id,
            action_id: dispatch.action_id,
            wait_until_ms: dispatch.wait_until_ms,
        };
        Box::pin(async move {
            match held.node.action_kind {
                WorkflowActionKind::CaptureChangeset => {
                    let asked: ChangesetCaptureParams =
                        serde_json::from_str(&held.node.action_params)?;
                    blocking(move || {
                        // Asked before the working tree is read, so a grant already gone costs no
                        // read; the hold asks it again around each write.
                        held.still_authorised()?;
                        capture(&changesets, &asked, run_id, &held)
                    })
                    .await
                }
                WorkflowActionKind::MaterializeChangeset => {
                    let asked: ChangesetMaterializeParams =
                        serde_json::from_str(&held.node.action_params)?;
                    blocking(move || {
                        held.still_authorised()?;
                        version_in_scope(
                            &changesets,
                            &held.definition,
                            &asked,
                            held.environment_id,
                        )?;
                        materialise_version(&changesets, &asked, &held)
                    })
                    .await
                }
                WorkflowActionKind::CreateSession => {
                    create_session_node(node_context, Arc::new(held)).await
                }
                // A command runs through a POSIX shell as the root of a session, which this
                // platform has not.
                WorkflowActionKind::ShellCommand if !cfg!(windows) => {
                    command_node(node_context, Arc::new(held)).await
                }
                other => {
                    Err(kr_automation::AutomationError::ActionUnavailable { action_kind: other })
                }
            }
        })
    }
}

/// A workflow node's grant, held in force while the change-set service commits the node's effect.
///
/// The change-set service asks for this around every transaction that commits an effect of its
/// own: the clone identity a capture fixes, a new change set and its version, the row a
/// materialisation is written under. Everything before those transactions can wait, for a blocking
/// thread, for the store's own lock, for a whole working tree to be read, and a grant withdrawn in
/// any of those intervals must leave nothing behind. So each hold takes the daemon's registry,
/// which is what a revocation takes to complete, refuses while a fence is owed, reads the grant as
/// it stands and checks the node against it, and only then runs the effect. A revocation that
/// begins while the effect commits finishes after it.
struct HeldGrant {
    daemon: Arc<Daemon>,
    authority: Arc<dyn AuthoritySource>,
    definition: WorkflowDefinition,
    node: WorkflowNode,
    environment_id: EnvironmentId,
    /// Why a hold refused, kept in the automation engine's own terms for the runner to answer
    /// with once the change-set service has passed the refusal back.
    refused: std::sync::Mutex<Option<kr_automation::AutomationError>>,
}

impl HeldGrant {
    /// Reads the grant as it stands now and checks this node against it.
    fn still_authorised(&self) -> kr_automation::Result<()> {
        let grant = self
            .authority
            .grant(self.definition.grant_reference, self.daemon.now_ms())?;
        kr_automation::authority::check_node(
            &grant,
            &self.definition,
            &self.node,
            self.environment_id,
        )
    }

    /// The refusal a hold recorded, in the engine's terms, when the change-set service reports
    /// that its effect was not admitted.
    ///
    /// A refusal is not an outcome: the effect did not commit, so the engine pauses the node as it
    /// would have if its own check had refused a moment earlier.
    fn refusal_of(
        &self,
        error: kr_changeset::ChangeSetError,
    ) -> kr_automation::Result<ActionOutcome> {
        match error {
            kr_changeset::ChangeSetError::NotAdmitted { code, detail } => Err(self
                .refused
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .unwrap_or_else(|| {
                    if code == ErrorCode::PermissionDenied {
                        kr_automation::AutomationError::PermissionDenied(detail.to_string())
                    } else {
                        kr_automation::AutomationError::AuthorityUnavailable(detail.to_string())
                    }
                })),
            other => Ok(ActionOutcome::Failed {
                error: kr_project::git::redact(&other.to_string()),
            }),
        }
    }

    fn refuse(&self, refusal: kr_automation::AutomationError) -> kr_changeset::ChangeSetError {
        let code = ProtocolError::from(&refusal).code;
        let detail = refusal.to_string();
        *self
            .refused
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(refusal);
        kr_changeset::ChangeSetError::NotAdmitted {
            code,
            detail: detail.into(),
        }
    }
}

impl kr_changeset::store::StillAdmitted for HeldGrant {
    fn hold(
        &self,
        effect: &mut dyn FnMut() -> kr_changeset::Result<()>,
    ) -> kr_changeset::Result<()> {
        let daemon = self.daemon.get().map_err(|refusal| self.refuse(refusal))?;
        // The effect runs on a blocking task of this daemon's own, so waiting here for the registry
        // blocks nothing but this node.
        let held = tokio::runtime::Handle::current().block_on(daemon.hold_registry(|| {
            match self.still_authorised() {
                Ok(()) => effect(),
                Err(refusal) => Err(self.refuse(refusal)),
            }
        }));
        match held {
            Ok(inner) => inner,
            Err(error) => {
                let refusal = error.to_protocol_error();
                Err(self.refuse(if refusal.code == ErrorCode::PermissionDenied {
                    kr_automation::AutomationError::PermissionDenied(refusal.message)
                } else {
                    kr_automation::AutomationError::AuthorityUnavailable(refusal.message)
                }))
            }
        }
    }
}

impl HeldGrant {
    /// Records why a hold refused, in the engine's terms, and answers the refusal the daemon's
    /// create path is given.
    ///
    /// The create reads the refusal as the authority it stood on being gone, and the dispatch
    /// that asked for it reads the engine's own term back out, so the node pauses as it would
    /// have if the engine's check had refused it a moment earlier.
    fn refuse_session(&self, refusal: kr_automation::AutomationError) -> ControllerError {
        let detail = refusal.to_string();
        *self
            .refused
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(refusal);
        ControllerError::PermissionDenied { detail }
    }

    /// The refusal a hold recorded, once.
    fn take_refusal(&self) -> Option<kr_automation::AutomationError> {
        self.refused
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

/// What a dispatch that creates a session needs beside its grant.
#[derive(Clone)]
struct NodeContext {
    daemon: Arc<Daemon>,
    changesets: Arc<ChangeSetService>,
    ledger: Arc<ResourceLedger>,
    scratch_root: PathBuf,
    live: Arc<LiveNodes>,
    run_id: kr_protocol::ids::WorkflowRunId,
    action_id: kr_protocol::ids::ActionId,
    /// The moment the engine stops waiting for this dispatch, on automation's clock.
    wait_until_ms: u64,
}

/// The principal a workflow's sessions are created under: stable, scoped to the definition's
/// grant, and the same for every run of it.
fn workflow_principal(grant: GrantId) -> kr_automation::Result<ActorId> {
    ActorId::new(session_principal(grant)).map_err(|error| {
        kr_automation::AutomationError::InvalidArgument(format!(
            "the principal for grant {grant} is not an identifier: {error}"
        ))
    })
}

/// The digest of what a node's create token stands for: the workflow, its revision, the node and
/// what the node asks for. Nothing in it changes between a run's attempts, so a retry of the same
/// node after a restart is the same create and never an identifier reused for another one.
fn node_digest(
    definition: &WorkflowDefinition,
    node: &WorkflowNode,
) -> kr_protocol::scalars::Digest256 {
    let text = format!(
        "{}\n{}\n{}\n{}\n{}\n{:?}",
        definition.workflow_id,
        definition.revision.get(),
        node.node_id,
        node.action_kind.as_str(),
        node.action_params,
        node.declared_environment.0,
    );
    kr_protocol::scalars::Digest256::from_bytes(kr_cbor::sha256(text.as_bytes()))
}

/// The admission a node's session stands on, as the daemon's create path asks it under its
/// registry guard: the node's grant, read as it stands now on both clocks, and then the moment the
/// engine stops waiting for the node, read after the grant has been decided.
fn node_admission(
    controller: &Arc<Controller>,
    held: &Arc<HeldGrant>,
    wait_until_ms: u64,
) -> Arc<dyn Fn(&crate::registry::Registry) -> Result<()> + Send + Sync> {
    let held = Arc::clone(held);
    controller.workflow_admission(move || {
        held.still_authorised()
            .map_err(|refusal| held.refuse_session(refusal))?;
        if held.daemon.now_ms() >= wait_until_ms {
            return Err(
                held.refuse_session(kr_automation::AutomationError::AuthorityUnavailable(
                    "the wait for this node ended before its session could start".to_owned(),
                )),
            );
        }
        Ok(())
    })
}

/// What a create that did not produce a session comes to for its node.
///
/// A refusal of the authority the create stood on pauses the node, with nothing claimed; a launch
/// that may still complete is unknown; anything else is a failure of the node, with nothing left
/// behind to release.
fn creation_failed(
    held: &HeldGrant,
    error: ControllerError,
) -> kr_automation::Result<ActionOutcome> {
    if let Some(refusal) = held.take_refusal() {
        return Err(refusal);
    }
    match error {
        ControllerError::PermissionDenied { detail } => {
            Err(kr_automation::AutomationError::PermissionDenied(detail))
        }
        ControllerError::WindowExpired { detail } => {
            Err(kr_automation::AutomationError::AuthorityUnavailable(detail))
        }
        ControllerError::Uncertain { detail } => Ok(ActionOutcome::Unknown {
            detail: kr_project::git::redact(&detail),
        }),
        other => Ok(ActionOutcome::Failed {
            error: kr_project::git::redact(&other.to_string()),
        }),
    }
}

/// Creates the session a `create_session` node asks for and leaves it running.
///
/// The session is the node's output and belongs to whoever uses it afterwards; the dispatch owns
/// nothing to release, so it writes no ledger row.
async fn create_session_node(
    context: NodeContext,
    held: Arc<HeldGrant>,
) -> kr_automation::Result<ActionOutcome> {
    let controller = context.daemon.get()?;
    let create: kr_protocol::session::SessionCreateParams =
        serde_json::from_str(&held.node.action_params)?;
    let order = crate::service::WorkflowCreate {
        actor_id: workflow_principal(held.definition.grant_reference)?,
        token: context.action_id,
        digest: node_digest(&held.definition, &held.node),
        create,
        root: None,
        admit: node_admission(&controller, &held, context.wait_until_ms),
    };
    match controller.workflow_session_create(order).await {
        Ok(created) => Ok(ActionOutcome::Success {
            output: NodeOutput::CreateSession {
                session_id: created.session.session_id,
            },
        }),
        Err(error) => creation_failed(&held, error),
    }
}

/// The interpreter a command runs through: a POSIX shell given the command line.
const COMMAND_INTERPRETER: &str = "/bin/sh";

/// How often a dispatch asks whether its session has closed.
const CLOSURE_POLL: std::time::Duration = std::time::Duration::from_millis(300);

/// How long a dispatch that was asked to stop waits for its session's closure before it leaves the
/// rest to the sweep.
const STOP_WAIT: std::time::Duration = std::time::Duration::from_secs(20);

/// Runs a `shell_command` node: the command is the root of a session of its own, and the node's
/// result is how that root ended.
///
/// What the dispatch will own is written to the ledger before any of it is made. The work then
/// runs on a task of the daemon's own, so the engine dropping the wait for it, at a deadline or a
/// cancellation, cannot drop a session in the middle of being created: the task finishes what it
/// began, closes the session if it was asked to stop, and releases what it owned.
async fn command_node(
    context: NodeContext,
    held: Arc<HeldGrant>,
) -> kr_automation::Result<ActionOutcome> {
    // The daemon is looked up for each call and never held across the command, which can run for
    // as long as the node's wait: a task that kept it would keep a daemon that is being let go.
    context.daemon.get()?;
    let params: kr_protocol::automation::ShellCommandParams =
        serde_json::from_str(&held.node.action_params)?;
    // Where it runs: the workspace the definition names, which may be a shared checkout because
    // the definition named it, or a private directory made for this node alone.
    let workspace_id = held.definition.resource_scope.workspace_id.0;
    let scratch = match workspace_id {
        Some(_) => None,
        None => Some(
            context
                .scratch_root
                .join(context.action_id.get().to_string()),
        ),
    };
    let cwd = match (workspace_id, scratch.as_ref()) {
        (Some(workspace_id), _) => {
            let changesets = Arc::clone(&context.changesets);
            let resolved = blocking(move || changesets.resolve(workspace_id))
                .await
                .map_err(|error| {
                    kr_automation::AutomationError::PermissionDenied(format!(
                        "the workspace this command runs in cannot be resolved: {}",
                        kr_project::git::redact(&error.to_string())
                    ))
                })?;
            resolved.path.display().to_string()
        }
        (None, Some(scratch)) => scratch.display().to_string(),
        (None, None) => unreachable!("a command with no workspace has a scratch directory"),
    };
    // Registered before anything is written down or made, so no sweep takes the row of a
    // dispatch that is still running.
    let task = context.live.begin(context.action_id);
    let owned = Owned {
        action_id: context.action_id,
        run_id: context.run_id,
        node_id: held.node.node_id.clone(),
        kind: held.node.action_kind,
        grant_id: held.definition.grant_reference,
        owns_session: true,
        materialisation_id: None,
        scratch: scratch.as_ref().map(|path| path.display().to_string()),
        workspace_id,
        session_id: None,
        state: OwnedState::Open,
    };
    let began = {
        let ledger = Arc::clone(&context.ledger);
        let now = context.daemon.now_ms();
        blocking(move || ledger.begin(&owned, now)).await
    };
    if let Err(error) = began {
        context.live.end(context.action_id);
        return Err(error);
    }
    let (sender, receiver) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let action_id = context.action_id;
        let live = Arc::clone(&context.live);
        let outcome = drive_command(
            &context,
            &held,
            &task,
            Command {
                text: params.command,
                cwd,
                scratch,
                workspace_id,
            },
        )
        .await;
        live.end(action_id);
        let _ = sender.send(outcome);
    });
    receiver.await.unwrap_or_else(|_| {
        Ok(ActionOutcome::Unknown {
            detail: "the task that ran this command ended without saying how it came out"
                .to_owned(),
        })
    })
}

/// What a command node runs and where.
struct Command {
    text: String,
    cwd: String,
    scratch: Option<PathBuf>,
    workspace_id: Option<kr_protocol::ids::WorkspaceId>,
}

/// Makes the session a command runs as the root of, waits for it to close, and releases what the
/// dispatch owned.
async fn drive_command(
    context: &NodeContext,
    held: &Arc<HeldGrant>,
    task: &Arc<NodeTask>,
    command: Command,
) -> kr_automation::Result<ActionOutcome> {
    let actor_id = workflow_principal(held.definition.grant_reference)?;
    let controller = context.daemon.get()?;
    // The place it runs in exists before the session is asked for.
    if let Some(scratch) = command.scratch.clone() {
        let root = context.scratch_root.clone();
        blocking(move || kr_ipc::paths::create_private_tree(&root, &scratch))
            .await
            .map_err(|error| {
                kr_automation::AutomationError::InvalidArgument(format!(
                    "the directory this command runs in could not be made: {error}"
                ))
            })?;
    }
    // A run holds the workspace its node runs in, so a removal waits for it.
    if let Some(workspace_id) = command.workspace_id {
        let changesets = Arc::clone(&context.changesets);
        let run_id = context.run_id;
        blocking(move || changesets.project().bind_run(workspace_id, run_id, true))
            .await
            .map_err(|error| {
                kr_automation::AutomationError::PermissionDenied(format!(
                    "the workspace this command runs in cannot be held for the run: {}",
                    kr_project::git::redact(&error.to_string())
                ))
            })?;
    }
    let admit = node_admission(&controller, held, context.wait_until_ms);
    // The command may start no later than the moment the engine stops waiting for the node,
    // expressed on the clock the worker reads too.
    let remaining = context
        .wait_until_ms
        .saturating_sub(context.daemon.now_ms());
    let not_after = controller.boot_elapsed_ms().saturating_add(remaining);
    let create = kr_protocol::session::SessionCreateParams {
        environment_id: context.changesets.environment_id(),
        presentation: kr_protocol::session::Presentation::Invisible,
        shell: Nullable::null(),
        shell_mode: kr_protocol::session::ShellMode::NativeCompat,
        cwd: Nullable::some(command.cwd),
        dimensions: Nullable::null(),
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        environment_snapshot: Vec::new(),
        palette: Nullable::null(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
        terminal: Nullable::null(),
    };
    let order = crate::service::WorkflowCreate {
        actor_id: actor_id.clone(),
        token: context.action_id,
        digest: node_digest(&held.definition, &held.node),
        create,
        root: Some(crate::service::HeldRoot {
            command: kr_protocol::worker::RootCommand {
                interpreter: COMMAND_INTERPRETER.to_owned(),
                command: command.text,
                not_after_boot_ms: kr_protocol::scalars::U64::new(not_after),
            },
            workflow: kr_protocol::worker::WorkflowSession {
                workflow_run_id: context.run_id,
                node_id: held.node.node_id.clone(),
            },
            admit: Arc::clone(&admit),
        }),
        admit,
    };
    let created = match controller.workflow_session_create(order).await {
        Ok(created) => created,
        Err(error) => {
            // Nothing was made, so there is nothing to wait for; what the dispatch wrote down is
            // released by the sweep, which finds no session and releases the rest.
            return creation_failed(held, error);
        }
    };
    drop(controller);
    let session_id = created.session.session_id;
    // The session is written down at once and bound to the workspace it runs in: a live session
    // is a writer there, which a capture that wants the workspace held still has to count.
    {
        let ledger = Arc::clone(&context.ledger);
        let changesets = Arc::clone(&context.changesets);
        let action_id = context.action_id;
        let workspace_id = command.workspace_id;
        let noted = blocking(move || -> kr_automation::Result<()> {
            ledger.note_session(action_id, session_id)?;
            if let Some(workspace_id) = workspace_id {
                changesets
                    .project()
                    .bind_session(workspace_id, session_id, true)
                    .map_err(|error| {
                        kr_automation::AutomationError::InvalidArgument(format!(
                            "the session was not bound to its workspace: {}",
                            kr_project::git::redact(&error.to_string())
                        ))
                    })?;
            }
            Ok(())
        })
        .await;
        if let Err(error) = noted {
            eprintln!(
                "kr-controller: the session of workflow node {} was not written down: {error}",
                context.action_id.get()
            );
        }
    }
    let closure = wait_for_closure(context, task, &actor_id, session_id).await;
    let outcome = match &closure {
        Some(closure) => command_outcome(closure),
        None => ActionOutcome::Unknown {
            detail: "the session this command ran in had not closed when the dispatch stopped \
                     waiting, so how the command came out is not established"
                .to_owned(),
        },
    };
    // What the dispatch owned is released once the session's closure accounts for its worker.
    // Otherwise the row stays open and the sweep keeps looking.
    if closure
        .as_ref()
        .is_some_and(|closure| !left_unaccounted(closure))
    {
        release_row(
            Arc::clone(&context.changesets),
            Arc::clone(&context.ledger),
            context.scratch_root.clone(),
            context.action_id,
        )
        .await;
    }
    Ok(outcome)
}

/// Whether a closure could not account for the session's own worker, which may then still write
/// where the session ran.
fn left_unaccounted(closure: &kr_protocol::session::ClosureRecord) -> bool {
    closure
        .surviving
        .iter()
        .any(|resource| resource.kind == crate::archive::UNACCOUNTED_WORKER)
}

/// Waits for a session's closure, closing the session when its dispatch is asked to stop.
///
/// Nothing records a root's exit by itself, so each look asks whether the session's worker has
/// gone. A dispatch asked to stop closes the session once and then waits a bounded time for the
/// closure; one that is not recorded in that time is left to the sweep.
async fn wait_for_closure(
    context: &NodeContext,
    task: &Arc<NodeTask>,
    actor_id: &ActorId,
    session_id: kr_protocol::ids::SessionId,
) -> Option<kr_protocol::session::ClosureRecord> {
    let mut stop_by: Option<tokio::time::Instant> = None;
    loop {
        // A daemon that is gone has nobody to ask; the next daemon's sweep finds the session.
        let controller = context.daemon.get().ok()?;
        if stop_by.is_none() && task.cancelled.load(Ordering::SeqCst) {
            stop_by = Some(tokio::time::Instant::now() + STOP_WAIT);
            let closed = controller
                .workflow_session_close(crate::service::WorkflowClose {
                    actor_id,
                    run_id: context.run_id,
                    session_id,
                    node_action: context.action_id,
                })
                .await;
            if let Err(error) = closed {
                eprintln!(
                    "kr-controller: the session of workflow node {} was not closed when its \
                     dispatch was asked to stop: {error}",
                    context.action_id.get()
                );
            }
        }
        match controller.workflow_session_closure(session_id).await {
            Ok(Some(closure)) => return Some(closure),
            Ok(None) => {}
            Err(error) => {
                eprintln!(
                    "kr-controller: the closure of workflow node {}'s session was not read: \
                     {error}",
                    context.action_id.get()
                );
            }
        }
        drop(controller);
        if stop_by.is_some_and(|by| tokio::time::Instant::now() >= by) {
            return None;
        }
        tokio::time::sleep(CLOSURE_POLL).await;
    }
}

/// What a command node comes to from how its session closed.
///
/// A node succeeds only when the command's own root exited normally with status zero. A session
/// that was closed for another reason, by a request, a crash or the host's shutdown, says nothing
/// reliable about the command, whatever status it shows.
fn command_outcome(closure: &kr_protocol::session::ClosureRecord) -> ActionOutcome {
    use kr_protocol::session::ClosureReason;

    let session_id = closure.session_id;
    match closure.reason {
        ClosureReason::RootExit => match closure.root_exit_code.0.map(|code| code.get()) {
            Some(0) => ActionOutcome::Success {
                output: NodeOutput::ShellCommand { session_id },
            },
            Some(code) => ActionOutcome::Failed {
                error: format!("the command exited with status {code}"),
            },
            None => ActionOutcome::Unknown {
                detail: "the command's session closed with no exit status recorded".to_owned(),
            },
        },
        ClosureReason::RootSignal => ActionOutcome::Failed {
            error: match closure.root_signal.0.as_deref() {
                Some(signal) => format!("the command was ended by signal {signal}"),
                None => "the command was ended by a signal".to_owned(),
            },
        },
        ClosureReason::RootLaunchFailed => ActionOutcome::Failed {
            error: "the command could not be started".to_owned(),
        },
        reason @ (ClosureReason::CloseRequested
        | ClosureReason::WorkerCrash
        | ClosureReason::DesktopLost
        | ClosureReason::HostShutdown) => ActionOutcome::Unknown {
            detail: format!(
                "the command's session closed with reason {}, so how the command came out is not \
                 established",
                reason.as_str()
            ),
        },
    }
}

/// Releases what a dispatch owned and marks its row released: the directory it ran in, and the
/// run's hold on the workspace it ran in.
async fn release_row(
    changesets: Arc<ChangeSetService>,
    ledger: Arc<ResourceLedger>,
    scratch_root: PathBuf,
    action_id: kr_protocol::ids::ActionId,
) {
    let released = blocking(move || -> kr_automation::Result<()> {
        let Some(row) = ledger.get(action_id)? else {
            return Ok(());
        };
        if let Some(scratch) = row.scratch.as_ref() {
            let path = PathBuf::from(scratch);
            // Only a directory under the one this host makes them in is removed.
            if path.starts_with(&scratch_root) {
                match std::fs::remove_dir_all(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(kr_automation::AutomationError::InvalidArgument(format!(
                            "the directory a command ran in was not removed: {error}"
                        )));
                    }
                }
            }
        }
        if let (Some(workspace_id), Some(session_id)) = (row.workspace_id, row.session_id)
            && let Err(error) = changesets
                .project()
                .bind_session(workspace_id, session_id, false)
        {
            return Err(kr_automation::AutomationError::InvalidArgument(format!(
                "the session's binding to its workspace was not ended: {}",
                kr_project::git::redact(&error.to_string())
            )));
        }
        if let Some(workspace_id) = row.workspace_id {
            // The run's hold ends with this node's: a paused run does not keep a workspace.
            if let Err(error) = changesets
                .project()
                .bind_run(workspace_id, row.run_id, false)
            {
                return Err(kr_automation::AutomationError::InvalidArgument(format!(
                    "the run's hold on its workspace was not ended: {}",
                    kr_project::git::redact(&error.to_string())
                )));
            }
        }
        ledger.release(action_id)
    })
    .await;
    if let Err(error) = released {
        eprintln!(
            "kr-controller: what a workflow command owned was not released, and the sweep will \
             try again: {error}"
        );
    }
}

impl HostActions {
    /// Closes and releases what no dispatch of this daemon owns any longer, and answers how many
    /// dispatches' resources are still owed their release.
    ///
    /// A row belongs to its dispatch while the dispatch is running here. After a restart there
    /// are none, so every row is taken: a session whose command outlived its node is closed, and
    /// once its closure accounts for its worker the directory, the hold and the row go. A row
    /// whose session was never made is released. Nothing here waits for the run to end, only for
    /// the session's closure.
    pub(crate) async fn sweep(&self, service: &AutomationService) -> usize {
        let Ok(controller) = self.daemon.get() else {
            return 0;
        };
        let ledger = Arc::clone(&self.ledger);
        let rows = match blocking(move || ledger.open_rows()).await {
            Ok(rows) => rows,
            Err(error) => {
                eprintln!("kr-controller: the workflow resource ledger was not read: {error}");
                return 1;
            }
        };
        let mut owed = 0;
        for row in rows {
            if self.live.get(row.action_id).is_some() {
                owed += 1;
                continue;
            }
            let store = Arc::clone(service.store());
            let (run_id, node_id) = (row.run_id, row.node_id.clone());
            let running = matches!(
                blocking(move || store.node_status(run_id, &node_id)).await,
                Ok(Some(kr_protocol::automation::NodeStatus::Running))
            );
            if running {
                owed += 1;
                continue;
            }
            let Ok(actor_id) = workflow_principal(row.grant_id) else {
                owed += 1;
                continue;
            };
            let session = if row.owns_session {
                controller
                    .workflow_session_of(&actor_id, row.action_id)
                    .await
            } else {
                Ok(None)
            };
            match session {
                Ok(Some(session_id)) => {
                    match controller.workflow_session_closure(session_id).await {
                        Ok(Some(closure)) if !left_unaccounted(&closure) => {}
                        Ok(Some(_)) => {
                            owed += 1;
                            continue;
                        }
                        Ok(None) => {
                            // Closed once, with the same request every time, so a close that was
                            // sent before is answered from its receipt.
                            let closed = controller
                                .workflow_session_close(crate::service::WorkflowClose {
                                    actor_id: &actor_id,
                                    run_id: row.run_id,
                                    session_id,
                                    node_action: row.action_id,
                                })
                                .await;
                            if let Err(error) = closed {
                                eprintln!(
                                    "kr-controller: a workflow session its node left behind was \
                                     not closed: {error}"
                                );
                            }
                            owed += 1;
                            continue;
                        }
                        Err(error) => {
                            eprintln!(
                                "kr-controller: the closure of a workflow session its node left \
                                 behind was not read: {error}"
                            );
                            owed += 1;
                            continue;
                        }
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    eprintln!(
                        "kr-controller: a workflow node's session could not be looked up: {error}"
                    );
                    owed += 1;
                    continue;
                }
            }
            release_row(
                Arc::clone(&self.changesets),
                Arc::clone(&self.ledger),
                self.scratch_root.clone(),
                row.action_id,
            )
            .await;
        }
        owed
    }
}

/// Refuses a materialisation of a version the workflow's scope does not reach.
///
/// A materialisation names a version, and the version names the environment and the workspace it
/// was captured from. A definition scoped to one workspace may not read another's work through a
/// version identifier, and a version from another environment is not this host's to write out.
fn version_in_scope(
    changesets: &ChangeSetService,
    definition: &WorkflowDefinition,
    asked: &ChangesetMaterializeParams,
    environment_id: EnvironmentId,
) -> kr_automation::Result<()> {
    // A version that cannot be read cannot be checked, and a version that does not exist yet can
    // be captured before the materialisation reads it. Either way the dispatch is refused: what is
    // materialised is only ever a version whose scope was checked here, by the one rule every
    // caller bounded by a scope is held to.
    use crate::changeset::{OutOfScope, ScopedEnvironments, VersionScope};

    let refused = |detail: String| kr_automation::AutomationError::PermissionDenied(detail);
    crate::changeset::version_in_scope(
        changesets,
        asked.change_set_id,
        Some(asked.version),
        &VersionScope {
            environments: ScopedEnvironments::One(environment_id),
            workspace: definition.resource_scope.workspace_id.0,
            sessions: None,
            captured_since: None,
        },
    )
    .map(|_| ())
    .map_err(|out| match out {
        OutOfScope::Unreadable(error) => refused(format!(
            "change set {} version {} could not be checked against workflow {}'s scope: {}",
            asked.change_set_id,
            asked.version,
            definition.workflow_id,
            kr_project::git::redact(&error.to_string())
        )),
        OutOfScope::Environment { captured_in } => refused(format!(
            "change set {} version {} was captured in environment {}, and this host acts in {}",
            asked.change_set_id, asked.version, captured_in, environment_id
        )),
        OutOfScope::Workspace {
            captured_from,
            declared,
        } => refused(format!(
            "change set {} version {} was captured from workspace {}, and workflow {} is scoped \
             to workspace {declared}",
            asked.change_set_id, asked.version, captured_from, definition.workflow_id
        )),
        // A workflow's scope names neither sessions nor a moment, so neither can refuse one.
        OutOfScope::Session | OutOfScope::History => refused(format!(
            "change set {} version {} is outside workflow {}'s scope",
            asked.change_set_id, asked.version, definition.workflow_id
        )),
    })
}

/// Why this host cannot hold a workspace still while a workflow's capture reads it.
///
/// A reservation promises that every writer is kept off the workspace for as long as it holds.
/// The first two reasons are the workspace's own and stay true whatever this host does; the third
/// is this host's, and holds until its writers ask for a reservation before they write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Unheld {
    /// A shared existing checkout, which the user's own tools write and nothing here holds off.
    SharedCheckout,
    /// Live sessions hold the workspace, and a session's shell writes where it runs.
    HeldBySessions(usize),
    /// This host's own writers, an applied version, a materialisation and the workspace
    /// operations, do not ask for a reservation before they write.
    WritersDoNotAsk,
}

impl Unheld {
    /// Why a workspace of `kind` that `bound_sessions` live sessions hold cannot be held still.
    fn of(kind: kr_protocol::project::WorkspaceKind, bound_sessions: usize) -> Self {
        if kind == kr_protocol::project::WorkspaceKind::SharedExisting {
            Self::SharedCheckout
        } else if bound_sessions > 0 {
            Self::HeldBySessions(bound_sessions)
        } else {
            Self::WritersDoNotAsk
        }
    }
}

impl std::fmt::Display for Unheld {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SharedCheckout => formatter.write_str(
                "it is a shared existing checkout, which the user's own tools write and nothing \
                 on this host can hold off",
            ),
            Self::HeldBySessions(count) => write!(
                formatter,
                "{count} live sessions hold it, and a session's shell writes where it runs"
            ),
            Self::WritersDoNotAsk => formatter.write_str(
                "this host's own writers, applying a version, materialising one and the workspace \
                 operations, do not yet ask for a reservation before they write",
            ),
        }
    }
}

/// The quiescence authority a workflow's capture asks for a reservation.
///
/// Every reservation is refused, because none of [`Unheld`]'s reasons is ever absent: a
/// reservation that did not keep every writer off would let a capture claim a quiesced tree it
/// did not read. A capture of the working tree therefore records the per-file consistency it
/// performs and never claims a quiesced tree, and a node that requires one fails, naming the
/// reason that applies to its workspace. An atomic snapshot is untouched by this: it reads the base
/// commit's own Git objects rather than the working tree, and asks for no reservation.
#[derive(Debug)]
struct WorkflowQuiescence;

impl kr_changeset::QuiescenceAuthority for WorkflowQuiescence {
    fn reserve(
        &self,
        _subject: kr_changeset::QuiescenceSubject,
    ) -> kr_changeset::Result<Option<Box<dyn kr_changeset::QuiescenceLease + '_>>> {
        Ok(None)
    }
}

/// Captures one version of a workspace, recorded as this run's work, under the node's held grant.
fn capture(
    changesets: &ChangeSetService,
    asked: &ChangesetCaptureParams,
    run_id: kr_protocol::ids::WorkflowRunId,
    held: &HeldGrant,
) -> kr_automation::Result<ActionOutcome> {
    // A node that requires a quiesced capture requires what this host cannot perform, and it is
    // told which of the reasons applies to its workspace rather than only that it was refused.
    if asked.required_consistency.0
        == Some(kr_protocol::changeset::SourceConsistency::QuiescedCapture)
    {
        let workspace =
            match changesets
                .project()
                .workspace_read(&kr_protocol::project::WorkspaceReadParams {
                    workspace_id: asked.workspace_id,
                }) {
                Ok(read) => read.workspace,
                Err(error) => return held.refusal_of(error.into()),
            };
        return Ok(ActionOutcome::Failed {
            error: format!(
                "this capture requires a quiesced capture, and this host cannot hold workspace {} \
                 still: {}",
                asked.workspace_id,
                Unheld::of(workspace.kind, workspace.bound_sessions.len())
            ),
        });
    }
    let order = CaptureOrder {
        workspace_id: asked.workspace_id,
        change_set_id: asked.change_set_id.0,
        label: &asked.label,
        request: kr_changeset::capture::CaptureRequest {
            policy: &asked.policy,
            grant: &asked.grant,
            quiescence_declared: asked.quiescence_declared,
            required_consistency: asked.required_consistency.0,
            // The reservation is asked for, and refused: see [`WorkflowQuiescence`]. The capture
            // records the per-file consistency it performs, and a declaration is recorded beside
            // it.
            quiescence: Some(kr_changeset::Quiescence {
                authority: &WorkflowQuiescence,
                workspace_id: asked.workspace_id,
            }),
        },
        pin: asked.pin,
        // The run is the provenance, whatever the document said. A definition cannot claim its
        // captures belong to another run, and a later node reading this version can tell which
        // execution produced it.
        provenance: Provenance {
            actor_id: kr_protocol::ids::ActorId::new("automation").unwrap_or_else(|_| {
                kr_protocol::ids::ActorId::new("kr").expect("a static actor identifier")
            }),
            method: "changeset.capture".to_owned(),
            session_id: asked.session_id,
            workflow_run_id: Nullable::some(run_id),
            derived_from: Nullable(None),
            derivation: String::new(),
            note: asked.note.clone(),
        },
        admitted: Some(held),
    };
    match changesets.capture(&order) {
        Ok((version, _pinned)) => Ok(ActionOutcome::Success {
            output: NodeOutput::CaptureChangeset {
                version: kr_protocol::changeset::VersionRef {
                    change_set_id: version.change_set_id,
                    version: version.version,
                },
            },
        }),
        Err(error) => held.refusal_of(error),
    }
}

/// Materialises one exact immutable version into a private directory, under the node's held grant.
fn materialise_version(
    changesets: &ChangeSetService,
    asked: &ChangesetMaterializeParams,
    held: &HeldGrant,
) -> kr_automation::Result<ActionOutcome> {
    let named = kr_protocol::changeset::VersionRef {
        change_set_id: asked.change_set_id,
        version: asked.version,
    };
    match materialise::materialise(changesets, named, asked.purpose, &asked.label, Some(held)) {
        // A materialisation that could not write every path the version holds is not the version.
        // A later node reading it on a success edge would be reading something else, so a partial
        // result fails and names how much is missing.
        Ok(record) if !record.unapplied.is_empty() => Ok(ActionOutcome::Failed {
            error: format!(
                "materialisation {} of change set {} version {} left {} of its paths unwritten",
                record.materialisation_id,
                named.change_set_id,
                named.version,
                record.unapplied.len()
            ),
        }),
        Ok(record) => Ok(ActionOutcome::Success {
            output: NodeOutput::MaterializeChangeset {
                version: named,
                materialisation_id: record.materialisation_id,
            },
        }),
        Err(error) => held.refusal_of(error),
    }
}

/// How long the trigger dispatcher waits before it tries again after a pass that failed, stopped
/// short or took up a run nothing was executing.
///
/// Such a pass can be made again by the same cause, and a pass that writes raises the signals it
/// waits on, so it waits this long whatever those signals say. A cause that goes away without a
/// write to the journal, a grant source that can be read again, is found by the next try.
const DISPATCH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// How many passes the trigger dispatcher has finished, kept for this host's own tests and
/// nothing at all in a shipped build.
#[derive(Clone, Debug, Default)]
struct PassCount(#[cfg(any(test, feature = "testing"))] Arc<std::sync::atomic::AtomicU64>);

impl PassCount {
    fn finished(&self) {
        #[cfg(any(test, feature = "testing"))]
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(any(test, feature = "testing"))]
    fn get(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// The automation service, as the daemon holds it.
///
/// Opening it recovers the journal and executes nothing. It decides and holds nothing either
/// until it is bound to the daemon that owns it ([`AutomationModule::bind`]). Execution waits for
/// [`AutomationModule::start`], which the daemon calls once its own start has passed every gate it
/// has. From then on the module owns the task that starts the runs derived triggers ask for, which
/// lives exactly as long as the module does.
#[derive(Debug)]
pub struct AutomationModule {
    service: Arc<AutomationService>,
    /// The daemon every grant is decided under and every change-set write is held under.
    daemon: Arc<Daemon>,
    /// The actions the service's runs carry out, held here for the sweep of what they leave.
    actions: Arc<HostActions>,
    /// The runs recovery resumed, held until execution starts.
    resumed: std::sync::Mutex<Option<Vec<kr_automation::StartedRun>>>,
    /// The trigger dispatcher, once execution has started.
    dispatcher: std::sync::OnceLock<tokio::task::JoinHandle<()>>,
    /// The sweep of what node dispatches left behind, once execution has started.
    sweeper: std::sync::OnceLock<tokio::task::JoinHandle<()>>,
    /// How many passes the dispatcher has finished.
    passes: PassCount,
}

impl Drop for AutomationModule {
    fn drop(&mut self) {
        if let Some(dispatcher) = self.dispatcher.get() {
            dispatcher.abort();
        }
        if let Some(sweeper) = self.sweeper.get() {
            sweeper.abort();
        }
    }
}

/// How long the sweep waits before it looks again at resources that are still owed their release.
const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Releases what node dispatches left behind, for as long as the daemon holds the service.
///
/// It looks once when execution starts, which is how a command a stopped daemon left running is
/// found, and again whenever a dispatch begins or ends. While resources are still owed it looks
/// again every [`SWEEP_INTERVAL`], so a session that is slow to close is not forgotten; when
/// nothing is owed it waits for a dispatch and keeps no timer.
async fn sweep_loop(actions: Arc<HostActions>, service: Arc<AutomationService>) {
    loop {
        let owed = actions.sweep(&service).await;
        if owed == 0 {
            actions.live.changed.notified().await;
        } else {
            tokio::select! {
                () = actions.live.changed.notified() => {}
                () = tokio::time::sleep(SWEEP_INTERVAL) => {}
            }
        }
    }
}

/// Runs the trigger dispatcher for as long as the daemon holds the service.
///
/// It first executes the runs a stopped daemon left unfinished, which the module recovered when it
/// was opened, and then starts the runs the journal's settled-node events trigger. After a pass
/// that found nothing wrong it waits for what can give it work: a change to the journal (a run
/// admitted, a node settled, a workflow enabled) or a run's place being given back. It keeps no
/// timer then. After a pass that failed, stopped short or took up a run nothing was executing it
/// waits [`DISPATCH_INTERVAL`] and tries again, whatever is raised meanwhile. Each run executes on
/// a task of its own, so one long run does not hold the rest of a chain back. Every decision is
/// the journal's: the dispatcher's own position commits with the runs it starts, so a daemon that
/// stops in the middle neither loses a trigger nor starts one twice.
async fn dispatch(
    service: Arc<AutomationService>,
    daemon: Arc<Daemon>,
    resumed: Vec<kr_automation::StartedRun>,
    passes: PassCount,
) {
    for run in resumed {
        execute_apart(&service, run);
    }
    let woken = service.events();
    let mut changes = service.store().changes();
    loop {
        // Marked before the pass reads the journal, so what is committed while it runs is seen by
        // the pass after it.
        changes.borrow_and_update();
        let mut clean = true;
        // A run nothing in this daemon executes any longer, because its execution ended without
        // settling it, is taken up again, so it does not hold one of its workflow's places until
        // the next restart.
        let taken_up = {
            let service = Arc::clone(&service);
            let daemon = Arc::clone(&daemon);
            blocking(move || service.recover(daemon.now_ms())).await
        };
        match taken_up {
            Ok(runs) => {
                // A run taken up may end the way the last one did, so the pass after this one is
                // not made at once.
                clean &= runs.is_empty();
                for run in runs {
                    execute_apart(&service, run);
                }
            }
            Err(error) => {
                clean = false;
                eprintln!(
                    "kr-controller: the workflow runs nothing is executing were not taken up: \
                     {error}"
                );
            }
        }
        let admitted = {
            let service = Arc::clone(&service);
            let daemon = Arc::clone(&daemon);
            blocking(move || service.admit_triggers(daemon.now_ms())).await
        };
        // Every run the pass committed is executed, including those committed before a later
        // event stopped it: each is in the journal already, and nothing else would start it
        // before the next restart.
        for run in admitted.started {
            execute_apart(&service, run);
        }
        if let Some(error) = admitted.stopped {
            clean = false;
            eprintln!(
                "kr-controller: the workflow trigger dispatcher stopped before its last trigger: \
                 {error}"
            );
        }
        // A run that stopped freed a slot, so the runs waiting for one start as far as the slots
        // allow, oldest first.
        let queued = {
            let service = Arc::clone(&service);
            let daemon = Arc::clone(&daemon);
            blocking(move || service.start_queued(daemon.now_ms())).await
        };
        for run in queued.started {
            execute_apart(&service, run);
        }
        if let Some(error) = queued.stopped {
            clean = false;
            eprintln!(
                "kr-controller: the workflow runs waiting for a slot were not started: {error}"
            );
        }
        // The events every consumer that reads them has passed are no longer owed. Removing them
        // is housekeeping: a failure here leaves them in the stream and changes no decision.
        let pruned = {
            let service = Arc::clone(&service);
            blocking(move || service.store().prune()).await
        };
        if let Err(error) = pruned {
            clean = false;
            eprintln!("kr-controller: the workflow journal kept events it no longer owes: {error}");
        }
        passes.finished();
        // The journal is gone with the service, which the module holds for as long as it runs
        // this.
        if !wait_to_look_again(clean, &woken, &mut changes).await {
            return;
        }
    }
}

/// Waits until the dispatcher has a reason to look at the journal again, and answers whether it
/// still has one to wait for.
///
/// After a clean pass that is a change to the journal or a run's place being given back, with no
/// timer. After one that was not clean it is [`DISPATCH_INTERVAL`] and nothing else: a pass that
/// wrote before it failed has raised the journal's signal itself, and that signal must not be what
/// makes the next pass follow it at once.
async fn wait_to_look_again(
    clean: bool,
    woken: &tokio::sync::Notify,
    changes: &mut tokio::sync::watch::Receiver<u64>,
) -> bool {
    if !clean {
        tokio::time::sleep(DISPATCH_INTERVAL).await;
        return true;
    }
    tokio::select! {
        () = woken.notified() => true,
        changed = changes.changed() => changed.is_ok(),
    }
}

/// Executes one admitted run on a task of its own.
fn execute_apart(service: &Arc<AutomationService>, run: kr_automation::StartedRun) {
    let service = Arc::clone(service);
    tokio::spawn(async move {
        // A run that stopped on a refusal has recorded the pause it owes; nobody is waiting on
        // this one for an answer.
        let _ = service.execute(run).await;
    });
}

impl AutomationModule {
    /// Opens the environment's automation service on its own journal, and recovers it.
    ///
    /// Recovery settles what a stopped daemon left running and decides which runs resume. It
    /// executes none of them: nothing runs until [`Self::start`], and no grant is decided until
    /// the module is bound to its daemon ([`Self::bind`]).
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the journal cannot be opened.
    pub async fn open(
        paths: &kr_ipc::paths::EnvironmentPaths,
        environment_id: EnvironmentId,
        changesets: Arc<ChangeSetService>,
    ) -> Result<Self> {
        // The state directory, not the runtime one: a causal budget has to survive a reboot, and
        // a runtime directory is cleared by one.
        let state_dir = paths.state_dir().to_path_buf();
        let daemon = Arc::new(Daemon::default());
        let grants: Arc<dyn AuthoritySource> = Arc::new(HostGrants {
            daemon: Arc::clone(&daemon),
        });
        // What the commands the workflows run own is written down in a ledger of its own, beside
        // the journal and not in it: the journal's stored format is read by the release before
        // this one, which a ledger table in it would stop reading.
        let ledger = {
            let state_dir = state_dir.clone();
            tokio::task::spawn_blocking(move || ResourceLedger::open(&state_dir))
                .await
                .map_err(|_| ControllerError::RegistryUnavailable {
                    detail: "the workflow resource ledger could not be opened".to_owned(),
                })?
                .map_err(|error| ControllerError::RegistryUnavailable {
                    detail: kr_project::git::redact(&error.to_string()),
                })?
        };
        let actions = Arc::new(HostActions {
            changesets,
            authority: Arc::clone(&grants),
            daemon: Arc::clone(&daemon),
            environment_id,
            ledger: Arc::new(ledger),
            scratch_root: state_dir.join("workflow-scratch"),
            live: Arc::new(LiveNodes::default()),
        });
        let host = Host {
            environment_id,
            runner: Arc::clone(&actions) as Arc<dyn ActionRunner>,
            authority: grants,
            clock: Arc::new(DaemonClock(Arc::clone(&daemon))),
            ceilings: Arc::new(DaemonCeilings(Arc::clone(&daemon))),
        };
        let service =
            tokio::task::spawn_blocking(move || AutomationService::open(&state_dir, host))
                .await
                .map_err(|_| ControllerError::RegistryUnavailable {
                    detail: "the automation journal could not be opened".to_owned(),
                })?
                .map_err(|error| ControllerError::RegistryUnavailable {
                    detail: kr_project::git::redact(&error.to_string()),
                })?;
        let service = Arc::new(service);
        // What a stopped daemon left unfinished is recovered here, before this daemon serves a
        // single request, and every dispatcher pass takes up whatever a run's execution leaves
        // unsettled after that. A run a caller starts is held from inside the transaction that
        // makes it running, so no recovery takes it for an interrupted one.
        let resumed = {
            let service = Arc::clone(&service);
            let daemon = Arc::clone(&daemon);
            blocking(move || service.recover(daemon.now_ms()))
                .await
                .map_err(|error| ControllerError::RegistryUnavailable {
                    detail: format!(
                        "the workflows a stopped daemon left unfinished could not be recovered: {}",
                        kr_project::git::redact(&error.to_string())
                    ),
                })?
        };
        Ok(Self {
            service,
            daemon,
            actions,
            resumed: std::sync::Mutex::new(Some(resumed)),
            dispatcher: std::sync::OnceLock::new(),
            sweeper: std::sync::OnceLock::new(),
            passes: PassCount::default(),
        })
    }

    /// Binds this module to the daemon that owns it.
    ///
    /// From here on every grant a workflow names is decided under that daemon's own model and
    /// every change-set write a node makes is held under its registry. The daemon binds the module
    /// as it is built, before it serves anything; binding again changes nothing.
    pub fn bind(&self, daemon: Weak<Controller>) {
        let _ = self.daemon.bound.set(daemon);
    }

    /// Starts executing: the runs recovery resumed, then the runs derived triggers ask for.
    ///
    /// The daemon calls this last in its start, once every gate the start has is behind it: the
    /// configuration it puts into force first, whose withdrawal of authority may owe a fence that
    /// has to be up before anything is dispatched. A start that fails before this point has
    /// executed nothing a stopped daemon left behind. Calling it again starts nothing further.
    pub fn start(&self) {
        self.sweeper.get_or_init(|| {
            tokio::spawn(sweep_loop(
                Arc::clone(&self.actions),
                Arc::clone(&self.service),
            ))
        });
        self.dispatcher.get_or_init(|| {
            let resumed = self
                .resumed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .unwrap_or_default();
            tokio::spawn(dispatch(
                Arc::clone(&self.service),
                Arc::clone(&self.daemon),
                resumed,
                self.passes.clone(),
            ))
        });
    }

    /// How many passes the trigger dispatcher has finished. For this host's own tests.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn dispatch_passes(&self) -> u64 {
        self.passes.get()
    }

    /// Returns the service itself.
    #[must_use]
    pub const fn service(&self) -> &Arc<AutomationService> {
        &self.service
    }

    /// Returns the journal this service keeps.
    #[must_use]
    pub fn journal(&self) -> &Arc<WorkflowStore> {
        self.service.store()
    }

    /// Returns true when this daemon serves the method.
    #[must_use]
    pub fn serves(method: Method) -> bool {
        method.group() == MethodGroup::Automation
    }

    /// Checks that an automation mutation's envelope and its parameters name the same subject.
    ///
    /// A workflow belongs to the environment rather than to one session or one foreground
    /// application, and the method registry's own selectors say so. A request that names either
    /// is refused rather than producing a receipt against something the effect never touched.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when the two disagree.
    pub fn check_subject(method: Method, mutation: &MutationRequest) -> Result<()> {
        if mutation.target.application_instance_id.is_present() {
            return Err(ControllerError::InvalidArgument(format!(
                "{} acts on a workflow, not on an application",
                method.as_str()
            )));
        }
        if mutation.target.session_id.as_ref().is_some() {
            return Err(ControllerError::InvalidArgument(format!(
                "{} acts on a workflow, which belongs to this environment rather than to a \
                 session",
                method.as_str()
            )));
        }
        match method {
            Method::WorkflowInstall => {
                let params: WorkflowInstallParams = parse(&mutation.params)?;
                if params.definition.workflow_id != params.workflow_id {
                    return Err(ControllerError::InvalidArgument(
                        "the request and the definition it carries name different workflows"
                            .to_owned(),
                    ));
                }
            }
            Method::WorkflowEnable => {
                let _: WorkflowEnableParams = parse(&mutation.params)?;
            }
            Method::WorkflowPause => {
                let _: WorkflowPauseParams = parse(&mutation.params)?;
            }
            Method::WorkflowRun => {
                let params: WorkflowRunParams = parse(&mutation.params)?;
                if params.event_id.trim().is_empty() {
                    return Err(ControllerError::InvalidArgument(
                        "a trigger names the event it carries, which is what deduplicates it"
                            .to_owned(),
                    ));
                }
            }
            _ => {
                return Err(ControllerError::InvalidArgument(format!(
                    "{} is not an automation mutation this daemon serves",
                    method.as_str()
                )));
            }
        }
        Ok(())
    }

    /// Serves one automation read and returns the frame it answers with.
    ///
    /// `caller_grant` is the grant a paired device holds, when one is asking: it is shown only
    /// the workflows that act under that grant. The owner at this machine passes `None`.
    #[must_use]
    pub async fn read_frame(
        &self,
        request: &Request,
        caller_grant: Option<GrantId>,
    ) -> ControlFrame {
        frame(request.request_id, self.read(request, caller_grant).await)
    }

    /// Answers an action this service has already performed for this caller, if it has.
    ///
    /// This runs **before** the freshness window is considered, because a retry after a lost
    /// reply carries the window the action was first admitted under and this connection holds a
    /// newer one. Refusing it for that would deny a caller its own completed result.
    ///
    /// An action either has a record, written in the same transaction as its effect, or has not
    /// been performed; there is no record of one still under way to be mistaken for either. A
    /// run that is still dispatching nodes has its record, and a repeat is told where it stands.
    #[must_use]
    pub async fn retained(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
    ) -> Option<ControlFrame> {
        let key = action_key(actor_id, mutation, method).ok()?;
        let service = Arc::clone(&self.service);
        match blocking(move || service.answered(&key)).await {
            Ok(None) => None,
            Ok(Some(answer)) => Some(frame(mutation.request_id, encode_answer(&answer))),
            Err(error) => Some(frame(mutation.request_id, Err(error.into()))),
        }
    }

    /// Serves one automation read.
    ///
    /// # Errors
    ///
    /// Returns the refusal the service decided, under the service's own code.
    pub async fn read(
        &self,
        request: &Request,
        caller_grant: Option<GrantId>,
    ) -> Answer<ParamsValue> {
        let Some(method) = request.method.method() else {
            return Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "the method is not in the registry",
            ));
        };
        if method != Method::WorkflowRead {
            return Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "{} is not an automation read this daemon serves",
                    method.as_str()
                ),
            ));
        }
        let service = Arc::clone(&self.service);
        let params = request.params.clone();
        let now_ms = self.daemon.now_ms();
        blocking(move || {
            let asked: WorkflowReadParams = typed(&params)?;
            encode(&service.read(&asked, caller_grant, now_ms)?)
        })
        .await
    }

    /// Serves one automation mutation as an action, answering an exact repeat from its record.
    ///
    /// `admission` is the daemon's answer to whether the admission this mutation was accepted
    /// under still stands. The journal asks it inside the transaction that performs the action,
    /// immediately before the action's first write, so an action cannot begin under an admission
    /// that lapsed while it waited for a blocking thread or for the journal's own lock; and it is
    /// asked only when there is no record to answer from, so a retry still gets its own result.
    ///
    /// `caller_grant` is the grant a paired device holds, when one is submitting: the action
    /// reaches only a workflow that acts under that grant. The owner at this machine passes `None`.
    ///
    /// # Errors
    ///
    /// Returns the refusal the service decided, under the service's own code.
    pub async fn write(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        admission: Admission,
        caller_grant: Option<GrantId>,
    ) -> Answer<ParamsValue> {
        let key = action_key(actor_id, mutation, method)?;
        let service = Arc::clone(&self.service);
        let params = mutation.params.clone();
        let now_ms = self.daemon.now_ms();
        let still_admitted = move || -> kr_automation::Result<()> {
            admission().map_err(|refusal| kr_automation::AutomationError::Lapsed {
                code: refusal.code,
                detail: refusal.message,
            })
        };
        match method {
            // A run dispatches its nodes and waits for each of them, so it stays on this task
            // rather than occupying a blocking thread for as long as the work takes.
            Method::WorkflowRun => {
                let asked: WorkflowRunParams = typed(&params)?;
                let submitted = Submitted {
                    key: &key,
                    admission: &still_admitted,
                    caller_grant,
                };
                encode(&service.run(&asked, &submitted, now_ms).await?)
            }
            Method::WorkflowInstall => {
                blocking(move || {
                    let asked: WorkflowInstallParams = typed(&params)?;
                    let submitted = Submitted {
                        key: &key,
                        admission: &still_admitted,
                        caller_grant,
                    };
                    encode(&service.install(&asked, &submitted, now_ms)?)
                })
                .await
            }
            Method::WorkflowEnable => {
                blocking(move || {
                    let asked: WorkflowEnableParams = typed(&params)?;
                    let submitted = Submitted {
                        key: &key,
                        admission: &still_admitted,
                        caller_grant,
                    };
                    encode(&service.enable(&asked, &submitted, now_ms)?)
                })
                .await
            }
            Method::WorkflowPause => {
                blocking(move || {
                    let asked: WorkflowPauseParams = typed(&params)?;
                    let submitted = Submitted {
                        key: &key,
                        admission: &still_admitted,
                        caller_grant,
                    };
                    encode(&service.pause(&asked, &submitted, now_ms)?)
                })
                .await
            }
            other => Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "{} is not an automation mutation this daemon serves",
                    other.as_str()
                ),
            )),
        }
    }
}

/// The daemon's answer to whether a mutation's admission still stands.
pub type Admission =
    Arc<dyn Fn() -> std::result::Result<(), ProtocolError> + Send + Sync + 'static>;

/// The journal's key for one submitted mutation: the verified actor, its action identifier, the
/// method and the digest of everything the mutation carried.
fn action_key(actor_id: &ActorId, mutation: &MutationRequest, method: Method) -> Answer<ActionKey> {
    let digest = kr_protocol::digest::mutation_digest(mutation, actor_id)
        .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))?;
    Ok(ActionKey {
        actor_id: actor_id.as_str().to_owned(),
        action_id: mutation.action_id.to_string(),
        method: method.as_str().to_owned(),
        digest: digest.as_bytes().to_vec(),
    })
}

/// Encodes what an earlier submission of an action came to.
fn encode_answer(answer: &Recorded) -> Answer<ParamsValue> {
    match answer {
        Recorded::Installed(result) => encode(result),
        Recorded::Enabled(result) => encode(result),
        Recorded::Paused(result) => encode(result),
        Recorded::Ran(result) => encode(result),
    }
}

/// Runs one synchronous call on a blocking task.
///
/// A dropped connection cannot cancel it: the task owns the work, and only the reply is lost.
async fn blocking<T, F>(work: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(value) => value,
        Err(error) => std::panic::resume_unwind(error.into_panic()),
    }
}

/// The response frame one automation answer goes out as.
pub(crate) fn frame(request_id: RequestId, outcome: Answer<ParamsValue>) -> ControlFrame {
    ControlFrame::Response(Response {
        request_id,
        outcome: match outcome {
            Ok(value) => Outcome::Ok(value),
            Err(error) => Outcome::Error(error),
        },
    })
}

fn parse<T: kr_protocol::wire::WireMessage>(params: &ParamsValue) -> Result<T> {
    params
        .to_typed()
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
}

fn typed<T: kr_protocol::wire::WireMessage>(params: &ParamsValue) -> Answer<T> {
    params
        .to_typed()
        .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))
}

fn encode<T: serde::Serialize>(value: &T) -> Answer<ParamsValue> {
    ParamsValue::from_typed(value)
        .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An automation service on a journal in `directory`, with no workflow in it.
    fn idle_service(directory: &std::path::Path) -> Arc<AutomationService> {
        Arc::new(
            kr_automation::AutomationService::open(
                directory,
                kr_automation::Host {
                    environment_id: kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid()),
                    runner: Arc::new(kr_automation::MockActionRunner::new()),
                    authority: Arc::new(kr_automation::GrantTable::new()),
                    clock: Arc::new(kr_automation::SystemClock),
                    ceilings: Arc::new(kr_automation::FixedCeilings {
                        sessions: 8,
                        managed_spend: 0,
                    }),
                },
            )
            .expect("the journal opens"),
        )
    }

    /// KR-PERF-003: a dispatcher with nothing to do keeps no timer. Its first passes settle what
    /// the journal's own registration writes; after that, hours of waiting run none.
    #[tokio::test(start_paused = true)]
    async fn an_idle_dispatcher_runs_no_pass_while_the_journal_does_not_change() {
        let directory = tempfile::tempdir().expect("a directory");
        let passes = PassCount::default();
        let task = tokio::spawn(dispatch(
            idle_service(directory.path()),
            Arc::new(Daemon::default()),
            Vec::new(),
            passes.clone(),
        ));
        tokio::time::sleep(std::time::Duration::from_secs(60 * 60)).await;
        let settled = passes.get();
        assert!(settled > 0, "the dispatcher made its first pass");
        tokio::time::sleep(std::time::Duration::from_secs(60 * 60)).await;
        assert_eq!(passes.get(), settled, "an hour of waiting made no pass");
        task.abort();
    }

    /// Waits, in virtual time and without moving it more than a millisecond at a time, until the
    /// dispatcher has finished `count` passes.
    async fn until_passes(passes: &PassCount, count: u64) {
        while passes.get() < count {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    }

    /// A run the journal holds as running and nothing executes, for a workflow of no nodes that is
    /// `installed` or is not.
    fn a_run_nothing_executes(service: &AutomationService, installed: bool) {
        let definition = kr_automation::create_workflow_definition(
            kr_protocol::ids::WorkflowId::new(kr_ipc::new_uuid()),
            1,
            "orphaned",
            kr_protocol::ids::GrantId::new(kr_ipc::new_uuid()),
            Vec::new(),
            Vec::new(),
        );
        let now = kr_ipc::now_ms().get();
        if installed {
            service
                .store()
                .save_definition(&definition, now)
                .expect("the revision is installed");
        }
        service
            .store()
            .commit_trigger_and_run(
                kr_protocol::ids::WorkflowRunId::new(kr_ipc::new_uuid()),
                &definition,
                "evt-orphan",
                &kr_automation::CausalContext::new_root(),
                now,
            )
            .expect("the run is recorded as running");
    }

    /// KR-REQ-25.19: a run the journal holds as running and nothing executes is taken up, and the
    /// pass that took it up is followed by the next after the interval, not at once: the run's
    /// place being given back, and the changes its execution makes, are what the pass would
    /// otherwise follow itself with. Then the dispatcher is idle again.
    #[tokio::test(start_paused = true)]
    async fn a_pass_that_took_up_a_run_is_followed_after_the_interval_and_not_at_once() {
        let directory = tempfile::tempdir().expect("a directory");
        let service = idle_service(directory.path());
        a_run_nothing_executes(&service, true);
        let passes = PassCount::default();
        let task = tokio::spawn(dispatch(
            Arc::clone(&service),
            Arc::new(Daemon::default()),
            Vec::new(),
            passes.clone(),
        ));
        until_passes(&passes, 1).await;
        assert_eq!(passes.get(), 1, "the first pass took the run up");
        tokio::time::sleep(DISPATCH_INTERVAL - std::time::Duration::from_millis(100)).await;
        assert_eq!(
            passes.get(),
            1,
            "and nothing followed it before the interval"
        );
        tokio::time::sleep(std::time::Duration::from_secs(60 * 60)).await;
        let settled = passes.get();
        assert!(settled > 1, "the interval was followed by a pass");
        tokio::time::sleep(std::time::Duration::from_secs(60 * 60)).await;
        assert_eq!(
            passes.get(),
            settled,
            "and once the run's own events were read the dispatcher went idle"
        );
        task.abort();
    }

    /// KR-PERF-003: a running run whose revision the journal does not hold cannot be executed, and
    /// every pass finds it again. That is not a reason for a pass to follow itself: the dispatcher
    /// goes idle as it would with nothing to do.
    #[tokio::test(start_paused = true)]
    async fn a_run_that_cannot_be_taken_up_does_not_keep_the_dispatcher_passing() {
        let directory = tempfile::tempdir().expect("a directory");
        let service = idle_service(directory.path());
        a_run_nothing_executes(&service, false);
        let passes = PassCount::default();
        let task = tokio::spawn(dispatch(
            service,
            Arc::new(Daemon::default()),
            Vec::new(),
            passes.clone(),
        ));
        tokio::time::sleep(std::time::Duration::from_secs(60 * 60)).await;
        let settled = passes.get();
        assert!(settled > 0, "the dispatcher made its first pass");
        tokio::time::sleep(std::time::Duration::from_secs(60 * 60)).await;
        assert_eq!(passes.get(), settled, "an hour of waiting made no pass");
        task.abort();
    }

    /// KR-REQ-25.19: a node that settles inside a run that has not ended is read by the dispatcher
    /// when the journal commits it, by the journal's own signal: no run ends here, and the
    /// dispatcher keeps no timer to find it.
    #[tokio::test(start_paused = true)]
    async fn a_settled_node_is_read_when_it_is_committed_and_not_when_its_run_ends() {
        let directory = tempfile::tempdir().expect("a directory");
        let service = idle_service(directory.path());
        let passes = PassCount::default();
        let task = tokio::spawn(dispatch(
            Arc::clone(&service),
            Arc::new(Daemon::default()),
            Vec::new(),
            passes.clone(),
        ));
        tokio::time::sleep(std::time::Duration::from_secs(60 * 60)).await;
        let position = || {
            service
                .store()
                .consumer_position(kr_automation::TRIGGER_CONSUMER)
                .expect("the journal reads")
        };
        assert_eq!(
            position(),
            Some(0),
            "the dispatcher is registered and has read nothing"
        );

        let admit = || Ok(());
        let key = kr_automation::ActionKey {
            actor_id: "local:test".to_owned(),
            action_id: kr_ipc::new_uuid().to_string(),
            method: "workflow.run".to_owned(),
            digest: vec![1],
        };
        service
            .store()
            .act(
                &kr_automation::Submitted {
                    key: &key,
                    admission: &admit,
                    caller_grant: None,
                },
                kr_ipc::now_ms().get(),
                |journal| {
                    let sequence = journal.record_event(
                        &kr_automation::store::JournalEventKind::NodeSettled {
                            run_id: kr_protocol::ids::WorkflowRunId::new(kr_ipc::new_uuid()),
                            workflow_id: kr_protocol::ids::WorkflowId::new(kr_ipc::new_uuid()),
                            revision: 1,
                            node_id: "tests".to_owned(),
                            action_id: kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
                            status: kr_protocol::automation::NodeStatus::Failed,
                            produced: None,
                            chain: kr_automation::store::EventChain {
                                causal_root_id: kr_protocol::ids::CausalRootId::new(
                                    kr_ipc::new_uuid(),
                                ),
                                generation: 1,
                                depth: 0,
                                parent_run_id: None,
                                parent_node_id: None,
                            },
                        },
                        kr_ipc::now_ms().get(),
                    )?;
                    Ok((kr_automation::ActionRecord::done(&"settled")?, sequence))
                },
            )
            .expect("the journal commits the action");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert!(
            position().is_some_and(|read| read > 0),
            "the dispatcher read the event"
        );
        task.abort();
    }

    /// KR-PERF-003: a pass that writes and then fails, every time, is made once in each interval.
    /// The trigger refuses the dispatcher's subscription after its consumer's row is written, so
    /// each pass counts a change in the journal and fails with it rolled back, and the change it
    /// counted is the signal the pass waits on. Taking the cause away with no write to the journal
    /// is found by the next try.
    #[tokio::test(start_paused = true)]
    async fn a_pass_that_keeps_failing_after_it_wrote_is_made_once_in_each_interval() {
        let directory = tempfile::tempdir().expect("a directory");
        let service = idle_service(directory.path());
        let other = rusqlite::Connection::open(
            directory
                .path()
                .join(kr_automation::store::WORKFLOW_DB_NAME),
        )
        .expect("the journal's file opens");
        other
            .busy_timeout(std::time::Duration::from_secs(10))
            .expect("a busy timeout");
        other
            .execute_batch(
                "CREATE TRIGGER refuse_subscription BEFORE INSERT ON event_subscriptions
                 BEGIN SELECT RAISE(ABORT, 'refused'); END;",
            )
            .expect("a trigger");
        let passes = PassCount::default();
        let task = tokio::spawn(dispatch(
            Arc::clone(&service),
            Arc::new(Daemon::default()),
            Vec::new(),
            passes.clone(),
        ));
        tokio::time::sleep(DISPATCH_INTERVAL * 10).await;
        let made = passes.get();
        assert!(
            (1..=12).contains(&made),
            "ten intervals of a failure that persists made {made} passes"
        );
        assert_eq!(
            service
                .store()
                .consumer_position(kr_automation::TRIGGER_CONSUMER)
                .expect("the journal reads"),
            None,
            "the dispatcher is not registered while the cause stands"
        );

        other
            .execute_batch("DROP TRIGGER refuse_subscription;")
            .expect("the trigger goes");
        tokio::time::sleep(DISPATCH_INTERVAL * 2).await;
        assert_eq!(
            service
                .store()
                .consumer_position(kr_automation::TRIGGER_CONSUMER)
                .expect("the journal reads"),
            Some(0),
            "and is, once the cause is gone, with no write to the journal to say so"
        );
        task.abort();
    }

    /// After a pass that was not clean the wait is the interval and nothing else: the journal's
    /// signal, which a pass that wrote before it failed raised itself, and a run's place given
    /// back, both already waiting, do not end it. After a clean pass either signal ends it at
    /// once, and with neither the wait has no end of its own.
    #[tokio::test(start_paused = true)]
    async fn the_wait_after_a_pass_is_the_interval_after_a_failure_and_an_event_after_a_clean_one()
    {
        use std::time::Duration;
        let woken = tokio::sync::Notify::new();
        woken.notify_one();
        let (journal, mut changes) = tokio::sync::watch::channel(0_u64);
        journal.send_modify(|version| *version += 1);
        {
            let wait = wait_to_look_again(false, &woken, &mut changes);
            tokio::pin!(wait);
            assert!(
                tokio::time::timeout(DISPATCH_INTERVAL - Duration::from_millis(1), &mut wait)
                    .await
                    .is_err(),
                "a failed pass is not followed by the signals it raised"
            );
            assert_eq!(
                tokio::time::timeout(Duration::from_millis(2), &mut wait).await,
                Ok(true),
                "and is followed when the interval has gone"
            );
        }

        // Each signal alone, new each time: the wait takes whichever it finds first.
        let only_woken = tokio::sync::Notify::new();
        only_woken.notify_one();
        let (silent, mut unchanged) = tokio::sync::watch::channel(0_u64);
        assert_eq!(
            tokio::time::timeout(
                Duration::from_millis(1),
                wait_to_look_again(true, &only_woken, &mut unchanged)
            )
            .await,
            Ok(true),
            "a clean pass is followed by a run's place given back"
        );
        let nothing = tokio::sync::Notify::new();
        let (changing, mut changed) = tokio::sync::watch::channel(0_u64);
        changing.send_modify(|version| *version += 1);
        assert_eq!(
            tokio::time::timeout(
                Duration::from_millis(1),
                wait_to_look_again(true, &nothing, &mut changed)
            )
            .await,
            Ok(true),
            "and by a change to the journal"
        );
        assert!(
            tokio::time::timeout(
                Duration::from_secs(60 * 60),
                wait_to_look_again(true, &nothing, &mut changed)
            )
            .await
            .is_err(),
            "with neither a clean pass is followed by nothing, however long it waits"
        );
        drop(silent);
    }

    /// A workflow's capture is never held still, and the reason given is the workspace's own when
    /// it has one.
    #[test]
    fn a_workflow_capture_is_refused_its_reservation_with_the_reason_that_applies() {
        use kr_changeset::QuiescenceAuthority;
        use kr_protocol::project::WorkspaceKind;
        assert_eq!(
            Unheld::of(WorkspaceKind::SharedExisting, 2),
            Unheld::SharedCheckout
        );
        assert_eq!(
            Unheld::of(WorkspaceKind::Isolated, 1),
            Unheld::HeldBySessions(1)
        );
        assert_eq!(
            Unheld::of(WorkspaceKind::Isolated, 0),
            Unheld::WritersDoNotAsk
        );
        let subject = kr_changeset::QuiescenceSubject {
            workspace_id: kr_protocol::ids::WorkspaceId::new(
                kr_protocol::scalars::Uuid::from_bytes([3; 16]),
            ),
            work_tree: kr_transfer::ObjectIdentity {
                device: 1,
                file_id: 2,
            },
        };
        assert!(
            WorkflowQuiescence
                .reserve(subject)
                .expect("an answer")
                .is_none(),
            "no reservation is granted"
        );
    }

    /// A starting anchor for the clock tests, at `ms` and the manual clock's `at`.
    fn anchored(ms: u64, at: kr_transport::clock::ContinuousInstant) -> Anchor {
        let reading = std::time::Duration::from_millis(ms);
        Anchor {
            reading,
            at,
            last: reading,
        }
    }

    /// Readings taken more often than the wall clock moves, or between whole milliseconds, round
    /// none of the continuous time away: a stopped wall clock read every half millisecond does not
    /// hold automation time still, and reads 250.5 ms apart against a wall clock that moves 250 ms
    /// lose no more than a thousandth.
    #[test]
    fn frequent_or_fractional_readings_lose_no_time() {
        use kr_transport::clock::ContinuousClock;
        let continuous = kr_transport::clock::ManualClock::new();
        let mut anchor = anchored(10_000, continuous.now());
        for _ in 0..10_000 {
            continuous.advance(std::time::Duration::from_micros(500));
            anchor = reading_at(anchor, 10_000, continuous.now()).1;
        }
        let (stopped, _) = reading_at(anchor, 10_000, continuous.now());
        assert!(
            stopped >= 10_000 + 4_995,
            "five seconds against a stopped wall clock moved the reading by {}",
            stopped - 10_000
        );

        let mut anchor = anchored(10_000, continuous.now());
        let mut wall = 10_000;
        let mut now = 0;
        for _ in 0..2_000 {
            continuous.advance(std::time::Duration::from_micros(250_500));
            wall += 250;
            let (read, kept) = reading_at(anchor, wall, continuous.now());
            anchor = kept;
            now = read;
        }
        assert!(
            now >= 10_000 + 501_000 - 501,
            "501 seconds moved the reading by {}",
            now - 10_000
        );
    }

    /// Automation's clock follows a wall clock that keeps pace, drift and a suspension included,
    /// and follows one set forward; a wall clock set back an hour does not hold it: it runs on at
    /// all but a thousandth of continuous time.
    #[test]
    fn automation_time_runs_on_through_a_wall_clock_wound_back() {
        use kr_transport::clock::ContinuousClock;
        let continuous = kr_transport::clock::ManualClock::new();
        let mut anchor = anchored(10_000, continuous.now());
        let mut read = |advance_ms: u64, wall: u64| {
            continuous.advance(std::time::Duration::from_millis(advance_ms));
            let (now, kept) = reading_at(anchor, wall, continuous.now());
            anchor = kept;
            now
        };

        // In step, then a wall clock a hundred parts in a million slow: followed within a
        // millisecond.
        let mut wall = 10_000;
        for _ in 0..8 {
            wall += 250;
            assert_eq!(read(250, wall), wall);
        }
        for step in 1..=400_u64 {
            wall += if step % 40 == 0 { 249 } else { 250 };
            let now = read(250, wall);
            assert!(now >= wall && now <= wall + 1, "{now} follows {wall}");
        }

        // A suspension of an hour that the wall clock counts 1.8 seconds short, with no step: the
        // wall clock is still followed.
        wall += 3_598_200;
        assert_eq!(read(3_600_000, wall), wall);

        // The wall clock is set back an hour. A minute later the reading has moved on by all but
        // a thousandth of that minute, and never backwards on the way.
        let before = wall;
        let mut last = before;
        for step in 1..=240_u64 {
            let now = read(250, before - 3_600_000 + step * 250);
            assert!(now >= last, "never backwards");
            last = now;
        }
        assert!(
            (before + 59_940..=before + 60_000).contains(&last),
            "the minute counted: {}",
            last - before
        );

        // A wall clock set forward past the count is followed at once.
        assert_eq!(read(250, 9_000_000), 9_000_000);
        assert_eq!(read(250, 9_000_250), 9_000_250);
    }

    /// Whatever the wall clock does, each stretch of continuous time moves automation's reading on
    /// by all but a thousandth of it, and the reading never goes backwards.
    #[test]
    fn no_wall_clock_holds_automation_time_back() {
        use kr_transport::clock::ContinuousClock;
        let continuous = kr_transport::clock::ManualClock::new();
        let mut anchor = anchored(1_000_000, continuous.now());
        let mut wall: u64 = 1_000_000;
        let mut seed: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = |bound: u64| {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (seed >> 33) % bound
        };
        let mut last = anchor.last;
        let mut last_ms = 1_000_000;
        for _ in 0..20_000 {
            let advance = 1 + next(5_000);
            wall = match next(100) {
                0 => wall.saturating_sub(3_600_000),
                1 => wall + 86_400_000,
                2 => wall.saturating_sub(next(2_000)),
                _ => wall + advance - next(3).min(advance),
            };
            let step = std::time::Duration::from_micros(advance * 1_000 + next(1_000));
            continuous.advance(step);
            let (now_ms, kept) = reading_at(anchor, wall, continuous.now());
            anchor = kept;
            assert!(now_ms >= last_ms, "never backwards");
            let moved = kept.last.checked_sub(last).expect("never backwards");
            assert!(
                moved + std::time::Duration::from_nanos(1) >= step - step / SLEW_PARTS,
                "{step:?} of continuous time moved the reading on by {moved:?}"
            );
            last = kept.last;
            last_ms = now_ms;
        }
    }

    #[test]
    fn the_daemon_serves_the_whole_automation_group() {
        for method in [
            Method::WorkflowInstall,
            Method::WorkflowEnable,
            Method::WorkflowPause,
            Method::WorkflowRun,
            Method::WorkflowRead,
        ] {
            assert!(
                AutomationModule::serves(method),
                "{} belongs to this service",
                method.as_str()
            );
        }
        // A change set, a session and a grant are other services'.
        assert!(!AutomationModule::serves(Method::ChangesetCapture));
        assert!(!AutomationModule::serves(Method::SessionCreate));
        assert!(!AutomationModule::serves(Method::GrantCreate));
    }

    #[test]
    fn every_method_of_the_group_requires_the_management_right() {
        use kr_protocol::rights::ActionRight;

        // Section 23's method-group row: the whole group is under `automation.manage`.
        for method in [
            Method::WorkflowInstall,
            Method::WorkflowEnable,
            Method::WorkflowPause,
            Method::WorkflowRun,
            Method::WorkflowRead,
        ] {
            let entry = method.entry();
            assert!(
                entry.required_rights.iter().any(|required| matches!(
                    required.authority,
                    kr_protocol::authority::RequiredAuthority::Right { right }
                        if right == ActionRight::AutomationManage
                )),
                "{} requires automation.manage",
                method.as_str()
            );
        }
    }

    #[test]
    fn every_method_of_the_group_is_reachable_from_a_local_caller() {
        use kr_protocol::actor::ActorIngress;
        use kr_protocol::authority::AuthorityDecision;

        for method in [
            Method::WorkflowInstall,
            Method::WorkflowEnable,
            Method::WorkflowPause,
            Method::WorkflowRun,
            Method::WorkflowRead,
        ] {
            let decision = kr_protocol::method::decide(
                method.as_str(),
                method.entry().version,
                ActorIngress::LocalIpc,
            );
            assert!(
                matches!(decision, AuthorityDecision::Listed(_)),
                "{} is not reachable from a local caller",
                method.as_str()
            );
        }
    }
}
