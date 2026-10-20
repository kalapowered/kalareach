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

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Weak};

use kr_automation::resources::{Owned, OwnedState, ResourceLedger, session_principal};
use kr_automation::{
    ActionKey, ActionOutcome, ActionRunner, Answer as Recorded, AuthoritySource, AutomationService,
    Dispatch, Host, Submitted, WorkflowStore,
};
use kr_changeset::ChangeSetService;
use kr_changeset::materialise::{self, Outputs, RunReport};
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
use crate::service::{Controller, NodeSession};

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

impl HostGrants {
    /// Reads the grant a workflow names and the ingress this host decides it under.
    fn read(
        &self,
        grant_id: GrantId,
    ) -> kr_automation::Result<(
        Arc<Controller>,
        crate::grants::GrantRecord,
        ActorIngress,
        kr_transport::clock::ContinuousInstant,
    )> {
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
        Ok((daemon, record, ingress, read_at))
    }
}

impl AuthoritySource for HostGrants {
    fn grant(&self, grant_id: GrantId, now_ms: u64) -> kr_automation::Result<Grant> {
        let (daemon, record, ingress, read_at) = self.read(grant_id)?;
        let rights = daemon.decide_for_workflow(&record, ingress, now_ms, read_at)?;
        // The grant as this host leaves it: a configured ceiling or an organisation lease that
        // narrows it narrows what the workflow may do, and the node is checked against the result.
        Ok(Grant {
            actions: rights,
            ..record.grant
        })
    }

    fn grant_standing(
        &self,
        grant_id: GrantId,
        now_ms: u64,
    ) -> kr_automation::Result<(Grant, Option<std::time::Duration>)> {
        let (daemon, record, ingress, read_at) = self.read(grant_id)?;
        let (rights, ends_in) =
            daemon.decide_for_workflow_until(&record, ingress, now_ms, read_at)?;
        Ok((
            Grant {
                actions: rights,
                ..record.grant
            },
            ends_in,
        ))
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
    /// Held while a dispatch writes down its row and takes its run's hold on a workspace, and
    /// while a release ends that hold, so the hold ends with the last row that holds it and never
    /// under a row that has just begun.
    holds: Arc<std::sync::Mutex<()>>,
    /// The nodes whose session the sweep of this daemon has already asked to close.
    closing: std::sync::Mutex<HashSet<kr_protocol::ids::ActionId>>,
    /// How many looks the sweep has finished, for this host's own tests.
    sweeps: PassCount,
}

/// The node dispatches this daemon is running, each with the state its cancellation sets.
///
/// A dispatch owns its ledger row while it is in here, and the sweep takes none of those: the
/// sweep is for what no task of this daemon owns.
#[derive(Debug, Default)]
struct LiveNodes {
    nodes: std::sync::Mutex<HashMap<kr_protocol::ids::ActionId, Arc<NodeTask>>>,
    /// Told when a dispatch ends or begins, so the sweep looks again.
    changed: tokio::sync::Notify,
}

/// One running dispatch, as the engine's cancellation and the node's own admission see it.
#[derive(Debug, Default)]
struct NodeTask {
    state: std::sync::Mutex<TaskState>,
    /// Woken by a cancellation, so a dispatch that waits between two looks at its session does
    /// not sleep through the request to stop it.
    woken: tokio::sync::Notify,
}

#[derive(Clone, Copy, Debug, Default)]
struct TaskState {
    /// The run was cancelled, or the node's wait ended and the engine asked it to stop.
    cancelled: bool,
    /// The node's session passed its admission at the launch transition.
    committed: bool,
}

impl NodeTask {
    fn state(&self) -> std::sync::MutexGuard<'_, TaskState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn cancelled(&self) -> bool {
        self.state().cancelled
    }

    /// Asks the node to stop. Whatever has not started never will: the worker's claim of a node
    /// that was asked to stop is refused. A session that passed its first admission is stopped
    /// only by a node that closes its session; one that keeps it cannot be stopped from here, and
    /// the answer is that it was not.
    fn cancel(&self, closes_its_session: bool) -> bool {
        let mut state = self.state();
        state.cancelled = true;
        let stopped = !state.committed || closes_its_session;
        drop(state);
        self.woken.notify_one();
        stopped
    }

    /// Whether the node's session may start: not when the node was asked to stop. It is asked at
    /// the launch transition and again at the worker's claim, under the registry guard.
    fn commit(&self) -> bool {
        let mut state = self.state();
        if state.cancelled {
            return false;
        }
        state.committed = true;
        true
    }
}

/// A dispatch's place among the running ones, given up when it is dropped.
struct LiveEntry {
    live: Arc<LiveNodes>,
    action_id: kr_protocol::ids::ActionId,
    task: Arc<NodeTask>,
}

impl Drop for LiveEntry {
    fn drop(&mut self) {
        self.live.end(self.action_id, &self.task);
    }
}

impl LiveNodes {
    fn enter(self: &Arc<Self>, action_id: kr_protocol::ids::ActionId) -> LiveEntry {
        let task = Arc::new(NodeTask::default());
        self.nodes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(action_id, Arc::clone(&task));
        self.changed.notify_one();
        LiveEntry {
            live: Arc::clone(self),
            action_id,
            task,
        }
    }

    fn get(&self, action_id: kr_protocol::ids::ActionId) -> Option<Arc<NodeTask>> {
        self.nodes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&action_id)
            .cloned()
    }

    fn end(&self, action_id: kr_protocol::ids::ActionId, task: &Arc<NodeTask>) {
        let mut nodes = self
            .nodes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if nodes
            .get(&action_id)
            .is_some_and(|held| Arc::ptr_eq(held, task))
        {
            nodes.remove(&action_id);
        }
        drop(nodes);
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
    /// flag, closes the session, and releases what it owned once the closure is recorded. A
    /// `create_session` node is stopped only while its session has not passed its first
    /// admission, and the node of one that has settles unknown. Its worker's claim is refused if
    /// it comes after the request, so no program starts, and a session whose claim came before it
    /// stays. Nothing is claimed about what a command did before it stopped.
    ///
    /// Neither change-set kind can be stopped once it has begun: the change-set service offers no
    /// point inside a capture or a materialisation to stop at. An action that outlives its wait
    /// and cannot be stopped is left unknown, and its dependants pause for review.
    fn cancel(&self, dispatch: &Dispatch<'_>) -> kr_automation::Cancellation {
        let kind = dispatch.node.action_kind;
        if matches!(
            kind,
            WorkflowActionKind::ShellCommand
                | WorkflowActionKind::RunTests
                | WorkflowActionKind::CreateSession
        ) && let Some(task) = self.live.get(dispatch.action_id)
            && task.cancel(kr_automation::definition::runs_a_command(kind))
        {
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
        // A node that makes a session takes its place among the running ones now, before the
        // engine has polled it, so a cancellation that arrives first still finds it. The place is
        // given up when the node's task ends, or here if nothing ever polls the future.
        let entry = matches!(
            dispatch.node.action_kind,
            WorkflowActionKind::ShellCommand
                | WorkflowActionKind::RunTests
                | WorkflowActionKind::CreateSession
        )
        .then(|| self.live.enter(dispatch.action_id));
        let node_context = NodeContext {
            daemon: Arc::clone(&self.daemon),
            changesets: Arc::clone(&self.changesets),
            ledger: Arc::clone(&self.ledger),
            scratch_root: self.scratch_root.clone(),
            holds: Arc::clone(&self.holds),
            run_id,
            action_id: dispatch.action_id,
            wait_until_ms: dispatch.wait_until_ms,
        };
        Box::pin(async move {
            match (held.node.action_kind, entry) {
                (WorkflowActionKind::CaptureChangeset, _) => {
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
                (WorkflowActionKind::MaterializeChangeset, _) => {
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
                (WorkflowActionKind::CreateSession, Some(entry)) => {
                    create_session_node(node_context, Arc::new(held), entry).await
                }
                // A command runs through a POSIX shell as the root of a session, which this
                // platform has not.
                (WorkflowActionKind::ShellCommand, Some(entry)) if !cfg!(windows) => {
                    command_node(node_context, Arc::new(held), entry, false).await
                }
                (WorkflowActionKind::RunTests, Some(entry)) if !cfg!(windows) => {
                    command_node(node_context, Arc::new(held), entry, true).await
                }
                (other, _) => {
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
        self.standing().map(|_| ())
    }

    /// Reads the grant as it stands now, checks this node against it, and answers the moment the
    /// grant stands until, in milliseconds of the machine's continuous clock since boot: the
    /// earliest of its own expiry, an organisation lease and a bounded offline validity, `None`
    /// when it has no end.
    ///
    /// The clock is read before the decision, and the time the grant has left once the decision is
    /// made, credited as a bound is, is added to that reading, so the moment is never
    /// later than the grant's end: whatever the decision took comes off the grant and is never
    /// added to it.
    fn standing(&self) -> kr_automation::Result<Option<u64>> {
        let daemon = self.daemon.get()?;
        let ends_at = grant_end_on_the_boot_clock(
            || daemon.boot_elapsed_ms(),
            || {
                let (grant, ends_in) = self
                    .authority
                    .grant_standing(self.definition.grant_reference, self.daemon.now_ms())?;
                kr_automation::authority::check_node(
                    &grant,
                    &self.definition,
                    &self.node,
                    self.environment_id,
                )?;
                Ok(ends_in)
            },
        )?;
        Ok(ends_at)
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
    holds: Arc<std::sync::Mutex<()>>,
    run_id: kr_protocol::ids::WorkflowRunId,
    action_id: kr_protocol::ids::ActionId,
    /// The moment the engine stops waiting for this dispatch, on automation's clock.
    wait_until_ms: u64,
}

/// What `elapsed_ms` of continuous time is held to be worth when a bound is worked out from it:
/// all of it less the rate allowance ([`kr_ipc::clock::RATE_ALLOWANCE_PPM`]), the deduction rounded
/// up. [`kr_ipc::clock::credited`] rounds the deduction down, which is right for time a projection
/// credits and wrong for a bound, which must never fall after the end it stands on.
fn credited_for_a_bound(elapsed_ms: u64) -> u64 {
    elapsed_ms.saturating_sub(
        elapsed_ms
            .saturating_mul(kr_ipc::clock::RATE_ALLOWANCE_PPM)
            .div_ceil(1_000_000),
    )
}

/// The moment a grant stands until, on the machine's continuous clock, from a reading taken before
/// it was decided and the time the decision says it has left.
///
/// The reading comes first and the left-over time is added to it, never to a reading taken
/// afterwards, so a decision that is slow shortens the moment and never lengthens it. The time is
/// credited as a bound is ([`credited_for_a_bound`]): the platform's time service can slow the
/// clock the worker reads, and the moment must not outlast the grant because of it.
fn grant_end_on_the_boot_clock(
    read_boot_ms: impl FnOnce() -> u64,
    decide: impl FnOnce() -> kr_automation::Result<Option<std::time::Duration>>,
) -> kr_automation::Result<Option<u64>> {
    let read_at = read_boot_ms();
    Ok(decide()?.map(|ends_in| {
        let ends_in_ms = u64::try_from(ends_in.as_millis()).unwrap_or(u64::MAX);
        read_at.saturating_add(credited_for_a_bound(ends_in_ms))
    }))
}

/// The moment a node's wait ends on the machine's continuous clock, from the two readings taken
/// together, `boot_ms` of that clock and `now_ms` of automation's, and the moment the wait ends on
/// automation's, which is after `now_ms`.
///
/// `now_ms` is automation's clock rounded down to the millisecond, so the time left it implies can
/// be up to a millisecond more than there is: that millisecond comes off before the time is
/// credited as a bound is ([`credited_for_a_bound`]), and the moment is never later than the wait's
/// end.
fn wait_end_on_the_boot_clock(boot_ms: u64, now_ms: u64, wait_until_ms: u64) -> u64 {
    boot_ms.saturating_add(credited_for_a_bound(
        wait_until_ms.saturating_sub(now_ms).saturating_sub(1),
    ))
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
/// registry guard: whether the node was asked to stop, the node's grant, read as it stands now on
/// both clocks, and then the moment the engine stops waiting for the node, read after the grant
/// has been decided.
///
/// It answers the last moment the session's process may be created, in milliseconds of the machine's
/// continuous clock since boot, when it has one. The grant's end bounds every session; the moment
/// the engine stops waiting bounds a command as well, because the node's result is the command's
/// and nobody is waiting for it after that. A session a `create_session` node makes is the node's
/// output and outlives its wait, so only the grant bounds it. Each is the moment it ends read now
/// and never a duration added to a later reading, so a delay between this answer and the process's
/// creation counts against it.
fn node_admission(
    controller: &Arc<Controller>,
    held: &Arc<HeldGrant>,
    wait_until_ms: u64,
    task: &Arc<NodeTask>,
    bounded_by_the_wait: bool,
) -> crate::service::WorkflowAdmission {
    let held = Arc::clone(held);
    let task = Arc::clone(task);
    controller.workflow_admission(move || {
        if !task.commit() {
            return Err(
                held.refuse_session(kr_automation::AutomationError::AuthorityUnavailable(
                    "the node was asked to stop before its session could start".to_owned(),
                )),
            );
        }
        let grant_ends = held
            .standing()
            .map_err(|refusal| held.refuse_session(refusal))?;
        let daemon = held
            .daemon
            .get()
            .map_err(|refusal| held.refuse_session(refusal))?;
        let (boot_ms, now_ms) = (daemon.boot_elapsed_ms(), held.daemon.now_ms());
        if now_ms >= wait_until_ms {
            return Err(
                held.refuse_session(kr_automation::AutomationError::AuthorityUnavailable(
                    "the wait for this node ended before its session could start".to_owned(),
                )),
            );
        }
        let wait_ends =
            bounded_by_the_wait.then(|| wait_end_on_the_boot_clock(boot_ms, now_ms, wait_until_ms));
        Ok(grant_ends.into_iter().chain(wait_ends).min())
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
/// nothing to release, so it writes no ledger row. The create runs on a task of the daemon's own:
/// the engine drops the wait for it at a deadline or a cancellation, and a create dropped between
/// its reservation and its launch would leave a reservation that counts against the session
/// limit until the next start. The task finishes what it began, and a create that is refused at
/// its admission leaves nothing.
async fn create_session_node(
    context: NodeContext,
    held: Arc<HeldGrant>,
    entry: LiveEntry,
) -> kr_automation::Result<ActionOutcome> {
    let controller = context.daemon.get()?;
    let create: kr_protocol::session::SessionCreateParams =
        serde_json::from_str(&held.node.action_params)?;
    let order = crate::service::WorkflowCreate {
        actor_id: workflow_principal(held.definition.grant_reference)?,
        token: context.action_id,
        digest: node_digest(&held.definition, &held.node),
        create,
        command: None,
        admit: node_admission(
            &controller,
            &held,
            context.wait_until_ms,
            &entry.task,
            false,
        ),
    };
    let (sender, receiver) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let outcome = match controller.workflow_session_create(order).await {
            Ok(created) => Ok(ActionOutcome::Success {
                output: NodeOutput::CreateSession {
                    session_id: created.session.session_id,
                },
            }),
            Err(error) => creation_failed(&held, error),
        };
        drop(entry);
        let _ = sender.send(outcome);
    });
    receiver.await.unwrap_or_else(|_| {
        Ok(ActionOutcome::Unknown {
            detail: "the task that created this session ended without saying how it came out"
                .to_owned(),
        })
    })
}

/// The interpreter a command runs through: a POSIX shell given the command line.
const COMMAND_INTERPRETER: &str = "/bin/sh";

/// How soon a dispatch first asks whether its session has closed, and the longest it waits
/// between two looks while the command runs.
const CLOSURE_POLL: std::time::Duration = std::time::Duration::from_millis(300);
const CLOSURE_POLL_LONGEST: std::time::Duration = std::time::Duration::from_secs(2);

/// How long a dispatch that was asked to stop waits for its session's closure before it leaves the
/// rest to the sweep.
const STOP_WAIT: std::time::Duration = std::time::Duration::from_secs(20);

/// Runs a `shell_command` node: the command is the root of a session of its own, and the node's
/// result is how that root ended.
///
/// Everything the dispatch does runs on a task of the daemon's own, from taking its place among
/// the running dispatches to releasing what it made: the engine dropping the wait for it, at a
/// deadline or a cancellation, cannot drop a session in the middle of being created, or leave a
/// place that nothing ends. What the dispatch will own is written to the ledger before any of it
/// is made.
async fn command_node(
    context: NodeContext,
    held: Arc<HeldGrant>,
    entry: LiveEntry,
    tests: bool,
) -> kr_automation::Result<ActionOutcome> {
    // The daemon is looked up for each call and never held across the command, which can run for
    // as long as the node's wait: a task that kept it would keep a daemon that is being let go.
    context.daemon.get()?;
    // A node's parameters are read before its task starts, so one that cannot be read is a refusal
    // of the node and not a task that ended without an answer.
    let (command, suite) = if tests {
        let params: kr_protocol::automation::RunTestsParams =
            serde_json::from_str(&held.node.action_params)?;
        (None, Some(params))
    } else {
        let params: kr_protocol::automation::ShellCommandParams =
            serde_json::from_str(&held.node.action_params)?;
        (Some(params.command), None)
    };
    let (sender, receiver) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let outcome = match (command, suite) {
            (Some(command), _) => run_command(&context, &held, &entry.task, command).await,
            (None, Some(suite)) => run_tests(&context, &held, &entry.task, suite).await,
            (None, None) => unreachable!("a node is a command or a suite"),
        };
        drop(entry);
        let _ = sender.send(outcome);
    });
    receiver.await.unwrap_or_else(|_| {
        Ok(ActionOutcome::Unknown {
            detail: "the task that ran this command ended without saying how it came out"
                .to_owned(),
        })
    })
}

/// Where a command runs: the workspace the definition names, checked against the identity the
/// project service recorded for it, or a private directory made for this node alone.
async fn command_directory(
    context: &NodeContext,
    workspace_id: Option<kr_protocol::ids::WorkspaceId>,
    scratch: Option<&std::path::Path>,
) -> kr_automation::Result<String> {
    let path = match (workspace_id, scratch) {
        (Some(workspace_id), _) => {
            let changesets = Arc::clone(&context.changesets);
            // Opened as a capture opens it: the tree at the recorded path must be the one the
            // project service recorded, by device and inode. A directory that was moved, removed
            // or replaced since is refused, and a command never runs in a place nobody chose.
            blocking(move || -> std::result::Result<PathBuf, String> {
                let resolved = changesets
                    .resolve(workspace_id)
                    .map_err(|error| error.to_string())?;
                let opened = changesets
                    .open_repository(&resolved)
                    .map_err(|error| error.to_string())?;
                Ok(opened.top_level().to_path_buf())
            })
            .await
            .map_err(|error| {
                kr_automation::AutomationError::PermissionDenied(format!(
                    "the workspace this command runs in is not the one that was recorded: {}",
                    kr_project::git::redact(&error)
                ))
            })?
        }
        (None, Some(scratch)) => scratch.to_path_buf(),
        (None, None) => unreachable!("a command with no workspace has a scratch directory"),
    };
    path.into_os_string().into_string().map_err(|_| {
        kr_automation::AutomationError::InvalidArgument(
            "the directory this command runs in has no text form a session can be asked for"
                .to_owned(),
        )
    })
}

/// Runs a command node's dispatch to its end and releases what it made, unless that cannot be
/// established yet and the sweep takes the row.
async fn run_command(
    context: &NodeContext,
    held: &Arc<HeldGrant>,
    task: &Arc<NodeTask>,
    text: String,
) -> kr_automation::Result<ActionOutcome> {
    let workspace_id = held.definition.resource_scope.workspace_id.0;
    let scratch = match workspace_id {
        Some(_) => None,
        None => Some(
            context
                .scratch_root
                .join(context.action_id.get().to_string()),
        ),
    };
    let cwd = command_directory(context, workspace_id, scratch.as_deref()).await?;
    let owned = Owned {
        action_id: context.action_id,
        run_id: context.run_id,
        node_id: held.node.node_id.clone(),
        kind: held.node.action_kind,
        grant_id: held.definition.grant_reference,
        owns_session: true,
        materialisation_id: None,
        scratch: scratch.as_ref().map(|path| path.display().to_string()),
        scratch_identity: None,
        workspace_id,
        session_id: None,
        worker: None,
        boot: Some(context.daemon.get()?.boot().clone()),
        state: OwnedState::Open,
    };
    // The row is written down before any of what it stands for is made, and the run's hold on its
    // workspace is taken in the same step, so a release that ends the hold never does so under a
    // row that has just begun.
    {
        let ledger = Arc::clone(&context.ledger);
        let changesets = Arc::clone(&context.changesets);
        let holds = Arc::clone(&context.holds);
        let (run_id, now) = (context.run_id, context.daemon.now_ms());
        blocking(move || -> kr_automation::Result<()> {
            let _hold = holds
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            ledger.begin(&owned, now)?;
            if let Some(workspace_id) = workspace_id {
                changesets
                    .project()
                    .bind_run(workspace_id, run_id, true)
                    .map_err(|error| {
                        kr_automation::AutomationError::PermissionDenied(format!(
                            "the workspace this command runs in cannot be held for the run: {}",
                            kr_project::git::redact(&error.to_string())
                        ))
                    })?;
            }
            Ok(())
        })
        .await?;
    }
    // The place it runs in exists before the session is asked for, and its identity is written
    // down before the command can start.
    if let Some(scratch) = scratch.clone() {
        let ledger = Arc::clone(&context.ledger);
        let (root, action_id) = (context.scratch_root.clone(), context.action_id);
        let environment_id = context.changesets.environment_id();
        blocking(move || -> kr_automation::Result<()> {
            let identity = make_scratch(environment_id, &root, &scratch)?;
            ledger.note_scratch_identity(action_id, &identity)
        })
        .await?;
    }
    let driven = drive_command(context, held, task, cwd, text, workspace_id).await;
    // Nothing made means nothing to wait for. Otherwise what the dispatch owned is released once
    // its session's closure accounts for the worker; if it cannot yet, the row stays open and the
    // sweep keeps looking.
    if driven.release {
        release_row(context, context.action_id).await;
    }
    driven.outcome
}

/// What driving a command came to, and whether the dispatch may release what it owned now.
struct Driven {
    outcome: kr_automation::Result<ActionOutcome>,
    release: bool,
    /// How the session ended, when its closure was recorded: what a test run is judged by.
    closure: Option<kr_protocol::session::ClosureRecord>,
    /// The session, and when it began, once it was made.
    session: Option<(
        kr_protocol::ids::SessionId,
        kr_protocol::scalars::TimestampMs,
    )>,
}

impl Driven {
    fn nothing_was_made(outcome: kr_automation::Result<ActionOutcome>) -> Self {
        Self {
            outcome,
            release: true,
            closure: None,
            session: None,
        }
    }
}

/// Makes the directory a command with no workspace runs in, and answers its identity.
///
/// The directory is made here and nowhere else, through a handle on the scratch root, and what is
/// recorded is what that handle reports about it: the object and the filesystem it is on. One
/// that is already there is the leftover of this node's own earlier attempt only if it is private
/// and empty, and is refused otherwise.
fn make_scratch(
    environment_id: EnvironmentId,
    root: &std::path::Path,
    scratch: &std::path::Path,
) -> kr_automation::Result<String> {
    use kr_transfer::{AuthorisedDirectory, Privacy, RelativeName};

    let refused = |what: &str, error: &dyn std::fmt::Display| {
        kr_automation::AutomationError::InvalidArgument(format!(
            "the directory this command runs in {what}: {error}"
        ))
    };
    kr_ipc::paths::create_private_tree(root, root)
        .map_err(|error| refused("could not be made", &error))?;
    let name = scratch
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| refused("has no name", &"its path ends in no name"))
        .and_then(|name| {
            RelativeName::parse(name).map_err(|error| refused("has no usable name", &error))
        })?;
    let held = AuthorisedDirectory::open_root(environment_id, root)
        .map_err(|error| refused("could not be reached", &error))?;
    let taken = held
        .occupied(&name)
        .map_err(|error| refused("could not be looked at", &error))?;
    let opened = if taken {
        // The name is taken: the leftover of this node's own earlier attempt, if it is private
        // and empty.
        let opened = held
            .subdirectory(&name)
            .map_err(|error| refused("could not be opened", &error))?;
        opened
            .check_privacy(Privacy::Exclusive)
            .map_err(|error| refused("is not private", &error))?;
        let empty = opened
            .handle()
            .entries()
            .map_err(|error| refused("could not be read", &error))?
            .next()
            .is_none();
        if !empty {
            return Err(refused("is not empty", &"it is not this node's to use"));
        }
        opened
    } else {
        held.create_new_subdirectory(&name, Privacy::Exclusive)
            .map_err(|error| refused("could not be made", &error))?
    };
    opened
        .recorded()
        .map_err(|error| refused("could not be identified", &error))
        .and_then(|recorded| {
            identity_text(recorded)
                .ok_or_else(|| refused("could not be identified", &"it reports no filesystem"))
        })
}

/// A directory's identity as the ledger keeps it: its device, its inode and the filesystem it is
/// on, as the handle that made it reported them. A directory whose filesystem the handle did not
/// report has no identity to keep.
fn identity_text(recorded: kr_transfer::RecordedIdentity) -> Option<String> {
    Some(format!(
        "{}:{}:{}",
        recorded.object.device, recorded.object.file_id, recorded.filesystem?
    ))
}

/// The identity a directory was recorded under, from its text form ([`identity_text`]).
#[cfg(unix)]
fn parse_identity(text: &str) -> Option<kr_transfer::RecordedIdentity> {
    let mut parts = text.splitn(3, ':');
    let device = parts.next()?.parse().ok()?;
    let file_id = parts.next()?.parse().ok()?;
    let filesystem = Some(kr_transfer::FilesystemId::from_hex(parts.next()?)?);
    Some(kr_transfer::RecordedIdentity::from_parts(
        device, file_id, filesystem,
    ))
}

/// Removes the directory a command ran in, when it is still the one that was made, and answers
/// what it left, if anything.
///
/// The removal is the project's own one for a directory it recorded
/// ([`AuthorisedDirectory::remove_tree`]), asked the way a staging directory's is: the scratch
/// root is opened without following a link and the directory beneath it through that handle, it
/// has to be the recorded object on the recorded filesystem, it is made private again when the
/// command loosened its mode (as unpacking an archive does) and has to be one only this account can
/// change, and the contents go through handles the removal holds, staying on the directory's own
/// mount, holding no more than [`kr_transfer::authority::MAX_REMOVAL_DEPTH`] levels. A tree the
/// removal does not take (a mount inside it, a tree too deep, a directory in it that its owner
/// cannot write or one whose owner read bit the command removed, a macOS access-control list on
/// the directory, entries still being written, a failure of the storage) stays where it is and the
/// answer names why, so the row that owns it is released and the leftover is named rather than the
/// row being owed for ever; one try is made. Another directory at the path, or none, is not this
/// host's to remove and is not named. A directory that was never identified was never used, and
/// is removed only if it is empty. On a filesystem that reports no identity of its own the
/// filesystem part of a record is zeros, and the check rests on the device and the inode.
///
/// What this cannot promise is what [`AuthorisedDirectory::remove_tree`] states: between the last
/// look at the entry and its removal, a process of this same account can put an empty directory
/// there, which then goes in its place.
#[cfg(unix)]
fn remove_scratch(
    environment_id: EnvironmentId,
    root: &std::path::Path,
    path: &std::path::Path,
    identity: Option<&str>,
) -> Option<String> {
    remove_scratch_after_root_opened(environment_id, root, path, identity, || {})
}

/// [`remove_scratch`], calling `opened_root` once the scratch root has been opened and before
/// anything beneath it is looked at: the moment a root replaced after its open must change
/// nothing.
#[cfg(unix)]
fn remove_scratch_after_root_opened(
    environment_id: EnvironmentId,
    root: &std::path::Path,
    path: &std::path::Path,
    identity: Option<&str>,
    opened_root: impl FnOnce(),
) -> Option<String> {
    use kr_transfer::{AuthorisedDirectory, Escape, ObjectIdentity, Privacy, RelativeName};
    use rustix::fs::{AtFlags, CWD, Mode, OFlags, fchmod, openat, unlinkat};
    use rustix::io::Errno;
    use std::os::unix::fs::MetadataExt;

    if path.parent() != Some(root) {
        return None;
    }
    let name_text = path.file_name().and_then(std::ffi::OsStr::to_str)?;
    let name = RelativeName::parse(name_text).ok()?;
    // The scratch root is opened without following a link, and the directory's removal or its
    // opening goes through that handle: a root replaced by a link is refused and what the link
    // leads to is never touched.
    let opened = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let parent = match openat(CWD, root, opened, Mode::empty()) {
        Ok(parent) => parent,
        Err(Errno::NOENT) => return None,
        Err(error) => return Some(format!("the scratch root could not be opened: {error}")),
    };
    opened_root();
    let Some(recorded) = identity else {
        // Never identified, so never used: whatever is in it was not put there by this host, and
        // only an empty directory goes.
        return match unlinkat(&parent, name_text, AtFlags::REMOVEDIR) {
            Ok(()) => {
                if let Err(error) =
                    kr_flush::flush_held_directory(&parent, kr_flush::NameKind::Directory)
                {
                    eprintln!(
                        "kr-controller: the removal of the workflow command's directory {} was not \
                         flushed: {error}",
                        path.display()
                    );
                }
                None
            }
            // Gone, or a file or a link in its place: not the directory that was made.
            Err(Errno::NOENT | Errno::NOTDIR) => None,
            Err(Errno::NOTEMPTY) => Some("it holds entries this host did not put there".to_owned()),
            Err(error) => Some(format!("it could not be removed: {error}")),
        };
    };
    let Some(expected) = parse_identity(recorded) else {
        return Some("the identity recorded for it cannot be read".to_owned());
    };
    // The object at the name, by its own handle, so that what is made private and what the
    // library then checks and removes are the same object.
    let child = match openat(&parent, name_text, opened, Mode::empty()) {
        Ok(child) => child,
        // Gone, or a file or a link in its place: not the directory that was made.
        Err(Errno::NOENT | Errno::NOTDIR | Errno::LOOP) => return None,
        Err(error) => return Some(format!("it could not be opened: {error}")),
    };
    let identity_of =
        |descriptor: &rustix::fd::OwnedFd| -> std::result::Result<ObjectIdentity, String> {
            let spare = descriptor
                .try_clone()
                .map_err(|error| format!("could not be looked at: {error}"))?;
            let about = std::fs::File::from(spare)
                .metadata()
                .map_err(|error| format!("could not be looked at: {error}"))?;
            Ok(ObjectIdentity {
                device: about.dev(),
                file_id: about.ino(),
            })
        };
    let found = match identity_of(&child) {
        Ok(found) => found,
        Err(reason) => return Some(format!("it {reason}")),
    };
    let held = match AuthorisedDirectory::open_root(environment_id, root) {
        Ok(held) => held,
        Err(refusal) => return Some(refusal.to_string()),
    };
    // The library opens the root by its path once more: it has to be the root that was opened
    // without following a link, or a root replaced in between is refused and named.
    match identity_of(&parent) {
        Ok(root_identity) if held.check_identity(root_identity).is_ok() => {}
        Ok(_) => return Some("the scratch root changed while it was being opened".to_owned()),
        Err(reason) => return Some(format!("the scratch root {reason}")),
    }
    let directory = match held.subdirectory(&name) {
        Ok(directory) => directory,
        Err(Escape::NotFound { .. } | Escape::Link { .. } | Escape::WrongKind { .. }) => {
            return None;
        }
        Err(refusal) => return Some(refusal.to_string()),
    };
    if directory.check_identity(found).is_err() {
        return None;
    }
    // The recorded directory is the recorded one under whatever device number its filesystem has
    // now. Another directory is not this host's; a failure to ask is a leftover to name.
    match directory.check_recorded(expected) {
        Ok(_) => {}
        Err(Escape::IdentityChanged { .. }) => return None,
        Err(refusal) => return Some(refusal.to_string()),
    }
    // A command can loosen the mode of its own directory, as unpacking an archive does. It is the
    // recorded object, so it is this account's to make private again; the check that follows is
    // then what shows another account's ownership or an access list.
    let _ = fchmod(&child, Mode::RWXU);
    if let Err(refusal) = directory.check_privacy(Privacy::Exclusive) {
        return Some(format!(
            "it is not a directory only this account can change: {refusal}"
        ));
    }
    if let Err(refusal) = held.remove_tree(&name, directory) {
        return Some(refusal.to_string());
    }
    if let Err(error) = held.sync(kr_flush::NameKind::Directory) {
        eprintln!(
            "kr-controller: the removal of the workflow command's directory {} was not flushed: \
             {error}",
            path.display()
        );
    }
    None
}

#[cfg(not(unix))]
fn remove_scratch(
    _environment_id: EnvironmentId,
    _root: &std::path::Path,
    _path: &std::path::Path,
    _identity: Option<&str>,
) -> Option<String> {
    Some("a directory a command ran in is removed on POSIX hosts".to_owned())
}

/// Makes the session a command runs as the root of, waits for it to close, and says whether what
/// the dispatch owned may be released.
async fn drive_command(
    context: &NodeContext,
    held: &Arc<HeldGrant>,
    task: &Arc<NodeTask>,
    cwd: String,
    text: String,
    bound_workspace: Option<kr_protocol::ids::WorkspaceId>,
) -> Driven {
    let actor_id = match workflow_principal(held.definition.grant_reference) {
        Ok(actor_id) => actor_id,
        Err(error) => return Driven::nothing_was_made(Err(error)),
    };
    let controller = match context.daemon.get() {
        Ok(controller) => controller,
        Err(error) => return Driven::nothing_was_made(Err(error)),
    };
    let admit = node_admission(&controller, held, context.wait_until_ms, task, true);
    let create = kr_protocol::session::SessionCreateParams {
        environment_id: context.changesets.environment_id(),
        presentation: kr_protocol::session::Presentation::Invisible,
        shell: Nullable::null(),
        shell_mode: kr_protocol::session::ShellMode::NativeCompat,
        cwd: Nullable::some(cwd),
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
        command: Some((
            kr_protocol::worker::RootCommand {
                interpreter: COMMAND_INTERPRETER.to_owned(),
                command: text,
            },
            kr_protocol::worker::WorkflowSession {
                workflow_run_id: context.run_id,
                node_id: held.node.node_id.clone(),
            },
        )),
        admit,
    };
    let created = match controller.workflow_session_create(order).await {
        Ok(created) => created,
        Err(error) => {
            // A create that made no session leaves nothing to wait for. One whose launch may
            // still complete has a session the registry holds under the node's token: it is
            // written down with its worker, the sweep closes it, and the row stays.
            let session = controller
                .workflow_session_of(&actor_id, context.action_id)
                .await;
            if let Ok(Some(found)) = &session {
                note_node_session(context, found, bound_workspace).await;
            }
            let outcome = creation_failed(held, error);
            return Driven {
                outcome,
                release: matches!(session, Ok(None)),
                closure: None,
                session: None,
            };
        }
    };
    let session_id = created.session.session_id;
    let began_at_ms = created.session.created_at_ms;
    // The session is written down at once, with its worker's process, and bound to the workspace
    // it runs in: a live session is a writer there, which a capture that wants the workspace held
    // still has to count. The worker's process is the one the launcher reported, which the
    // registry keeps after the session has closed.
    let worker = controller
        .workflow_session_of(&actor_id, context.action_id)
        .await
        .ok()
        .flatten()
        .and_then(|found| found.worker);
    drop(controller);
    note_node_session(
        context,
        &NodeSession { session_id, worker },
        bound_workspace,
    )
    .await;
    let closure = wait_for_closure(context, task, &actor_id, session_id).await;
    let outcome = match &closure {
        Some(closure) => command_outcome(closure),
        None => ActionOutcome::Unknown {
            detail: "the session this command ran in had not closed when the dispatch stopped \
                     waiting, so how the command came out is not established"
                .to_owned(),
        },
    };
    Driven {
        outcome: Ok(outcome),
        release: closure
            .as_ref()
            .is_some_and(|closure| !left_unaccounted(closure)),
        closure,
        session: Some((session_id, began_at_ms)),
    }
}

/// Writes down the session a dispatch made and the process of its worker, and binds the session to
/// the workspace it runs in.
async fn note_node_session(
    context: &NodeContext,
    found: &NodeSession,
    workspace_id: Option<kr_protocol::ids::WorkspaceId>,
) {
    let ledger = Arc::clone(&context.ledger);
    let changesets = Arc::clone(&context.changesets);
    let action_id = context.action_id;
    let (session_id, worker) = (found.session_id, found.worker.clone());
    let noted = blocking(move || -> kr_automation::Result<()> {
        ledger.note_session(action_id, session_id, worker.as_ref())?;
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

/// Runs a `run_tests` node: the suite the host's configuration names, as the root of a session of
/// its own, in a private copy of the version it is to test, and the node's result is what this
/// host observed of that session, never a caller's account of it.
///
/// Nothing is made before the suite is found in the configuration the daemon accepted, the version
/// is found inside the workflow's scope and the suite's declared outputs are found to agree with
/// the version. The copy is then made under the identifier the ledger row already names, so a stop
/// at any point leaves something the sweep finds from the row. When the session has closed, the
/// copy is read back and the version it still holds, or what it holds instead, is recorded with
/// the command's exit status as evidence against the version; the copy is released after that.
async fn run_tests(
    context: &NodeContext,
    held: &Arc<HeldGrant>,
    task: &Arc<NodeTask>,
    params: kr_protocol::automation::RunTestsParams,
) -> kr_automation::Result<ActionOutcome> {
    let controller = context.daemon.get()?;
    // One accepted configuration is read for the whole dispatch.
    let suite = match controller.workflow_test_suite(&params.suite) {
        Ok(suite) => suite,
        Err(detail) => return Ok(ActionOutcome::Failed { error: detail }),
    };
    drop(controller);
    let version = params.version;
    let outputs = {
        let (changesets, held, declared) = (
            Arc::clone(&context.changesets),
            Arc::clone(held),
            suite.outputs.clone(),
        );
        let checked = blocking(
            move || -> kr_automation::Result<std::result::Result<Outputs, String>> {
                held.still_authorised()?;
                version_in_scope(
                    &changesets,
                    &held.definition,
                    &ChangesetMaterializeParams {
                        change_set_id: version.change_set_id,
                        version: version.version,
                        purpose: kr_protocol::changeset::MaterialisationPurpose::Test,
                        label: String::new(),
                    },
                    held.environment_id,
                )?;
                let manifest = changesets
                    .manifest(version.change_set_id, version.version)
                    .map_err(|error| {
                        kr_automation::AutomationError::PermissionDenied(format!(
                            "the version this suite tests could not be read: {}",
                            kr_project::git::redact(&error.to_string())
                        ))
                    })?;
                Ok(Outputs::new(&declared, &manifest))
            },
        )
        .await?;
        match checked {
            Ok(outputs) => outputs,
            Err(detail) => {
                return Ok(ActionOutcome::Failed {
                    error: format!(
                        "the outputs suite {} declares cannot be used: {detail}",
                        params.suite
                    ),
                });
            }
        }
    };
    let materialisation_id = kr_protocol::ids::MaterialisationId::new(kr_ipc::new_uuid());
    let owned = Owned {
        action_id: context.action_id,
        run_id: context.run_id,
        node_id: held.node.node_id.clone(),
        kind: held.node.action_kind,
        grant_id: held.definition.grant_reference,
        owns_session: true,
        materialisation_id: Some(materialisation_id),
        scratch: None,
        scratch_identity: None,
        workspace_id: None,
        session_id: None,
        worker: None,
        boot: Some(context.daemon.get()?.boot().clone()),
        state: OwnedState::Open,
    };
    {
        let ledger = Arc::clone(&context.ledger);
        let now = context.daemon.now_ms();
        blocking(move || ledger.begin(&owned, now)).await?;
    }
    // The copy of the version, written under the grant the node holds.
    let made = {
        let (changesets, held) = (Arc::clone(&context.changesets), Arc::clone(held));
        let label = format!("{} for workflow node {}", params.suite, held.node.node_id);
        blocking(move || {
            materialise::materialise_as(
                &changesets,
                materialisation_id,
                version,
                kr_protocol::changeset::MaterialisationPurpose::Test,
                &label,
                Some(&*held),
            )
        })
        .await
    };
    let record = match made {
        Ok(record) if record.unapplied.is_empty() => record,
        failed => {
            // Nothing was run, so nothing is owed a wait: the copy, if one was begun, goes now.
            release_row(context, context.action_id).await;
            return match failed {
                Ok(record) => Ok(ActionOutcome::Failed {
                    error: format!(
                        "the copy of version {} of change set {} left {} of its paths unwritten, \
                         so no tests ran",
                        version.version,
                        version.change_set_id,
                        record.unapplied.len()
                    ),
                }),
                Err(error) => held.refusal_of(error),
            };
        }
    };
    let driven = drive_command(
        context,
        held,
        task,
        record.directory_path.clone(),
        suite.command.clone(),
        None,
    )
    .await;
    let outcome = match (&driven.closure, &driven.session) {
        (Some(closure), Some((session_id, began_at_ms))) => {
            observe_tests(
                context,
                held,
                &TestRun {
                    suite: &params.suite,
                    command_digest: kr_changeset::objects::hex_of(
                        kr_changeset::objects::digest_of(suite.command.as_bytes()),
                    ),
                    version,
                    materialisation_id,
                    outputs,
                    session_id: *session_id,
                    began_at_ms: *began_at_ms,
                },
                closure,
            )
            .await
        }
        _ => driven.outcome,
    };
    if driven.release {
        release_row(context, context.action_id).await;
    }
    outcome
}

/// What a test run is recorded against.
struct TestRun<'a> {
    suite: &'a str,
    /// The digest of the command the suite's configuration gave when the node dispatched, so a
    /// result says which command ran and the command's text is kept out of it.
    command_digest: String,
    version: kr_protocol::changeset::VersionRef,
    materialisation_id: kr_protocol::ids::MaterialisationId,
    outputs: Outputs,
    session_id: kr_protocol::ids::SessionId,
    began_at_ms: kr_protocol::scalars::TimestampMs,
}

/// Records what this host observed of a finished test session, and judges the node by it.
///
/// A result is recorded only for a suite that ran to an end of its own: it exited with a status, or
/// a signal ended it. A suite that never started, or that was stopped, has no result to record, and
/// the node's answer is how the session closed. Of the suites that ran, the session's own exit
/// status and the copy as it is read back now decide the node. A suite that exits zero against a
/// copy that still holds exactly the version has passed that version; one that exits zero against a
/// copy that was changed, or that cannot be read back, has passed nothing this host can name, and
/// the node is left unknown. A non-zero status or a signal fails the node whatever the copy holds,
/// once what was observed is recorded; when that cannot be recorded the node is left unknown.
async fn observe_tests(
    context: &NodeContext,
    held: &HeldGrant,
    run: &TestRun<'_>,
    closure: &kr_protocol::session::ClosureRecord,
) -> kr_automation::Result<ActionOutcome> {
    use kr_protocol::changeset::{EvidenceKind, TestedSource};
    use kr_protocol::session::ClosureReason;

    // How the session closed decides everything but a pass: the same account a command's node gives.
    let outcome = command_outcome(closure);
    let ended = match closure.reason {
        ClosureReason::RootExit => closure
            .root_exit_code
            .0
            .map(|code| format!("exited with status {}", code.get())),
        ClosureReason::RootSignal => Some(match closure.root_signal.0.as_deref() {
            Some(signal) => format!("was ended by signal {signal}"),
            None => "was ended by a signal".to_owned(),
        }),
        _ => None,
    };
    let Some(ended) = ended else {
        return Ok(outcome);
    };
    let report = RunReport {
        command: run.suite.to_owned(),
        profile: format!("workflow run_tests; command digest {}", run.command_digest),
        tool: kr_protocol::changeset::ToolIdentity {
            name: COMMAND_INTERPRETER.to_owned(),
            version: "not reported".to_owned(),
        },
        receipt: kr_protocol::changeset::ExecutionReceipt {
            started_at_ms: run.began_at_ms,
            ended_at_ms: closure.closed_at_ms,
            exit_status: closure.root_exit_code,
            // A signal stopped it rather than it finishing.
            stopped: closure.reason != ClosureReason::RootExit,
            detail: format!(
                "observed by this host: session {}, workflow run {}, node {}; the suite {ended}",
                run.session_id, context.run_id, held.node.node_id
            ),
        },
        outputs: Vec::new(),
    };
    let recorded = {
        let changesets = Arc::clone(&context.changesets);
        let (id, outputs, version, suite) = (
            run.materialisation_id,
            run.outputs.clone(),
            run.version,
            run.suite.to_owned(),
        );
        let session_id = run.session_id;
        blocking(
            move || -> kr_changeset::Result<kr_protocol::changeset::MaterialisationResult> {
                let result = materialise::record_result_with(&changesets, id, &report, &outputs)?;
                changesets.record_evidence(
                    version.change_set_id,
                    version.version,
                    EvidenceKind::TestResult,
                    &format!(
                        "suite '{suite}' in session {session_id} {ended}; the tested source is {}",
                        match result.tested_source {
                            TestedSource::UnmodifiedVersion => "this version, unmodified",
                            TestedSource::Indeterminate => "indeterminate",
                        }
                    ),
                )?;
                Ok(result)
            },
        )
        .await
    };
    let result = match recorded {
        Ok(result) => result,
        Err(error) => {
            return Ok(ActionOutcome::Unknown {
                detail: format!(
                    "the suite's session closed, but what this host observed could not be \
                     recorded: {}",
                    kr_project::git::redact(&error.to_string())
                ),
            });
        }
    };
    Ok(match outcome {
        // Only a suite that passed is judged by what it ran against.
        ActionOutcome::Success { .. } => match result.tested_source {
            TestedSource::UnmodifiedVersion => ActionOutcome::Success {
                output: NodeOutput::RunTests {
                    suite: run.suite.to_owned(),
                    version: run.version,
                },
            },
            TestedSource::Indeterminate => ActionOutcome::Unknown {
                detail: format!(
                    "the suite exited with status 0, but what it ran against cannot be \
                     established: {}",
                    result.attestation
                ),
            },
        },
        other => other,
    })
}

/// Whether a closure could not account for the session's own worker, which may then still write
/// where the session ran.
fn left_unaccounted(closure: &kr_protocol::session::ClosureRecord) -> bool {
    closure
        .surviving
        .iter()
        .any(|resource| resource.kind == crate::archive::UNACCOUNTED_WORKER)
}

/// Whether the worker a row recorded is gone: the boot it ran in has ended, or the kernel says
/// the process that was recorded has.
fn worker_has_ended(row: &Owned, boot: &kr_protocol::identity::BootIdentity) -> bool {
    row.boot.as_ref().is_some_and(|recorded| recorded != boot)
        || row.worker.as_ref().is_some_and(|worker| {
            matches!(
                kr_ipc::identity::process_state(worker),
                kr_ipc::identity::ProcessState::Ended
            )
        })
}

/// Waits for a session's closure, closing the session when its dispatch is asked to stop.
///
/// Nothing records a root's exit by itself, so each look asks whether the session's worker has
/// gone, at first often and then less often while the command runs. A dispatch asked to stop
/// closes the session once and then waits a bounded time for the closure; one that is not recorded
/// in that time is left to the sweep.
async fn wait_for_closure(
    context: &NodeContext,
    task: &Arc<NodeTask>,
    actor_id: &ActorId,
    session_id: kr_protocol::ids::SessionId,
) -> Option<kr_protocol::session::ClosureRecord> {
    let mut stop_by: Option<tokio::time::Instant> = None;
    let mut poll = CLOSURE_POLL;
    loop {
        // A daemon that is gone has nobody to ask; the next daemon's sweep finds the session.
        let controller = context.daemon.get().ok()?;
        if stop_by.is_none() && task.cancelled() {
            stop_by = Some(tokio::time::Instant::now() + STOP_WAIT);
            poll = CLOSURE_POLL;
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
        tokio::select! {
            () = tokio::time::sleep(poll) => {}
            () = task.woken.notified() => {}
        }
        poll = (poll * 2).min(CLOSURE_POLL_LONGEST);
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

/// Releases what a dispatch owned and marks its row released: the directory it ran in, the
/// session's binding to its workspace, and the run's hold on the workspace when no other row of
/// the run holds it. Answers whether the row is released; a row that is not stays open for the
/// sweep to try again.
async fn release_row(context: &NodeContext, action_id: kr_protocol::ids::ActionId) -> bool {
    release(
        Arc::clone(&context.changesets),
        Arc::clone(&context.ledger),
        context.scratch_root.clone(),
        Arc::clone(&context.holds),
        context.daemon.now_ms(),
        action_id,
    )
    .await
}

async fn release(
    changesets: Arc<ChangeSetService>,
    ledger: Arc<ResourceLedger>,
    scratch_root: PathBuf,
    holds: Arc<std::sync::Mutex<()>>,
    now_ms: u64,
    action_id: kr_protocol::ids::ActionId,
) -> bool {
    let released = blocking(move || -> kr_automation::Result<()> {
        let Some(row) = ledger.get(action_id)? else {
            return Ok(());
        };
        if row.state == OwnedState::Released {
            return Ok(());
        }
        if let Some(scratch) = row.scratch.as_ref()
            && let Some(reason) = remove_scratch(
                changesets.environment_id(),
                &scratch_root,
                std::path::Path::new(scratch),
                row.scratch_identity.as_deref(),
            )
        {
            eprintln!(
                "kr-controller: the directory a workflow command ran in was left where it is \
                 ({reason}): {scratch}"
            );
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
        // The copy a test run was given, by the identifier the row named before it was made: taken
        // away when it has a record, and its empty directory when a stop left one with none.
        if let Some(materialisation_id) = row.materialisation_id {
            match materialise::release(&changesets, materialisation_id) {
                Ok(_) => {}
                Err(kr_changeset::ChangeSetError::UnknownMaterialisation { .. }) => {
                    materialise::discard_unrecorded(&changesets, materialisation_id).map_err(
                        |error| {
                            kr_automation::AutomationError::InvalidArgument(format!(
                                "a test run's directory was not taken away: {}",
                                kr_project::git::redact(&error.to_string())
                            ))
                        },
                    )?;
                }
                Err(error) => {
                    return Err(kr_automation::AutomationError::InvalidArgument(format!(
                        "a test run's copy of its version was not released: {}",
                        kr_project::git::redact(&error.to_string())
                    )));
                }
            }
        }
        // The run holds a workspace once however many of its nodes ran there, so the hold ends
        // with the last row that holds it. A dispatch that is taking the hold for a node that
        // has just begun waits behind this, and finds its row counted.
        let _hold = holds
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(workspace_id) = row.workspace_id
            && !ledger.another_holds(row.run_id, workspace_id, action_id)?
            && let Err(error) = changesets
                .project()
                .bind_run(workspace_id, row.run_id, false)
        {
            return Err(kr_automation::AutomationError::InvalidArgument(format!(
                "the run's hold on its workspace was not ended: {}",
                kr_project::git::redact(&error.to_string())
            )));
        }
        ledger.release(action_id, now_ms)
    })
    .await;
    if let Err(error) = &released {
        eprintln!(
            "kr-controller: what a workflow command owned was not released, and the sweep will \
             try again: {error}"
        );
    }
    released.is_ok()
}

/// How long released rows are kept for a person who reads the ledger.
const RELEASED_ROWS_KEPT_MS: u64 = 7 * 24 * 60 * 60 * 1000;

impl HostActions {
    /// Closes and releases what no dispatch of this daemon owns any longer, and answers how many
    /// rows are still owed their release and need another look on a timer.
    ///
    /// A row belongs to its dispatch while the dispatch is running here, and its end wakes the
    /// sweep, so such a row asks for no timer. After a restart there are no dispatches, so every
    /// row is taken: a session whose command outlived its node is closed, and once its closure
    /// accounts for its worker the directory, the hold and the row go. A closure that could not
    /// account for the worker waits for the kernel to say the worker's process ended, or for the
    /// boot it ran in to end. A row whose session was never made is released. Nothing here waits
    /// for the run to end, only for the session's closure.
    pub(crate) async fn sweep(&self, service: &AutomationService) -> usize {
        let Ok(controller) = self.daemon.get() else {
            return 0;
        };
        let ledger = Arc::clone(&self.ledger);
        let before_ms = self.daemon.now_ms().saturating_sub(RELEASED_ROWS_KEPT_MS);
        let rows = match blocking(move || {
            ledger.forget_released_before(before_ms)?;
            ledger.open_rows()
        })
        .await
        {
            Ok(rows) => rows,
            Err(error) => {
                eprintln!("kr-controller: the workflow resource ledger was not read: {error}");
                return 1;
            }
        };
        let mut stuck = 0;
        for mut row in rows {
            if self.live.get(row.action_id).is_some() {
                continue;
            }
            let store = Arc::clone(service.store());
            let (run_id, node_id) = (row.run_id, row.node_id.clone());
            let running = matches!(
                blocking(move || store.node_status(run_id, &node_id)).await,
                Ok(Some(kr_protocol::automation::NodeStatus::Running))
            );
            if running {
                stuck += 1;
                continue;
            }
            let Ok(actor_id) = workflow_principal(row.grant_id) else {
                stuck += 1;
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
                Ok(Some(found)) => {
                    let session_id = found.session_id;
                    // A dispatch that ended before it wrote its session down leaves a row with no
                    // worker. The registry keeps the process the launcher started, so the row is
                    // given it before anything is decided from it.
                    if row.worker.is_none() && found.worker.is_some() {
                        let ledger = Arc::clone(&self.ledger);
                        let (action_id, worker) = (row.action_id, found.worker.clone());
                        let noted = blocking(move || {
                            ledger.note_session(action_id, session_id, worker.as_ref())
                        })
                        .await;
                        match noted {
                            Ok(()) => row.worker = found.worker,
                            Err(error) => eprintln!(
                                "kr-controller: the worker of a workflow session its node left \
                                 behind was not written down: {error}"
                            ),
                        }
                    }
                    match controller.workflow_session_closure(session_id).await {
                        Ok(Some(closure)) if !left_unaccounted(&closure) => {}
                        Ok(Some(_)) if worker_has_ended(&row, controller.boot()) => {}
                        Ok(Some(_)) => {
                            stuck += 1;
                            continue;
                        }
                        Ok(None) => {
                            self.close_once(&controller, &actor_id, &row, session_id)
                                .await;
                            stuck += 1;
                            continue;
                        }
                        Err(error) => {
                            eprintln!(
                                "kr-controller: the closure of a workflow session its node left \
                                 behind was not read: {error}"
                            );
                            stuck += 1;
                            continue;
                        }
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    eprintln!(
                        "kr-controller: a workflow node's session could not be looked up: {error}"
                    );
                    stuck += 1;
                    continue;
                }
            }
            let released = release(
                Arc::clone(&self.changesets),
                Arc::clone(&self.ledger),
                self.scratch_root.clone(),
                Arc::clone(&self.holds),
                self.daemon.now_ms(),
                row.action_id,
            )
            .await;
            if released {
                self.closing
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&row.action_id);
            } else {
                stuck += 1;
            }
        }
        stuck
    }

    /// Asks the session a row left behind to close, once in this daemon. Every close of a node is
    /// the same request, so a daemon that asks again is answered from the first one's receipt, and
    /// a closure that is slow to be recorded is waited for by looking, not by asking again.
    async fn close_once(
        &self,
        controller: &Arc<Controller>,
        actor_id: &ActorId,
        row: &Owned,
        session_id: kr_protocol::ids::SessionId,
    ) {
        let asked = self
            .closing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&row.action_id);
        if asked {
            return;
        }
        let closed = controller
            .workflow_session_close(crate::service::WorkflowClose {
                actor_id,
                run_id: row.run_id,
                session_id,
                node_action: row.action_id,
            })
            .await;
        match closed {
            // Remembered only when a worker was asked. A session whose worker has not reported
            // yet is asked again at the next look, once its worker is there to be asked.
            Ok(true) => {
                self.closing
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(row.action_id);
            }
            Ok(false) => {}
            Err(error) => {
                eprintln!(
                    "kr-controller: a workflow session its node left behind was not closed: \
                     {error}"
                );
            }
        }
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

/// How long the sweep waits before it looks again at resources that are still owed their release,
/// and the longest it waits when the same rows stay owed.
const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
const SWEEP_LONGEST: std::time::Duration = std::time::Duration::from_secs(300);

/// Releases what node dispatches left behind, for as long as the daemon holds the service.
///
/// It looks once when execution starts, which is how a command a stopped daemon left running is
/// found, and again whenever a dispatch begins or ends. While rows no dispatch owns are still owed
/// their release it looks again on a timer, which doubles while nothing changes, so a session
/// that is slow to close is not forgotten and a row that cannot be released does not wake the
/// daemon every few seconds for ever. When nothing is owed it waits for a dispatch and keeps no
/// timer.
async fn sweep_loop(actions: Arc<HostActions>, service: Arc<AutomationService>) {
    let mut wait = SWEEP_INTERVAL;
    loop {
        let owed = actions.sweep(&service).await;
        actions.sweeps.finished();
        if owed == 0 {
            wait = SWEEP_INTERVAL;
            actions.live.changed.notified().await;
        } else {
            tokio::select! {
                () = actions.live.changed.notified() => wait = SWEEP_INTERVAL,
                () = tokio::time::sleep(wait) => wait = (wait * 2).min(SWEEP_LONGEST),
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
            holds: Arc::new(std::sync::Mutex::new(())),
            closing: std::sync::Mutex::new(HashSet::new()),
            sweeps: PassCount::default(),
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

    /// How many looks the sweep of what node dispatches left behind has finished, kept for this
    /// host's own tests.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn sweep_passes(&self) -> u64 {
        self.actions.sweeps.get()
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

    #[cfg(unix)]
    fn environment() -> EnvironmentId {
        EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([1; 16]))
    }

    /// A private directory made the way a command's is, beneath `root`, and the identity the ledger
    /// would keep for it.
    #[cfg(unix)]
    fn made(root: &std::path::Path, name: &str) -> (std::path::PathBuf, String) {
        use kr_transfer::{AuthorisedDirectory, Privacy, RelativeName};

        let held = AuthorisedDirectory::open_root(environment(), root).expect("the root opens");
        let opened = held
            .create_new_subdirectory(
                &RelativeName::parse(name).expect("a name"),
                Privacy::Exclusive,
            )
            .expect("the directory is made");
        (
            root.join(name),
            identity_text(opened.recorded().expect("it has an identity")).expect("a filesystem"),
        )
    }

    /// A directory a node's earlier attempt left is reused while it is empty, and has the identity
    /// it was made with; one with entries in it is not this node's to use and is refused.
    #[cfg(unix)]
    #[test]
    fn a_leftover_directory_is_reused_only_while_it_is_empty() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("a root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("the root is private");
        let scratch = root.path().join("node");

        let first = make_scratch(environment(), root.path(), &scratch).expect("it is made");
        let again =
            make_scratch(environment(), root.path(), &scratch).expect("an empty one is reused");
        assert_eq!(again, first, "the leftover is the directory that was made");

        std::fs::write(scratch.join("file"), b"x").expect("a file in it");
        assert!(
            make_scratch(environment(), root.path(), &scratch).is_err(),
            "a leftover with entries is refused"
        );
        assert!(scratch.join("file").exists(), "and left as it is");
    }

    /// The directory a command ran in is removed with what is in it only while it still has the
    /// identity written down for it. Another directory at its path, private as the made one was, is
    /// left alone, and one that was never identified is removed only when it is empty, through the
    /// scratch root's handle and never a path that a link in its place leads elsewhere. The
    /// control is the directory that was made, which goes with its contents.
    #[cfg(unix)]
    #[test]
    fn a_directory_is_removed_only_while_it_is_the_one_that_was_made() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("a root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("the root is private");

        let (scratch, identity) = made(root.path(), "node");
        std::fs::create_dir(scratch.join("inner")).expect("a directory in it");
        std::fs::write(scratch.join("inner").join("output"), b"x").expect("a file in it");
        assert_eq!(
            remove_scratch(environment(), root.path(), &scratch, Some(&identity)),
            None,
            "the directory that was made goes without a leftover"
        );
        assert!(!scratch.exists(), "and with its contents");

        // Moved aside, not removed: a removed directory's inode can be handed to the next one.
        let (scratch, identity) = made(root.path(), "node");
        std::fs::rename(&scratch, root.path().join("moved")).expect("it is moved aside");
        std::fs::create_dir(&scratch).expect("another directory is put at its path");
        std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o700))
            .expect("as private as the made one was");
        std::fs::write(scratch.join("precious"), b"y").expect("a file in it");
        assert_eq!(
            remove_scratch(environment(), root.path(), &scratch, Some(&identity)),
            None
        );
        assert!(
            scratch.join("precious").exists(),
            "another directory is left alone"
        );
        std::fs::remove_dir_all(&scratch).expect("cleared");

        std::fs::create_dir(&scratch).expect("an unidentified directory");
        assert_eq!(
            remove_scratch(environment(), root.path(), &scratch, None),
            None,
            "an empty one is removed"
        );
        assert!(!scratch.exists());
        std::fs::create_dir(&scratch).expect("an unidentified directory");
        std::fs::write(scratch.join("precious"), b"z").expect("a file in it");
        assert!(
            remove_scratch(environment(), root.path(), &scratch, None).is_some(),
            "a full one is left, and named"
        );
        assert!(
            scratch.join("precious").exists(),
            "an unidentified directory with contents stays"
        );

        let elsewhere = tempfile::tempdir().expect("another root");
        let outside = elsewhere.path().join("node");
        let (_, identity) = made(elsewhere.path(), "node");
        assert_eq!(
            remove_scratch(environment(), root.path(), &outside, Some(&identity)),
            None
        );
        assert!(outside.exists(), "a path outside the root is never removed");
        std::fs::remove_dir(&outside).expect("emptied");
        std::fs::create_dir(&outside).expect("an unidentified directory outside the root");
        assert_eq!(
            remove_scratch(environment(), root.path(), &outside, None),
            None
        );
        assert!(
            outside.exists(),
            "an unidentified one outside the root is never removed"
        );
    }

    /// A scratch root replaced by a link leads nowhere: what the link points at is never touched.
    /// The root is replaced before the call here, so the open of the root without following a link
    /// refuses it, for a directory that was never identified and for one that was.
    #[cfg(unix)]
    #[test]
    fn a_scratch_root_replaced_by_a_link_removes_nothing_it_leads_to() {
        let parent = tempfile::tempdir().expect("a parent");
        let outside = parent.path().join("outside");
        let (_, identity) = made(&outside_with_nodes(&outside), "node-two");
        let root = parent.path().join("scratch");
        std::os::unix::fs::symlink(&outside, &root).expect("the root is a link");

        let left = remove_scratch(environment(), &root, &root.join("node"), None);
        assert!(left.is_some(), "the refused root is named");
        assert!(
            outside.join("node").exists(),
            "what the link leads to is not removed"
        );
        let left = remove_scratch(
            environment(),
            &root,
            &root.join("node-two"),
            Some(&identity),
        );
        assert!(
            left.is_some(),
            "the refused root is named for an identified one"
        );
        assert!(
            outside.join("node-two").exists(),
            "an identified directory is not removed through the link either"
        );
    }

    /// A directory outside the scratch root, holding an empty directory a link to it would lead a
    /// path to.
    #[cfg(unix)]
    fn outside_with_nodes(outside: &std::path::Path) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        std::fs::create_dir_all(outside.join("node")).expect("an empty directory outside");
        std::fs::set_permissions(outside, std::fs::Permissions::from_mode(0o700))
            .expect("the directory is private");
        outside.to_path_buf()
    }

    /// A scratch root replaced after it was opened changes nothing: the directory beneath it is the
    /// one the opened root holds, and what a link in its place leads to is never removed. The
    /// root is moved aside and a link to a directory that holds a directory of the same name is put
    /// at its path, in the moment after the open, for a directory that was never identified and
    /// for one that was. The first is removed through the opened root, which is the moved one, and
    /// a removal by path would take what the link leads to instead; the second is refused by name,
    /// because the root the library opens again is not the one that was opened.
    #[cfg(unix)]
    #[test]
    fn a_scratch_root_replaced_after_it_was_opened_removes_nothing_it_leads_to() {
        use std::os::unix::fs::PermissionsExt;

        for identified in [false, true] {
            let parent = tempfile::tempdir().expect("a parent");
            let outside = outside_with_nodes(&parent.path().join("outside"));
            let root = parent.path().join("scratch");
            std::fs::create_dir(&root).expect("a root");
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                .expect("the root is private");
            let (scratch, identity) = made(&root, "node");
            let swap = || {
                std::fs::rename(&root, parent.path().join("moved")).expect("the root is moved");
                std::os::unix::fs::symlink(&outside, &root).expect("a link is put at its path");
            };
            let left = remove_scratch_after_root_opened(
                environment(),
                &root,
                &scratch,
                identified.then_some(identity.as_str()),
                swap,
            );
            let moved = parent.path().join("moved").join("node");
            assert!(
                outside.join("node").exists(),
                "what the link leads to is not removed (identified: {identified})"
            );
            if identified {
                assert!(
                    left.is_some_and(|reason| reason.contains("scratch root")),
                    "the root that changed is named"
                );
                assert!(moved.exists(), "a refused root removes nothing beneath it");
            } else {
                assert_eq!(left, None);
                assert!(
                    !moved.exists(),
                    "the empty directory the opened root holds goes"
                );
            }
        }
    }

    /// A directory on another filesystem than the one it was recorded on is left alone, though its
    /// device and inode are the recorded ones: the identity names the filesystem too. The control
    /// is the same directory under the identity it was made with.
    #[cfg(unix)]
    #[test]
    fn a_directory_on_another_filesystem_than_the_recorded_one_is_left_alone() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("a root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("the root is private");
        let (scratch, identity) = made(root.path(), "node");
        std::fs::write(scratch.join("file"), b"x").expect("a file in it");
        let (object, _) = identity.rsplit_once(':').expect("three parts");
        let elsewhere = format!(
            "{object}:{}",
            kr_transfer::FilesystemId::from_bytes([0xab; kr_transfer::FilesystemId::LEN])
        );
        assert_eq!(
            remove_scratch(environment(), root.path(), &scratch, Some(&elsewhere)),
            None
        );
        assert!(
            scratch.join("file").exists(),
            "a directory on another filesystem is not removed"
        );
        assert_eq!(
            remove_scratch(environment(), root.path(), &scratch, Some(&identity)),
            None
        );
        assert!(!scratch.exists(), "under its own identity it goes");
    }

    /// A command that unpacks an archive loosens the mode of the directory it runs in. It is still
    /// the recorded directory, and it goes: it is made private again before it is asked whether
    /// only this account can change it.
    #[cfg(unix)]
    #[test]
    fn a_directory_whose_mode_the_command_loosened_is_removed() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("a root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("the root is private");
        let (scratch, identity) = made(root.path(), "node");
        std::fs::write(scratch.join("file"), b"x").expect("a file in it");
        std::fs::set_permissions(&scratch, std::fs::Permissions::from_mode(0o755))
            .expect("the command loosened its mode");
        assert_eq!(
            remove_scratch(environment(), root.path(), &scratch, Some(&identity)),
            None
        );
        assert!(!scratch.exists());
    }

    /// A chain of directories deeper than the removal holds handles for is a tree it will not
    /// take: it is left where it is and named, and nothing else comes of it: the row that owns it
    /// is released and the leftover is for a person to look at.
    #[cfg(unix)]
    #[test]
    fn a_tree_the_removal_will_not_take_is_left_and_named() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("a root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("the root is private");

        let (scratch, identity) = made(root.path(), "node");
        let mut deep = scratch.clone();
        for _ in 0..=kr_transfer::authority::MAX_REMOVAL_DEPTH + 4 {
            deep.push("a");
        }
        std::fs::create_dir_all(&deep).expect("a deep chain is made");
        assert!(
            remove_scratch(environment(), root.path(), &scratch, Some(&identity)).is_some(),
            "the deep chain is left and named"
        );
        assert!(scratch.is_dir(), "and it is left where it is");
        std::fs::remove_dir_all(&scratch).expect("the chain is taken apart");
    }

    /// A directory inside the tree that its owner cannot write stops the removal, and the tree is
    /// left and named: the control is the same tree writable. Run as the superuser, a mode stops
    /// nothing, and the case then has nothing to show.
    #[cfg(unix)]
    #[test]
    fn a_directory_inside_that_its_owner_cannot_write_is_left_and_named() {
        use std::os::unix::fs::PermissionsExt;

        if rustix::process::geteuid().is_root() {
            return;
        }
        let root = tempfile::tempdir().expect("a root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("the root is private");
        let (scratch, identity) = made(root.path(), "node");
        std::fs::create_dir(scratch.join("cache")).expect("a directory in it");
        std::fs::write(scratch.join("cache").join("module"), b"x").expect("a file in it");
        std::fs::set_permissions(
            scratch.join("cache"),
            std::fs::Permissions::from_mode(0o555),
        )
        .expect("a build left it read-only");
        assert!(
            remove_scratch(environment(), root.path(), &scratch, Some(&identity)).is_some(),
            "a directory inside that its owner cannot write is left and named"
        );
        assert!(scratch.join("cache").join("module").exists());
        std::fs::set_permissions(
            scratch.join("cache"),
            std::fs::Permissions::from_mode(0o755),
        )
        .expect("it is opened again");
        assert_eq!(
            remove_scratch(environment(), root.path(), &scratch, Some(&identity)),
            None,
            "the same tree, writable, is removed"
        );
        assert!(!scratch.exists());
    }

    /// A directory the host may not take out of its parent is left and named like any other tree
    /// the removal will not take. The control is the parent as the host made it. Run as the
    /// superuser, a mode stops nothing, and the case then has nothing to show.
    #[cfg(unix)]
    #[test]
    fn a_directory_the_host_may_not_take_out_of_its_parent_is_left_and_named() {
        use std::os::unix::fs::PermissionsExt;

        if rustix::process::geteuid().is_root() {
            return;
        }
        let root = tempfile::tempdir().expect("a root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("the root is private");
        let (scratch, identity) = made(root.path(), "node");

        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o500))
            .expect("the parent is closed to writing");
        let left = remove_scratch(environment(), root.path(), &scratch, Some(&identity));
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("the parent is opened again");
        assert!(left.is_some(), "the empty directory is left and named");
        assert!(scratch.is_dir());

        assert_eq!(
            remove_scratch(environment(), root.path(), &scratch, Some(&identity)),
            None,
            "the control: the parent as the host made it lets it go"
        );
        assert!(!scratch.exists());
    }

    /// A wait's end is held to the moment it ends less the millisecond that rounding down the
    /// reading may have added, credited as a bound is: with 9,999 ms left by the rounded reading
    /// the moment is 9,997 ms after the boot reading and never later, because the true time left
    /// can be 9,998.001 and 100 ppm of it is a further fraction.
    #[test]
    fn a_waits_end_is_held_to_the_reading_it_was_rounded_from() {
        for (left, after) in [
            (10_000_u64, 9_998_u64),
            (9_999, 9_997),
            (2, 0),
            (1, 0),
            (0, 0),
        ] {
            assert_eq!(
                wait_end_on_the_boot_clock(1_000, 5_000, 5_000 + left),
                1_000 + after,
                "{left} ms left by the rounded reading"
            );
        }
    }

    /// The moment a grant stands until is measured from a reading taken before the grant was
    /// decided: a decision that takes five seconds shortens the moment by five seconds and never
    /// lengthens it. The time left is credited as a bound is, with the deduction rounded up: a
    /// grant with 9,999 ms left stands until 9,998 ms after the reading, not 9,999, because 100 ppm
    /// of 9,999 ms is a fraction of a millisecond the clock the worker reads may lose.
    #[test]
    fn a_slow_decision_shortens_the_moment_a_grant_stands_until() {
        use std::time::Duration;

        for (left, credited) in [(10_000_u64, 9_999_u64), (9_999, 9_998), (1, 0), (0, 0)] {
            let clock = std::cell::Cell::new(1_000_u64);
            let ends_at = grant_end_on_the_boot_clock(
                || clock.get(),
                || {
                    // The decision takes five seconds and finds `left` milliseconds left.
                    clock.set(6_000);
                    Ok(Some(Duration::from_millis(left)))
                },
            )
            .expect("decided");
            assert_eq!(
                ends_at,
                Some(1_000 + credited),
                "{left} ms left, from the reading before the decision and not the one after it"
            );
        }
        let unbounded = grant_end_on_the_boot_clock(|| 1_000, || Ok(None)).expect("decided");
        assert_eq!(unbounded, None, "a grant with no end has no moment");
    }

    /// A worker a closure could not account for is gone when the boot it ran in has ended, or when
    /// the kernel says the process that was recorded has. One that is still running in the same
    /// boot is not, and a row that recorded neither says nothing.
    #[test]
    fn a_worker_is_gone_when_its_boot_or_its_process_has_ended() {
        use kr_protocol::identity::{BootIdentity, BootIdentitySource};

        let boot = |byte: u8| BootIdentity {
            source: BootIdentitySource::LinuxBootId,
            value: kr_protocol::scalars::Bytes::new(vec![byte; 4]),
        };
        let row = |worker, boot| Owned {
            action_id: kr_protocol::ids::ActionId::new(kr_protocol::scalars::Uuid::from_bytes(
                [1; 16],
            )),
            run_id: kr_protocol::ids::WorkflowRunId::new(kr_protocol::scalars::Uuid::from_bytes(
                [2; 16],
            )),
            node_id: "command".to_owned(),
            kind: WorkflowActionKind::ShellCommand,
            grant_id: GrantId::new(kr_protocol::scalars::Uuid::from_bytes([3; 16])),
            owns_session: true,
            materialisation_id: None,
            scratch: None,
            scratch_identity: None,
            workspace_id: None,
            session_id: None,
            worker,
            boot,
            state: OwnedState::Open,
        };
        let running = kr_ipc::identity::current_process_start_identity().expect("this process");
        let ended = kr_ipc::identity::ended_process_identity(u32::MAX - 1);

        assert!(
            !worker_has_ended(&row(Some(running.clone()), Some(boot(1))), &boot(1)),
            "a worker still running in the same boot is not gone"
        );
        assert!(
            worker_has_ended(&row(Some(running), Some(boot(1))), &boot(2)),
            "a worker of an earlier boot is gone with that boot"
        );
        assert!(
            worker_has_ended(&row(Some(ended), Some(boot(1))), &boot(1)),
            "a worker the kernel says has ended is gone"
        );
        assert!(
            !worker_has_ended(&row(None, None), &boot(1)),
            "a row that recorded neither says nothing"
        );
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
