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

use std::sync::{Arc, Weak};

use kr_automation::{
    ActionKey, ActionOutcome, ActionRunner, Answer as Recorded, AuthoritySource, AutomationService,
    Dispatch, Host, Submitted, SystemClock, WorkflowStore,
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
struct Daemon(std::sync::OnceLock<Weak<Controller>>);

impl Daemon {
    /// The daemon, while it is serving.
    fn get(&self) -> kr_automation::Result<Arc<Controller>> {
        self.0.get().and_then(Weak::upgrade).ok_or_else(|| {
            kr_automation::AutomationError::AuthorityUnavailable(
                "this host's daemon is not serving".to_owned(),
            )
        })
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
        let bound = Daemon::default();
        let _ = bound.0.set(Arc::downgrade(daemon));
        Self {
            daemon: Arc::new(bound),
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
/// The two change-set kinds are real: they reach the environment's change-set service, and the
/// version each one produces records the run that asked for it, so the evidence a later node reads
/// is bound to the execution that made it rather than to a claim about it. The node's grant is
/// held in force around every transaction that commits the effect ([`HeldGrant`]), the way a
/// caller's admission is held around a change-set method's own.
///
/// Every other registered kind is refused by name. A refusal is not an uncertain outcome: nothing
/// was dispatched, so the node failed and its dependants see a failure rather than a result
/// nobody produced.
pub struct HostActions {
    changesets: Arc<ChangeSetService>,
    authority: Arc<dyn AuthoritySource>,
    daemon: Arc<Daemon>,
    environment_id: EnvironmentId,
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
            .grant(self.definition.grant_reference, kr_ipc::now_ms().get())?;
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
    // materialised is only ever a version whose scope was checked here.
    let version = changesets
        .record(asked.change_set_id, Some(asked.version))
        .map_err(|error| {
            kr_automation::AutomationError::PermissionDenied(format!(
                "change set {} version {} could not be checked against workflow {}'s scope: {}",
                asked.change_set_id,
                asked.version,
                definition.workflow_id,
                kr_project::git::redact(&error.to_string())
            ))
        })?;
    if version.environment_id != environment_id {
        return Err(kr_automation::AutomationError::PermissionDenied(format!(
            "change set {} version {} was captured in environment {}, and this host acts in {}",
            asked.change_set_id, asked.version, version.environment_id, environment_id
        )));
    }
    if let Some(declared) = definition.resource_scope.workspace_id.0
        && version.workspace_id != declared
    {
        return Err(kr_automation::AutomationError::PermissionDenied(format!(
            "change set {} version {} was captured from workspace {}, and workflow {} is scoped \
             to workspace {declared}",
            asked.change_set_id, asked.version, version.workspace_id, definition.workflow_id
        )));
    }
    Ok(())
}

/// Captures one version of a workspace, recorded as this run's work, under the node's held grant.
fn capture(
    changesets: &ChangeSetService,
    asked: &ChangesetCaptureParams,
    run_id: kr_protocol::ids::WorkflowRunId,
    held: &HeldGrant,
) -> kr_automation::Result<ActionOutcome> {
    let order = CaptureOrder {
        workspace_id: asked.workspace_id,
        change_set_id: asked.change_set_id.0,
        label: &asked.label,
        request: kr_changeset::capture::CaptureRequest {
            policy: &asked.policy,
            grant: &asked.grant,
            quiescence_declared: asked.quiescence_declared,
            required_consistency: asked.required_consistency.0,
            // No workflow offers a quiescence reservation, so a capture here is never a quiesced
            // one; a declaration is recorded beside the class the service decides.
            quiescence: None,
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

/// How long the trigger dispatcher waits before it looks again for triggers a wake-up missed.
const DISPATCH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

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
    /// The runs recovery resumed, held until execution starts.
    resumed: std::sync::Mutex<Option<Vec<kr_automation::StartedRun>>>,
    /// The trigger dispatcher, once execution has started.
    dispatcher: std::sync::OnceLock<tokio::task::JoinHandle<()>>,
}

impl Drop for AutomationModule {
    fn drop(&mut self) {
        if let Some(dispatcher) = self.dispatcher.get() {
            dispatcher.abort();
        }
    }
}

/// Runs the trigger dispatcher for as long as the daemon holds the service.
///
/// It first executes the runs a stopped daemon left unfinished, which the module recovered when it
/// was opened, and then starts the runs the journal's settled-node events trigger,
/// whenever a run stops and on a timer for anything that did not wake it. Each run executes on a task of its own, so one long run does not hold the rest
/// of a chain back. Every decision is the journal's: the dispatcher's own position commits with the
/// runs it starts, so a daemon that stops in the middle neither loses a trigger nor starts one twice.
async fn dispatch(service: Arc<AutomationService>, resumed: Vec<kr_automation::StartedRun>) {
    for run in resumed {
        execute_apart(&service, run);
    }
    let woken = service.events();
    loop {
        let admitted = {
            let service = Arc::clone(&service);
            blocking(move || service.admit_triggers(kr_ipc::now_ms().get())).await
        };
        // Every run the pass committed is executed, including those committed before a later
        // event stopped it: each is in the journal already, and nothing else would start it
        // before the next restart.
        for run in admitted.started {
            execute_apart(&service, run);
        }
        if let Some(error) = admitted.stopped {
            eprintln!(
                "kr-controller: the workflow trigger dispatcher stopped before its last trigger: \
                 {error}"
            );
        }
        // The events every consumer that reads them has passed are no longer owed. Removing them
        // is housekeeping: a failure here leaves them in the stream and changes no decision.
        let pruned = {
            let service = Arc::clone(&service);
            blocking(move || service.store().prune()).await
        };
        if let Err(error) = pruned {
            eprintln!("kr-controller: the workflow journal kept events it no longer owes: {error}");
        }
        tokio::select! {
            () = woken.notified() => {}
            () = tokio::time::sleep(DISPATCH_INTERVAL) => {}
        }
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
        let host = Host {
            environment_id,
            runner: Arc::new(HostActions {
                changesets,
                authority: Arc::clone(&grants),
                daemon: Arc::clone(&daemon),
                environment_id,
            }),
            authority: grants,
            clock: Arc::new(SystemClock),
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
        // single request. Recovering later would race a run a caller started in the meantime,
        // which recovery would take for an interrupted one.
        let resumed = {
            let service = Arc::clone(&service);
            blocking(move || service.recover(kr_ipc::now_ms().get()))
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
            resumed: std::sync::Mutex::new(Some(resumed)),
            dispatcher: std::sync::OnceLock::new(),
        })
    }

    /// Binds this module to the daemon that owns it.
    ///
    /// From here on every grant a workflow names is decided under that daemon's own model and
    /// every change-set write a node makes is held under its registry. The daemon binds the module
    /// as it is built, before it serves anything; binding again changes nothing.
    pub fn bind(&self, daemon: Weak<Controller>) {
        let _ = self.daemon.0.set(daemon);
    }

    /// Starts executing: the runs recovery resumed, then the runs derived triggers ask for.
    ///
    /// The daemon calls this last in its start, once every gate the start has is behind it: the
    /// configuration it puts into force first, whose withdrawal of authority may owe a fence that
    /// has to be up before anything is dispatched. A start that fails before this point has
    /// executed nothing a stopped daemon left behind. Calling it again starts nothing further.
    pub fn start(&self) {
        self.dispatcher.get_or_init(|| {
            let resumed = self
                .resumed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .unwrap_or_default();
            tokio::spawn(dispatch(Arc::clone(&self.service), resumed))
        });
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
        let now_ms = kr_ipc::now_ms().get();
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
        let now_ms = kr_ipc::now_ms().get();
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
