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
//! * The admission is checked once more immediately before the write, because everything in
//!   between can wait: for this task to be scheduled, for a blocking thread, for a journal's lock.
//! * **The grant a definition names is this host's own.** The engine never sees a grant a request
//!   carried. It asks [`HostGrants`], which reads the daemon's grant store, so an expiry, a
//!   revocation or a revoked ancestor decides what a workflow may do, and it decides that again
//!   before every node the run dispatches.
//! * **An action is a real effect or it is a refusal.** [`HostActions`] carries out the change-set
//!   nodes against the environment's own change-set service, binding each result to the run that
//!   asked for it. Every other action kind is refused by name. Nothing here writes a success
//!   receipt for work that was never done.
//!
//! The journal lives in the environment's state directory beside the registry, because section 24
//! requires a causal budget to survive a restart and a reboot, and a runtime directory does not
//! survive a reboot on every platform this host runs on.

use std::sync::Arc;

use kr_automation::{
    ActionKey, ActionOutcome, ActionRunner, Answer as Recorded, AuthoritySource, AutomationService,
    Dispatch, Submitted, WorkflowStore,
};
use kr_changeset::ChangeSetService;
use kr_changeset::materialise;
use kr_changeset::service::CaptureOrder;
use kr_protocol::automation::{
    WorkflowEnableParams, WorkflowInstallParams, WorkflowPauseParams, WorkflowReadParams,
    WorkflowRunParams,
};
use kr_protocol::changeset::{ChangesetCaptureParams, ChangesetMaterializeParams, Provenance};
use kr_protocol::envelope::{
    ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::grant::Grant;
use kr_protocol::ids::{ActorId, GrantId, RequestId};
use kr_protocol::method::{Method, MethodGroup};
use kr_protocol::scalars::Nullable;
use kr_protocol::sharing::GrantState;

use crate::error::{ControllerError, Result};
use crate::sharing::SharingService;

/// What an automation call answers with: the method's result, or the refusal the service decided.
pub type Answer<T> = std::result::Result<T, ProtocolError>;

/// This host's grants, as the automation engine reads them.
///
/// A definition names a grant identifier and nothing more. Whether that grant still authorises
/// anything is the grant store's to say: it holds the expiry, the revocation and the cascade a
/// revoked ancestor causes. Asking it here, rather than trusting a grant a request carried, is
/// what stops a workflow from acting under authority nobody holds.
#[derive(Debug)]
pub struct HostGrants {
    sharing: Arc<SharingService>,
}

impl HostGrants {
    /// Reads grants from the daemon's own store.
    #[must_use]
    pub const fn new(sharing: Arc<SharingService>) -> Self {
        Self { sharing }
    }
}

impl AuthoritySource for HostGrants {
    fn grant(&self, grant_id: GrantId, now_ms: u64) -> kr_automation::Result<Grant> {
        let record = self
            .sharing
            .grants()
            .record(grant_id)
            .map_err(|error| {
                kr_automation::AutomationError::AuthorityUnavailable(error.to_string())
            })?
            .ok_or_else(|| {
                kr_automation::AutomationError::PermissionDenied(format!(
                    "grant {grant_id} is not one this host issued"
                ))
            })?;
        match record.state(now_ms) {
            GrantState::Active => Ok(record.grant),
            GrantState::Revoked => Err(kr_automation::AutomationError::PermissionDenied(format!(
                "grant {grant_id} has been revoked"
            ))),
            GrantState::Expired => Err(kr_automation::AutomationError::PermissionDenied(format!(
                "grant {grant_id} has expired"
            ))),
            GrantState::Pending => Err(kr_automation::AutomationError::PermissionDenied(format!(
                "grant {grant_id} has not been redeemed"
            ))),
        }
    }
}

/// The actions this host carries out for a workflow node.
///
/// The two change-set kinds are real: they reach the environment's change-set service, and the
/// version each one produces records the run that asked for it, so the evidence a later node reads
/// is bound to the execution that made it rather than to a claim about it.
///
/// Every other registered kind is refused by name. A refusal is not an uncertain outcome: nothing
/// was dispatched, so the node failed and its dependants see a failure rather than a result
/// nobody produced.
pub struct HostActions {
    changesets: Arc<ChangeSetService>,
}

impl std::fmt::Debug for HostActions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostActions")
            .finish_non_exhaustive()
    }
}

impl HostActions {
    /// Carries out change-set nodes against `changesets`.
    #[must_use]
    pub const fn new(changesets: Arc<ChangeSetService>) -> Self {
        Self { changesets }
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
        let action_kind = dispatch.node.action_kind.clone();
        let params = dispatch.node.action_params.clone();
        let run_id = dispatch.run_id;
        Box::pin(async move {
            match action_kind.as_str() {
                "capture_changeset" => {
                    let asked: ChangesetCaptureParams = serde_json::from_str(&params)?;
                    Ok(blocking(move || capture(&changesets, &asked, run_id)).await)
                }
                "materialize_changeset" => {
                    let asked: ChangesetMaterializeParams = serde_json::from_str(&params)?;
                    Ok(blocking(move || materialise_version(&changesets, &asked)).await)
                }
                other => Err(kr_automation::AutomationError::ActionUnavailable {
                    action_kind: other.to_owned(),
                }),
            }
        })
    }
}

/// Captures one version of a workspace, recorded as this run's work.
fn capture(
    changesets: &ChangeSetService,
    asked: &ChangesetCaptureParams,
    run_id: kr_protocol::ids::WorkflowRunId,
) -> ActionOutcome {
    let order = CaptureOrder {
        workspace_id: asked.workspace_id,
        change_set_id: asked.change_set_id.0,
        label: &asked.label,
        request: kr_changeset::capture::CaptureRequest {
            policy: &asked.policy,
            grant: &asked.grant,
            quiescence_declared: asked.quiescence_declared,
            required_consistency: asked.required_consistency.0,
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
    };
    match changesets.capture(&order) {
        Ok((version, _pinned)) => ActionOutcome::Success {
            output: format!(
                "captured change set {} version {}",
                version.change_set_id, version.version
            ),
        },
        Err(error) => ActionOutcome::Failed {
            error: kr_project::git::redact(&error.to_string()),
        },
    }
}

/// Materialises one exact immutable version into a private directory.
fn materialise_version(
    changesets: &ChangeSetService,
    asked: &ChangesetMaterializeParams,
) -> ActionOutcome {
    let named = kr_protocol::changeset::VersionRef {
        change_set_id: asked.change_set_id,
        version: asked.version,
    };
    match materialise::materialise(changesets, named, asked.purpose, &asked.label) {
        // A materialisation that could not write every path the version holds is not the version.
        // A later node reading it on a success edge would be reading something else, so a partial
        // result fails and names how much is missing.
        Ok(record) if !record.unapplied.is_empty() => ActionOutcome::Failed {
            error: format!(
                "materialisation {} of change set {} version {} left {} of its paths unwritten",
                record.materialisation_id,
                named.change_set_id,
                named.version,
                record.unapplied.len()
            ),
        },
        Ok(record) => ActionOutcome::Success {
            output: format!(
                "materialised change set {} version {} as {}",
                named.change_set_id, named.version, record.materialisation_id
            ),
        },
        Err(error) => ActionOutcome::Failed {
            error: kr_project::git::redact(&error.to_string()),
        },
    }
}

/// The automation service, as the daemon holds it.
#[derive(Debug)]
pub struct AutomationModule {
    service: Arc<AutomationService>,
}

impl AutomationModule {
    /// Opens the environment's automation service on its own journal.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the journal cannot be opened.
    pub async fn open(
        paths: &kr_ipc::paths::EnvironmentPaths,
        sharing: Arc<SharingService>,
        changesets: Arc<ChangeSetService>,
    ) -> Result<Self> {
        // The state directory, not the runtime one: a causal budget has to survive a reboot, and
        // a runtime directory is cleared by one.
        let state_dir = paths.state_dir().to_path_buf();
        let service = tokio::task::spawn_blocking(move || {
            AutomationService::open(
                &state_dir,
                Arc::new(HostActions::new(changesets)),
                Arc::new(HostGrants::new(sharing)),
            )
        })
        .await
        .map_err(|_| ControllerError::RegistryUnavailable {
            detail: "the automation journal could not be opened".to_owned(),
        })?
        .map_err(|error| ControllerError::RegistryUnavailable {
            detail: kr_project::git::redact(&error.to_string()),
        })?;
        Ok(Self {
            service: Arc::new(service),
        })
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
    #[must_use]
    pub async fn read_frame(&self, request: &Request) -> ControlFrame {
        frame(request.request_id, self.read(request).await)
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
    pub async fn read(&self, request: &Request) -> Answer<ParamsValue> {
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
            encode(&service.read(&asked, now_ms)?)
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
    /// # Errors
    ///
    /// Returns the refusal the service decided, under the service's own code.
    pub async fn write(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        admission: Admission,
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
                };
                encode(&service.run(&asked, &submitted, now_ms).await?)
            }
            Method::WorkflowInstall => {
                blocking(move || {
                    let asked: WorkflowInstallParams = typed(&params)?;
                    let submitted = Submitted {
                        key: &key,
                        admission: &still_admitted,
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

fn parse<T: serde::de::DeserializeOwned + serde::Serialize>(params: &ParamsValue) -> Result<T> {
    params
        .to_typed()
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
}

fn typed<T: serde::de::DeserializeOwned + serde::Serialize>(params: &ParamsValue) -> Answer<T> {
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
