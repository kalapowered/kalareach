//! The environment's change-set service, hosted by the control daemon.
//!
//! The daemon owns the service's lifetime and its admission; `kr-changeset` owns the versions,
//! their content, their materialisations and the applies. What this module adds is the part that
//! has to be the daemon's.
//!
//! * Every method of the "Changes and diffs" group arrives through the daemon's ordinary path. A
//!   read is checked against current authority; a mutation carries an action window, is checked
//!   against the method registry and its rights, and runs on a task that a dropped connection
//!   cannot cancel part way through.
//! * The admission is checked once more immediately before the write, because everything in
//!   between can wait: for this task to be scheduled, for a blocking thread, for a journal's lock.
//! * The service's calls are synchronous and some of them are long: a capture reads a whole
//!   working tree and a materialisation writes one out. They run on blocking tasks rather than on
//!   the daemon's reactor, and the task owns the work so only the reply is lost when a connection
//!   goes.
//!
//! A change-set refusal reaches the caller under the code the service decided, not one this module
//! chose for it: `DRAFT_CONFLICT` for a destination that is not what a request expects,
//! `SOURCE_CHANGED` for a working tree that kept changing under a capture, `OUTCOME_UNKNOWN` for
//! an apply this host could not finish, and the project service's own codes for a repository it
//! refused.
//!
//! **The action record is this service's own.** A repeat of an action is answered from the reply
//! the first attempt recorded, and that reply is read back through the rule that decides which of
//! its fields are this host's own explanations and which are values the caller asked for. Only the
//! service that produced a result knows that about it, so each service keeps its own record rather
//! than handing another one bytes it cannot read.

use std::sync::Arc;

use kr_changeset::ChangeSetService;
use kr_changeset::apply::{self, ApplyOrder};
use kr_changeset::materialise;
use kr_changeset::service::CaptureOrder;
use kr_changeset::store::RetainedOutcome;
use kr_project::ProjectService;
use kr_protocol::changeset::{
    ChangesetCaptureParams, ChangesetCaptureResult, ChangesetMaterializeParams,
    ChangesetMaterializeResult, ChangesetReadParams, ChangesetReadResult, DestinationClass,
    DiffApplyParams, DiffApplyResult, DiffReadParams, Provenance, VersionRef,
};
use kr_protocol::envelope::{
    ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, ActorId, RequestId};
use kr_protocol::method::{Method, MethodGroup};
use kr_protocol::scalars::Nullable;

use crate::error::{ControllerError, Result};

/// What a change-set call answers with: the method's result, or the refusal the service decided.
pub type Answer<T> = std::result::Result<T, ProtocolError>;

/// The change-set service, as the daemon holds it.
#[derive(Debug)]
pub struct ChangeSetModule {
    service: Arc<ChangeSetService>,
}

impl ChangeSetModule {
    /// Opens the environment's change-set service on top of its project service.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store or its directories cannot
    /// be prepared, or when recovery cannot run.
    pub async fn open(
        paths: &kr_ipc::paths::EnvironmentPaths,
        project: Arc<ProjectService>,
    ) -> Result<Self> {
        let paths = paths.clone();
        let service = tokio::task::spawn_blocking(move || {
            let service = ChangeSetService::open(&paths, project)?;
            // An apply an earlier daemon died inside is settled before anything is served, so a
            // caller never reads an apply that is open for ever.
            service.recover_before_serving()?;
            Ok::<_, kr_changeset::ChangeSetError>(service)
        })
        .await
        .map_err(|_| ControllerError::RegistryUnavailable {
            detail: "the change-set service could not be opened".to_owned(),
        })?
        .map_err(|error| ControllerError::RegistryUnavailable {
            // Printed on the daemon's own standard error at startup as well as answered with, and
            // it can name a state directory a caller chose, so it goes through the same rule every
            // other message from these services does.
            detail: kr_project::git::redact(&error.to_string()),
        })?;
        Ok(Self {
            service: Arc::new(service),
        })
    }

    /// Returns the service itself.
    #[must_use]
    pub const fn service(&self) -> &Arc<ChangeSetService> {
        &self.service
    }

    /// Returns true when this daemon serves the method.
    #[must_use]
    pub fn serves(method: Method) -> bool {
        method.group() == MethodGroup::ChangesAndDiffs
    }

    /// Checks that a change-set mutation's envelope and its parameters name the same subject.
    ///
    /// A change set acts on a repository's work rather than on a session or a foreground
    /// application, so a target that names one is refused rather than producing a receipt against
    /// something the effect never touched.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when the two disagree.
    pub fn check_subject(method: Method, mutation: &MutationRequest) -> Result<()> {
        if mutation.target.application_instance_id.is_present() {
            return Err(ControllerError::InvalidArgument(format!(
                "{} acts on a change set, not on an application",
                method.as_str()
            )));
        }
        match method {
            Method::ChangesetCapture => {
                let _: ChangesetCaptureParams = parse(&mutation.params)?;
            }
            Method::ChangesetMaterialize => {
                let _: ChangesetMaterializeParams = parse(&mutation.params)?;
            }
            Method::DiffApply | Method::DiffRevert => {
                let params: DiffApplyParams = parse(&mutation.params)?;
                if params.destination != DestinationClass::Proposal
                    && params.workspace_id.0.is_none()
                {
                    return Err(ControllerError::InvalidArgument(
                        "this destination class names the workspace it writes to".to_owned(),
                    ));
                }
            }
            _ => {
                return Err(ControllerError::InvalidArgument(format!(
                    "{} is not a change-set mutation this daemon serves",
                    method.as_str()
                )));
            }
        }
        Ok(())
    }

    /// Answers an action this service has already performed for this caller, if it has.
    ///
    /// This runs **before** the freshness window is considered, because a retry after a lost reply
    /// carries the window the action was first admitted under and this connection holds a newer
    /// one. Refusing it for that would deny a caller its own completed result.
    #[must_use]
    pub async fn retained(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
    ) -> Option<ControlFrame> {
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id).ok()?;
        let service = Arc::clone(&self.service);
        let actor = actor_id.clone();
        let action_id = mutation.action_id.get();
        let name = method.as_str();
        let outcome = blocking(move || {
            service
                .retained_action(&actor, action_id, name, digest)
                .map_err(ProtocolError::from)
        })
        .await;
        match outcome {
            // The blocking task itself failed, which says nothing about the action.
            Err(error) => Some(frame(mutation.request_id, Err(error))),
            Ok(None) => None,
            Ok(Some(RetainedOutcome::Ok(result))) => Some(frame(
                mutation.request_id,
                kr_cbor::decode(&result, &kr_cbor::Limits::DEFAULT)
                    .map(ParamsValue::new)
                    .map_err(|error| {
                        ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string())
                    }),
            )),
            Ok(Some(RetainedOutcome::Error { code, detail })) => Some(frame(
                mutation.request_id,
                Err(ProtocolError::new(code, detail)),
            )),
        }
    }

    /// Serves one change-set read and returns the frame it answers with.
    #[must_use]
    pub async fn read_frame(&self, request: &Request) -> ControlFrame {
        frame(request.request_id, self.read(request).await)
    }

    /// Serves one change-set mutation and returns the frame it answers with.
    #[must_use]
    pub async fn write_frame(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
    ) -> ControlFrame {
        frame(
            mutation.request_id,
            self.write(actor_id, mutation, method).await,
        )
    }

    /// Serves one change-set read.
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
        let service = Arc::clone(&self.service);
        let params = request.params.clone();
        blocking(move || match method {
            Method::ChangesetRead => {
                let params: ChangesetReadParams = typed(&params)?;
                encode(&read_change_set(&service, &params)?)
            }
            Method::DiffRead => {
                let params: DiffReadParams = typed(&params)?;
                let version = version_of(&params)?;
                encode(&apply::read(&service, params.workspace_id.0, version)?)
            }
            _ => Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "{} is not a change-set read this daemon serves",
                    method.as_str()
                ),
            )),
        })
        .await
    }

    /// Serves one change-set mutation, answering an exact repeat from its retained record.
    ///
    /// # Errors
    ///
    /// Returns the refusal the service decided, under the service's own code.
    pub async fn write(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
    ) -> Answer<ParamsValue> {
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id)
            .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))?;
        let service = Arc::clone(&self.service);
        let actor = actor_id.clone();
        let params = mutation.params.clone();
        let action_id = mutation.action_id.get();
        let name = method.as_str();
        blocking(move || {
            if let Some(retained) = service.retained_action(&actor, action_id, name, digest)? {
                return match retained {
                    RetainedOutcome::Ok(result) => {
                        kr_cbor::decode(&result, &kr_cbor::Limits::DEFAULT)
                            .map(ParamsValue::new)
                            .map_err(|error| {
                                ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string())
                            })
                    }
                    RetainedOutcome::Error { code, detail } => {
                        Err(ProtocolError::new(code, detail))
                    }
                };
            }
            // The claim is taken before the effect. Two copies of one action that both found no
            // record would otherwise both capture, both materialise or both write a working tree,
            // and returning one reply to both would not undo the second effect.
            //
            // An apply takes it one moment later, through the deferred claim below. Section 14
            // says a preflight conflict returns `DRAFT_CONFLICT` **without KR writes**, and a
            // claim row written before the preflight is a KR write that a crash would leave
            // behind for the next attempt to find. So the preflight runs first, reading only, and
            // the claim is taken the instant it passes and before anything is written. A capture
            // and a materialisation have no such reading phase and claim straight away.
            let deferred = DeferredClaim::new(&service, &actor, action_id, name, digest);
            if !matches!(method, Method::DiffApply | Method::DiffRevert)
                && !service.claim_action(&actor, action_id, name, digest)?
            {
                // Another copy holds it. Either it has settled, in which case its reply is the
                // answer, or it has not, in which case this host cannot say what became of the
                // action and says exactly that.
                return answer_from_retained(&service, &actor, action_id, name, digest);
            }
            // Every arm runs inside a closure, so a refusal the service decided reaches the
            // settlement below instead of returning from the task. An action whose failure was not
            // recorded could be performed again under the same identifier and succeed.
            let outcome = (|| -> Answer<ParamsValue> {
                match method {
                    Method::ChangesetCapture => {
                        encode(&capture(&service, &actor, &typed(&params)?)?)
                    }
                    Method::ChangesetMaterialize => {
                        encode(&materialise_version(&service, &typed(&params)?)?)
                    }
                    Method::DiffApply | Method::DiffRevert => encode(&run_apply(
                        &service,
                        &actor,
                        ActionId::new(action_id),
                        &typed(&params)?,
                        method == Method::DiffRevert,
                        Some(&deferred),
                    )?),
                    _ => Err(ProtocolError::new(
                        ErrorCode::InvalidArgument,
                        format!(
                            "{} is not a change-set mutation this daemon serves",
                            method.as_str()
                        ),
                    )),
                }
            })();
            // The claim went to another copy of this action. That copy is the one that acts, and
            // this one answers from its reply rather than recording a second outcome over it.
            if deferred.lost() {
                return answer_from_retained(&service, &actor, action_id, name, digest);
            }
            // An apply that refused before its claim wrote nothing at all, and there is nothing to
            // settle or to give back: the action is untouched and the caller can ask again with
            // what it now knows is there. That is every `DRAFT_CONFLICT` an apply returns.
            if matches!(method, Method::DiffApply | Method::DiffRevert) && !deferred.taken() {
                return outcome;
            }
            let record = match &outcome {
                Ok(value) => {
                    RetainedOutcome::Ok(kr_cbor::to_canonical_vec(value).map_err(|error| {
                        ProtocolError::new(ErrorCode::InvalidArgument, error.to_string())
                    })?)
                }
                Err(error) => RetainedOutcome::Error {
                    code: error.code,
                    detail: error.message.clone(),
                },
            };
            // Recorded before it is returned, so the reply and the record cannot disagree about
            // what happened.
            service.settle_action(&actor, action_id, name, digest, &record)?;
            outcome
        })
        .await
    }
}

/// Reads one change set: the version asked for, every version of it, and everything that names it.
fn read_change_set(
    service: &ChangeSetService,
    params: &ChangesetReadParams,
) -> kr_changeset::Result<ChangesetReadResult> {
    let version = service.record(params.change_set_id, params.version.0)?;
    let named = VersionRef {
        change_set_id: version.change_set_id,
        version: version.version,
    };
    Ok(ChangesetReadResult {
        versions: service.versions(params.change_set_id)?,
        materialisations: materialise::every(service, named.change_set_id, named.version)?,
        results: materialise::results(service, named.change_set_id, named.version)?,
        evidence: service.evidence(named.change_set_id, named.version)?,
        version,
    })
}

/// Returns the version a diff read names, when it names one.
fn version_of(params: &DiffReadParams) -> Answer<Option<VersionRef>> {
    match (params.change_set_id.0, params.version.0) {
        (None, None) => Ok(None),
        (Some(change_set_id), Some(version)) => Ok(Some(VersionRef {
            change_set_id,
            version,
        })),
        (Some(_), None) => Err(ProtocolError::new(
            ErrorCode::InvalidArgument,
            "a diff read of a change set names the exact version it reads",
        )),
        (None, Some(_)) => Err(ProtocolError::new(
            ErrorCode::InvalidArgument,
            "a version number names no change set on its own",
        )),
    }
}

/// Captures one version.
fn capture(
    service: &ChangeSetService,
    actor_id: &ActorId,
    params: &ChangesetCaptureParams,
) -> kr_changeset::Result<ChangesetCaptureResult> {
    let order = CaptureOrder {
        workspace_id: params.workspace_id,
        change_set_id: params.change_set_id.0,
        label: &params.label,
        request: kr_changeset::capture::CaptureRequest {
            policy: &params.policy,
            grant: &params.grant,
            quiescence_declared: params.quiescence_declared,
            required_consistency: params.required_consistency.0,
        },
        pin: params.pin,
        provenance: Provenance {
            actor_id: actor_id.clone(),
            method: "changeset.capture".to_owned(),
            session_id: params.session_id,
            workflow_run_id: params.workflow_run_id,
            derived_from: Nullable(None),
            derivation: String::new(),
            note: params.note.clone(),
        },
    };
    let (version, pinned) = service.capture(&order)?;
    Ok(ChangesetCaptureResult { version, pinned })
}

/// Materialises one exact version into a private directory.
fn materialise_version(
    service: &ChangeSetService,
    params: &ChangesetMaterializeParams,
) -> kr_changeset::Result<ChangesetMaterializeResult> {
    let materialisation = materialise::materialise(
        service,
        VersionRef {
            change_set_id: params.change_set_id,
            version: params.version,
        },
        params.purpose,
        &params.label,
    )?;
    Ok(ChangesetMaterializeResult {
        materialisation,
        limitations: materialise::limitations(),
    })
}

/// One action's claim, taken the instant the apply's preflight has passed.
///
/// It remembers what became of it, because the two outcomes the caller has to tell apart are
/// "nothing was claimed, so nothing was written" and "another copy holds this action".
struct DeferredClaim<'a> {
    service: &'a ChangeSetService,
    actor: &'a ActorId,
    action_id: kr_protocol::scalars::Uuid,
    method: &'a str,
    digest: kr_protocol::scalars::Digest256,
    state: std::cell::Cell<ClaimState>,
}

/// What became of a deferred claim.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ClaimState {
    /// It was never asked for: the work refused before it reached the moment it is taken.
    Untried,
    /// This copy of the action holds it.
    Taken,
    /// Another copy of the action holds it.
    Lost,
}

impl<'a> DeferredClaim<'a> {
    fn new(
        service: &'a ChangeSetService,
        actor: &'a ActorId,
        action_id: kr_protocol::scalars::Uuid,
        method: &'a str,
        digest: kr_protocol::scalars::Digest256,
    ) -> Self {
        Self {
            service,
            actor,
            action_id,
            method,
            digest,
            state: std::cell::Cell::new(ClaimState::Untried),
        }
    }

    fn taken(&self) -> bool {
        self.state.get() == ClaimState::Taken
    }

    fn lost(&self) -> bool {
        self.state.get() == ClaimState::Lost
    }
}

impl kr_changeset::apply::ActionClaim for DeferredClaim<'_> {
    fn claim(&self) -> kr_changeset::Result<bool> {
        let held =
            self.service
                .claim_action(self.actor, self.action_id, self.method, self.digest)?;
        self.state.set(if held {
            ClaimState::Taken
        } else {
            ClaimState::Lost
        });
        Ok(held)
    }
}

/// Answers from the record another copy of this action left, or says nothing is known yet.
fn answer_from_retained(
    service: &ChangeSetService,
    actor: &ActorId,
    action_id: kr_protocol::scalars::Uuid,
    method: &str,
    digest: kr_protocol::scalars::Digest256,
) -> Answer<ParamsValue> {
    match service.retained_action(actor, action_id, method, digest)? {
        Some(RetainedOutcome::Ok(result)) => kr_cbor::decode(&result, &kr_cbor::Limits::DEFAULT)
            .map(ParamsValue::new)
            .map_err(|error| ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string())),
        Some(RetainedOutcome::Error { code, detail }) => Err(ProtocolError::new(code, detail)),
        None => Err(ProtocolError::new(
            ErrorCode::OutcomeUnknown,
            "another copy of this action is running and has not said what it came to",
        )),
    }
}

/// Applies or reverts one version at one destination.
fn run_apply(
    service: &ChangeSetService,
    actor_id: &ActorId,
    action_id: ActionId,
    params: &DiffApplyParams,
    revert: bool,
    claim: Option<&dyn kr_changeset::apply::ActionClaim>,
) -> kr_changeset::Result<DiffApplyResult> {
    let order = ApplyOrder {
        action_id,
        version: VersionRef {
            change_set_id: params.change_set_id,
            version: params.version,
        },
        destination: params.destination,
        workspace_id: params.workspace_id.0,
        expected_reference: params.expected_reference.0.as_ref(),
        affected: &params.affected,
        paths: &params.paths,
        preflight_only: params.preflight_only,
        acknowledged_limitations: &params.acknowledged_limitations,
        revert,
        provenance: Provenance {
            actor_id: actor_id.clone(),
            method: if revert { "diff.revert" } else { "diff.apply" }.to_owned(),
            session_id: Nullable(None),
            workflow_run_id: Nullable(None),
            derived_from: Nullable(None),
            derivation: String::new(),
            note: String::new(),
        },
        claim,
    };
    apply::apply(service, &order)
}

/// Runs one synchronous service call on a blocking task.
///
/// A dropped connection cannot cancel it: the task owns the work, and only the reply is lost.
async fn blocking<T, F>(work: F) -> Answer<T>
where
    T: Send + 'static,
    F: FnOnce() -> Answer<T> + Send + 'static,
{
    tokio::task::spawn_blocking(work).await.unwrap_or_else(|_| {
        Err(ProtocolError::new(
            ErrorCode::OutcomeUnknown,
            "the change-set service could not report what happened to this action",
        ))
    })
}

fn frame(request_id: RequestId, outcome: Answer<ParamsValue>) -> ControlFrame {
    ControlFrame::Response(Response {
        request_id,
        outcome: match outcome {
            Ok(value) => Outcome::Ok(value),
            Err(error) => Outcome::Error(error),
        },
    })
}

fn parse<T: serde::de::DeserializeOwned + serde::Serialize>(params: &ParamsValue) -> Result<T> {
    params.to_typed().map_err(|error| {
        ControllerError::InvalidArgument(kr_project::git::redact(&error.to_string()))
    })
}

fn typed<T: serde::de::DeserializeOwned + serde::Serialize>(params: &ParamsValue) -> Answer<T> {
    params.to_typed().map_err(|error| {
        // A decoding refusal quotes what it could not decode, which is whatever the request
        // carried, so it goes through the project service's own rule before it is answered with.
        ProtocolError::new(
            ErrorCode::InvalidArgument,
            kr_project::git::redact(&error.to_string()),
        )
    })
}

fn encode<T: serde::Serialize>(value: &T) -> Answer<ParamsValue> {
    ParamsValue::from_typed(value)
        .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_daemon_serves_the_whole_changes_and_diffs_group() {
        for method in [
            Method::DiffRead,
            Method::DiffApply,
            Method::DiffRevert,
            Method::ChangesetCapture,
            Method::ChangesetRead,
            Method::ChangesetMaterialize,
        ] {
            assert!(
                ChangeSetModule::serves(method),
                "{} belongs to this service",
                method.as_str()
            );
        }
        // A repository, a workspace and a plugin catalogue are other services'.
        assert!(!ChangeSetModule::serves(Method::ProjectInit));
        assert!(!ChangeSetModule::serves(Method::WorkspaceCreate));
        assert!(!ChangeSetModule::serves(Method::CatalogueAdd));
        assert!(!ChangeSetModule::serves(Method::UploadBegin));
    }

    #[test]
    fn every_method_of_the_group_carries_the_right_the_specification_names() {
        use kr_protocol::rights::ActionRight;

        // Section 23's method-group row: `files.read` for content, `files.apply_diff` for apply
        // and revert, `changeset.create` for capture and `workspace.manage` for materialisation.
        for (method, right) in [
            (Method::DiffRead, ActionRight::FilesRead),
            (Method::DiffApply, ActionRight::FilesApplyDiff),
            (Method::DiffRevert, ActionRight::FilesApplyDiff),
            (Method::ChangesetCapture, ActionRight::ChangesetCreate),
            (Method::ChangesetRead, ActionRight::FilesRead),
            (Method::ChangesetMaterialize, ActionRight::WorkspaceManage),
        ] {
            let entry = method.entry();
            assert!(
                entry.required_rights.iter().any(|required| matches!(
                    required.authority,
                    kr_protocol::authority::RequiredAuthority::Right { right: held }
                        if held == right
                )),
                "{} requires {}",
                method.as_str(),
                right.as_str()
            );
        }
    }

    #[test]
    fn every_method_of_the_group_is_reachable_from_a_local_caller() {
        use kr_protocol::actor::ActorIngress;
        use kr_protocol::authority::AuthorityDecision;

        for method in [
            Method::DiffRead,
            Method::DiffApply,
            Method::DiffRevert,
            Method::ChangesetCapture,
            Method::ChangesetRead,
            Method::ChangesetMaterialize,
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

    #[test]
    fn a_read_of_a_change_set_names_the_exact_version_it_reads() {
        // A change set with no version is the latest; a version with no change set names nothing.
        let change_set_id = kr_protocol::ids::ChangeSetId::new(kr_ipc::new_uuid());
        let version = kr_protocol::ids::ChangeSetVersion::new(3);
        assert_eq!(
            version_of(&DiffReadParams {
                workspace_id: Nullable(None),
                change_set_id: Nullable(Some(change_set_id)),
                version: Nullable(Some(version)),
            })
            .expect("a complete reference"),
            Some(VersionRef {
                change_set_id,
                version
            })
        );
        assert!(
            version_of(&DiffReadParams {
                workspace_id: Nullable(None),
                change_set_id: Nullable(Some(change_set_id)),
                version: Nullable(None),
            })
            .is_err()
        );
        assert!(
            version_of(&DiffReadParams {
                workspace_id: Nullable(None),
                change_set_id: Nullable(None),
                version: Nullable(Some(version)),
            })
            .is_err()
        );
    }
}
