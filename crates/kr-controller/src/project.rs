//! The environment's project service, hosted by the control daemon.
//!
//! The daemon owns the service's lifetime and its admission; `kr-project` owns the store, the
//! repositories, the workspaces and the restricted Git execution profile. What this module adds is
//! the part that has to be the daemon's.
//!
//! * Every project and workspace method arrives through the daemon's ordinary path. A read is
//!   checked against current authority before and after it runs; a mutation carries an action
//!   window, is checked against the method registry, and runs on a task that a dropped connection
//!   cannot cancel part way. Nothing here has a second admission path of its own.
//! * The admission is checked once more immediately before the write, because everything in
//!   between can wait: for this task to be scheduled, for a blocking thread, for the journal's
//!   lock. An action whose accepted deadline passed while it queued does not go on to write.
//! * The service's calls are synchronous and some of them are long: a clone reaches the network,
//!   and a materialisation copies files. They run on blocking tasks rather than on the daemon's
//!   reactor, and the task owns the work so only the reply is lost when a connection goes.
//!
//! A project refusal reaches the caller under the code the service decided, not a code this module
//! chose for it: `REPOSITORY_UNTRUSTED` for a remote or a configuration this host will not use,
//! `SOURCE_CHANGED` for a repository whose object is no longer the one its record names,
//! `RESOURCE_UNAVAILABLE` for a workspace a live session still holds, and so on.
//!
//! The daemon also gives the service the one thing it cannot know for itself: which sessions are
//! bound to a workspace and still live, which is what refuses a removal.

use std::sync::Arc;

use kr_project::ProjectService;
use kr_project::store::{Action, RetainedOutcome};
use kr_protocol::envelope::{
    ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActorId, RequestId};
use kr_protocol::method::{Method, MethodGroup};

use crate::error::{ControllerError, Result};

/// What a project call answers with: the method's result, or the refusal the service decided.
pub type Answer<T> = std::result::Result<T, ProtocolError>;

/// The project service, as the daemon holds it.
#[derive(Debug)]
pub struct ProjectModule {
    service: Arc<ProjectService>,
}

impl ProjectModule {
    /// Opens the environment's project service and resolves whatever an earlier daemon left
    /// unfinished.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store, the Git profile or the
    /// recovery cannot be prepared.
    pub async fn open(paths: &kr_ipc::paths::EnvironmentPaths) -> Result<Self> {
        // Opening the store migrates it, resolving Git reads the installed program, and recovery
        // examines directories. All three are blocking work, so they run on a blocking task rather
        // than on the daemon's reactor.
        let paths = paths.clone();
        let service = tokio::task::spawn_blocking(move || {
            let service = ProjectService::open(&paths)?;
            // A publication interrupted between its two commits is resolved before anything is
            // served, so a repository record never names an object this daemon has not found.
            service.recover()?;
            Ok::<_, kr_project::ProjectError>(service)
        })
        .await
        .map_err(|_| ControllerError::RegistryUnavailable {
            detail: "the project service could not be opened".to_owned(),
        })?
        .map_err(|error| ControllerError::RegistryUnavailable {
            detail: error.to_string(),
        })?;
        Ok(Self {
            service: Arc::new(service),
        })
    }

    /// Returns the service itself.
    #[must_use]
    pub const fn service(&self) -> &Arc<ProjectService> {
        &self.service
    }

    /// Returns true when this daemon serves the method.
    #[must_use]
    pub fn serves(method: Method) -> bool {
        matches!(
            method.group(),
            MethodGroup::ProjectRepositories | MethodGroup::Workspaces
        )
    }

    /// Checks that a project mutation's envelope and its parameters name the same subject.
    ///
    /// A project acts on neither a session nor a foreground application, so a target that names
    /// one is refused rather than producing a receipt against something the effect never touched.
    /// Where the parameters carry an environment, it has to be the one the target names.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when the two disagree.
    pub fn check_subject(method: Method, mutation: &MutationRequest) -> Result<()> {
        if mutation.target.session_id.is_present()
            || mutation.target.application_instance_id.is_present()
        {
            return Err(ControllerError::InvalidArgument(format!(
                "{} acts on a repository or a working copy, not on a session or an application",
                method.as_str()
            )));
        }
        let named = match method {
            Method::ProjectInit => {
                let params: kr_protocol::project::ProjectInitParams = parse(&mutation.params)?;
                Some(params.destination.environment_id)
            }
            Method::ProjectClone => {
                let params: kr_protocol::project::ProjectCloneParams = parse(&mutation.params)?;
                Some(params.destination.environment_id)
            }
            Method::ProjectAdopt => {
                let params: kr_protocol::project::ProjectAdoptParams = parse(&mutation.params)?;
                Some(params.destination.environment_id)
            }
            // The remaining mutations name a repository, a workspace or an operation, none of
            // which the envelope's target can carry. The environment is checked for every mutation
            // before this point, and the service checks the named object against its own record.
            Method::ProjectOperationCancel | Method::WorkspaceCreate | Method::WorkspaceRemove => {
                None
            }
            _ => {
                return Err(ControllerError::InvalidArgument(format!(
                    "{} is not a project mutation this daemon serves",
                    method.as_str()
                )));
            }
        };
        if let Some(named) = named
            && named != mutation.target.environment_id
        {
            return Err(ControllerError::InvalidArgument(
                "the request's target and its parameters name different environments".to_owned(),
            ));
        }
        Ok(())
    }

    /// Answers an action this service has already performed for this caller, if it has.
    ///
    /// This runs **before** the freshness window is considered, because a retry after a lost reply
    /// carries the window the action was first admitted under and this connection holds a newer
    /// one. Refusing it for that would deny a caller its own completed result, which is the one
    /// thing an action identifier exists to prevent.
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

    /// Serves one project read and returns the frame it answers with.
    #[must_use]
    pub async fn read_frame(&self, request: &Request) -> ControlFrame {
        frame(request.request_id, self.read(request).await)
    }

    /// Serves one project mutation and returns the frame it answers with.
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

    /// Serves one project read.
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
            Method::ProjectList => encode(&service.project_list(&typed(&params)?)?),
            Method::ProjectRead => encode(&service.project_read(&typed(&params)?)?),
            Method::WorkspaceList => encode(&service.workspace_list(&typed(&params)?)?),
            Method::WorkspaceRead => encode(&service.workspace_read(&typed(&params)?)?),
            _ => Err(ProtocolError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "{} is not a project read this daemon serves",
                    method.as_str()
                ),
            )),
        })
        .await
    }

    /// Serves one project mutation, answering an exact repeat from its retained record.
    ///
    /// The de-duplication key is the actor and the action together, and the payload digest decides
    /// whether a repeat is the same action or a reused identifier. That is what makes a lost reply
    /// to `project.clone` resolvable without cloning twice.
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
            // The action this mutation is performed under. Each of these methods commits it beside
            // the state it changes, which is what makes a second copy of one action find the claim
            // rather than starting a second clone.
            let performed = Action {
                actor_id: actor.clone(),
                action_id,
                method: name.to_owned(),
                payload_digest: digest,
            };
            // Every arm runs inside a closure, so a refusal the service decided reaches the
            // retention below instead of returning from the task. An action whose failure was not
            // retained could be performed again under the same identifier and succeed.
            let outcome = (|| -> Answer<ParamsValue> {
                match method {
                    Method::ProjectInit => {
                        encode(&service.project_init(&actor, &typed(&params)?, Some(&performed))?)
                    }
                    Method::ProjectClone => encode(&service.project_clone(
                        &actor,
                        &typed(&params)?,
                        Some(&performed),
                    )?),
                    Method::ProjectAdopt => encode(&service.project_adopt(
                        &actor,
                        &typed(&params)?,
                        Some(&performed),
                    )?),
                    Method::ProjectOperationCancel => {
                        encode(&service.project_operation_cancel(&actor, &typed(&params)?)?)
                    }
                    Method::WorkspaceCreate => encode(&service.workspace_create(
                        &actor,
                        &typed(&params)?,
                        Some(&performed),
                    )?),
                    Method::WorkspaceRemove => {
                        encode(&service.workspace_remove(&typed(&params)?, Some(&performed))?)
                    }
                    _ => Err(ProtocolError::new(
                        ErrorCode::InvalidArgument,
                        format!(
                            "{} is not a project mutation this daemon serves",
                            method.as_str()
                        ),
                    )),
                }
            })();
            // Recorded before it is returned, so the reply and the record cannot disagree about
            // what happened. The methods above recorded their own inside their transaction; this
            // insert leaves an existing row alone and covers the rest. When another copy of this
            // action recorded first, that record is the answer both callers get.
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
            match service.record_action(&actor, action_id, name, digest, &record)? {
                None => outcome,
                Some(RetainedOutcome::Ok(result)) => {
                    kr_cbor::decode(&result, &kr_cbor::Limits::DEFAULT)
                        .map(ParamsValue::new)
                        .map_err(|error| {
                            ProtocolError::new(ErrorCode::OutcomeUnknown, error.to_string())
                        })
                }
                Some(RetainedOutcome::Error { code, detail }) => {
                    Err(ProtocolError::new(code, detail))
                }
            }
        })
        .await
    }
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
            "the project service could not report what happened to this action",
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
    fn the_daemon_serves_the_project_and_workspace_groups() {
        for method in [
            Method::ProjectList,
            Method::ProjectRead,
            Method::ProjectInit,
            Method::ProjectClone,
            Method::ProjectAdopt,
            Method::ProjectOperationCancel,
            Method::WorkspaceList,
            Method::WorkspaceCreate,
            Method::WorkspaceRead,
            Method::WorkspaceRemove,
        ] {
            assert!(
                ProjectModule::serves(method),
                "{} belongs to this service",
                method.as_str()
            );
        }
        // A change set and a diff are their own services, and a plugin catalogue is not a source
        // repository at all.
        assert!(!ProjectModule::serves(Method::ChangesetCapture));
        assert!(!ProjectModule::serves(Method::DiffRead));
        assert!(!ProjectModule::serves(Method::CatalogueAdd));
        assert!(!ProjectModule::serves(Method::UploadBegin));
    }

    #[test]
    fn every_project_method_the_daemon_serves_is_reachable_from_a_local_caller() {
        use kr_protocol::actor::ActorIngress;
        use kr_protocol::authority::AuthorityDecision;

        for method in [
            Method::ProjectList,
            Method::ProjectRead,
            Method::ProjectInit,
            Method::ProjectClone,
            Method::ProjectAdopt,
            Method::ProjectOperationCancel,
            Method::WorkspaceList,
            Method::WorkspaceCreate,
            Method::WorkspaceRead,
            Method::WorkspaceRemove,
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
    fn a_catalogue_method_cannot_create_a_source_repository() {
        // Section 14 paragraph 1: `catalogue.*` is reserved for plugin repositories and cannot
        // create a source repository. The two are different method groups and this service serves
        // only one of them.
        for method in [
            Method::CatalogueList,
            Method::CatalogueAdd,
            Method::CatalogueSync,
        ] {
            assert!(!ProjectModule::serves(method));
            assert_ne!(method.group(), MethodGroup::ProjectRepositories);
            assert_ne!(method.group(), MethodGroup::Workspaces);
        }
    }
}
