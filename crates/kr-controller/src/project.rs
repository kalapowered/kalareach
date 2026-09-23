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
//!
//! And it lends the service this host's owner. Authorising a location and binding a repository to
//! one enlarge what this host will do, so the owner confirms each through the ceremony this host
//! already runs for its other sensitive actions: a challenge bound to the exact digest, the rights,
//! this host and a short expiry, answered under the enrolled owner signer and spent once. A host
//! with no enrolled owner confirms nothing and authorises nothing.

use std::sync::{Arc, Mutex, OnceLock};

use kr_pairing::confirm::{ConfirmationExpectation, ConfirmationLedger, HostEnrolment};
use kr_pairing::platform::PairingClock;
use kr_project::ProjectService;
use kr_project::policy::{Enlargement, OwnerAuthority};
use kr_project::store::{Action, RetainedOutcome};
use kr_protocol::envelope::{
    ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActorId, DeviceId, GrantId, RequestId};
use kr_protocol::method::{Method, MethodGroup};
use kr_protocol::pairing::{OwnerConfirmationProof, OwnerConfirmationRequest, SensitiveAction};
use kr_protocol::scalars::{AuthorisationKey, EndpointKey};

use crate::error::{ControllerError, Result};

/// What a project call answers with: the method's result, or the refusal the service decided.
pub type Answer<T> = std::result::Result<T, ProtocolError>;

/// The project service, as the daemon holds it.
#[derive(Debug)]
pub struct ProjectModule {
    service: Arc<ProjectService>,
    /// This host's owner, once one is enrolled.
    owner: OnceLock<Arc<HostOwner>>,
}

/// How often expired owner challenges are let go, with the directories they held open.
///
/// A challenge lives as long as the ledger's own deadline, two minutes. Sweeping twice a minute
/// means a challenge nobody answers holds its directory for at most half a minute beyond that.
const CHALLENGE_SWEEP: std::time::Duration = std::time::Duration::from_secs(30);

/// This host's owner, as the project service's location decisions reach it.
///
/// The challenge is issued, verified and spent here, against this host's own ledger, identity and
/// enrolled signer. A challenge the caller made up, one issued for another digest, another set of
/// rights or another host, one that has run out and one already spent are all refused before the
/// service acts.
pub struct HostOwner {
    host_device_id: DeviceId,
    host_endpoint_id: EndpointKey,
    signer: AuthorisationKey,
    enrolment: HostEnrolment,
    clock: Arc<dyn PairingClock + Send + Sync>,
    ledger: Mutex<ConfirmationLedger>,
}

impl std::fmt::Debug for HostOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostOwner")
            .field("host_device_id", &self.host_device_id)
            .field("enrolment", &self.enrolment)
            .finish_non_exhaustive()
    }
}

impl HostOwner {
    /// Builds the owner a network registration enrolled.
    #[must_use]
    pub fn new(
        host_device_id: DeviceId,
        host_endpoint_id: EndpointKey,
        signer: AuthorisationKey,
        enrolment: HostEnrolment,
        clock: Arc<dyn PairingClock + Send + Sync>,
    ) -> Self {
        Self {
            host_device_id,
            host_endpoint_id,
            signer,
            enrolment,
            clock,
            ledger: Mutex::new(ConfirmationLedger::new()),
        }
    }

    fn ledger(&self) -> std::sync::MutexGuard<'_, ConfirmationLedger> {
        self.ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// What a challenge for this enlargement has to say, member for member.
    fn expectation<'a>(&self, enlargement: &'a Enlargement) -> ConfirmationExpectation<'a> {
        ConfirmationExpectation {
            action: SensitiveAction::EnlargeGrant,
            action_digest: enlargement.action_digest,
            host_device_id: self.host_device_id,
            host_endpoint_id: self.host_endpoint_id,
            // An owner location sends authority to no device, so its challenge names none.
            destination_keys: None,
            destination_rights: &enlargement.rights,
        }
    }
}

impl OwnerAuthority for HostOwner {
    fn challenge(
        &self,
        enlargement: &Enlargement,
    ) -> std::result::Result<OwnerConfirmationRequest, ProtocolError> {
        let request = kr_pairing::confirm::request_confirmation(
            self.clock.as_ref(),
            SensitiveAction::EnlargeGrant,
            enlargement.action_digest,
            None,
            enlargement.rights.iter().copied().collect(),
            self.host_device_id,
            self.host_endpoint_id,
        )
        .map_err(|error| refused(&error))?;
        let mut ledger = self.ledger();
        ledger.expire(self.clock.as_ref());
        ledger.issue(&request, self.clock.as_ref());
        Ok(request)
    }

    fn outstanding(&self, request: &OwnerConfirmationRequest) -> bool {
        let mut ledger = self.ledger();
        // The ledger's own deadline, on the machine's continuous clock and bound to this boot, is
        // the one that decides: a wall clock moved back does not keep a challenge alive.
        ledger.expire(self.clock.as_ref());
        ledger.outstanding(request.confirmation_id) == Some(request)
    }

    fn verify(
        &self,
        enlargement: &Enlargement,
        proof: &OwnerConfirmationProof,
    ) -> std::result::Result<(), ProtocolError> {
        self.expectation(enlargement)
            .require(&proof.request)
            .map_err(|error| refused(&error))?;
        // The ledger's own copy has to be the challenge presented, so a challenge the caller
        // composed is refused before its signature is believed.
        if !self.outstanding(&proof.request) {
            return Err(refused(
                &kr_pairing::PairingError::OwnerConfirmationRequired,
            ));
        }
        kr_pairing::confirm::verify_confirmation(
            self.clock.as_ref(),
            &proof.request,
            proof,
            // This host's own enrolled signer, never one the proof supplies.
            &self.signer,
            self.enrolment,
        )
        .map_err(|error| refused(&error))
    }

    fn consume(&self, proof: &OwnerConfirmationProof) -> std::result::Result<(), ProtocolError> {
        self.ledger()
            .consume(&proof.request, self.clock.as_ref())
            .map_err(|error| refused(&error))
    }
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
            // This one is printed on the daemon's own standard error at startup as well as
            // answered with, and it can name a state directory a caller chose, so it goes through
            // the same rule as every other message this service produces.
            detail: kr_project::git::redact(&error.to_string()),
        })?;
        Ok(Self {
            service: Arc::new(service),
            owner: OnceLock::new(),
        })
    }

    /// Returns the service itself.
    #[must_use]
    pub const fn service(&self) -> &Arc<ProjectService> {
        &self.service
    }

    /// Lends the service this host's owner, once, and starts letting go of the challenges the
    /// owner's ledger lets go of.
    ///
    /// A challenge nobody answers holds the directory it was issued for until the ledger lets it
    /// go. The service lets go of it the next time a location method runs, and the sweep this
    /// starts makes sure it does so even when none does, so enrolment needs the runtime the sweep
    /// runs on: an owner enrolled without one would hold directories nothing ever lets go of, and
    /// is refused instead. The sweep holds the service weakly, so it ends with the daemon, and it
    /// runs where blocking work belongs, because letting go closes directories.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::NotConfigured`] when there is no runtime to sweep on, or when an
    /// owner is already enrolled: a host has one owner signer, and a second enrolment would be a
    /// second authority over the same decisions.
    pub fn enrol_owner(&self, owner: Arc<HostOwner>) -> Result<()> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            ControllerError::NotConfigured(
                "the owner is enrolled by a running daemon, which lets go of the challenges nobody \
                 answers"
                    .to_owned(),
            )
        })?;
        self.owner.set(Arc::clone(&owner)).map_err(|_| {
            ControllerError::NotConfigured(
                "this host's owner is already enrolled for its project locations".to_owned(),
            )
        })?;
        let service = Arc::downgrade(&self.service);
        runtime.spawn(async move {
            let mut every = tokio::time::interval(CHALLENGE_SWEEP);
            every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                every.tick().await;
                let (service, owner) = (service.clone(), Arc::clone(&owner));
                let swept = tokio::task::spawn_blocking(move || {
                    service
                        .upgrade()
                        .map(|service| service.expire_challenges(owner.as_ref()))
                })
                .await;
                // No service is the daemon gone, and a sweep that could not run is the end of it.
                if !matches!(swept, Ok(Some(_))) {
                    break;
                }
            }
        });
        Ok(())
    }

    fn owner(&self) -> Option<Arc<HostOwner>> {
        self.owner.get().cloned()
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
            Method::ProjectLocationAuthorise => {
                let params: kr_protocol::project::ProjectLocationAuthoriseParams =
                    parse(&mutation.params)?;
                Some(params.environment_id)
            }
            // The remaining mutations name a repository, a workspace, an operation or a location,
            // none of which the envelope's target can carry. The environment is checked for every
            // mutation before this point, and the service checks the named object against its own
            // record.
            Method::ProjectOperationCancel
            | Method::WorkspaceCreate
            | Method::WorkspaceRemove
            | Method::ProjectLocationWithdraw
            | Method::ProjectLocationAttach => None,
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
            Method::ProjectLocationList => {
                encode(&service.project_location_list(&typed(&params)?)?)
            }
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
    /// `grant` is the grant the caller holds, which only the door that admitted the caller knows:
    /// a paired device's, or none for a caller on this machine's own socket. The service reads it
    /// as the caller's class, so nothing the request carries can make a device the owner.
    ///
    /// # Errors
    ///
    /// Returns the refusal the service decided, under the service's own code.
    pub async fn write<A>(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        admission: A,
        grant: Option<GrantId>,
    ) -> Answer<ParamsValue>
    where
        A: Fn() -> std::result::Result<(), ProtocolError> + Send + 'static,
    {
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id)
            .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))?;
        let service = Arc::clone(&self.service);
        let actor = actor_id.clone();
        let params = mutation.params.clone();
        let action_id = mutation.action_id.get();
        let name = method.as_str();
        if matches!(
            method,
            Method::ProjectLocationAuthorise | Method::ProjectLocationAttach
        ) {
            let owner = self.owner();
            return blocking(move || {
                confirmed(
                    &service, &actor, action_id, name, digest, method, &params, owner, &admission,
                )
            })
            .await;
        }
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
            // Nothing retained, so this is a first admission and it is about to act. The
            // admission is asked about here rather than before the blocking task started: the
            // task had to be scheduled and this store had to be opened, both of which wait, and a
            // first admission may not begin under a deadline that has passed or a registration
            // that has been withdrawn. A retry never reaches this, because the record above
            // answered it: section 9 keeps a receipt readable after the freshness that admitted it
            // is gone.
            admission()?;
            // The action this mutation is performed under. Each of these methods commits it beside
            // the state it changes, which is what makes a second copy of one action find the claim
            // rather than starting a second clone.
            let claim = Action {
                actor_id: actor.clone(),
                action_id,
                method: name.to_owned(),
                payload_digest: digest,
            };
            // And the admission travels with it into the service, which asks it again inside the
            // transaction that begins the effect. What lies between the answer above and that
            // transaction is the service's own preparation — a destination resolved, a repository
            // opened and surveyed, the journal's lock taken — and a grant revoked or expired in
            // there has to reach an action that then does not begin.
            let performed = kr_project::store::Performed::from(Some(&claim)).admitted(&admission);
            let performed = match grant {
                Some(grant) => performed.bounded_by(grant),
                None => performed,
            };
            // Every arm runs inside a closure, so a refusal the service decided reaches the
            // retention below instead of returning from the task. An action whose failure was not
            // retained could be performed again under the same identifier and succeed.
            let outcome = (|| -> Answer<ParamsValue> {
                match method {
                    Method::ProjectInit => {
                        encode(&service.project_init(&actor, &typed(&params)?, performed)?)
                    }
                    Method::ProjectClone => {
                        encode(&service.project_clone(&actor, &typed(&params)?, performed)?)
                    }
                    Method::ProjectAdopt => {
                        encode(&service.project_adopt(&actor, &typed(&params)?, performed)?)
                    }
                    Method::ProjectOperationCancel => encode(&service.project_operation_cancel(
                        &actor,
                        &typed(&params)?,
                        performed,
                    )?),
                    Method::WorkspaceCreate => {
                        encode(&service.workspace_create(&actor, &typed(&params)?, performed)?)
                    }
                    Method::WorkspaceRemove => {
                        encode(&service.workspace_remove(&typed(&params)?, performed)?)
                    }
                    Method::ProjectLocationWithdraw => {
                        encode(&service.project_location_withdraw(&typed(&params)?, performed)?)
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

/// The owner-confirmation refusal a caller is told, under the ceremony's own code.
fn refused(error: &kr_pairing::PairingError) -> ProtocolError {
    ProtocolError::new(
        error.code(),
        format!("the owner's confirmation does not authorise this: {error}"),
    )
}

/// Performs one of the owner's two confirmed location decisions.
///
/// These keep their own record rather than having one kept here. The first submission of each is
/// answered with a challenge and performs nothing, so it is not an outcome to keep: a record of it
/// would refuse the proof-bearing submission of the same action as a conflicting request. The
/// second submission keeps its answer in the transaction that performs it, and a failure after its
/// challenge is spent is kept by the service too. A refusal before anything was spent is kept by
/// nobody, and the same action can be submitted again.
#[expect(
    clippy::too_many_arguments,
    reason = "one confirmed decision is its service, its actor, its action, its method and \
              digest, its parameters, the owner that confirms it and the admission it runs under; \
              each is part of the decision, and a struct would hide which of them a caller left out"
)]
fn confirmed<A>(
    service: &ProjectService,
    actor: &ActorId,
    action_id: kr_protocol::scalars::Uuid,
    name: &str,
    digest: kr_protocol::scalars::Digest256,
    method: Method,
    params: &ParamsValue,
    owner: Option<Arc<HostOwner>>,
    admission: &A,
) -> Answer<ParamsValue>
where
    A: Fn() -> std::result::Result<(), ProtocolError>,
{
    // A retry of an answered action is answered before its admission is asked about, as every
    // other mutation's is: a receipt stays readable after the freshness that admitted it is gone.
    // Only a settled answer comes back from here. A claim still open, which a submission in the
    // middle of its confirmation holds, is not an answer: the retry goes on into the service and
    // waits for that submission's transition there, then reads what it recorded.
    if let Some(retained) = service.retained_action(actor, action_id, name, digest)? {
        return match retained {
            RetainedOutcome::Ok(result) => kr_cbor::decode(&result, &kr_cbor::Limits::DEFAULT)
                .map(ParamsValue::new)
                .map_err(|error| {
                    ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string())
                }),
            RetainedOutcome::Error { code, detail } => Err(ProtocolError::new(code, detail)),
        };
    }
    admission()?;
    let claim = Action {
        actor_id: actor.clone(),
        action_id,
        method: name.to_owned(),
        payload_digest: digest,
    };
    let performed = kr_project::store::Performed::from(Some(&claim)).admitted(admission);
    let owner = owner.as_deref().map(|owner| owner as &dyn OwnerAuthority);
    match method {
        Method::ProjectLocationAuthorise => {
            encode(&service.project_location_authorise(actor, &typed(params)?, performed, owner)?)
        }
        Method::ProjectLocationAttach => {
            encode(&service.project_location_attach(actor, &typed(params)?, performed, owner)?)
        }
        _ => Err(ProtocolError::new(
            ErrorCode::InvalidArgument,
            format!(
                "{} is not an owner decision this daemon confirms",
                method.as_str()
            ),
        )),
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
    params.to_typed().map_err(|error| {
        ControllerError::InvalidArgument(kr_project::git::redact(&error.to_string()))
    })
}

fn typed<T: kr_protocol::wire::WireMessage>(params: &ParamsValue) -> Answer<T> {
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
            Method::ProjectLocationList,
            Method::ProjectLocationAuthorise,
            Method::ProjectLocationWithdraw,
            Method::ProjectLocationAttach,
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
            Method::ProjectLocationList,
            Method::ProjectLocationAuthorise,
            Method::ProjectLocationWithdraw,
            Method::ProjectLocationAttach,
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
