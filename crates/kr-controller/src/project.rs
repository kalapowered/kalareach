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
//! this host and a short expiry, signed by one of this host's owner devices and spent once. A host
//! that is not on the network, or has no owner device yet, confirms nothing and authorises nothing.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use kr_pairing::confirm::ConfirmationExpectation;
use kr_project::ProjectService;
use kr_project::policy::{Enlargement, OwnerAuthority};
use kr_project::store::{Action, ActionState, RetainedOutcome};
use kr_protocol::confirmation::{ConfirmationDisplay, DescribedAction};
use kr_protocol::envelope::{
    ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActorId, GrantId, RequestId};
use kr_protocol::method::{Method, MethodGroup};
use kr_protocol::pairing::{
    DevicePublicKeys, OwnerConfirmationProof, OwnerConfirmationRequest, SensitiveAction,
};
use kr_protocol::scalars::Nullable;

use crate::error::{ControllerError, Result};
use crate::given::Given;
use crate::service::net::owner::Resolved;
use crate::service::net::pairing::PairingHost;

/// What a project call answers with: the method's result, or the refusal the service decided.
pub type Answer<T> = std::result::Result<T, ProtocolError>;

/// The project service, as the daemon holds it.
#[derive(Debug)]
pub struct ProjectModule {
    service: Arc<ProjectService>,
    /// This host's owner, once one is enrolled.
    owner: OnceLock<Arc<HostOwner>>,
    /// How often the sweep of the challenges runs.
    sweep_every: std::time::Duration,
    /// How many sweeps of the challenges have finished.
    #[cfg(feature = "testing")]
    sweeps: Arc<tokio::sync::watch::Sender<u64>>,
}

/// How often expired owner challenges are let go, with the directories they held open.
///
/// A challenge lives as long as the ledger's own deadline, two minutes. Sweeping twice a minute
/// means a challenge nobody answers holds its directory for at most half a minute beyond that.
const CHALLENGE_SWEEP: std::time::Duration = std::time::Duration::from_secs(30);

/// This host's owner, as the project service's location decisions reach it.
///
/// It is the owner every other sensitive action on this host is confirmed by: the owner devices the
/// pairing service enrolled, the live paired devices whose grant holds `host.manage` and is in
/// force. The challenge is issued in that service's ledger and listed to those devices with what it
/// approves. A proof is verified against the owner device whose key it names, while that device is
/// still one, and the spend is checked against current authority again and written to the same
/// acceptance record before the service acts. A challenge the caller made up, one issued for
/// another digest, another set of rights or another host, one that has run out, one already spent
/// and one signed by anything but an owner device are all refused.
pub struct HostOwner {
    pairing: Arc<PairingHost>,
}

impl std::fmt::Debug for HostOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostOwner")
            .field("host_device_id", &self.pairing.identity().device_id)
            .finish_non_exhaustive()
    }
}

impl HostOwner {
    /// Lends the project service the owner confirmations of this host's pairing service.
    #[must_use]
    pub const fn new(pairing: Arc<PairingHost>) -> Self {
        Self { pairing }
    }

    /// The four public keys of the device that holds `grant`, which a confirmation of a location
    /// for that grant is bound to.
    ///
    /// The device is found in this host's own records and has to be paired, with its grant in
    /// force, and to have declared all four keys: an owner is shown the device it enlarges
    /// authority for, so a device whose keys this host does not hold in full cannot be named.
    fn destination(&self, grant: GrantId) -> std::result::Result<DevicePublicKeys, ProtocolError> {
        let rows = self.pairing.rows();
        let devices = rows
            .directory()
            .devices()
            .map_err(|error| error.to_protocol_error())?;
        let refused = |why: String| ProtocolError::new(ErrorCode::PermissionDenied, why);
        let Some(device) = devices
            .into_iter()
            .find(|device| device.grant.grant_id == grant && device.is_paired())
        else {
            return Err(refused(format!(
                "no paired device holds grant {grant}, so no location is confirmed for it"
            )));
        };
        if !rows
            .lifetimes()
            .in_force(&device)
            .map_err(|error| error.to_protocol_error())?
        {
            return Err(refused(format!(
                "grant {grant} is no longer in force, so no location is confirmed for it"
            )));
        }
        device.public_keys().ok_or_else(|| {
            refused(format!(
                "the device that holds grant {grant} has not declared all four of its public keys, \
                 so no confirmation can name it: the device declares them first with \
                 device.keys.complete"
            ))
        })
    }

    /// The keys an enlargement sends authority to: the holder of its grant, or nobody for the
    /// owner's own location.
    fn destination_of(
        &self,
        enlargement: &Enlargement,
    ) -> std::result::Result<Option<DevicePublicKeys>, ProtocolError> {
        enlargement
            .destination
            .map(|grant| self.destination(grant))
            .transpose()
    }

    /// What a challenge for a location's enlargement has to say, member for member.
    fn expectation<'a>(
        &self,
        enlargement: &'a Enlargement,
        destination: Option<&'a DevicePublicKeys>,
    ) -> ConfirmationExpectation<'a> {
        self.pairing.owner().expectation(
            SensitiveAction::EnlargeGrant,
            enlargement.action_digest,
            destination,
            &enlargement.rights,
        )
    }
}

impl OwnerAuthority for HostOwner {
    fn challenge(
        &self,
        enlargement: &Enlargement,
    ) -> std::result::Result<OwnerConfirmationRequest, ProtocolError> {
        let destination = self.destination_of(enlargement)?;
        self.pairing
            .owner()
            .challenge(Resolved {
                action: SensitiveAction::EnlargeGrant,
                digest: enlargement.action_digest,
                destination,
                rights: enlargement.rights.clone(),
                // What an owner device shows the owner before it signs: the device the authority
                // goes to, when it goes to one.
                display: ConfirmationDisplay::Described(DescribedAction {
                    action: SensitiveAction::EnlargeGrant,
                    action_digest: enlargement.action_digest,
                    destination_keys: Nullable(destination),
                    destination_rights: enlargement.rights.clone(),
                }),
                bootstrap: false,
            })
            .map_err(|error| error.to_protocol_error())
    }

    fn outstanding(&self, request: &OwnerConfirmationRequest) -> bool {
        self.pairing.owner().outstanding(request)
    }

    fn verify(
        &self,
        enlargement: &Enlargement,
        proof: &OwnerConfirmationProof,
    ) -> std::result::Result<(), ProtocolError> {
        let destination = self.destination_of(enlargement)?;
        self.pairing
            .owner()
            .verify_presented(&self.expectation(enlargement, destination.as_ref()), proof)
            .map_err(|error| error.to_protocol_error())
    }

    fn consume(
        &self,
        enlargement: &Enlargement,
        proof: &OwnerConfirmationProof,
    ) -> std::result::Result<(), ProtocolError> {
        // The proof was verified against the enlargement it answers. The spend holds it to the
        // enlargement's own shape and to the ledger's own copy of the challenge, and names the
        // device by the keys it holds now. The acceptance record then reads the signer's
        // authority and the device's keys in its own transaction, so a device that rotated a key
        // since this read is not authorised: the owner confirms the location again.
        let destination = self.destination_of(enlargement)?;
        self.pairing
            .owner()
            .spend_presented(
                &self.expectation(enlargement, destination.as_ref()),
                proof,
                "project.location",
            )
            .map(|_| ())
            .map_err(|error| error.to_protocol_error())
    }
}

impl ProjectModule {
    /// Opens the environment's project service and resolves whatever an earlier daemon left
    /// unfinished.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store, the Git profile's
    /// directories or the recovery cannot be prepared. Git itself is not looked for here: a host
    /// without a usable Git opens the module, and each request that runs Git is refused.
    pub async fn open(paths: &kr_ipc::paths::EnvironmentPaths) -> Result<Self> {
        // Opening the store migrates it, preparing the profile makes its directories, and recovery
        // examines directories. All three are blocking work, so they run on a blocking task rather
        // than on the daemon's reactor.
        let paths = paths.clone();
        #[cfg(feature = "testing")]
        let git_read_bound = crate::testing::git_read_bound();
        let service = tokio::task::spawn_blocking(move || {
            #[cfg(feature = "testing")]
            let mut service = ProjectService::open(&paths)?;
            #[cfg(not(feature = "testing"))]
            let service = ProjectService::open(&paths)?;
            #[cfg(feature = "testing")]
            if let Some(bound) = git_read_bound {
                service.hold_git_read_deadline(bound);
            }
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
            sweep_every: CHALLENGE_SWEEP,
            #[cfg(feature = "testing")]
            sweeps: Arc::new(tokio::sync::watch::channel(0).0),
        })
    }

    /// Makes the sweep of the challenges that [`Self::enrol_owner`] starts run every `every`, after
    /// the one it runs at once. A suite that looks at what the sweep holds gives it a period no
    /// test reaches, so that no sweep but the first can run while it looks. For this host's own
    /// tests; nothing in the daemon sets it.
    #[cfg(feature = "testing")]
    pub fn sweep_challenges_every(&mut self, every: std::time::Duration) {
        self.sweep_every = every;
    }

    /// A count that changes each time a sweep of the challenges finishes. For this host's own
    /// tests.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn challenge_sweeps(&self) -> tokio::sync::watch::Receiver<u64> {
        self.sweeps.subscribe()
    }

    /// Returns the service itself.
    #[must_use]
    pub const fn service(&self) -> &Arc<ProjectService> {
        &self.service
    }

    /// Proves whether this host runs Git for a paired device, on a blocking thread: the proof
    /// starts a process.
    pub async fn qualify(&self) -> Arc<kr_project::service::Qualification> {
        let service = Arc::clone(&self.service);
        Arc::new(
            tokio::task::spawn_blocking(move || service.qualify())
                .await
                .unwrap_or_else(|_| {
                    kr_project::service::Qualification::refused(
                        kr_project::service::Refusal::Invocation,
                        "the proof could not run to its end",
                    )
                }),
        )
    }

    /// Lends the service this host's owner, once, and starts letting go of the challenges the
    /// owner's ledger lets go of.
    ///
    /// A challenge nobody answers holds the directory it was issued for until the ledger lets it
    /// go. The service lets go of it the next time a location method runs, and the sweep this
    /// starts makes sure it does so even when none does, so enrolment needs the runtime the sweep
    /// runs on: an owner enrolled without one would hold directories nothing ever lets go of, and
    /// is refused instead. The sweep holds the service and the owner weakly, and takes hold of them
    /// for one sweep at a time: the owner holds this host's pairing service and its stores, so the
    /// sweep keeps none of them between its sweeps, only for the sweep under way when the daemon
    /// is let go of, and it ends at its next tick. It is not the only holder of the pairing
    /// service: the transport's accept loop, which is aborted when its listener goes, and the
    /// tasks that serve connections hold it on their own terms, the second until their connection
    /// ends. The sweep runs where blocking work belongs, because letting go closes directories.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::NotConfigured`] when there is no runtime to sweep on, or when an
    /// owner is already enrolled: a host has one owner, and a second enrolment would be a second
    /// authority over the same decisions.
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
        let owner = Arc::downgrade(&owner);
        let period = self.sweep_every;
        #[cfg(feature = "testing")]
        let finished = Arc::clone(&self.sweeps);
        runtime.spawn(async move {
            let mut every = tokio::time::interval(period);
            every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                every.tick().await;
                let (service, owner) = (service.clone(), owner.clone());
                let swept = tokio::task::spawn_blocking(move || {
                    let (service, owner) = (service.upgrade()?, owner.upgrade()?);
                    Some(service.expire_challenges(owner.as_ref()))
                })
                .await;
                // No service or no owner is the daemon gone, and a sweep that could not run is the
                // end of it.
                if !matches!(swept, Ok(Some(_))) {
                    break;
                }
                #[cfg(feature = "testing")]
                finished.send_modify(|sweeps| *sweeps += 1);
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
        let outcome = blocking(move || kept(&service, &actor, action_id, name, digest)).await;
        match outcome {
            // The blocking task itself failed, which says nothing about the action.
            Err(error) => Some(frame(mutation.request_id, Err(error))),
            Ok(None) => None,
            Ok(Some(retained)) => Some(frame(mutation.request_id, recorded(retained))),
        }
    }

    /// Says what an exact repeat of a project action is owed when the window it carries admits
    /// nothing here, because this connection never issued it or it has expired on this connection,
    /// if this service holds anything for its action.
    ///
    /// [`Self::retained`] answers a settled action and has nothing for one whose claim is open,
    /// which is an action whose first attempt is still carrying it out, or ended without recording
    /// what it did. Such an action is not a first one, so a window that admits nothing is no reason
    /// to refuse it: that refusal is definite, and a client takes it for the host's word that
    /// nothing was done. The repeat is told what the host knows: it holds the claim and no record
    /// of what the attempt came to, and cannot tell a running attempt from one that ended
    /// unrecorded. A claim the first attempt settled since the lookup is answered with its record. `None` is an action this service holds no claim for: a first
    /// admission, which has no window to be admitted under, or a copy that arrived before the first
    /// attempt wrote its claim. The door tells the two apart by whether another arrival holds the
    /// action, which the service cannot see.
    pub async fn held_answer(
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
            // One read: a claim that is open at one read and settled at the next is not absent.
            service
                .action_state(&actor, action_id, name, digest)
                .map_err(|error| {
                    ControllerError::found_unreadable_on_the_wire(error.into(), RECORDS)
                })
        })
        .await;
        match outcome {
            Err(error) => Some(frame(mutation.request_id, Err(error))),
            Ok(ActionState::Absent) => None,
            Ok(ActionState::Open) => Some(frame(
                mutation.request_id,
                Err(ControllerError::claim_without_outcome().to_protocol_error()),
            )),
            Ok(ActionState::Settled(retained)) => {
                Some(frame(mutation.request_id, recorded(retained)))
            }
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
    /// An answer this reads from the record an earlier submission of the action left is given as a
    /// copy, and goes back only while `retained` says the authority the mutation arrived under
    /// stands. `admission` is the check a first admission begins under, deadline included;
    /// `retained` is the one a recorded answer is owed, without the deadline a receipt outlives.
    /// A copy is found after the lookup the door made before it considered a first admission, and
    /// after waits of its own, so `retained` is asked once the answer is in hand, whichever place
    /// found it.
    ///
    /// # Errors
    ///
    /// Returns the refusal the service decided, under the service's own code.
    pub async fn write<A, R>(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        admission: A,
        retained: R,
        grant: Option<GrantId>,
    ) -> Given<Answer<ParamsValue>>
    where
        A: Fn() -> std::result::Result<(), ProtocolError> + Send + 'static,
        R: Fn() -> std::result::Result<(), ProtocolError> + Send + Sync + 'static,
    {
        let copied = Arc::new(AtomicBool::new(false));
        let retained = Arc::new(retained);
        let answer = self
            .perform(
                actor_id,
                mutation,
                method,
                admission,
                Arc::clone(&retained),
                grant,
                &copied,
            )
            .await;
        let copied = copied.load(Ordering::Acquire);
        // The answer first, then the authority it is owed: a refusal replaces what the record
        // held, as the shared check replaces it everywhere a recorded answer goes back, and is
        // given as a copy that was withheld. The conflict of a reused identifier is no copy, and is
        // held to the same check.
        let reused = answer
            .as_ref()
            .is_err_and(|refusal| refusal.code == ErrorCode::IdConflict);
        Given::checked(answer, copied, reused, || retained())
    }

    /// [`Self::write`], setting `copied` when the answer is the record's.
    #[allow(clippy::too_many_arguments)]
    async fn perform<A, R>(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        admission: A,
        retained: Arc<R>,
        grant: Option<GrantId>,
        copied: &Arc<AtomicBool>,
    ) -> Answer<ParamsValue>
    where
        A: Fn() -> std::result::Result<(), ProtocolError> + Send + 'static,
        R: Fn() -> std::result::Result<(), ProtocolError> + Send + Sync + 'static,
    {
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id)
            .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))?;
        let copied = Arc::clone(copied);
        let claimed = Arc::new(AtomicBool::new(false));
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
                    &*retained, &copied,
                )
            })
            .await;
        }
        blocking(move || {
            if let Some(retained) = kept_noting(&service, &actor, action_id, name, digest, &copied)?
            {
                copied.store(true, Ordering::Release);
                return recorded(retained);
            }
            // Nothing retained, so this is a first admission and it is about to act. The
            // admission is asked about here rather than before the blocking task started: the
            // task had to be scheduled and this store had to be opened, both of which wait, and a
            // first admission may not begin under a deadline that has passed or a registration
            // that has been withdrawn. A retry whose record settled never reaches this, because
            // the record above answered it: section 9 keeps a receipt readable after the freshness
            // that admitted it is gone. One whose first attempt has not settled its claim does,
            // and is not refused as though it were a first admission.
            if let Err(answer) = admitted_to_begin(
                &service, &actor, action_id, name, digest, &admission, &*retained, &copied,
            ) {
                return answer;
            }
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
            let performed = kr_project::store::Performed::from(Some(&claim))
                .admitted(&admission)
                .telling(&copied)
                .holding(&claimed);
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
            // A row that is there already is another attempt's unless this attempt wrote the claim
            // for its action, which only one attempt can: the methods that claim settle their own
            // row, and an answer read back from it is this attempt's own.
            //
            // A row that cannot be written leaves the claim as it was. An action that was carried
            // out is then not told as a failure of the store, which says nothing took effect.
            //
            // A refusal that cannot be written down is not told as a definite one: it can be a
            // word about what another copy of the action did, such as the destination it made,
            // and a client takes a definite refusal for the host's word that nothing was done. The
            // record is read instead. It is the answer where the action has one, this attempt's own
            // refusal included when it wrote the claim and settled it; where there is none to be
            // read, the outcome is not known.
            let existing = match service.record_action(&actor, action_id, name, digest, &record) {
                Ok(existing) => existing,
                Err(error) if outcome.is_ok() => {
                    return Err(ProtocolError::new(
                        ErrorCode::OutcomeUnknown,
                        format!(
                            "this action was performed and this host could not record what it \
                             came to: {error}"
                        ),
                    ));
                }
                Err(_) => {
                    return match service.retained_action(&actor, action_id, name, digest) {
                        Ok(Some(retained)) => {
                            if !claimed.load(Ordering::Acquire) {
                                copied.store(true, Ordering::Release);
                            }
                            recorded(retained)
                        }
                        Ok(None) => Err(ControllerError::refusal_not_recorded()),
                        Err(error @ kr_project::ProjectError::IdConflict { .. }) => {
                            Err(error.into())
                        }
                        Err(_) => Err(ControllerError::refusal_not_recorded()),
                    };
                }
            };
            if existing.is_some() && !claimed.load(Ordering::Acquire) {
                copied.store(true, Ordering::Release);
            }
            match existing {
                None => outcome,
                Some(retained) => recorded(retained),
            }
        })
        .await
    }
}

/// The records this module's store keeps, as a repeat is told of them when they cannot be read.
const RECORDS: &str = "project actions";

/// The record an action left, read for a repeat of it.
///
/// A journal that cannot be read is not one that holds no record: the action may have been carried
/// out, so the repeat is told that what became of it is not known. A reused identifier keeps its
/// code. The lookup cannot tell a first action from a repeat, so a first action on a journal that
/// cannot be read is told the same.
fn kept(
    service: &ProjectService,
    actor: &ActorId,
    action_id: kr_protocol::scalars::Uuid,
    name: &str,
    digest: kr_protocol::scalars::Digest256,
) -> Answer<Option<RetainedOutcome>> {
    service
        .retained_action(actor, action_id, name, digest)
        .map_err(|error| ControllerError::found_unreadable_on_the_wire(error.into(), RECORDS))
}

/// [`kept`] for a mutation about to be performed, noting in `copied` when the lookup refuses
/// because the record cannot be read.
///
/// A row that cannot be read says that a record exists, so what the lookup refuses with goes back as
/// a copy does, under the authority the mutation arrived under. The conflict of a reused identifier
/// is no copy, and [`ProjectModule::write`] holds it to the same check by its code.
fn kept_noting(
    service: &ProjectService,
    actor: &ActorId,
    action_id: kr_protocol::scalars::Uuid,
    name: &str,
    digest: kr_protocol::scalars::Digest256,
    copied: &AtomicBool,
) -> Answer<Option<RetainedOutcome>> {
    kept(service, actor, action_id, name, digest).inspect_err(|refusal| {
        if refusal.code != ErrorCode::IdConflict {
            copied.store(true, Ordering::Release);
        }
    })
}

/// Asks the admission an action begins under, for an action that found no settled record, and
/// says either that the action may begin or what answers it instead.
///
/// A claim with no outcome is not a record, so a copy of an action whose first attempt is still
/// carrying it out, or ended without recording what it did, comes here too. The admission refusing
/// it is then no word about an action that never began: the first attempt did. What the journal
/// holds is read once, after the refusal: a claim still open tells the copy that what became of the
/// action is not known, a claim the first attempt has settled since is the copy's answer, and no
/// claim leaves the refusal as it is, as for any first action. What the journal holds goes back
/// only under the authority the copy arrived under: a claim still open is told only while
/// `retained` says it stands, and a settled record is a copy, which [`ProjectModule::write`]
/// holds to the same check.
#[expect(
    clippy::too_many_arguments,
    reason = "the action's identity, the two questions its admission answers and the flag that \
              says the answer is the record's are each part of one decision"
)]
fn admitted_to_begin<A, R>(
    service: &ProjectService,
    actor: &ActorId,
    action_id: kr_protocol::scalars::Uuid,
    name: &str,
    digest: kr_protocol::scalars::Digest256,
    admission: &A,
    retained: &R,
    copied: &AtomicBool,
) -> std::result::Result<(), Answer<ParamsValue>>
where
    A: Fn() -> std::result::Result<(), ProtocolError>,
    R: Fn() -> std::result::Result<(), ProtocolError>,
{
    let Err(refusal) = admission() else {
        return Ok(());
    };
    match service.action_state(actor, action_id, name, digest) {
        Ok(ActionState::Absent) => Err(Err(refusal)),
        // That an action is still being carried out is told to the caller that may be told of the
        // action, asked with the state in hand: a fence owed or a registration replaced is the
        // refusal, whatever the claim says.
        Ok(ActionState::Open) => Err(Err(match retained() {
            Ok(()) => ControllerError::claim_without_outcome().to_protocol_error(),
            Err(lapsed) => lapsed,
        })),
        // A settled record is a copy, and `write` asks the retained check of every copy.
        Ok(ActionState::Settled(found)) => {
            copied.store(true, Ordering::Release);
            Err(recorded(found))
        }
        // A record that cannot be read says that one exists, so it goes back as a copy does. The
        // conflict of a reused identifier is no copy; `write` holds it to the check by its code.
        Err(error) => {
            let told = ControllerError::found_unreadable_on_the_wire(error.into(), RECORDS);
            if told.code != ErrorCode::IdConflict {
                copied.store(true, Ordering::Release);
            }
            Err(Err(told))
        }
    }
}

/// The answer a record of an action is: the result it kept, or the refusal it kept. A result that
/// cannot be decoded leaves open what the action came to.
fn recorded(retained: RetainedOutcome) -> Answer<ParamsValue> {
    match retained {
        RetainedOutcome::Ok(result) => kr_cbor::decode(&result, &kr_cbor::Limits::DEFAULT)
            .map(ParamsValue::new)
            .map_err(|_| ControllerError::record_unreadable(RECORDS).to_protocol_error()),
        RetainedOutcome::Error { code, detail } => Err(ProtocolError::new(code, detail)),
    }
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
              digest, its parameters, the owner that confirms it and the two questions its \
              admission answers; each is part of the decision, and a struct would hide which of \
              them a caller left out"
)]
fn confirmed<A, R>(
    service: &ProjectService,
    actor: &ActorId,
    action_id: kr_protocol::scalars::Uuid,
    name: &str,
    digest: kr_protocol::scalars::Digest256,
    method: Method,
    params: &ParamsValue,
    owner: Option<Arc<HostOwner>>,
    admission: &A,
    retained: &R,
    copied: &AtomicBool,
) -> Answer<ParamsValue>
where
    A: Fn() -> std::result::Result<(), ProtocolError>,
    R: Fn() -> std::result::Result<(), ProtocolError>,
{
    // A retry of an answered action is answered before its admission is asked about, as every
    // other mutation's is: a receipt stays readable after the freshness that admitted it is gone.
    // Only a settled answer comes back from here. A claim still open, which a submission in the
    // middle of its confirmation holds, is not an answer: the retry goes on into the service and
    // waits for that submission's transition there, then reads what it recorded.
    if let Some(retained) = kept_noting(service, actor, action_id, name, digest, copied)? {
        copied.store(true, Ordering::Release);
        return recorded(retained);
    }
    if let Err(answer) = admitted_to_begin(
        service, actor, action_id, name, digest, admission, retained, copied,
    ) {
        return answer;
    }
    let claim = Action {
        actor_id: actor.clone(),
        action_id,
        method: name.to_owned(),
        payload_digest: digest,
    };
    let performed = kr_project::store::Performed::from(Some(&claim))
        .admitted(admission)
        .telling(copied);
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
