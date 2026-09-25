//! The plugin catalogue and plugin method groups, hosted by the control daemon.
//!
//! The daemon owns the admission and the environment; `kr-plugin-catalogue` owns the trust roots,
//! the budgets, the signed snapshot, the packages, what an installed package may do and the
//! receipts of the actions performed on them. What this module adds is the part that has to be
//! the daemon's.
//!
//! * Every method arrives through the daemon's ordinary path. A read is checked against current
//!   authority, a mutation carries an action window and is checked against the method registry,
//!   and neither has an admission path of its own.
//! * The admission travels into the catalogue as an [`Authority`], and the catalogue asks it again
//!   where the change becomes durable. [`DaemonAdmission`] answers by holding this daemon's
//!   connection table for the length of the commit, so a withdrawal lands wholly before the change
//!   or wholly after it.
//! * Adopting a trust root, granting a capability and an installation that widens what a package
//!   may do are the owner's decisions, and section 10 says outright that an operating-system
//!   identity is not that decision. Those methods carry the owner's confirmation of one exact
//!   action: the challenge this host issued and is still holding, answered under the enrolled
//!   signer, bound to the root, the grant or the installation in front of the owner, and consumed
//!   here so one ceremony authorises one action. The accepted confirmation is checked again inside
//!   the same commit.
//! * An action is claimed before it is performed, and its effect and the answer it gave commit in
//!   one transaction, so a resubmission is answered from that record rather than performed again,
//!   and an action a stopped daemon left mid-way reads as unknown rather than as refused.
//! * Enlarging trust is never a side effect of another method. A sync verifies inside the ceiling
//!   the enrolment already has and refuses a generation that would need more; an install that may
//!   do more than the installation it replaces, or, with nothing to replace, more than its
//!   repository's ceiling permits by itself, and every release that installs a native bridge, is
//!   refused unless it carries the owner's confirmation of that exact installation.

pub(crate) mod files;
pub mod native_bridge;

use std::sync::Arc;

use kr_plugin_catalogue::transport::RepositoryTransport;
use kr_plugin_catalogue::{
    Authority, CapabilityCeiling, Catalogue, CatalogueError, CatalogueResult, Change, Claimed,
    Effect, Enrolment, Installation, InstallationGrant, InstallationView, Owner, ReceiptClaim,
    ReceiptKey, ReceiptRecord, Recording, RepositoryId, RepositoryKind, RepositoryView, Transition,
    capability_from_str,
};
use kr_plugin_sdk::capability::PluginCapability;
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::version::PackageVersion;
use kr_protocol::actor::ActorIngress;
use kr_protocol::catalogue as wire;
use kr_protocol::envelope::{
    ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{
    ActionId, ActorId, EnvironmentId, PluginId, RepositoryGeneration, RequestId,
};
use kr_protocol::method::{Method, MethodGroup};
use kr_protocol::receipt::ReceiptState;
use kr_protocol::scalars::{Digest256, Nullable, U64};
use tokio::sync::Mutex;

use crate::sharing::{ConfirmedAction, OwnerConfirmations};

/// What a catalogue call answers with: the method's result, or the refusal the service decided.
pub type Answer<T> = std::result::Result<T, ProtocolError>;

/// What a catalogue mutation is admitted under, as the catalogue and its receipt see it.
///
/// It is the catalogue's [`Authority`], asked again where each change becomes durable, and it
/// says which wall-clock deadline the mutation was accepted under, which its receipt records.
pub trait Admission: Authority {
    /// The deadline this mutation was accepted under, on the wall clock, where it has one.
    fn accepted_deadline_ms(&self) -> Option<u64>;
}

impl Admission for Owner {
    fn accepted_deadline_ms(&self) -> Option<u64> {
        None
    }
}

/// A catalogue mutation's admission, as this daemon carries it.
///
/// It is asked twice. [`Authority::check`] before the slow work, so a lapsed admission stops
/// without downloading anything, and [`Authority::commit`] where the change becomes durable,
/// holding this daemon's table of admitted connections for the length of the commit. Revoking
/// authority and withdrawing a connection take the same table, so neither can be ordered between
/// the check and the change.
pub struct DaemonAdmission {
    controller: Arc<crate::service::Controller>,
    admitted: crate::authority::AdmittedMutation,
}

impl DaemonAdmission {
    /// The admission one connection's mutation was accepted under.
    #[must_use]
    pub fn new(
        controller: Arc<crate::service::Controller>,
        admitted: crate::authority::AdmittedMutation,
    ) -> Self {
        Self {
            controller,
            admitted,
        }
    }
}

impl Authority for DaemonAdmission {
    fn check(&self) -> CatalogueResult<()> {
        self.controller
            .check_registration(&self.admitted)
            .map_err(|error| CatalogueError::Refused(error.to_protocol_error()))
    }

    fn commit(
        &self,
        _effect: &Effect,
        commit: &mut dyn FnMut() -> CatalogueResult<()>,
    ) -> CatalogueResult<()> {
        self.controller
            .under_registration(&self.admitted, commit)
            .map_err(|error| CatalogueError::Refused(error.to_protocol_error()))?
    }

    fn owner_confirmed(&self) -> bool {
        false
    }
}

impl Admission for DaemonAdmission {
    fn accepted_deadline_ms(&self) -> Option<u64> {
        self.controller.receipt_deadline_ms(&self.admitted)
    }
}

/// An admission that also carries the owner's accepted confirmation of one exact action.
///
/// The confirmation was accepted, and its challenge consumed, once. What is asked again at the
/// commit is whether that accepted confirmation still covers this action on this host within its
/// lifetime, inside the same held order as the admission itself.
struct Confirmed<'a> {
    admission: &'a dyn Authority,
    confirmed: ConfirmedAction,
    action_digest: Digest256,
    confirmations: &'a dyn OwnerConfirmations,
    subject: &'static str,
}

impl Confirmed<'_> {
    fn covers(&self) -> CatalogueResult<()> {
        self.confirmed
            .covers(
                self.action_digest,
                self.confirmations.host_device_id(),
                self.confirmations.clock(),
                self.subject,
            )
            .map_err(|error| CatalogueError::Refused(error.to_protocol_error()))
    }
}

impl Authority for Confirmed<'_> {
    fn check(&self) -> CatalogueResult<()> {
        self.admission.check()?;
        self.covers()
    }

    fn commit(
        &self,
        effect: &Effect,
        commit: &mut dyn FnMut() -> CatalogueResult<()>,
    ) -> CatalogueResult<()> {
        self.admission.commit(effect, &mut || {
            self.covers()?;
            commit()
        })
    }

    fn owner_confirmed(&self) -> bool {
        true
    }
}

/// How this host's catalogue reaches its repositories.
///
/// A directory on this host is read where it is, and an address is fetched with this product's
/// trust and through `proxy`, or directly when that is `None`. A host whose certificate
/// verification cannot be set up still reads the repositories on its own disk, and says why
/// whenever it is asked to fetch one.
#[must_use]
pub fn repository_transport(proxy: Option<&kr_transport::config::ProxyUrl>) -> RepositoryTransport {
    match kr_client::services::http::client_builder(proxy) {
        Ok(builder) => RepositoryTransport::over(builder),
        Err(error) => {
            RepositoryTransport::local_only(format!("this host fetches no repository: {error}"))
        }
    }
}

/// The catalogue, as the daemon holds it.
#[derive(Debug)]
pub struct CatalogueModule {
    catalogue: Arc<Mutex<Catalogue>>,
    environment_id: EnvironmentId,
}

impl CatalogueModule {
    /// Opens the environment's catalogue.
    ///
    /// Every action an earlier daemon left mid-dispatch is settled as unknown here, before this
    /// one serves anything: its change may have been made, so it is never performed again and
    /// never reported as refused.
    ///
    /// Its repositories are fetched with this product's trust and through `proxy`, the one this
    /// host's configuration document selected when the daemon started, or directly when it
    /// selected none; a directory on this host is read where it is.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ControllerError::RegistryUnavailable`] when the catalogue's directory or
    /// its records cannot be opened.
    pub fn open(
        paths: &kr_ipc::paths::EnvironmentPaths,
        proxy: Option<&kr_transport::config::ProxyUrl>,
    ) -> crate::Result<Self> {
        let root = paths.state_dir().join("catalogue");
        let unavailable = |error: CatalogueError| crate::ControllerError::RegistryUnavailable {
            detail: error.to_string(),
        };
        let mut catalogue =
            Catalogue::open(&root, Arc::new(repository_transport(proxy))).map_err(unavailable)?;
        catalogue
            .recover_interrupted(kr_ipc::now_ms().get())
            .map_err(unavailable)?;
        Ok(Self {
            catalogue: Arc::new(Mutex::new(catalogue)),
            environment_id: paths.environment_id(),
        })
    }

    /// Returns true when this daemon serves the method.
    #[must_use]
    pub fn serves(method: Method) -> bool {
        matches!(
            method.group(),
            MethodGroup::PluginCatalogues | MethodGroup::Plugins
        )
    }

    /// Checks that a catalogue mutation's envelope and its parameters name the same subject.
    ///
    /// A catalogue and a package belong to an environment, not to a session or a foreground
    /// application, so a target that names one is refused rather than producing a receipt against
    /// something the effect never touched.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ControllerError::InvalidArgument`] when the two disagree.
    pub fn check_subject(method: Method, mutation: &MutationRequest) -> crate::Result<()> {
        if mutation.target.session_id.is_present()
            || mutation.target.application_instance_id.is_present()
        {
            return Err(crate::ControllerError::InvalidArgument(format!(
                "{} acts on a catalogue or a package, not on a session or an application",
                method.as_str()
            )));
        }
        let named = match method {
            Method::CatalogueAdd => subject::<wire::CatalogueAddParams>(&mutation.params)?,
            Method::CatalogueSync => subject::<wire::CatalogueSyncParams>(&mutation.params)?,
            Method::CataloguePin => subject::<wire::CataloguePinParams>(&mutation.params)?,
            Method::CatalogueRemove => subject::<wire::CatalogueRemoveParams>(&mutation.params)?,
            Method::PluginInstall => subject::<wire::PluginInstallParams>(&mutation.params)?,
            Method::PluginRemove => subject::<wire::PluginRemoveParams>(&mutation.params)?,
            Method::PluginPin => subject::<wire::PluginPinParams>(&mutation.params)?,
            Method::PluginEnable | Method::PluginDisable => {
                subject::<wire::PluginEnableParams>(&mutation.params)?
            }
            Method::PluginGrant => subject::<wire::PluginGrantParams>(&mutation.params)?,
            _ => {
                return Err(crate::ControllerError::InvalidArgument(format!(
                    "{} is not a catalogue mutation this daemon serves",
                    method.as_str()
                )));
            }
        };
        if named != mutation.target.environment_id {
            return Err(crate::ControllerError::InvalidArgument(
                "the request's target and its parameters name different environments".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns the catalogue itself, for a caller that already holds the daemon.
    #[must_use]
    pub const fn catalogue(&self) -> &Arc<Mutex<Catalogue>> {
        &self.catalogue
    }

    /// Serves one catalogue or plugin read and returns the frame it answers with.
    #[must_use]
    pub async fn read_frame(&self, ingress: ActorIngress, request: &Request) -> ControlFrame {
        frame(request.request_id, self.read(ingress, request).await)
    }

    /// Serves one catalogue or plugin read.
    ///
    /// `ingress` is where the request arrived. The registry lists each of these reads at more than
    /// one ingress, so the answer is decided at the caller's own: a method kept to private IPC
    /// stays unreachable from a paired device even though this module serves both.
    ///
    /// # Errors
    ///
    /// Returns the refusal the catalogue decided, under the catalogue's own code.
    pub async fn read(&self, ingress: ActorIngress, request: &Request) -> Answer<ParamsValue> {
        let Some(method) = request.method.method() else {
            return Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "the method is not in the registry",
            ));
        };
        match kr_protocol::method::decide(request.method.as_str(), request.method_version, ingress)
        {
            kr_protocol::authority::AuthorityDecision::Listed(_) => {}
            kr_protocol::authority::AuthorityDecision::Denied(reason) => {
                return Err(match reason.error_code() {
                    ErrorCode::UnsupportedSchema => ProtocolError::new(
                        ErrorCode::UnsupportedSchema,
                        format!(
                            "{} is not implemented at version {}",
                            request.method.as_str(),
                            request.method_version
                        ),
                    ),
                    _ => ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        format!(
                            "{} is not a read this daemon serves",
                            request.method.as_str()
                        ),
                    ),
                });
            }
        }
        let catalogue = self.catalogue.lock().await;
        match method {
            Method::CatalogueList => {
                let params: wire::CatalogueListParams = typed(&request.params)?;
                self.check_environment(params.environment_id)?;
                let views = catalogue.repository_views().map_err(ProtocolError::from)?;
                encode(&wire::CatalogueListResult {
                    catalogues: views.iter().map(summary).collect(),
                })
            }
            Method::PluginList => {
                let params: wire::PluginListParams = typed(&request.params)?;
                self.check_environment(params.environment_id)?;
                let views = catalogue
                    .installation_views(params.environment_id)
                    .map_err(ProtocolError::from)?;
                encode(&wire::PluginListResult {
                    plugins: views
                        .iter()
                        .map(plugin_summary)
                        .collect::<Answer<Vec<_>>>()?,
                })
            }
            Method::PluginCapabilities => {
                let params: wire::PluginCapabilitiesParams = typed(&request.params)?;
                self.check_environment(params.environment_id)?;
                let view = catalogue
                    .installation_view(params.environment_id, &params.plugin_id)
                    .map_err(ProtocolError::from)?;
                let installation = &view.installation;
                // The repository may have been removed since this package was installed. An
                // installed package stays usable, so an answer about it never depends on an
                // enrolment: no enrolment and no index are answers, and the evidence is then built
                // from what the installation itself recorded. A record or an index this host
                // cannot read is not such an answer and is returned as the failure it is.
                let generation = match catalogue
                    .repository(&installation.repository)
                    .map_err(ProtocolError::from)?
                {
                    Some(_) => catalogue
                        .active(&installation.repository)
                        .map_err(ProtocolError::from)?
                        .map_or(1, |active| active.generation),
                    None => 1,
                };
                let current = catalogue
                    .current_index(&installation.repository)
                    .map_err(ProtocolError::from)?;
                let evidence_records = if let Some(index) = current.as_ref()
                    && let Some(entry) = index.find(&installation.plugin_id, &installation.version)
                {
                    evidence(entry, installation, generation)?
                } else {
                    fallback_evidence(installation, generation)?
                };
                encode(&wire::PluginCapabilitiesResult {
                    plugin: plugin_summary(&view)?,
                    capabilities: grants(&installation.requested, &view.decisions)?,
                    evidence: evidence_records,
                })
            }
            _ => Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                format!("{} is not a read this daemon serves", method.as_str()),
            )),
        }
    }

    /// Returns the answer a retained catalogue or plugin mutation is owed.
    #[must_use]
    pub async fn retained(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        _method: Method,
    ) -> Option<ControlFrame> {
        // A mutation whose digest cannot be computed is refused for that when it is performed;
        // there is no receipt to find for it here.
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id).ok()?;
        let catalogue = self.catalogue.lock().await;
        match catalogue.receipt(&receipt_key(actor_id, mutation.action_id)) {
            Ok(Some(record)) => Some(frame(
                mutation.request_id,
                answered(&record, &digest, mutation.action_id),
            )),
            Ok(None) => None,
            Err(error) => Some(frame(mutation.request_id, Err(error.into()))),
        }
    }

    /// Returns one catalogue action's receipt, for `action.read` in the host's own scope.
    ///
    /// The receipt belongs to the actor that submitted the action, and nobody else reads it here.
    /// `None` means this catalogue holds no receipt for that actor's action.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::StorageUnavailable`] when the record cannot be read.
    pub async fn action_read(
        &self,
        actor_id: &ActorId,
        action_id: ActionId,
    ) -> Answer<Option<kr_protocol::receipt::ActionReadResult>> {
        let catalogue = self.catalogue.lock().await;
        let Some(record) = catalogue
            .receipt(&receipt_key(actor_id, action_id))
            .map_err(ProtocolError::from)?
        else {
            return Ok(None);
        };
        Ok(Some(action_read_result(actor_id, action_id, &record)?))
    }

    /// Serves one catalogue or plugin mutation and returns the frame it answers with.
    #[must_use]
    pub async fn write_frame(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        confirmations: Option<&dyn OwnerConfirmations>,
        admission: Arc<dyn Admission>,
    ) -> ControlFrame {
        frame(
            mutation.request_id,
            self.write(actor_id, mutation, method, confirmations, admission)
                .await,
        )
    }

    /// Serves one catalogue or plugin mutation as the owner acting directly, with no admission
    /// window to lapse.
    #[must_use]
    pub async fn write_frame_admitted(
        &self,
        mutation: &MutationRequest,
        method: Method,
        confirmations: Option<&dyn OwnerConfirmations>,
    ) -> ControlFrame {
        let actor = ActorId::new("kr:local").expect("a default actor");
        self.write_frame(
            &actor,
            mutation,
            method,
            confirmations,
            Arc::new(Owner::acting()),
        )
        .await
    }

    /// Serves one catalogue or plugin mutation.
    ///
    /// `confirmations` is where the two confirmed methods check the owner's decision. `None` is a
    /// host with no enrolled owner signer, which refuses them rather than performing them under
    /// the identity of whoever called.
    ///
    /// # Errors
    ///
    /// Returns the refusal the catalogue decided, under the catalogue's own code.
    pub async fn write(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        confirmations: Option<&dyn OwnerConfirmations>,
        admission: Arc<dyn Admission>,
    ) -> Answer<ParamsValue> {
        let mut catalogue = self.catalogue.lock().await;
        admission.check().map_err(ProtocolError::from)?;
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id)
            .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))?;
        let key = receipt_key(actor_id, mutation.action_id);
        let claim = ReceiptClaim {
            key: key.clone(),
            digest: digest.as_bytes().to_vec(),
            method: method.as_str().to_owned(),
            method_version: mutation.method_version.0,
            deadline_ms: admission.accepted_deadline_ms(),
        };
        // Claimed before anything is performed, and durably: a claim this host cannot record is a
        // refusal, because an action performed without one could be performed twice.
        match catalogue
            .claim(&claim, kr_ipc::now_ms().get())
            .map_err(ProtocolError::from)?
        {
            Claimed::Retained(record) => return answered(&record, &digest, mutation.action_id),
            Claimed::Fresh => {}
        }
        // Every change the action makes commits through this recording, so what it left behind
        // when it stops is known rather than guessed.
        let recording = Recording::new(&*admission);
        let outcome = self
            .perform_write(
                &mut catalogue,
                mutation,
                method,
                confirmations,
                &recording,
                key.clone(),
            )
            .await;
        let Err(error) = outcome else {
            return outcome;
        };
        // Refused only when nothing of the action committed; anything else is unknown, and the
        // answer names what the action left behind. The caller is told the same thing every later
        // resubmission is told.
        let failure = recording.failure(&error);
        // A settlement this host cannot record leaves the claim dispatching, and every later
        // reader is told that is unknown: the action is never performed again, and nobody is told
        // it had no effect on the strength of a record that was never written.
        let _ = catalogue.settle_failure(&key, &failure, kr_ipc::now_ms().get());
        Err(failure.into_answer())
    }

    async fn perform_write(
        &self,
        catalogue: &mut Catalogue,
        mutation: &MutationRequest,
        method: Method,
        confirmations: Option<&dyn OwnerConfirmations>,
        admission: &dyn Authority,
        key: ReceiptKey,
    ) -> Answer<ParamsValue> {
        let now = kr_ipc::now_ms().get();
        let mut answer: Option<ParamsValue> = None;
        match method {
            Method::CatalogueAdd => {
                let params: wire::CatalogueAddParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                let enrolment = enrolment_from(&params)?;
                // Adopting a root is the owner's act. The confirmation names this repository, this
                // root and this ceiling, so one obtained for a narrower enrolment does not adopt a
                // wider one. Re-anchoring an existing repository is two deliberate acts,
                // `catalogue.remove` and `catalogue.add`, so that a root never changes underneath
                // a repository somebody is already using.
                let plan = crate::sharing::CatalogueTrustPlan {
                    environment_id: params.environment_id,
                    catalogue_id: enrolment.id.to_string(),
                    root_digest: enrolment.root_digest().to_string(),
                    root_key_ids: enrolment
                        .root_key_ids()
                        .map_err(ProtocolError::from)?
                        .into_iter()
                        .collect(),
                    ceiling: params.ceiling.iter().cloned().collect(),
                };
                let action_digest = plan
                    .action_digest()
                    .map_err(|error| error.to_protocol_error())?;
                let (confirmations, confirmed) = confirm(
                    confirmations,
                    crate::sharing::CatalogueTrustPlan::sensitive_action(),
                    action_digest,
                    &params.owner_confirmation,
                    "enrolment",
                )?;
                let confirmed = Confirmed {
                    admission,
                    confirmed,
                    action_digest,
                    confirmations,
                    subject: "enrolment",
                };
                let mut render = settle(&mut answer, |transition| match transition {
                    Transition::Enrolled(view) => Ok(wire::CatalogueAddResult {
                        catalogue: summary(view),
                    }),
                    _ => Err(unexpected(transition)),
                });
                catalogue
                    .enrol_with(
                        enrolment,
                        &mut Change::settling(&confirmed, key, now, &mut render),
                    )
                    .map_err(ProtocolError::from)?;
            }
            Method::CatalogueSync => {
                let params: wire::CatalogueSyncParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                let id = repository_id(&params.catalogue_id)?;
                let mut render = settle(&mut answer, |transition| match transition {
                    Transition::Synced { outcome, .. } => Ok(wire::CatalogueSyncResult {
                        generation: outcome.generation,
                        entries: U64::new(outcome.entries as u64),
                        index_bytes: U64::new(outcome.index_bytes),
                        mirrored_payloads: U64::new(outcome.mirrored_payloads as u64),
                        delegations: outcome
                            .delegations
                            .iter()
                            .map(|(role, publisher_id)| wire::CatalogueDelegation {
                                role: role.clone(),
                                publisher_id: publisher_id.clone(),
                            })
                            .collect(),
                    }),
                    _ => Err(unexpected(transition)),
                });
                catalogue
                    .sync_with(&id, &mut Change::settling(admission, key, now, &mut render))
                    .await
                    .map_err(ProtocolError::from)?;
            }
            Method::CataloguePin => {
                let params: wire::CataloguePinParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                let id = repository_id(&params.catalogue_id)?;
                let mut render = settle(&mut answer, |transition| match transition {
                    Transition::Pinned(view) => Ok(wire::CataloguePinResult {
                        catalogue: summary(view),
                    }),
                    _ => Err(unexpected(transition)),
                });
                catalogue
                    .pin_with(
                        &id,
                        params.generation.0,
                        &mut Change::settling(admission, key, now, &mut render),
                    )
                    .map_err(ProtocolError::from)?;
            }
            Method::CatalogueRemove => {
                let params: wire::CatalogueRemoveParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                let id = repository_id(&params.catalogue_id)?;
                // A package installed from this repository stays installed, on the hash it was
                // installed at. Removing a repository is not a way to uninstall things somebody
                // is using, and the answer names what is still there.
                let mut render = settle(&mut answer, |transition| match transition {
                    Transition::Removed {
                        enrolment,
                        installed,
                    } => Ok(wire::CatalogueRemoveResult {
                        catalogue_id: enrolment.id.to_string(),
                        installed_packages: installed.clone(),
                    }),
                    _ => Err(unexpected(transition)),
                });
                catalogue
                    .remove_repository_with(
                        &id,
                        &mut Change::settling(admission, key, now, &mut render),
                    )
                    .map_err(ProtocolError::from)?;
            }
            Method::PluginInstall => {
                let params: wire::PluginInstallParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                let id = repository_id(&params.catalogue_id)?;
                let version = version(&params.version)?;
                let digest = digest(&params.package_digest)?;
                let grant = grant_from(&params.grant)?;
                // An installation that may do more than the one it replaces, or than its
                // repository's ceiling permits by itself, and every release that installs a native
                // bridge, is the owner's decision, and the catalogue decides whether this one is.
                // The confirmation names the repository and its ceiling with the release, the hash
                // and the grant, and is spent the way `plugin.grant` spends one: accepted and
                // consumed here, and asked again inside the commit.
                let (confirmed, decided_under) = match params.owner_confirmation.as_ref() {
                    None => (None, None),
                    Some(proof) => {
                        let enrolment = catalogue
                            .repository(&id)
                            .map_err(ProtocolError::from)?
                            .ok_or_else(|| {
                                ProtocolError::new(
                                    ErrorCode::ResourceUnavailable,
                                    format!("{id} is not enrolled"),
                                )
                            })?;
                        let plan = crate::sharing::PluginInstallPlan {
                            environment_id: params.environment_id,
                            catalogue_id: id.to_string(),
                            ceiling: enrolment
                                .ceiling
                                .capabilities()
                                .into_iter()
                                .map(|capability| capability.as_str().to_owned())
                                .collect(),
                            plugin_id: params.plugin_id.clone(),
                            version: version.to_string(),
                            package_digest: digest.to_string(),
                            grant: params.grant.iter().cloned().collect(),
                        };
                        let action_digest = plan
                            .action_digest()
                            .map_err(|error| error.to_protocol_error())?;
                        let (confirmations, confirmed) = confirm(
                            confirmations,
                            crate::sharing::PluginInstallPlan::sensitive_action(),
                            action_digest,
                            proof,
                            "installation",
                        )?;
                        (
                            Some(Confirmed {
                                admission,
                                confirmed,
                                action_digest,
                                confirmations,
                                subject: "installation",
                            }),
                            // The ceiling the owner was shown, which the catalogue holds the
                            // installation to once the repository is held and inside the commit.
                            Some(enrolment.ceiling),
                        )
                    }
                };
                let authority: &dyn Authority = match &confirmed {
                    Some(confirmed) => confirmed,
                    None => admission,
                };
                let mut render = settle(&mut answer, |transition| match transition {
                    Transition::Installed(view) => Ok(wire::PluginInstallResult {
                        plugin: plugin_summary(view)?,
                        capabilities: grants(&view.installation.requested, &view.decisions)?,
                    }),
                    _ => Err(unexpected(transition)),
                });
                catalogue
                    .install_with(
                        &id,
                        params.environment_id,
                        &params.plugin_id,
                        &version,
                        digest,
                        grant,
                        decided_under.as_ref(),
                        &mut Change::settling(authority, key, now, &mut render),
                    )
                    .await
                    .map_err(ProtocolError::from)?;
            }
            Method::PluginRemove => {
                let params: wire::PluginRemoveParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                let mut render = settle(&mut answer, |transition| match transition {
                    Transition::Uninstalled {
                        plugin_id,
                        closed_bindings,
                    } => Ok(wire::PluginRemoveResult {
                        plugin_id: plugin_id.clone(),
                        closed_bindings: U64::new(*closed_bindings),
                    }),
                    _ => Err(unexpected(transition)),
                });
                catalogue
                    .uninstall_with(
                        params.environment_id,
                        &params.plugin_id,
                        &mut Change::settling(admission, key, now, &mut render),
                    )
                    .map_err(ProtocolError::from)?;
            }
            Method::PluginPin => {
                let params: wire::PluginPinParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                let pin = params.package_digest.0.as_deref().map(digest).transpose()?;
                let mut render = settle(&mut answer, |transition| match transition {
                    Transition::Changed(view) => Ok(wire::PluginPinResult {
                        plugin: plugin_summary(view)?,
                    }),
                    _ => Err(unexpected(transition)),
                });
                catalogue
                    .pin_package_with(
                        params.environment_id,
                        &params.plugin_id,
                        pin,
                        &mut Change::settling(admission, key, now, &mut render),
                    )
                    .map_err(ProtocolError::from)?;
            }
            Method::PluginEnable | Method::PluginDisable => {
                let params: wire::PluginEnableParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                let mut render = settle(&mut answer, |transition| match transition {
                    Transition::Changed(view) => Ok(wire::PluginEnableResult {
                        plugin: plugin_summary(view)?,
                    }),
                    _ => Err(unexpected(transition)),
                });
                catalogue
                    .set_enabled_with(
                        params.environment_id,
                        &params.plugin_id,
                        method == Method::PluginEnable,
                        &mut Change::settling(admission, key, now, &mut render),
                    )
                    .await
                    .map_err(ProtocolError::from)?;
            }
            Method::PluginGrant => {
                let params: wire::PluginGrantParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                let grant = grant_from(&params.grant)?;
                // The grant is about the release the owner was shown. An installation that moved
                // on is a different decision, so the digest is checked before the confirmation is
                // even read rather than the change being applied to whatever is installed now.
                let installed = catalogue
                    .installation(params.environment_id, &params.plugin_id)
                    .map_err(ProtocolError::from)?
                    .ok_or_else(|| {
                        ProtocolError::new(
                            ErrorCode::ResourceUnavailable,
                            format!("{} is not installed in this environment", params.plugin_id),
                        )
                    })?;
                let named = digest(&params.package_digest)?;
                if installed.package_digest != named {
                    return Err(ProtocolError::new(
                        ErrorCode::IdConflict,
                        format!(
                            "{} is installed at {} and this grant is for {}",
                            params.plugin_id, installed.package_digest, named
                        ),
                    ));
                }
                let plan = crate::sharing::PluginGrantPlan {
                    environment_id: params.environment_id,
                    plugin_id: params.plugin_id.clone(),
                    version: installed.version.to_string(),
                    package_digest: named.to_string(),
                    grant: params.grant.iter().cloned().collect(),
                };
                let action_digest = plan
                    .action_digest()
                    .map_err(|error| error.to_protocol_error())?;
                let (confirmations, confirmed) = confirm(
                    confirmations,
                    crate::sharing::PluginGrantPlan::sensitive_action(),
                    action_digest,
                    &params.owner_confirmation,
                    "grant",
                )?;
                let confirmed = Confirmed {
                    admission,
                    confirmed,
                    action_digest,
                    confirmations,
                    subject: "grant",
                };
                let mut render = settle(&mut answer, |transition| match transition {
                    Transition::Changed(view) => Ok(wire::PluginGrantResult {
                        plugin: plugin_summary(view)?,
                        capabilities: grants(&view.installation.requested, &view.decisions)?,
                    }),
                    _ => Err(unexpected(transition)),
                });
                // The grant is bound to the release the owner was shown, and the catalogue refuses
                // it inside the commit if the installation moved to another one meanwhile.
                catalogue
                    .set_grant_with(
                        params.environment_id,
                        &params.plugin_id,
                        named,
                        grant,
                        &mut Change::settling(&confirmed, key, now, &mut render),
                    )
                    .map_err(ProtocolError::from)?;
            }
            _ => {
                return Err(ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    format!("{} is not a mutation this daemon serves", method.as_str()),
                ));
            }
        }
        answer.ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::OutcomeUnknown,
                format!(
                    "{} was performed and its answer was not recorded",
                    method.as_str()
                ),
            )
        })
    }

    /// Refuses a request for an environment this daemon does not own.
    fn check_environment(&self, environment_id: EnvironmentId) -> Answer<()> {
        if environment_id == self.environment_id {
            return Ok(());
        }
        Err(ProtocolError::new(
            ErrorCode::InvalidArgument,
            format!("this daemon owns environment {}", self.environment_id),
        ))
    }
}

/// The receipt key one actor's action is recorded under.
fn receipt_key(actor_id: &ActorId, action_id: ActionId) -> ReceiptKey {
    ReceiptKey::new(actor_id.as_str(), action_id.to_string())
}

/// Returns the answer a retained receipt gives a resubmission of the same action.
fn answered(
    record: &ReceiptRecord,
    digest: &Digest256,
    action_id: ActionId,
) -> Answer<ParamsValue> {
    if record.claim.digest != digest.as_bytes() {
        return Err(ProtocolError::new(
            ErrorCode::IdConflict,
            format!("action {action_id} was already used with different parameters"),
        ));
    }
    match record.state {
        ReceiptState::Applied => match &record.result {
            Some(bytes) => decode_result(bytes),
            None => Err(ProtocolError::new(
                ErrorCode::StorageUnavailable,
                format!("action {action_id} applied and its answer is not retained"),
            )),
        },
        ReceiptState::Refused | ReceiptState::Unknown | ReceiptState::Rejected => {
            Err(record.error.clone().unwrap_or_else(|| {
                ProtocolError::new(
                    ErrorCode::OutcomeUnknown,
                    format!("action {action_id} has no retained answer"),
                )
            }))
        }
        ReceiptState::Received | ReceiptState::Accepted | ReceiptState::Dispatching => {
            Err(ProtocolError::new(
                ErrorCode::OutcomeUnknown,
                format!(
                    "action {action_id} is being performed or was interrupted; it is not \
                     performed again, and action.read reports where it stands"
                ),
            ))
        }
    }
}

/// Builds the `action.read` answer for one retained catalogue receipt.
fn action_read_result(
    actor_id: &ActorId,
    action_id: ActionId,
    record: &ReceiptRecord,
) -> Answer<kr_protocol::receipt::ActionReadResult> {
    let digest: [u8; 32] = record.claim.digest.as_slice().try_into().map_err(|_| {
        ProtocolError::new(
            ErrorCode::StorageUnavailable,
            format!("action {action_id}'s receipt holds a digest this build cannot read"),
        )
    })?;
    let result = match (record.state, &record.result) {
        (ReceiptState::Applied, Some(bytes)) => Nullable(Some(decode_result(bytes)?)),
        _ => Nullable(None),
    };
    Ok(kr_protocol::receipt::ActionReadResult {
        receipt: kr_protocol::receipt::Receipt {
            action_id,
            actor_id: actor_id.clone(),
            method: kr_protocol::method::MethodName::new(&record.claim.method).map_err(
                |error| ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string()),
            )?,
            method_version: kr_protocol::method::MethodVersion(record.claim.method_version),
            revision: U64::new(record.revision),
            state: record.state,
            reason: Nullable(None),
            payload_digest: Digest256::from_bytes(digest),
            accepted_deadline_ms: Nullable(
                record
                    .claim
                    .deadline_ms
                    .map(kr_protocol::scalars::TimestampMs::new),
            ),
            error: Nullable(record.error.clone()),
            updated_at_ms: kr_protocol::scalars::TimestampMs::new(record.updated_at_ms),
        },
        result,
    })
}

fn decode_result(bytes: &[u8]) -> Answer<ParamsValue> {
    kr_cbor::decode(bytes, &kr_cbor::Limits::DEFAULT)
        .map(ParamsValue::new)
        .map_err(|error| ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string()))
}

/// Makes the settlement that renders a method's answer from what its change did.
///
/// The answer is rendered inside the change's own transaction and recorded there, and the same
/// value is what the caller is answered with, so the first answer and every retained one are the
/// same bytes.
fn settle<'a, T, F>(
    answer: &'a mut Option<ParamsValue>,
    render: F,
) -> impl FnMut(&Transition) -> CatalogueResult<Vec<u8>> + Send + 'a
where
    T: serde::Serialize,
    F: Fn(&Transition) -> Answer<T> + Send + 'a,
{
    move |transition| {
        let value = render(transition)
            .and_then(|result| encode(&result))
            .map_err(CatalogueError::Refused)?;
        let bytes = kr_cbor::encode(value.as_value());
        *answer = Some(value);
        Ok(bytes)
    }
}

fn unexpected(transition: &Transition) -> ProtocolError {
    ProtocolError::new(
        ErrorCode::StorageUnavailable,
        format!("the catalogue reported a change this method does not make: {transition:?}"),
    )
}

/// What a caller is told about one repository.
fn summary(view: &RepositoryView) -> wire::CatalogueSummary {
    let enrolment = &view.enrolment;
    wire::CatalogueSummary {
        catalogue_id: enrolment.id.to_string(),
        kind: kind_of(enrolment.kind),
        metadata_url: enrolment.metadata_url.to_string(),
        targets_url: enrolment.targets_url.to_string(),
        root_digest: enrolment.root_digest().to_string(),
        generation: Nullable(
            view.active
                .map(|active| RepositoryGeneration::new(active.generation)),
        ),
        pinned_generation: Nullable(enrolment.pinned_generation),
        budgets: wire::CatalogueBudgets {
            metadata_bytes: enrolment.budgets.metadata_bytes,
            metadata_entries: enrolment.budgets.metadata_entries,
            retained_generations: enrolment.budgets.retained_generations,
            retained_metadata_bytes: enrolment.budgets.retained_metadata_bytes,
            payload_cache_bytes: enrolment.budgets.payload_cache_bytes,
            full_offline_mirror: enrolment.budgets.full_offline_mirror,
        },
        ceiling: enrolment
            .ceiling
            .capabilities()
            .into_iter()
            .map(|capability| capability.as_str().to_owned())
            .collect(),
        entries: U64::new(view.active.map_or(0, |active| active.entries)),
        synced_at_ms: Nullable(None),
    }
}

/// What a caller is told about one installed package.
fn plugin_summary(view: &InstallationView) -> Answer<wire::PluginSummary> {
    let installation = &view.installation;
    Ok(wire::PluginSummary {
        plugin_id: plugin_id_of(installation)?,
        catalogue_id: installation.repository.to_string(),
        version: installation.version.to_string(),
        package_digest: installation.package_digest.to_string(),
        environment_id: installation.environment_id,
        enabled: installation.enabled,
        pinned: installation.pinned,
        revoked: view.revoked,
        live_bindings: U64::new(view.live_bindings),
    })
}

/// The evidence an installed package is described with when its repository publishes nothing
/// about it now: what the installation itself declared, untested.
fn fallback_evidence(
    installation: &Installation,
    generation: u64,
) -> Answer<Vec<wire::PluginCapabilityEvidence>> {
    let now = kr_ipc::now_ms();
    let revision = kr_protocol::ids::CapabilityRevision::new(generation.max(1));
    installation
        .requested
        .iter()
        .map(|request| {
            Ok(wire::PluginCapabilityEvidence {
                capability: capability_id(request.capability)?,
                capability_version: installation.version.to_string(),
                revision,
                subject: wire::PluginEvidenceSubject {
                    environment_id: installation.environment_id,
                    application: Nullable::null(),
                    terminal: Nullable::null(),
                    desktop_generation: Nullable::null(),
                },
                state: wire::PluginCapabilityState::NotTested,
                source: wire::PluginEvidenceSource::PackageDeclaration,
                package_digest: installation.package_digest.to_string(),
                profile_digest: Nullable::null(),
                invalidated_by: Vec::new(),
                disabled_reason: Nullable(Some(
                    "the package is installed offline and the catalogue has no qualification \
                     data for it"
                        .to_owned(),
                )),
                observed_at_ms: now,
            })
        })
        .collect()
}

fn grants(
    requested: &[kr_plugin_sdk::capability::CapabilityRequest],
    decisions: &[kr_plugin_catalogue::CapabilityDecision],
) -> Answer<Vec<wire::PluginCapabilityGrant>> {
    decisions
        .iter()
        .map(|decision| {
            let reason = requested
                .iter()
                .find(|request| request.capability == decision.capability)
                .map(|request| request.reason.as_str().to_owned())
                .unwrap_or_default();
            Ok(wire::PluginCapabilityGrant {
                capability: capability_id(decision.capability)?,
                requirement: requirement_of(decision.requirement),
                permitted: decision.permitted,
                reason,
            })
        })
        .collect()
}

fn evidence(
    entry: &kr_plugin_sdk::catalogue::IndexEntry,
    installation: &Installation,
    generation: u64,
) -> Answer<Vec<wire::PluginCapabilityEvidence>> {
    let now = kr_protocol::scalars::TimestampMs::new(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(0),
    );
    let revision = kr_protocol::ids::CapabilityRevision::new(generation.max(1));
    let mut records = Vec::new();
    for qualification in &entry.qualification {
        match kr_plugin_catalogue::evidence::from_qualification(
            entry,
            installation,
            qualification,
            revision,
            now,
        ) {
            Ok(record) => records.push(wire_evidence(&record)?),
            // A qualification this host will not read is reported as refused rather than left
            // out. Dropping it would make a publisher's rejected claim look the same as no claim
            // at all, and the person deciding whether to trust this package would not be told.
            Err(refusal) => records.push(wire::PluginCapabilityEvidence {
                capability: qualification.capability_id.clone(),
                capability_version: qualification.capability_version.to_string(),
                revision,
                subject: wire::PluginEvidenceSubject {
                    environment_id: installation.environment_id,
                    application: Nullable(Some(qualification.subject.to_string())),
                    terminal: Nullable(None),
                    desktop_generation: Nullable(None),
                },
                state: wire::PluginCapabilityState::NotTested,
                source: wire::PluginEvidenceSource::SignedRecord,
                package_digest: installation.package_digest.to_string(),
                profile_digest: Nullable(Some(qualification.profile_digest.to_string())),
                invalidated_by: vec![wire::PluginInvalidationTrigger::ProfileChanged],
                disabled_reason: Nullable(Some(format!(
                    "this host refused the publisher's qualification: {refusal}"
                ))),
                observed_at_ms: now,
            }),
        }
    }
    // What the installed package asks for is what its own manifest declared. The current entry is
    // a later statement about the same hash, and it does not add capabilities to answer for.
    for request in &installation.requested {
        let id = capability_id(request.capability)?;
        if records.iter().any(|record| record.capability == id) {
            continue;
        }
        let record = kr_plugin_catalogue::evidence::untested(
            installation,
            request.capability,
            revision,
            now,
        )
        .map_err(ProtocolError::from)?;
        records.push(wire_evidence(&record)?);
    }
    Ok(records)
}

fn wire_evidence(
    record: &kr_plugin_sdk::capability::CapabilityEvidence,
) -> Answer<wire::PluginCapabilityEvidence> {
    use kr_plugin_sdk::capability::{CapabilityState, EvidenceSource, InvalidationTrigger};
    Ok(wire::PluginCapabilityEvidence {
        capability: record.capability_id.clone(),
        capability_version: record.capability_version.to_string(),
        revision: record.revision,
        subject: wire::PluginEvidenceSubject {
            environment_id: record.subject.environment_id,
            application: Nullable(
                record
                    .subject
                    .application
                    .0
                    .as_ref()
                    .map(|label| label.as_str().to_owned()),
            ),
            terminal: Nullable(
                record
                    .subject
                    .terminal
                    .0
                    .as_ref()
                    .map(|label| label.as_str().to_owned()),
            ),
            desktop_generation: Nullable(
                record
                    .subject
                    .desktop_generation
                    .0
                    .as_ref()
                    .map(|label| label.as_str().to_owned()),
            ),
        },
        state: match record.state {
            CapabilityState::QualifiedAvailable => wire::PluginCapabilityState::QualifiedAvailable,
            CapabilityState::VersionQualified => wire::PluginCapabilityState::VersionQualified,
            CapabilityState::MissingInstallation => {
                wire::PluginCapabilityState::MissingInstallation
            }
            CapabilityState::PermissionRequired => wire::PluginCapabilityState::PermissionRequired,
            CapabilityState::Incompatible => wire::PluginCapabilityState::Incompatible,
            CapabilityState::TemporarilyUnavailable => {
                wire::PluginCapabilityState::TemporarilyUnavailable
            }
            CapabilityState::NotTested => wire::PluginCapabilityState::NotTested,
        },
        source: match record.source {
            EvidenceSource::HostProbe => wire::PluginEvidenceSource::HostProbe,
            EvidenceSource::LiveBinding => wire::PluginEvidenceSource::LiveBinding,
            EvidenceSource::SignedRecord => wire::PluginEvidenceSource::SignedRecord,
            EvidenceSource::PackageDeclaration => wire::PluginEvidenceSource::PackageDeclaration,
        },
        package_digest: record
            .identity
            .package_digest
            .0
            .map(|digest| digest.to_string())
            .unwrap_or_default(),
        profile_digest: Nullable(
            record
                .identity
                .profile_digest
                .0
                .map(|digest| digest.to_string()),
        ),
        invalidated_by: record
            .invalidated_by
            .iter()
            .map(|trigger| match trigger {
                InvalidationTrigger::BinaryChanged => {
                    wire::PluginInvalidationTrigger::BinaryChanged
                }
                InvalidationTrigger::BindingChanged => {
                    wire::PluginInvalidationTrigger::BindingChanged
                }
                InvalidationTrigger::SchemaChanged => {
                    wire::PluginInvalidationTrigger::SchemaChanged
                }
                InvalidationTrigger::OsPermissionChanged => {
                    wire::PluginInvalidationTrigger::OsPermissionChanged
                }
                InvalidationTrigger::DesktopGenerationChanged => {
                    wire::PluginInvalidationTrigger::DesktopGenerationChanged
                }
                InvalidationTrigger::ProfileChanged => {
                    wire::PluginInvalidationTrigger::ProfileChanged
                }
            })
            .collect(),
        disabled_reason: Nullable(
            record
                .disabled_reason
                .0
                .as_ref()
                .map(|reason| reason.as_str().to_owned()),
        ),
        observed_at_ms: record.observed_at,
    })
}

fn capability_id(capability: PluginCapability) -> Answer<kr_protocol::ids::CapabilityId> {
    kr_plugin_catalogue::evidence::capability_id(capability).map_err(ProtocolError::from)
}

const fn requirement_of(
    requirement: kr_plugin_catalogue::GrantRequirement,
) -> wire::PluginGrantRequirement {
    use kr_plugin_catalogue::GrantRequirement as Source;
    match requirement {
        Source::WithinCeiling => wire::PluginGrantRequirement::WithinCeiling,
        Source::RepositoryGrant => wire::PluginGrantRequirement::RepositoryGrant,
        Source::InstallationGrant => wire::PluginGrantRequirement::InstallationGrant,
        Source::ConfirmedInstallationGrant => {
            wire::PluginGrantRequirement::ConfirmedInstallationGrant
        }
    }
}

const fn kind_of(kind: RepositoryKind) -> wire::CatalogueKind {
    match kind {
        RepositoryKind::Official => wire::CatalogueKind::Official,
        RepositoryKind::Vendor => wire::CatalogueKind::Vendor,
        RepositoryKind::Community => wire::CatalogueKind::Community,
        RepositoryKind::Local => wire::CatalogueKind::Local,
        RepositoryKind::Mirror => wire::CatalogueKind::Mirror,
    }
}

/// Accepts the owner's confirmation of one exact action, or refuses the method.
///
/// The challenge is consumed here, once. What the change asks again at its commit is whether the
/// accepted confirmation still covers it, which reads without consuming anything.
///
/// A host with no enrolled owner signer has no way to obtain a confirmation, and section 10 does
/// not let it fall back to the identity of whoever called. It refuses, and says why.
fn confirm<'a>(
    confirmations: Option<&'a dyn OwnerConfirmations>,
    action: kr_protocol::pairing::SensitiveAction,
    action_digest: Digest256,
    proof: &kr_protocol::pairing::OwnerConfirmationProof,
    subject: &str,
) -> Answer<(&'a dyn OwnerConfirmations, ConfirmedAction)> {
    let confirmations = confirmations.ok_or_else(|| {
        ProtocolError::new(
            ErrorCode::PermissionDenied,
            format!(
                "this {subject} needs the owner's confirmation and this host has no enrolled \
                 owner signer to check one against"
            ),
        )
    })?;
    let confirmed = confirmations
        .accept(action, action_digest, proof)
        .map_err(|error| error.to_protocol_error())?;
    Ok((confirmations, confirmed))
}

fn enrolment_from(params: &wire::CatalogueAddParams) -> Answer<Enrolment> {
    let id = repository_id(&params.catalogue_id)?;
    let kind = match params.kind {
        wire::CatalogueKind::Official => RepositoryKind::Official,
        wire::CatalogueKind::Vendor => RepositoryKind::Vendor,
        wire::CatalogueKind::Community => RepositoryKind::Community,
        wire::CatalogueKind::Local => RepositoryKind::Local,
        wire::CatalogueKind::Mirror => RepositoryKind::Mirror,
    };
    let metadata_url = location(&params.metadata_url)?;
    let targets_url = location(&params.targets_url)?;
    let root = decode_root(&params.root)?;
    let mut ceiling = Vec::new();
    for name in &params.ceiling {
        ceiling.push(capability_from_str(name).map_err(ProtocolError::from)?);
    }
    let budgets = kr_plugin_sdk::limits::RepositoryBudgets {
        metadata_bytes: params.budgets.metadata_bytes,
        metadata_entries: params.budgets.metadata_entries,
        retained_generations: params.budgets.retained_generations,
        retained_metadata_bytes: params.budgets.retained_metadata_bytes,
        payload_cache_bytes: params.budgets.payload_cache_bytes,
        full_offline_mirror: params.budgets.full_offline_mirror,
    };
    Enrolment::new(
        id,
        kind,
        metadata_url,
        targets_url,
        root,
        budgets,
        CapabilityCeiling::with(ceiling),
    )
    .map_err(ProtocolError::from)
}

fn grant_from(names: &[String]) -> Answer<InstallationGrant> {
    let mut grant = InstallationGrant::none();
    for name in names {
        grant.add(capability_from_str(name).map_err(ProtocolError::from)?);
    }
    Ok(grant)
}

fn repository_id(text: &str) -> Answer<RepositoryId> {
    RepositoryId::new(text).map_err(ProtocolError::from)
}

fn location(text: &str) -> Answer<url::Url> {
    url::Url::parse(text).map_err(|source| {
        ProtocolError::new(
            ErrorCode::InvalidArgument,
            format!("{text} is not a repository location: {source}"),
        )
    })
}

fn decode_root(text: &str) -> Answer<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|source| {
            ProtocolError::new(
                ErrorCode::InvalidArgument,
                format!("the trust root is not base64: {source}"),
            )
        })
}

fn version(text: &str) -> Answer<PackageVersion> {
    PackageVersion::parse(text).map_err(|source| {
        ProtocolError::new(
            ErrorCode::InvalidArgument,
            format!("{text} is not a package version: {source}"),
        )
    })
}

fn digest(text: &str) -> Answer<PayloadDigest> {
    PayloadDigest::parse(text).map_err(|source| {
        ProtocolError::new(
            ErrorCode::InvalidArgument,
            format!("{text} is not a package hash: {source}"),
        )
    })
}

fn plugin_id_of(installation: &Installation) -> Answer<PluginId> {
    PluginId::new(installation.plugin_id.to_string()).map_err(|source| {
        ProtocolError::new(
            ErrorCode::StorageUnavailable,
            format!("an installed package has an unreadable identifier: {source}"),
        )
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

/// Returns the environment a mutation's parameters name.
fn subject<T>(params: &ParamsValue) -> crate::Result<EnvironmentId>
where
    T: kr_protocol::wire::WireMessage + HasEnvironment,
{
    let params: T = params
        .to_typed()
        .map_err(|error| crate::ControllerError::InvalidArgument(error.to_string()))?;
    Ok(params.environment_id())
}

/// What every catalogue and plugin mutation names.
trait HasEnvironment {
    /// Returns the environment the request acts in.
    fn environment_id(&self) -> EnvironmentId;
}

macro_rules! has_environment {
    ($($type:ty),+ $(,)?) => {
        $(
            impl HasEnvironment for $type {
                fn environment_id(&self) -> EnvironmentId {
                    self.environment_id
                }
            }
        )+
    };
}

has_environment!(
    wire::CatalogueAddParams,
    wire::CatalogueSyncParams,
    wire::CataloguePinParams,
    wire::CatalogueRemoveParams,
    wire::PluginInstallParams,
    wire::PluginRemoveParams,
    wire::PluginPinParams,
    wire::PluginEnableParams,
    wire::PluginGrantParams,
);

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

    /// KR-REQ-26.14: a repository address is fetched through the proxy this host selected. The
    /// proxy is asked for a tunnel to the repository, and when it refuses, the fetch fails rather
    /// than going around it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_repository_is_fetched_through_the_proxy_this_host_selected() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            0,
        )))
        .await
        .expect("a loopback port");
        let proxy_port = listener.local_addr().expect("an address").port();
        let asked = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let recorded = Arc::clone(&asked);
        let proxy = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read_u8().await {
                        Ok(byte) => head.push(byte),
                        Err(_) => break,
                    }
                }
                let line = String::from_utf8_lossy(&head)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                recorded
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(line);
                let _ = stream
                    .write_all(b"HTTP/1.1 403 Refused\r\ncontent-length: 0\r\n\r\n")
                    .await;
            }
        });
        // Nothing listens at the repository's address: a fetch that went around the proxy would
        // fail too, so what the proxy was asked is the whole of the evidence.
        let unused = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let repository = unused.local_addr().expect("an address");
        drop(unused);

        let transport = repository_transport(Some(
            &format!("http://127.0.0.1:{proxy_port}")
                .parse()
                .expect("a proxy address"),
        ));
        let Ok(stream) = tough::Transport::fetch(
            &transport,
            format!("https://{repository}/1.root.json")
                .parse()
                .expect("an address"),
        )
        .await
        else {
            panic!("the fetch answered without a stream");
        };
        let fetched = futures_util::TryStreamExt::try_collect::<Vec<tough::Bytes>>(stream).await;
        proxy.abort();
        assert!(fetched.is_err(), "the proxy refused every tunnel");
        let asked = asked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let tunnel = format!("CONNECT {repository} HTTP/1.1");
        assert!(
            !asked.is_empty() && asked.iter().all(|line| *line == tunnel),
            "{asked:?}"
        );
    }

    /// A loopback server that answers every request with `status` and `body`, and counts them.
    async fn answering(
        status: u16,
        body: &'static [u8],
    ) -> (
        String,
        Arc<std::sync::atomic::AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            0,
        )))
        .await
        .expect("a loopback port");
        let origin = format!(
            "http://127.0.0.1:{}",
            listener.local_addr().expect("an address").port()
        );
        let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&asked);
        let serving = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read_u8().await {
                        Ok(byte) => head.push(byte),
                        Err(_) => break,
                    }
                }
                let answer = format!(
                    "HTTP/1.1 {status} Answer\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(answer.as_bytes()).await;
                let _ = stream.write_all(body).await;
            }
        });
        (origin, asked, serving)
    }

    /// Fetches `address` through the transport a host with no proxy selected builds, and reads
    /// what arrives.
    ///
    /// The fetch itself always answers with a stream, and what the request came to arrives
    /// through it: the update client reads an error from the fetch as the file not being there.
    async fn fetched(address: &str) -> Result<Vec<u8>, tough::TransportError> {
        use futures_util::TryStreamExt as _;

        let Ok(stream) = tough::Transport::fetch(
            &repository_transport(None),
            address.parse().expect("an address"),
        )
        .await
        else {
            panic!("the fetch of {address} answered without a stream");
        };
        let chunks: Vec<tough::Bytes> = stream.try_collect().await?;
        Ok(chunks.concat())
    }

    /// A file a repository's server answers 403, 404 or 410 for is not there, which is how the
    /// update client finds the newest signed root. It is asked for once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_file_its_server_answers_403_404_or_410_for_is_not_there() {
        for status in [403, 404, 410] {
            let (origin, asked, serving) = answering(status, b"").await;
            let error = fetched(&format!("{origin}/2.root.json"))
                .await
                .expect_err("no such file");
            assert_eq!(
                error.kind(),
                tough::TransportErrorKind::FileNotFound,
                "{status}: {error}"
            );
            assert_eq!(
                asked.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "{status}"
            );
            serving.abort();
        }
    }

    /// A server that fails is asked again, four times in all, and then the fetch fails.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_server_that_fails_is_asked_again_and_then_the_fetch_fails() {
        let (origin, asked, serving) = answering(503, b"").await;
        let error = fetched(&format!("{origin}/timestamp.json"))
            .await
            .expect_err("the server keeps failing");
        assert_eq!(error.kind(), tough::TransportErrorKind::Other, "{error}");
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 4);
        serving.abort();
    }

    /// A file the server has is read whole, as it arrives.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_file_the_server_has_is_read_whole() {
        let (origin, asked, serving) = answering(200, b"{\"signed\": {}}").await;
        let body = fetched(&format!("{origin}/timestamp.json"))
            .await
            .expect("the file");
        assert_eq!(body, b"{\"signed\": {}}");
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 1);
        serving.abort();
    }

    /// A host whose certificate verification cannot be set up still reads a repository on its
    /// own disk, and says why whenever it is asked to fetch one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_host_that_cannot_verify_reads_its_disk_and_says_why_it_fetches_nothing() {
        use futures_util::TryStreamExt as _;

        let transport = RepositoryTransport::local_only("no certificate store");
        let directory = tempfile::tempdir().expect("a directory");
        let file = directory.path().join("1.root.json");
        std::fs::write(&file, b"{}").expect("a file");
        let read: Vec<tough::Bytes> = tough::Transport::fetch(
            &transport,
            url::Url::from_file_path(&file).expect("a file address"),
        )
        .await
        .expect("the file")
        .try_collect()
        .await
        .expect("its bytes");
        assert_eq!(read.concat(), b"{}");
        let Ok(stream) = tough::Transport::fetch(
            &transport,
            "https://plugins.example/1.root.json"
                .parse()
                .expect("an address"),
        )
        .await
        else {
            panic!("the fetch answered without a stream");
        };
        let refused = stream
            .try_collect::<Vec<tough::Bytes>>()
            .await
            .expect_err("nothing is fetched");
        assert!(
            std::error::Error::source(&refused)
                .is_some_and(|cause| cause.to_string() == "no certificate store"),
            "{refused:?}"
        );
    }

    #[test]
    fn the_daemon_serves_the_two_plugin_groups() {
        for method in [
            Method::CatalogueList,
            Method::CatalogueAdd,
            Method::CatalogueSync,
            Method::CataloguePin,
            Method::CatalogueRemove,
            Method::PluginList,
            Method::PluginInstall,
            Method::PluginRemove,
            Method::PluginPin,
            Method::PluginEnable,
            Method::PluginDisable,
            Method::PluginGrant,
            Method::PluginCapabilities,
        ] {
            assert!(CatalogueModule::serves(method), "{}", method.as_str());
        }
        // A plugin action is the worker's, not this daemon's.
        assert!(!CatalogueModule::serves(Method::PluginActionInvoke));
        assert!(!CatalogueModule::serves(Method::SessionCreate));
    }

    #[test]
    fn every_method_in_the_two_groups_has_one_exhaustive_authority_entry() {
        use kr_protocol::actor::ActorIngress;
        use kr_protocol::authority::AuthorityDecision;
        use kr_protocol::method::{MethodVersion, decide};

        for entry in kr_protocol::method::REGISTRY {
            if !matches!(
                entry.group,
                MethodGroup::PluginCatalogues | MethodGroup::Plugins
            ) {
                continue;
            }
            let AuthorityDecision::Listed(listed) =
                decide(entry.name, MethodVersion::V1, ActorIngress::LocalIpc)
            else {
                panic!("{} is not listed", entry.name);
            };
            assert_eq!(listed.name, entry.name);
            // Every mutating member of both groups requires host management.
            if listed.effect == kr_protocol::authority::EffectClass::Write {
                assert!(
                    listed.required_rights.iter().any(|required| matches!(
                        required.authority,
                        kr_protocol::authority::RequiredAuthority::Right {
                            right: kr_protocol::rights::ActionRight::HostManage
                        }
                    )),
                    "{} does not require host.manage",
                    entry.name
                );
            }
        }
    }

    #[test]
    fn a_new_root_always_needs_the_owners_confirmation() {
        use kr_protocol::authority::ConfirmationRequirement;
        let entry = kr_protocol::method::REGISTRY
            .iter()
            .find(|entry| entry.name == "catalogue.add")
            .expect("catalogue.add is registered");
        assert_eq!(entry.confirmation, ConfirmationRequirement::Always);
        let sync = kr_protocol::method::REGISTRY
            .iter()
            .find(|entry| entry.name == "catalogue.sync")
            .expect("catalogue.sync is registered");
        assert_eq!(
            sync.confirmation,
            ConfirmationRequirement::WhenEnlargingAuthority
        );
    }

    #[test]
    fn a_catalogue_refusal_keeps_its_own_code() {
        use kr_plugin_catalogue::CatalogueError;
        assert_eq!(
            ProtocolError::from(CatalogueError::UnavailableOffline {
                detail: "component.wasm is not cached here".to_owned(),
            })
            .code,
            ErrorCode::PackageUnavailableOffline
        );
        assert_eq!(
            ProtocolError::from(CatalogueError::Untrusted {
                detail: "the root is not trusted".to_owned(),
            })
            .code,
            ErrorCode::RepositoryUntrusted
        );
    }
}
