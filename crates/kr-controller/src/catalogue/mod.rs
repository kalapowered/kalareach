//! The plugin catalogue and plugin method groups, hosted by the control daemon.
//!
//! The daemon owns the admission and the environment; `kr-plugin-runtime` owns the trust roots,
//! the budgets, the signed snapshot, the packages and what an installed package may do. What this
//! module adds is the part that has to be the daemon's.
//!
//! * Every method arrives through the daemon's ordinary path. A read is checked against current
//!   authority, a mutation carries an action window and is checked against the method registry,
//!   and neither has an admission path of its own.
//! * The checks section 23 names for these two rows happen here, against the service's answers:
//!   the repository's root, generation and budgets for the catalogue group, and the package hash,
//!   the repository ceiling, the environment and the bindings for the plugin group.
//! * Adopting a trust root and granting a capability are the owner's decisions, and section 10
//!   says outright that an operating-system identity is not that decision. Both methods carry the
//!   owner's confirmation of one exact action: the challenge this host issued and is still
//!   holding, answered under the enrolled signer, bound to the root or the release in front of the
//!   owner, and consumed here so one ceremony authorises one action.
//! * Enlarging trust is never a side effect of another method. A sync verifies inside the ceiling
//!   the enrolment already has and refuses a generation that would need more; an install refuses a
//!   grant wider than the installation already held and names `plugin.grant`, which is the method
//!   whose whole purpose is that decision.
//!
//! Sync and installation reach the network and the filesystem and are slow. They run on the
//! daemon's runtime under the caller's own request, and the catalogue's own atomic activation is
//! what makes an interrupted one safe rather than anything this module does.

use std::sync::Arc;

use kr_plugin_runtime::catalogue::{
    CapabilityCeiling, Catalogue, CatalogueError, Enrolment, Installation, InstallationGrant,
    RepositoryId, RepositoryKind, capability_from_str,
};
use kr_plugin_sdk::capability::PluginCapability;
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::version::PackageVersion;
use kr_protocol::catalogue as wire;
use kr_protocol::envelope::{
    ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{
    ActionId, ActorId, EnvironmentId, PluginId, RepositoryGeneration, RequestId,
};
use kr_protocol::method::{Method, MethodGroup};
use kr_protocol::scalars::{Digest256, Nullable, U64};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::sync::Mutex;

use crate::sharing::{ConfirmedAction, OwnerConfirmations};

/// What a catalogue call answers with: the method's result, or the refusal the service decided.
pub type Answer<T> = std::result::Result<T, ProtocolError>;

#[derive(Debug, Serialize, Deserialize)]
struct ActionRecord {
    digest: String,
    state: String,
    result: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
        text
    })
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

fn action_path(root: &Path, actor_id: &ActorId, action_id: ActionId) -> PathBuf {
    root.join("actions").join(format!(
        "{}-{action_id}.json",
        hex(&kr_cbor::sha256(actor_id.as_str().as_bytes())[..8])
    ))
}

fn read_action_record(
    root: &Path,
    actor_id: &ActorId,
    action_id: ActionId,
    digest: &Digest256,
) -> Answer<Option<ParamsValue>> {
    let path = action_path(root, actor_id, action_id);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(ProtocolError::new(
                ErrorCode::StorageUnavailable,
                format!(
                    "failed to read action record at {}: {error}",
                    path.display()
                ),
            ));
        }
    };
    let record: ActionRecord = serde_json::from_str(&text)
        .map_err(|error| ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string()))?;
    if record.digest != hex(digest.as_bytes()) {
        return Err(ProtocolError::new(
            ErrorCode::IdConflict,
            format!("action {action_id} was already used with different parameters"),
        ));
    }
    match (record.state.as_str(), record.result, record.error) {
        ("applied", Some(result_hex), _) => {
            let bytes = unhex(&result_hex).ok_or_else(|| {
                ProtocolError::new(ErrorCode::StorageUnavailable, "unreadable retained result")
            })?;
            let value = kr_cbor::decode(&bytes, &kr_cbor::Limits::DEFAULT).map_err(|error| {
                ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string())
            })?;
            Ok(Some(ParamsValue::new(value)))
        }
        ("applied", None, _) => Ok(Some(ParamsValue::empty())),
        ("failed", _, Some(err_msg)) => Err(ProtocolError::new(
            ErrorCode::OutcomeUnknown,
            format!("action {action_id} previously failed: {err_msg}"),
        )),
        ("dispatching", _, _) => Err(ProtocolError::new(
            ErrorCode::OutcomeUnknown,
            format!(
                "action {action_id} is in progress or was interrupted; read status before retrying"
            ),
        )),
        _ => Err(ProtocolError::new(
            ErrorCode::OutcomeUnknown,
            format!("action {action_id} was recorded in unknown state"),
        )),
    }
}

fn write_action_record(
    root: &Path,
    actor_id: &ActorId,
    action_id: ActionId,
    record: &ActionRecord,
) -> Answer<()> {
    let path = action_path(root, actor_id, action_id);
    let parent = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)
        .map_err(|error| ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string()))?;
    let text = serde_json::to_string_pretty(record)
        .map_err(|error| ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string()))?;

    let temporary = parent.join(format!(
        ".{}-{}.tmp",
        action_id,
        hex(&kr_cbor::sha256(kr_ipc::new_uuid().as_bytes())[..6])
    ));
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string()))?;
    file.write_all(text.as_bytes())
        .map_err(|error| ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string()))?;
    file.sync_all()
        .map_err(|error| ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string()))?;
    drop(file);
    std::fs::rename(&temporary, &path)
        .map_err(|error| ProtocolError::new(ErrorCode::StorageUnavailable, error.to_string()))?;
    #[cfg(unix)]
    {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

fn mark_dispatching(
    root: &Path,
    actor_id: &ActorId,
    action_id: ActionId,
    digest: &Digest256,
) -> Answer<()> {
    write_action_record(
        root,
        actor_id,
        action_id,
        &ActionRecord {
            digest: hex(digest.as_bytes()),
            state: "dispatching".to_owned(),
            result: None,
            error: None,
        },
    )
}

fn settle_action(
    root: &Path,
    actor_id: &ActorId,
    action_id: ActionId,
    digest: &Digest256,
    result: &ParamsValue,
) -> Answer<()> {
    let encoded = hex(&kr_cbor::encode(result.as_value()));
    write_action_record(
        root,
        actor_id,
        action_id,
        &ActionRecord {
            digest: hex(digest.as_bytes()),
            state: "applied".to_owned(),
            result: Some(encoded),
            error: None,
        },
    )
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
    /// # Errors
    ///
    /// Returns [`crate::ControllerError::RegistryUnavailable`] when the catalogue's directory,
    /// its trust roots or its state cannot be read.
    pub fn open(paths: &kr_ipc::paths::EnvironmentPaths) -> crate::Result<Self> {
        let root = paths.state_dir().join("catalogue");
        let catalogue = Catalogue::open(&root).map_err(|error| {
            crate::ControllerError::RegistryUnavailable {
                detail: error.to_string(),
            }
        })?;
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
    pub async fn read_frame(&self, request: &Request) -> ControlFrame {
        frame(request.request_id, self.read(request).await)
    }

    /// Serves one catalogue or plugin read.
    ///
    /// # Errors
    ///
    /// Returns the refusal the catalogue decided, under the catalogue's own code.
    pub async fn read(&self, request: &Request) -> Answer<ParamsValue> {
        let Some(method) = request.method.method() else {
            return Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "the method is not in the registry",
            ));
        };
        match kr_protocol::method::decide(
            request.method.as_str(),
            request.method_version,
            kr_protocol::actor::ActorIngress::LocalIpc,
        ) {
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
                encode(&wire::CatalogueListResult {
                    catalogues: summaries(&catalogue)?,
                })
            }
            Method::PluginList => {
                let params: wire::PluginListParams = typed(&request.params)?;
                self.check_environment(params.environment_id)?;
                encode(&wire::PluginListResult {
                    plugins: plugin_summaries(&catalogue, params.environment_id)?,
                })
            }
            Method::PluginCapabilities => {
                let params: wire::PluginCapabilitiesParams = typed(&request.params)?;
                self.check_environment(params.environment_id)?;
                let installation =
                    installation_of(&catalogue, params.environment_id, &params.plugin_id)?;
                let decisions = catalogue
                    .capabilities(
                        &installation.repository,
                        params.environment_id,
                        &params.plugin_id,
                    )
                    .map_err(ProtocolError::from)?;
                let active = catalogue
                    .active(&installation.repository)
                    .map_err(ProtocolError::from)?;
                let generation = active.map(|a| a.generation).unwrap_or(1);
                let evidence_records = if let Ok(index) = catalogue.index(&installation.repository)
                    && let Some(entry) =
                        index.find(&plugin_id_of(&installation)?, &installation.version)
                {
                    evidence(entry, &installation, generation)?
                } else {
                    let now = kr_protocol::scalars::TimestampMs::new(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|elapsed| elapsed.as_millis().min(u128::from(u64::MAX)) as u64)
                            .unwrap_or(0),
                    );
                    let revision = kr_protocol::ids::CapabilityRevision::new(generation.max(1));
                    installation
                        .requested
                        .iter()
                        .map(|request| {
                            let id = capability_id(request.capability)?;
                            Ok(wire::PluginCapabilityEvidence {
                                capability: id,
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
                                disabled_reason: Nullable(Some("the package is installed offline and the catalogue has no qualification data for it".to_owned())),
                                observed_at_ms: now,
                            })
                        })
                        .collect::<Answer<Vec<_>>>()?
                };
                encode(&wire::PluginCapabilitiesResult {
                    plugin: summary_of(&catalogue, &installation)?,
                    capabilities: grants(&installation.requested, &decisions)?,
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
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id).ok()?;
        let catalogue = self.catalogue.lock().await;
        match read_action_record(catalogue.root(), actor_id, mutation.action_id, &digest) {
            Ok(Some(result)) => Some(ControlFrame::Response(Response {
                request_id: mutation.request_id,
                outcome: Outcome::Ok(result),
            })),
            Ok(None) => None,
            Err(error) => Some(frame(mutation.request_id, Err(error))),
        }
    }

    /// Serves one catalogue or plugin mutation and returns the frame it answers with.
    #[must_use]
    pub async fn write_frame<A>(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        confirmations: Option<&dyn OwnerConfirmations>,
        admission: A,
    ) -> ControlFrame
    where
        A: Fn() -> Answer<()> + Send + Sync,
    {
        frame(
            mutation.request_id,
            self.write(actor_id, mutation, method, confirmations, admission)
                .await,
        )
    }

    /// Serves one catalogue or plugin mutation with automatic admission and a default actor.
    #[must_use]
    pub async fn write_frame_admitted(
        &self,
        mutation: &MutationRequest,
        method: Method,
        confirmations: Option<&dyn OwnerConfirmations>,
    ) -> ControlFrame {
        let actor = ActorId::new("kr:local").expect("a default actor");
        self.write_frame(&actor, mutation, method, confirmations, || Ok(()))
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
    pub async fn write<A>(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        method: Method,
        confirmations: Option<&dyn OwnerConfirmations>,
        admission: A,
    ) -> Answer<ParamsValue>
    where
        A: Fn() -> Answer<()> + Send + Sync,
    {
        let mut catalogue = self.catalogue.lock().await;
        admission()?;
        let digest = kr_protocol::digest::mutation_digest(mutation, actor_id)
            .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))?;
        if let Some(retained) =
            read_action_record(catalogue.root(), actor_id, mutation.action_id, &digest)?
        {
            return Ok(retained);
        }
        mark_dispatching(catalogue.root(), actor_id, mutation.action_id, &digest)?;
        let outcome = self
            .perform_write(&mut catalogue, mutation, method, confirmations, &admission)
            .await;
        match outcome {
            Ok(result) => {
                settle_action(
                    catalogue.root(),
                    actor_id,
                    mutation.action_id,
                    &digest,
                    &result,
                )?;
                Ok(result)
            }
            Err(error) => {
                let _ = write_action_record(
                    catalogue.root(),
                    actor_id,
                    mutation.action_id,
                    &ActionRecord {
                        digest: hex(digest.as_bytes()),
                        state: "failed".to_owned(),
                        result: None,
                        error: Some(error.message.clone()),
                    },
                );
                Err(error)
            }
        }
    }

    async fn perform_write(
        &self,
        catalogue: &mut Catalogue,
        mutation: &MutationRequest,
        method: Method,
        confirmations: Option<&dyn OwnerConfirmations>,
        admission: &(impl Fn() -> Answer<()> + Send + Sync),
    ) -> Answer<ParamsValue> {
        let mut admit =
            || admission().map_err(|e| CatalogueError::PermissionDenied { detail: e.message });
        match method {
            Method::CatalogueAdd => {
                let params: wire::CatalogueAddParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                let enrolment = enrolment_from(&params)?;
                let id = enrolment.id.clone();
                // Adopting a root is the owner's act. The confirmation names this repository, this
                // root and this ceiling, so one obtained for a narrower enrolment does not adopt a
                // wider one. Re-anchoring an existing repository is two deliberate acts,
                // `catalogue.remove` and `catalogue.add`, so that a root never changes underneath
                // a repository somebody is already using.
                let plan = crate::sharing::CatalogueTrustPlan {
                    environment_id: params.environment_id,
                    catalogue_id: id.to_string(),
                    root_digest: enrolment.root_digest().to_string(),
                    root_key_ids: enrolment
                        .root_key_ids()
                        .map_err(ProtocolError::from)?
                        .into_iter()
                        .collect(),
                    ceiling: params.ceiling.iter().cloned().collect(),
                };
                let confirmed = confirm(
                    confirmations,
                    crate::sharing::CatalogueTrustPlan::sensitive_action(),
                    plan.action_digest(),
                    &params.owner_confirmation,
                    "enrolment",
                )?;
                // Again, immediately before the effect. A confirmation has a short lifetime, and
                // the checks and the store's lock between the acceptance and here take time.
                recheck(confirmations, &confirmed, plan.action_digest(), "enrolment")?;
                admission()?;
                catalogue
                    .enrol_with_admission(enrolment, true, &mut admit)
                    .map_err(ProtocolError::from)?;
                let catalogues = summaries(catalogue)?;
                let catalogue_summary = catalogues
                    .into_iter()
                    .find(|summary| summary.catalogue_id == id.as_str())
                    .ok_or_else(|| {
                        ProtocolError::new(
                            ErrorCode::StorageUnavailable,
                            "the repository was enrolled and could not be read back",
                        )
                    })?;
                encode(&wire::CatalogueAddResult {
                    catalogue: catalogue_summary,
                })
            }
            Method::CatalogueSync => {
                let params: wire::CatalogueSyncParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                let id = repository_id(&params.catalogue_id)?;
                admission()?;
                let outcome = catalogue
                    .sync_with_admission(&id, &mut admit)
                    .await
                    .map_err(ProtocolError::from)?;
                encode(&wire::CatalogueSyncResult {
                    generation: outcome.generation,
                    entries: U64::new(outcome.entries as u64),
                    index_bytes: U64::new(outcome.index_bytes),
                    mirrored_payloads: U64::new(outcome.mirrored_payloads as u64),
                    delegations: outcome
                        .delegations
                        .into_iter()
                        .map(|(role, publisher_id)| wire::CatalogueDelegation {
                            role,
                            publisher_id,
                        })
                        .collect(),
                })
            }
            Method::CataloguePin => {
                let params: wire::CataloguePinParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                let id = repository_id(&params.catalogue_id)?;
                admission()?;
                catalogue
                    .pin_with_admission(&id, params.generation.0, &mut admit)
                    .map_err(ProtocolError::from)?;
                let summary = summaries(catalogue)?
                    .into_iter()
                    .find(|summary| summary.catalogue_id == id.as_str())
                    .ok_or_else(|| {
                        ProtocolError::new(
                            ErrorCode::ResourceUnavailable,
                            "the repository is not enrolled",
                        )
                    })?;
                encode(&wire::CataloguePinResult { catalogue: summary })
            }
            Method::CatalogueRemove => {
                let params: wire::CatalogueRemoveParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                let id = repository_id(&params.catalogue_id)?;
                // A package installed from this repository stays installed, on the hash it was
                // installed at. Removing a repository is not a way to uninstall things somebody
                // is using, and the answer names what is still there.
                let installed: Vec<PluginId> = catalogue
                    .installations()
                    .all()
                    .into_iter()
                    .filter(|installation| installation.repository == id)
                    .map(plugin_id_of)
                    .collect::<Answer<Vec<_>>>()?;
                admission()?;
                catalogue
                    .remove_repository_with_admission(&id, &mut admit)
                    .map_err(ProtocolError::from)?;
                encode(&wire::CatalogueRemoveResult {
                    catalogue_id: id.to_string(),
                    installed_packages: installed,
                })
            }
            Method::PluginInstall => {
                let params: wire::PluginInstallParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                let id = repository_id(&params.catalogue_id)?;
                let version = version(&params.version)?;
                let digest = digest(&params.package_digest)?;
                let grant = grant_from(&params.grant)?;
                if grant.holds(PluginCapability::NativeBridgeInstall) {
                    return Err(ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        "granting native_bridge.install requires the owner confirmation ceremony via plugin.grant",
                    ));
                }
                admission()?;
                let installation = catalogue
                    .install_with_admission(
                        &id,
                        params.environment_id,
                        &params.plugin_id,
                        &version,
                        digest,
                        grant,
                        &mut admit,
                    )
                    .await
                    .map_err(ProtocolError::from)?;
                let decisions = catalogue
                    .capabilities(&id, params.environment_id, &params.plugin_id)
                    .map_err(ProtocolError::from)?;
                encode(&wire::PluginInstallResult {
                    plugin: summary_of(catalogue, &installation)?,
                    capabilities: grants(&installation.requested, &decisions)?,
                })
            }
            Method::PluginRemove => {
                let params: wire::PluginRemoveParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                admission()?;
                let closed = catalogue
                    .uninstall_with_admission(params.environment_id, &params.plugin_id, &mut admit)
                    .map_err(ProtocolError::from)?;
                encode(&wire::PluginRemoveResult {
                    plugin_id: params.plugin_id,
                    closed_bindings: U64::new(closed as u64),
                })
            }
            Method::PluginPin => {
                let params: wire::PluginPinParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                let pin = params.package_digest.0.as_deref().map(digest).transpose()?;
                admission()?;
                let installation = catalogue
                    .pin_package_with_admission(
                        params.environment_id,
                        &params.plugin_id,
                        pin,
                        &mut admit,
                    )
                    .map_err(ProtocolError::from)?;
                encode(&wire::PluginPinResult {
                    plugin: summary_of(catalogue, &installation)?,
                })
            }
            Method::PluginEnable | Method::PluginDisable => {
                let params: wire::PluginEnableParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                admission()?;
                let installation = catalogue
                    .set_enabled_with_admission(
                        params.environment_id,
                        &params.plugin_id,
                        method == Method::PluginEnable,
                        &mut admit,
                    )
                    .await
                    .map_err(ProtocolError::from)?;
                encode(&wire::PluginEnableResult {
                    plugin: summary_of(catalogue, &installation)?,
                })
            }
            Method::PluginGrant => {
                let params: wire::PluginGrantParams = typed(&mutation.params)?;
                self.check_environment(params.environment_id)?;
                let grant = grant_from(&params.grant)?;
                // The grant is about the release the owner was shown. An installation that moved
                // on is a different decision, so the digest is checked before the confirmation is
                // even read rather than the change being applied to whatever is installed now.
                let installed =
                    installation_of(catalogue, params.environment_id, &params.plugin_id)?;
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
                let confirmed = confirm(
                    confirmations,
                    crate::sharing::PluginGrantPlan::sensitive_action(),
                    plan.action_digest(),
                    &params.owner_confirmation,
                    "grant",
                )?;
                recheck(confirmations, &confirmed, plan.action_digest(), "grant")?;
                admission()?;
                let installation = catalogue
                    .set_grant_with_admission(
                        params.environment_id,
                        &params.plugin_id,
                        grant,
                        &mut admit,
                    )
                    .map_err(ProtocolError::from)?;
                let decisions = catalogue
                    .capabilities(
                        &installation.repository,
                        params.environment_id,
                        &params.plugin_id,
                    )
                    .map_err(ProtocolError::from)?;
                encode(&wire::PluginGrantResult {
                    plugin: summary_of(catalogue, &installation)?,
                    capabilities: grants(&installation.requested, &decisions)?,
                })
            }
            _ => Err(ProtocolError::new(
                ErrorCode::PermissionDenied,
                format!("{} is not a mutation this daemon serves", method.as_str()),
            )),
        }
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

fn summaries(catalogue: &Catalogue) -> Answer<Vec<wire::CatalogueSummary>> {
    let mut summaries = Vec::new();
    for enrolment in catalogue.repositories() {
        let active = catalogue
            .active(&enrolment.id)
            .map_err(ProtocolError::from)?;
        let entries = catalogue
            .index(&enrolment.id)
            .map(|index| index.entries.len() as u64)
            .unwrap_or(0);
        summaries.push(wire::CatalogueSummary {
            catalogue_id: enrolment.id.to_string(),
            kind: kind_of(enrolment.kind),
            metadata_url: enrolment.metadata_url.to_string(),
            targets_url: enrolment.targets_url.to_string(),
            root_digest: enrolment.root_digest().to_string(),
            generation: Nullable(active.map(|active| RepositoryGeneration::new(active.generation))),
            pinned_generation: Nullable(enrolment.pinned_generation),
            budgets: wire::CatalogueBudgets {
                metadata_bytes: enrolment.budgets.metadata_bytes,
                metadata_entries: enrolment.budgets.metadata_entries,
                payload_cache_bytes: enrolment.budgets.payload_cache_bytes,
                full_offline_mirror: enrolment.budgets.full_offline_mirror,
            },
            ceiling: enrolment
                .ceiling
                .capabilities()
                .into_iter()
                .map(|capability| capability.as_str().to_owned())
                .collect(),
            entries: U64::new(entries),
            synced_at_ms: Nullable(None),
        });
    }
    Ok(summaries)
}

fn plugin_summaries(
    catalogue: &Catalogue,
    environment_id: EnvironmentId,
) -> Answer<Vec<wire::PluginSummary>> {
    catalogue
        .installations()
        .all()
        .into_iter()
        .filter(|installation| installation.environment_id == environment_id)
        .map(|installation| summary_of(catalogue, installation))
        .collect()
}

fn summary_of(catalogue: &Catalogue, installation: &Installation) -> Answer<wire::PluginSummary> {
    let plugin_id = plugin_id_of(installation)?;
    let revoked = catalogue
        .index(&installation.repository)
        .ok()
        .and_then(|index| {
            index
                .find(&plugin_id, &installation.version)
                .map(|entry| !entry.accepts_new_bindings())
        })
        .unwrap_or(false);
    let live = catalogue
        .installations()
        .bindings()
        .iter()
        .filter(|binding| {
            binding.environment_id == installation.environment_id
                && binding.plugin_id.as_str() == installation.plugin_id.as_str()
        })
        .count();
    Ok(wire::PluginSummary {
        plugin_id,
        catalogue_id: installation.repository.to_string(),
        version: installation.version.to_string(),
        package_digest: installation.package_digest.to_string(),
        environment_id: installation.environment_id,
        enabled: installation.enabled,
        pinned: installation.pinned,
        revoked,
        live_bindings: U64::new(live as u64),
    })
}

fn installation_of(
    catalogue: &Catalogue,
    environment_id: EnvironmentId,
    plugin_id: &PluginId,
) -> Answer<Installation> {
    catalogue
        .installations()
        .all()
        .into_iter()
        .find(|installation| {
            installation.environment_id == environment_id
                && installation.plugin_id.as_str() == plugin_id.as_str()
        })
        .cloned()
        .ok_or_else(|| {
            ProtocolError::new(
                ErrorCode::ResourceUnavailable,
                format!("{plugin_id} is not installed in this environment"),
            )
        })
}

fn grants(
    requested: &[kr_plugin_sdk::capability::CapabilityRequest],
    decisions: &[kr_plugin_runtime::catalogue::CapabilityDecision],
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
        match kr_plugin_runtime::catalogue::evidence::from_qualification(
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
    for request in &entry.capabilities {
        let id = capability_id(request.capability)?;
        if records.iter().any(|record| record.capability == id) {
            continue;
        }
        let record = kr_plugin_runtime::catalogue::evidence::untested(
            entry,
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
    kr_plugin_runtime::catalogue::evidence::capability_id(capability).map_err(ProtocolError::from)
}

const fn requirement_of(
    requirement: kr_plugin_runtime::catalogue::GrantRequirement,
) -> wire::PluginGrantRequirement {
    use kr_plugin_runtime::catalogue::GrantRequirement as Source;
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
/// A host with no enrolled owner signer has no way to obtain a confirmation, and section 10 does
/// not let it fall back to the identity of whoever called. It refuses, and says why.
fn confirm(
    confirmations: Option<&dyn OwnerConfirmations>,
    action: kr_protocol::pairing::SensitiveAction,
    action_digest: crate::Result<kr_protocol::scalars::Digest256>,
    proof: &kr_protocol::pairing::OwnerConfirmationProof,
    subject: &str,
) -> Answer<ConfirmedAction> {
    let confirmations = confirmations.ok_or_else(|| {
        ProtocolError::new(
            ErrorCode::PermissionDenied,
            format!(
                "this {subject} needs the owner's confirmation and this host has no enrolled \
                 owner signer to check one against"
            ),
        )
    })?;
    let digest = action_digest.map_err(|error| error.to_protocol_error())?;
    confirmations
        .accept(action, digest, proof)
        .map_err(|error| error.to_protocol_error())
}

/// Checks the confirmation again immediately before the effect.
///
/// A confirmation is for a decision the owner is making now. Between the acceptance above and the
/// store's own lock there is parsing, a catalogue lock and whatever else is queued, and one
/// carried past its short deadline is no longer that decision.
fn recheck(
    confirmations: Option<&dyn OwnerConfirmations>,
    confirmed: &ConfirmedAction,
    action_digest: crate::Result<kr_protocol::scalars::Digest256>,
    subject: &str,
) -> Answer<()> {
    let confirmations = confirmations.ok_or_else(|| {
        ProtocolError::new(
            ErrorCode::PermissionDenied,
            format!("this {subject} needs the owner's confirmation"),
        )
    })?;
    let digest = action_digest.map_err(|error| error.to_protocol_error())?;
    confirmed
        .covers(
            digest,
            confirmations.host_device_id(),
            confirmations.clock(),
            subject,
        )
        .map_err(|error| error.to_protocol_error())
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
        use kr_plugin_runtime::catalogue::CatalogueError;
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
